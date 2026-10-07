// Copyright 2026 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tarball_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/compare"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

// failingLayer models a layer whose compression stream short-writes or whose
// Close surfaces an error mid-export.
type failingLayer struct{}

func (failingLayer) Digest() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, nil
}
func (failingLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}, nil
}
func (failingLayer) Compressed() (io.ReadCloser, error) {
	return nil, errors.New("simulated compression stream failure")
}
func (failingLayer) Uncompressed() (io.ReadCloser, error) {
	return nil, errors.New("simulated layer failure")
}
func (failingLayer) Size() (int64, error)                { return 42, nil }
func (failingLayer) MediaType() (types.MediaType, error) { return types.DockerLayer, nil }

func failingImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: failingLayer{}})
	if err != nil {
		t.Fatalf("mutate.Append: %v", err)
	}
	return img
}

func randomTagImage(t *testing.T, size int64, layers int64) (v1.Image, name.Tag) {
	t.Helper()
	img, err := random.Image(size, layers)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	tag, err := name.NewTag("gcr.io/foo/bar:latest")
	if err != nil {
		t.Fatalf("name.NewTag: %v", err)
	}
	return img, tag
}

// pendingCandidates returns unconfirmed candidate files left in dir for base.
func pendingCandidates(t *testing.T, dir, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+base+".tmp-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func assertLoadable(t *testing.T, p string, want v1.Image) {
	t.Helper()
	got, err := tarball.ImageFromPath(p, nil)
	if err != nil {
		t.Fatalf("ImageFromPath(%q): %v", p, err)
	}
	if err := validate.Image(got); err != nil {
		t.Fatalf("validate.Image: %v", err)
	}
	if want != nil {
		if err := compare.Images(want, got); err != nil {
			t.Fatalf("archive content mismatch: %v", err)
		}
	}
}

// A failed export must keep serving the previously confirmed archive and
// must not leave an unconfirmed candidate behind.
func TestWriteToFileFailureKeepsPreviousArchive(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")

	good, tag := randomTagImage(t, 256, 3)
	if err := tarball.WriteToFile(p, tag, good); err != nil {
		t.Fatalf("initial WriteToFile: %v", err)
	}

	if err := tarball.WriteToFile(p, tag, failingImage(t)); err == nil {
		t.Fatal("expected failing export to return an error")
	}

	assertLoadable(t, p, good)
	if left := pendingCandidates(t, dir, "image.tar"); len(left) != 0 {
		t.Fatalf("failed export left unconfirmed candidates: %v", left)
	}
}

// When no archive exists yet, a failed export must not create the target at
// all (so nothing half-written is mistaken for a complete image).
func TestWriteToFileFailureLeavesNoTarget(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")

	_, tag := randomTagImage(t, 64, 1)
	if err := tarball.WriteToFile(p, tag, failingImage(t)); err == nil {
		t.Fatal("expected failing export to return an error")
	}

	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("target should not exist after failed first export, stat err=%v", err)
	}
	if left := pendingCandidates(t, dir, "image.tar"); len(left) != 0 {
		t.Fatalf("failed export left unconfirmed candidates: %v", left)
	}
}

// Repeated exports replace the archive and preserve its permission bits.
func TestWriteToFileRepeatedExportAndPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")

	first, tag := randomTagImage(t, 128, 1)
	if err := tarball.WriteToFile(p, tag, first); err != nil {
		t.Fatalf("first WriteToFile: %v", err)
	}

	// New files carry the mode os.Create would have used: 0666 & umask.
	ref, err := os.Create(filepath.Join(dir, "ref"))
	if err != nil {
		t.Fatal(err)
	}
	wantNewMode := ref2Mode(t, ref)
	_ = ref.Close()
	if got := fileMode(t, p); got != wantNewMode {
		t.Fatalf("new archive mode = %o, want %o", got, wantNewMode)
	}

	// Restrict the confirmed archive; the replacement must keep those bits.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	second, tag2 := randomTagImage(t, 256, 2)
	if err := tarball.WriteToFile(p, tag2, second); err != nil {
		t.Fatalf("second WriteToFile: %v", err)
	}
	assertLoadable(t, p, second)
	if got := fileMode(t, p); got != 0o600 {
		t.Fatalf("replaced archive mode = %o, want 0600", got)
	}
	if left := pendingCandidates(t, dir, "image.tar"); len(left) != 0 {
		t.Fatalf("unconfirmed candidates left behind: %v", left)
	}
}

// Stale candidates abandoned by dead processes are recovered or removed,
// without touching unrelated files.
func TestWriteToFileReapsStaleCandidates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")

	// A complete candidate that was never renamed (crashed right at commit).
	var good bytes.Buffer
	goodImg, tag := randomTagImage(t, 128, 1)
	if err := tarball.Write(tag, goodImg, &good); err != nil {
		t.Fatalf("tarball.Write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".image.tar.tmp-abandoned-good"), good.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// And a half-written one.
	if err := os.WriteFile(filepath.Join(dir, ".image.tar.tmp-abandoned-bad"), []byte("half archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Unrelated files must be left exactly as they were.
	if err := os.WriteFile(filepath.Join(dir, "keepme"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".other.tar.tmp-x"), []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}

	next, nextTag := randomTagImage(t, 256, 2)
	if err := tarball.WriteToFile(p, nextTag, next); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}

	assertLoadable(t, p, next)
	if left := pendingCandidates(t, dir, "image.tar"); len(left) != 0 {
		t.Fatalf("stale candidates not reaped: %v", left)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "keepme")); err != nil || string(b) != "keep" {
		t.Fatalf("unrelated file was altered: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, ".other.tar.tmp-x")); err != nil || string(b) != "other" {
		t.Fatalf("another target's candidate was altered: %q %v", b, err)
	}
}

// If the fresh export fails but an abandoned complete candidate exists, the
// destination is recovered to that complete archive.
func TestWriteToFileFailureRecoversCompleteCandidate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")

	var good bytes.Buffer
	goodImg, tag := randomTagImage(t, 128, 1)
	if err := tarball.Write(tag, goodImg, &good); err != nil {
		t.Fatalf("tarball.Write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".image.tar.tmp-abandoned"), good.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := tarball.WriteToFile(p, tag, failingImage(t)); err == nil {
		t.Fatal("expected failing export to return an error")
	}

	// Target now holds the recovered complete candidate rather than nothing.
	assertLoadable(t, p, goodImg)
	if left := pendingCandidates(t, dir, "image.tar"); len(left) != 0 {
		t.Fatalf("unconfirmed candidates left behind: %v", left)
	}
}

// Concurrent exports to the same destination must all succeed, always leave
// a loadable archive, and never leave candidates behind.
func TestWriteToFileConcurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			img, _ := randomTagImage(t, 512, 2)
			tag, err := name.NewTag(fmt.Sprintf("gcr.io/foo/bar:%02d", i))
			if err != nil {
				errs <- err
				return
			}
			errs <- tarball.WriteToFile(p, tag, img)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent WriteToFile: %v", err)
		}
	}

	got, err := tarball.ImageFromPath(p, nil)
	if err != nil {
		t.Fatalf("ImageFromPath after concurrent exports: %v", err)
	}
	if err := validate.Image(got); err != nil {
		t.Fatalf("validate.Image: %v", err)
	}
	if left := pendingCandidates(t, dir, "image.tar"); len(left) != 0 {
		t.Fatalf("concurrent exports left candidates: %v", left)
	}
}

// A failed export to one destination must never remove another destination's
// confirmed archive (or its lock/candidates).
func TestWriteToFileFailureDoesNotTouchOtherTarget(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.tar")
	b := filepath.Join(dir, "b.tar")

	imgA, tagA := randomTagImage(t, 64, 1)
	imgB, tagB := randomTagImage(t, 64, 1)
	if err := tarball.WriteToFile(a, tagA, imgA); err != nil {
		t.Fatalf("WriteToFile(a): %v", err)
	}
	if err := tarball.WriteToFile(b, tagB, imgB); err != nil {
		t.Fatalf("WriteToFile(b): %v", err)
	}

	if err := tarball.WriteToFile(a, tagA, failingImage(t)); err == nil {
		t.Fatal("expected failing export to return an error")
	}

	assertLoadable(t, b, imgB)
	if _, err := os.Stat(filepath.Join(dir, ".b.tar.lock")); err != nil {
		t.Fatalf("other target's lock must not be removed: %v", err)
	}
}

func fileMode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat(%q): %v", p, err)
	}
	return fi.Mode().Perm()
}

func ref2Mode(t *testing.T, f *os.File) os.FileMode {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	return fi.Mode().Perm()
}
