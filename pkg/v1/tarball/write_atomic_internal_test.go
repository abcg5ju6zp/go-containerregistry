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

package tarball

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

// buildArchive assembles a docker-save style tar in memory.
// missing omits the layer member to simulate a short write.
func buildArchive(t *testing.T, missing bool) []byte {
	t.Helper()
	var layer bytes.Buffer
	gw := gzip.NewWriter(&layer)
	if _, err := gw.Write([]byte("layer contents")); err != nil {
		t.Fatalf("gzip Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:0000000000000000000000000000000000000000000000000000000000000000"]}}`)
	manifest := []byte(`[{"Config":"config.json","RepoTags":["gcr.io/foo/bar:latest"],"Layers":["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz"]}]`)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeEntry := func(name string, data []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("WriteHeader(%q): %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("Write(%q): %v", name, err)
		}
	}
	writeEntry("config.json", config)
	if !missing {
		writeEntry("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz", layer.Bytes())
	}
	writeEntry("manifest.json", manifest)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

func TestVerifyArchive(t *testing.T) {
	good := buildArchive(t, false)
	if err := verifyArchive(bytes.NewReader(good)); err != nil {
		t.Fatalf("verifyArchive(valid): %v", err)
	}

	if err := verifyArchive(bytes.NewReader(good[:len(good)/2])); err == nil {
		t.Fatal("verifyArchive(truncated): expected error, got nil")
	}

	if err := verifyArchive(bytes.NewReader([]byte("not a tarball"))); err == nil {
		t.Fatal("verifyArchive(garbage): expected error, got nil")
	}
}

func TestVerifyArchiveMissingMember(t *testing.T) {
	// Manifest references a layer that is not actually in the archive,
	// modeling a short-write the tar writer padded with zero blocks.
	err := verifyArchive(bytes.NewReader(buildArchive(t, true)))
	if err == nil || !strings.Contains(err.Error(), "0123456789abcdef") {
		t.Fatalf("expected missing layer error, got: %v", err)
	}
}

func TestVerifyArchiveEmptyManifest(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	manifest := []byte("[]")
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0644, Size: int64(len(manifest))}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := verifyArchive(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("expected error for empty manifest, got nil")
	}
}

func TestRecoverOrRemoveStaleCandidates(t *testing.T) {
	dir := t.TempDir()
	good := buildArchive(t, false)
	target := dir + "/image.tar"

	// A complete but never-committed candidate and a half-written one.
	if err := os.WriteFile(dir+"/.image.tar.tmp-deadbeef-good", good, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/.image.tar.tmp-deadbeef-bad", []byte("half archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A candidate belonging to a different destination must be left alone.
	if err := os.WriteFile(dir+"/.other.tar.tmp-cafe", []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}

	recoverOrRemoveStaleCandidates(dir, "image.tar", target)

	if got, err := os.ReadFile(target); err != nil {
		t.Fatalf("valid stale candidate should have been recovered as target: %v", err)
	} else if !bytes.Equal(got, good) {
		t.Fatal("recovered target does not match the complete candidate")
	}
	if _, err := os.Stat(dir + "/.image.tar.tmp-deadbeef-good"); !os.IsNotExist(err) {
		t.Fatal("recovered candidate should be gone after promotion")
	}
	if _, err := os.Stat(dir + "/.image.tar.tmp-deadbeef-bad"); !os.IsNotExist(err) {
		t.Fatal("corrupt stale candidate should have been removed")
	}
	if _, err := os.ReadFile(dir + "/.other.tar.tmp-cafe"); err != nil {
		t.Fatalf("unrelated candidate must not be touched: %v", err)
	}

	// Running the sweep again with nothing pending is a no-op and keeps the
	// confirmed target readable.
	recoverOrRemoveStaleCandidates(dir, "image.tar", target)
	if err := verifyTarball(target); err != nil {
		t.Fatalf("target no longer verifies after second sweep: %v", err)
	}
}

func TestCreateCandidateFileUnique(t *testing.T) {
	dir := t.TempDir()
	seen := map[string]bool{}
	for range 32 {
		f, name, err := createCandidateFile(dir, "image.tar")
		if err != nil {
			t.Fatalf("createCandidateFile: %v", err)
		}
		if seen[name] {
			t.Fatalf("duplicate candidate name %q", name)
		}
		seen[name] = true
		_ = f.Close()
	}
}
