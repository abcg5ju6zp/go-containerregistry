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

package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

func publishTestRegistry(t *testing.T, h http.Handler) (*httptest.Server, name.Repository) {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := name.NewRepository(fmt.Sprintf("%s/atomic", u.Host), name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	return s, repo
}

func publishHeadDigest(t *testing.T, ref name.Reference) (v1.Hash, bool) {
	t.Helper()
	got, err := Head(ref)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return v1.Hash{}, false
		}
		t.Fatalf("Head(%v): %v", ref, err)
	}
	return got.Digest, true
}

type byteCounter struct {
	rc io.ReadCloser
	n  *int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}
func (c *byteCounter) Close() error { return c.rc.Close() }

// TestFreezeManifestValidGraph enumerates every manifest and blob edge of a
// multi-platform index and gates confirmation correctly.
func TestFreezeManifestValidGraph(t *testing.T) {
	idx, err := random.Index(1024, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	m, err := taggableToManifest(idx)
	if err != nil {
		t.Fatal(err)
	}
	g, err := freezeManifest(m, false)
	if err != nil {
		t.Fatalf("freezeManifest(): %v", err)
	}

	// Root index + two child images.
	if got, want := len(g.manifests), 3; got != want {
		t.Fatalf("manifests = %d, want %d", got, want)
	}
	// Each child image contributes a config and a layer blob.
	var blobEdges int
	for _, bs := range g.blobs {
		blobEdges += len(bs)
	}
	if got, want := blobEdges, 4; got != want {
		t.Fatalf("blob edges = %d, want %d", got, want)
	}
	if g.root == (v1.Hash{}) {
		t.Fatal("root digest is empty")
	}

	// Nothing confirmed yet: gate must refuse.
	if err := g.gate(newConfirmations()); err == nil {
		t.Fatal("gate() = nil, want error before anything is confirmed")
	}

	// With every child manifest confirmed, their subtrees are transitively
	// satisfied and the gate (an index root has no direct blobs) passes.
	c := newConfirmations()
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range im.Manifests {
		c.mark(d.Digest)
	}
	if err := g.gate(c); err != nil {
		t.Fatalf("gate() with confirmed children = %v", err)
	}
}

// TestFreezeManifestRejectsBrokenIndexBinding ensures a graph that references
// a child digest its content does not have is rejected before any upload.
func TestFreezeManifestRejectsBrokenIndexBinding(t *testing.T) {
	child, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	bogus := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)}
	// The index advertises a bogus digest for content that actually hashes to
	// something else.
	corrupt := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        child,
		Descriptor: v1.Descriptor{Digest: bogus},
	})

	m, err := taggableToManifest(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freezeManifest(m, false); err == nil ||
		!strings.Contains(err.Error(), "descriptor graph mismatch") {
		t.Fatalf("freezeManifest() = %v, want descriptor graph mismatch", err)
	}

	reg := registry.New()
	var uploads, puts int32
	_, repo := publishTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/") {
			atomic.AddInt32(&uploads, 1)
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/") {
			atomic.AddInt32(&puts, 1)
		}
		reg.ServeHTTP(w, r)
	}))
	if err := WriteIndex(repo.Tag("latest"), corrupt); err == nil {
		t.Fatal("WriteIndex() = nil, want error for corrupt graph")
	}
	if got := atomic.LoadInt32(&uploads); got != 0 {
		t.Errorf("blob uploads initiated = %d, want 0", got)
	}
	if got := atomic.LoadInt32(&puts); got != 0 {
		t.Errorf("manifest puts = %d, want 0", got)
	}
}

// wrongConfigImage lies about its config digest.
type wrongConfigImage struct {
	v1.Image
	h v1.Hash
}

func (w *wrongConfigImage) ConfigName() (v1.Hash, error) { return w.h, nil }

func TestFreezeManifestRejectsBrokenConfigBinding(t *testing.T) {
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	bogus := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("f", 64)}
	bad := &wrongConfigImage{Image: img, h: bogus}

	m, err := taggableToManifest(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freezeManifest(m, false); err == nil ||
		!strings.Contains(err.Error(), "descriptor graph mismatch") {
		t.Fatalf("freezeManifest() = %v, want descriptor graph mismatch for config", err)
	}
}

// instrumentedRegistry wraps the in-memory registry with failure injection and
// counters.
type instrumentedRegistry struct {
	reg http.Handler
	t   *testing.T

	mu sync.Mutex
	// rejectManifest, when non-empty, makes PUT manifests/<digest> fail 400.
	rejectManifest string

	patchBytes       int64
	tagPuts          int32
	manifestPuts     int32
	hijackNextTagPUT bool
	// lieHEADTag, when non-empty, is returned as the tag digest on the first
	// tag HEAD after a tag PUT has been observed.
	lieHEADTag string
	lied       int32
}

func (i *instrumentedRegistry) handler(t *testing.T) http.Handler {
	i.t = t
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		isTag := strings.HasSuffix(path, "/manifests/latest")
		isManifest := strings.Contains(path, "/manifests/")

		if r.Method == http.MethodPut && isManifest {
			i.mu.Lock()
			reject := i.rejectManifest
			hijack := i.hijackNextTagPUT && isTag
			i.mu.Unlock()

			if reject != "" && strings.HasSuffix(path, reject) {
				http.Error(w, `{"errors":[{"code":"MANIFEST_INVALID","message":"injected failure"}]}`, http.StatusBadRequest)
				return
			}
			if isTag {
				// Count before any injected transport ambiguity, since the
				// registry does receive the PUT.
				atomic.AddInt32(&i.tagPuts, 1)
			} else {
				atomic.AddInt32(&i.manifestPuts, 1)
			}
			if hijack {
				i.mu.Lock()
				i.hijackNextTagPUT = false
				i.mu.Unlock()
				// Deliver the PUT to the registry, then sever the client
				// connection without a response: an ambiguous outcome that
				// only post-commit verification can decide.
				rec := httptest.NewRecorder()
				i.reg.ServeHTTP(rec, r)
				if rec.Code != http.StatusCreated {
					i.t.Errorf("hijacked registry PUT status = %d, want 201", rec.Code)
				}
				hj, ok := w.(http.Hijacker)
				if !ok {
					i.t.Fatal("ResponseWriter is not a Hijacker")
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					i.t.Fatalf("Hijack: %v", err)
				}
				_ = conn.Close()
				return
			}
		}

		if r.Method == http.MethodHead && isTag && i.lieHEADTag != "" &&
			atomic.LoadInt32(&i.tagPuts) >= 2 &&
			atomic.CompareAndSwapInt32(&i.lied, 0, 1) {
			// Emulate a different complete graph winning the tag between our
			// PUT and our verification.
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			w.Header().Set("Docker-Content-Digest", i.lieHEADTag)
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodPatch && strings.Contains(path, "/blobs/uploads/") {
			r.Body = &byteCounter{rc: r.Body, n: &i.patchBytes}
		}

		i.reg.ServeHTTP(w, r)
	})
}

// TestAtomicPushChildFailureKeepsTagAndReusesBlobs: a rejected child manifest
// leaves the existing tag in place while uploaded blobs persist; a later retry
// reuses them without re-streaming any bytes.
func TestAtomicPushChildFailureKeepsTagAndReusesBlobs(t *testing.T) {
	ir := &instrumentedRegistry{reg: registry.New()}
	_, repo := publishTestRegistry(t, ir.handler(t))
	tag := repo.Tag("latest")

	// Previous good image at the tag.
	oldImg, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(tag, oldImg); err != nil {
		t.Fatalf("initial Write(): %v", err)
	}
	oldDigest, ok := publishHeadDigest(t, tag)
	if !ok {
		t.Fatal("old tag missing after initial push")
	}

	// New multi-platform index; reject one of its child manifests.
	idx, err := random.Index(4096, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	ir.mu.Lock()
	ir.rejectManifest = im.Manifests[0].Digest.String()
	ir.mu.Unlock()

	if err := WriteIndex(tag, idx); err == nil {
		t.Fatal("WriteIndex() = nil, want child manifest failure")
	}

	// Tag must still point at the old image.
	if got, ok := publishHeadDigest(t, tag); !ok || got != oldDigest {
		t.Fatalf("tag after failed push = %v (ok=%v), want unchanged %v", got, ok, oldDigest)
	}
	if atomic.LoadInt64(&ir.patchBytes) == 0 {
		t.Fatal("expected some blobs to have been streamed during the failed attempt")
	}

	// Retry with the failure removed (fresh Pusher, like a new process).
	ir.mu.Lock()
	ir.rejectManifest = ""
	ir.mu.Unlock()
	atomic.StoreInt64(&ir.patchBytes, 0)
	if err := WriteIndex(tag, idx, WithRetryBackoff(fastBackoff)); err != nil {
		t.Fatalf("retry WriteIndex(): %v", err)
	}

	// Every blob was confirmed from the first attempt: zero bytes re-streamed.
	if got := atomic.LoadInt64(&ir.patchBytes); got != 0 {
		t.Errorf("retry streamed %d blob bytes, want 0 (all blobs reused)", got)
	}

	newDigest, ok := publishHeadDigest(t, tag)
	if !ok || newDigest == oldDigest {
		t.Fatalf("tag after retry = %v (ok=%v), want new index digest", newDigest, ok)
	}
	got, err := Index(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Index(got); err != nil {
		t.Fatalf("validate.Index: %v", err)
	}
	gotManifest, err := got.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(gotManifest.Manifests) != 2 {
		t.Fatalf("platforms = %d, want 2", len(gotManifest.Manifests))
	}
}

// TestTagPutAmbiguousConverges verifies that a tag PUT whose response is lost
// after the registry stored the manifest is decided as success by the
// post-commit HEAD, without a second PUT or re-upload.
func TestTagPutAmbiguousConverges(t *testing.T) {
	ir := &instrumentedRegistry{
		reg:              registry.New(),
		hijackNextTagPUT: true,
	}
	_, repo := publishTestRegistry(t, ir.handler(t))
	tag := repo.Tag("latest")

	idx, err := random.Index(4096, 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	// Disable retries so convergence is decided solely by verification.
	if err := WriteIndex(tag, idx, WithRetryPredicate(func(error) bool { return false })); err != nil {
		t.Fatalf("WriteIndex() = %v, want success decided by verification", err)
	}
	if got := atomic.LoadInt32(&ir.tagPuts); got != 1 {
		t.Errorf("tag PUTs = %d, want 1", got)
	}
	got, err := Index(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Index(got); err != nil {
		t.Fatalf("validate.Index: %v", err)
	}
}

// TestConcurrentSameTagSameContent collapses identical concurrent publishes
// through one Pusher into a single tag commit; independent Pushers also
// converge on success.
func TestConcurrentSameTagSameContent(t *testing.T) {
	ir := &instrumentedRegistry{reg: registry.New()}
	_, repo := publishTestRegistry(t, ir.handler(t))
	tag := repo.Tag("latest")

	idx, err := random.Index(4096, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}

	pusher, err := NewPusher()
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pusher.Push(context.Background(), tag, idx); err != nil {
				errMu.Lock()
				firstErr = err
				errMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("concurrent Push: %v", firstErr)
	}

	if got := atomic.LoadInt32(&ir.tagPuts); got != 1 {
		t.Errorf("tag PUTs within one Pusher = %d, want exactly 1", got)
	}
	if got, ok := publishHeadDigest(t, tag); !ok || got != wantDigest {
		t.Fatalf("tag = %v (ok=%v), want %v", got, ok, wantDigest)
	}

	// Independent Pushers (as separate processes) both succeed: identical
	// content means both verify the same wanted digest.
	p1, err := NewPusher()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NewPusher()
	if err != nil {
		t.Fatal(err)
	}
	var wg2 sync.WaitGroup
	for _, p := range []*Pusher{p1, p2} {
		wg2.Add(1)
		go func(p *Pusher) {
			defer wg2.Done()
			if err := p.Push(context.Background(), tag, idx); err != nil {
				errMu.Lock()
				firstErr = err
				errMu.Unlock()
			}
		}(p)
	}
	wg2.Wait()
	if firstErr != nil {
		t.Fatalf("independent Pushers: %v", firstErr)
	}
	if got, ok := publishHeadDigest(t, tag); !ok || got != wantDigest {
		t.Fatalf("tag after independent pushers = %v (ok=%v), want %v", got, ok, wantDigest)
	}
}

// TestConcurrentDifferentContentConflict injects a tag HEAD that resolves to a
// different digest right after an accepted PUT and asserts the decidable
// conflict error.
func TestConcurrentDifferentContentConflict(t *testing.T) {
	ir := &instrumentedRegistry{reg: registry.New()}
	_, repo := publishTestRegistry(t, ir.handler(t))
	tag := repo.Tag("latest")

	// Establish an older image at the tag.
	oldImg, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(tag, oldImg); err != nil {
		t.Fatal(err)
	}
	oldDigest, _ := oldImg.Digest()

	idx, err := random.Index(4096, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The first post-PUT verification HEAD sees the old digest, emulating a
	// concurrent publisher winning the tag between our PUT and verification.
	ir.lieHEADTag = oldDigest.String()

	if err := WriteIndex(tag, idx, WithRetryBackoff(fastBackoff)); !errors.Is(err, ErrTagCommitConflict) {
		t.Fatalf("WriteIndex() = %v, want ErrTagCommitConflict", err)
	}
}

// TestCanceledPushLeavesTagUntouched cancels an in-flight push while a blob
// upload is stalled and asserts the tag is never created; a follow-up push to
// the partially populated registry then completes and validates.
func TestCanceledPushLeavesTagUntouched(t *testing.T) {
	reg := registry.New()
	var once int32
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseStall := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch &&
			strings.Contains(r.URL.Path, "/blobs/uploads/") &&
			atomic.CompareAndSwapInt32(&once, 0, 1) {
			close(started)
			// Stay inflight until the test releases us after canceling the
			// client (client-side cancellation is what the push observes; do
			// not depend on server-side disconnect detection).
			<-release
			return
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		releaseStall()
		srv.Close()
	})

	tag, err := name.NewTag(fmt.Sprintf("%s/atomic:latest", srv.Listener.Addr().String()), name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}

	idx, err := random.Index(8192, 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- WriteIndex(tag, idx, WithContext(ctx)) }()

	<-started
	cancel()
	if err := <-done; err == nil {
		t.Fatal("WriteIndex() = nil, want cancellation error")
	}

	if _, err := Head(tag); err == nil {
		t.Fatal("Head(tag) = nil, want 404 after canceled push")
	}

	// Unblock the stalled handler before the registry needs to serve the
	// follow-up push and be shut down.
	releaseStall()

	if err := WriteIndex(tag, idx); err != nil {
		t.Fatalf("follow-up WriteIndex(): %v", err)
	}
	got, err := Index(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Index(got); err != nil {
		t.Fatalf("validate.Index: %v", err)
	}
}

// TestWriteIndexTagMovedOnlyAfterChildren asserts children are committed before
// the tag and that an identical re-push does no work.
func TestWriteIndexTagMovedOnlyAfterChildren(t *testing.T) {
	ir := &instrumentedRegistry{reg: registry.New()}
	_, repo := publishTestRegistry(t, ir.handler(t))
	tag := repo.Tag("latest")

	idx, err := random.Index(2048, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteIndex(tag, idx); err != nil {
		t.Fatalf("WriteIndex(): %v", err)
	}

	if got, want := atomic.LoadInt32(&ir.manifestPuts), int32(3); got != want {
		t.Errorf("child manifest puts = %d, want %d", got, want)
	}
	if got := atomic.LoadInt32(&ir.tagPuts); got != 1 {
		t.Errorf("tag puts = %d, want 1", got)
	}

	// Identical re-push: convergence fast path, no tag move and no bytes.
	atomic.StoreInt32(&ir.tagPuts, 0)
	atomic.StoreInt64(&ir.patchBytes, 0)
	if err := WriteIndex(tag, idx); err != nil {
		t.Fatalf("re-push WriteIndex(): %v", err)
	}
	if got := atomic.LoadInt32(&ir.tagPuts); got != 0 {
		t.Errorf("no-op repush moved the tag %d times, want 0", got)
	}
	if got := atomic.LoadInt64(&ir.patchBytes); got != 0 {
		t.Errorf("no-op repush streamed %d blob bytes, want 0", got)
	}
}

// TestWriteLayerUnaffected makes sure the layer-only API still uploads a blob
// without touching manifests and reuses the blob on a second call.
func TestWriteLayerUnaffected(t *testing.T) {
	reg := registry.New()
	var manifestTouches int32
	_, repo := publishTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			atomic.AddInt32(&manifestTouches, 1)
		}
		reg.ServeHTTP(w, r)
	}))
	l, err := random.Layer(2048, types.DockerLayer)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteLayer(repo, l); err != nil {
		t.Fatalf("WriteLayer(): %v", err)
	}
	if err := WriteLayer(repo, l); err != nil {
		t.Fatalf("second WriteLayer(): %v", err)
	}
	if got := atomic.LoadInt32(&manifestTouches); got != 0 {
		t.Errorf("WriteLayer touched manifests %d times, want 0", got)
	}
}
