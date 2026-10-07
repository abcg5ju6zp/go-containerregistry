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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/go-containerregistry/internal/retry"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// ErrTagCommitConflict is returned when a tagged publish has uploaded and
// verified all of its content, but the tag ultimately resolves to a different
// manifest digest than the one just committed. This happens when a concurrent
// publish of different content wins the race for the same tag. The registry is
// left in a valid state: both graphs are complete and content-addressed; only
// one can be referenced by the tag.
//
// A retry that pushes identical content after an ambiguous network response
// never produces this error; such publishes converge to success once the tag
// points at the wanted digest.
var ErrTagCommitConflict = errors.New("tag commit conflict: tag resolves to a different digest after commit")

// errManifestVerifyForbidden marks registries that disallow the verification
// HEAD after accepting a manifest PUT (some registries historically return
// 403 instead of 404 for pull-side checks during a push-scoped session).
var errManifestVerifyForbidden = errors.New("manifest verification forbidden")

// tagNotVisibleError is returned when a registry accepted a manifest PUT but
// the tag is not visible immediately afterwards, which can happen while the
// manifest propagates across eventually-consistent storage backends. It is
// temporary so the commit decision is retried instead of failing outright.
type tagNotVisibleError struct{}

func (tagNotVisibleError) Error() string   { return "accepted manifest is not yet visible at the tag" }
func (tagNotVisibleError) Temporary() bool { return true }

// terminalCommitError wraps an error that must not be retried by the tag
// finalizer (e.g. a decided conflict). It takes precedence over any
// caller-supplied retry predicate.
type terminalCommitError struct {
	err error
}

func (e *terminalCommitError) Error() string { return e.err.Error() }
func (e *terminalCommitError) Unwrap() error { return e.err }

// confirmations tracks content digests that have been *confirmed* present in
// the destination repository: a HEAD that matched, a cross-repo mount, or a
// 201 blob/manifest commit. A merely initiated upload session (202) is never
// confirmed. Confirmed content is safe to reuse on retry; anything not in this
// set must be uploaded (or re-confirmed) before a tag is allowed to move.
//
// Nothing is ever deleted from the registry by the write path, so content that
// was uploaded but not confirmed (e.g. the process exited mid-upload) is left
// intact and will simply be re-confirmed or uploaded again on a later attempt.
type confirmations struct {
	mu sync.Mutex
	m  map[v1.Hash]struct{}
}

func newConfirmations() *confirmations {
	return &confirmations{m: map[v1.Hash]struct{}{}}
}

func (c *confirmations) mark(h v1.Hash) {
	c.mu.Lock()
	c.m[h] = struct{}{}
	c.mu.Unlock()
}

func (c *confirmations) has(h v1.Hash) bool {
	c.mu.Lock()
	_, ok := c.m[h]
	c.mu.Unlock()
	return ok
}

// frozenGraph is the descriptor DAG captured ("fixed") and locally validated
// before any remote state is mutated. Enumerating the full node set up front is
// what lets the final tag update gate on every child manifest, config blob,
// layer and attached artifact being confirmed present, so a tag can never be
// moved to a manifest missing platforms or referenced content.
type frozenGraph struct {
	root v1.Hash

	// manifests contains every manifest node, including root.
	manifests map[v1.Hash]struct{}
	// children maps a manifest digest to the digests of manifests it
	// directly references (index children that are themselves manifests).
	children map[v1.Hash][]v1.Hash
	// blobs maps a manifest digest to the config/layer blobs it directly
	// references, honoring the foreign-layer upload policy.
	blobs map[v1.Hash][]v1.Hash
}

// gate returns an error unless every node the tag will reference is confirmed
// present in the destination. A confirmed child manifest transitively
// satisfies its whole subtree: an accepted manifest is registry-side proof
// that everything it references is present, which also covers content reused
// from an earlier attempt or a concurrent identical publish.
func (g *frozenGraph) gate(c *confirmations) error {
	stack := []v1.Hash{g.root}
	visited := map[v1.Hash]struct{}{}
	var missing []string
	for len(stack) > 0 {
		h := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := visited[h]; ok {
			continue
		}
		visited[h] = struct{}{}

		if h != g.root {
			if c.has(h) {
				// This manifest is already present; its subtree is satisfied
				// transitively.
				continue
			}
			// writeDeps pushes children before the tag is allowed to move, so
			// reaching here means the graph was never fully staged.
			missing = append(missing, "manifest "+h.String())
			continue
		}

		for _, b := range g.blobs[h] {
			if !c.has(b) {
				missing = append(missing, "blob "+b.String())
			}
		}
		kids := g.children[h]
		for i := len(kids) - 1; i >= 0; i-- {
			stack = append(stack, kids[i])
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("refusing to move tag: %d referenced digests are not confirmed in the repository: %v", len(missing), missing)
	}
	return nil
}

// freezeManifest materializes and validates the complete descriptor graph
// rooted at m. Parent descriptor digests are checked against the actual
// content digests of their children, image configs and layers are checked
// against manifest descriptors, and each manifest's raw bytes are hashed and
// compared to its declared digest. allowNondistributable controls whether
// foreign layers are part of the required blob set, matching upload policy.
//
// Streamed layers cannot be hashed before they are consumed, so a graph
// containing one cannot be frozen; callers fall back to the ordered lazy walk,
// which still only moves the tag after every upload has completed.
func freezeManifest(m manifest, allowNondistributable bool) (*frozenGraph, error) {
	g := &frozenGraph{
		manifests: map[v1.Hash]struct{}{},
		children:  map[v1.Hash][]v1.Hash{},
		blobs:     map[v1.Hash][]v1.Hash{},
	}
	seen := map[v1.Hash]struct{}{}

	var visit func(node manifest, declared *v1.Descriptor) error
	visit = func(node manifest, declared *v1.Descriptor) error {
		digest, err := node.Digest()
		if err != nil {
			return err
		}
		if declared != nil && declared.Digest != digest {
			return fmt.Errorf("descriptor graph mismatch: parent references %s, but child content has digest %s", declared.Digest, digest)
		}
		if _, ok := seen[digest]; ok {
			return nil
		}

		raw, err := node.RawManifest()
		if err != nil {
			return err
		}
		have, _, err := v1.SHA256(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		if have != digest {
			return fmt.Errorf("descriptor graph mismatch: declared digest %s does not match raw manifest digest %s", digest, have)
		}

		seen[digest] = struct{}{}
		g.manifests[digest] = struct{}{}

		mt, err := node.MediaType()
		if err != nil {
			return err
		}

		switch n := node.(type) {
		case v1.ImageIndex:
			if !mt.IsIndex() {
				// Trust unusual index media types (some registries omit it) but
				// don't walk a mislabeled image.
				return nil
			}
			im, err := n.IndexManifest()
			if err != nil {
				return err
			}
			children, err := partial.Manifests(n)
			if err != nil {
				return err
			}
			byDigest := map[v1.Hash]partial.Describable{}
			for _, child := range children {
				h, err := child.Digest()
				if err != nil {
					return err
				}
				byDigest[h] = child
			}
			for _, desc := range im.Manifests {
				child, ok := byDigest[desc.Digest]
				if !ok {
					return fmt.Errorf("descriptor graph mismatch: index %s references %s, which is not enumerated by the index", digest, desc.Digest)
				}
				switch child := child.(type) {
				case manifest:
					g.children[digest] = append(g.children[digest], desc.Digest)
					if err := visit(child, &desc); err != nil {
						return err
					}
				case v1.Layer:
					if err := requireBlob(desc, child, allowNondistributable); err != nil {
						return err
					}
					if desc.MediaType.IsDistributable() || allowNondistributable {
						g.blobs[digest] = append(g.blobs[digest], desc.Digest)
					}
				default:
					// A describable we cannot walk (e.g. unknown media types);
					// the parent binding has already been verified.
				}
			}

		case v1.Image:
			if mt.IsSchema1() {
				// Schema 1 digests are signature-derived and the format is
				// legacy; structural validation does not apply. The binding in
				// any parent descriptor was checked above.
				return nil
			}
			if err := freezeImage(n, allowNondistributable, g, digest); err != nil {
				return err
			}
		}

		return nil
	}

	root, err := m.Digest()
	if err != nil {
		return nil, err
	}
	if err := visit(m, nil); err != nil {
		return nil, err
	}
	g.root = root
	return g, nil
}

// requireBlob cross-checks a blob descriptor attached directly to an index
// against the layer's own digest and media type.
func requireBlob(desc v1.Descriptor, l v1.Layer, allowNondistributable bool) error {
	mt, err := l.MediaType()
	if err != nil {
		return err
	}
	if !mt.IsDistributable() && !allowNondistributable {
		return nil
	}
	digest, err := l.Digest()
	if err != nil {
		return err
	}
	if digest != desc.Digest {
		return fmt.Errorf("descriptor graph mismatch: descriptor references blob %s, layer content has digest %s", desc.Digest, digest)
	}
	return nil
}

func freezeImage(img v1.Image, allowNondistributable bool, g *frozenGraph, node v1.Hash) error {
	raw, err := img.RawManifest()
	if err != nil {
		return err
	}
	mf, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return err
	}

	// Validate the config binding. For locally-built images we can hash the
	// config bytes directly; for remote images (e.g. a Copy in flight) that
	// would cost an extra blob download we do not need because the source
	// registry is the content authority and the destination validates the
	// digest when the config blob is committed.
	if mf.Config.Digest.Hex != "" {
		if !isRemoteImage(img) {
			cfgName, err := img.ConfigName()
			if err != nil {
				return err
			}
			if cfgName != mf.Config.Digest {
				return fmt.Errorf("descriptor graph mismatch: manifest references config %s, but config content has digest %s", mf.Config.Digest, cfgName)
			}
		}
		g.blobs[node] = append(g.blobs[node], mf.Config.Digest)
	}

	layers, err := img.Layers()
	if err != nil {
		return err
	}
	byDigest := map[v1.Hash]v1.Layer{}
	for _, l := range layers {
		h, err := l.Digest()
		if err != nil {
			return err
		}
		byDigest[h] = l
	}
	for _, desc := range mf.Layers {
		l, ok := byDigest[desc.Digest]
		if !ok {
			return fmt.Errorf("descriptor graph mismatch: manifest references layer %s, which the image does not provide", desc.Digest)
		}
		mt := desc.MediaType
		if mt == "" {
			// Prefer the layer's own media type when the descriptor omits it.
			mt, _ = l.MediaType()
		}
		if !mt.IsDistributable() && !allowNondistributable {
			continue
		}
		// Map membership proves the layer's content digest equals the
		// descriptor binding; the destination independently rejects a digest
		// mismatch when the blob commits.
		g.blobs[node] = append(g.blobs[node], desc.Digest)
	}
	return nil
}

// isRemoteImage reports whether img was sourced from a remote registry.
// Remote images are always wrapped in a mountableImage (see Descriptor.Image
// and Descriptor.Schema1), so its presence distinguishes them from locally
// built images.
func isRemoteImage(img v1.Image) bool {
	_, ok := img.(*mountableImage)
	return ok
}

// tagLock returns the per-tag mutex used to collapse same-tag publishes within
// a Pusher into a single sequence of commit decisions.
func (rw *repoWriter) tagLock(identifier string) *sync.Mutex {
	v, _ := rw.tagLocks.LoadOrStore(identifier, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// peekManifest resolves the current digest of a tag (or digest reference).
// A 404 is reported as exists=false with no error; a 403 is surfaced as
// errManifestVerifyForbidden so callers can apply registry-compatible
// handling.
func (rw *repoWriter) peekManifest(ctx context.Context, ref name.Reference) (v1.Hash, bool, error) {
	f := &fetcher{
		target: ref.Context(),
		client: rw.w.getClient(),
	}
	got, err := f.headManifest(ctx, ref, allManifestMediaTypes)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) {
			switch terr.StatusCode {
			case http.StatusNotFound:
				return v1.Hash{}, false, nil
			case http.StatusForbidden:
				return v1.Hash{}, false, errManifestVerifyForbidden
			}
		}
		return v1.Hash{}, false, err
	}
	return got.Digest, true, nil
}

// finalizeTag is the single commit point for a tagged publish. The caller
// must hold the tag mutex and must already have uploaded and confirmed every
// referenced node.
//
// It converges retries and concurrent identical publishes into one decidable
// result:
//   - tag already at the wanted digest: success, no PUT;
//   - PUT succeeds and the tag verifies at the wanted digest: success;
//   - PUT fails ambiguously but verification finds the wanted digest: success
//     (the request was delivered);
//   - the tag verifies at a different digest while our PUT failed: the original
//     PUT error (tag never became ours);
//   - the tag verifies at a different digest after an accepted PUT:
//     ErrTagCommitConflict (a concurrent publisher of different content won);
//   - the accepted manifest is temporarily invisible: retry with backoff.
func (rw *repoWriter) finalizeTag(ctx context.Context, tag name.Tag, m manifest) error {
	wanted, err := m.Digest()
	if err != nil {
		return err
	}

	// Fast convergence for retries after an ambiguous response and for
	// concurrent callers that raced an identical publish to completion.
	if got, exists, err := rw.peekManifest(ctx, tag); err == nil && exists && got == wanted {
		rw.confirms.mark(wanted)
		return nil
	}

	// The tag move itself. commitManifest already retries transport flukes;
	// an error here is ambiguous -- the registry may or may not have stored
	// the manifest -- so the verification below decides the outcome.
	putErr := rw.commitManifest(ctx, tag, m)

	predicate := func(err error) bool {
		var terminal *terminalCommitError
		if errors.As(err, &terminal) {
			return false
		}
		return rw.w.predicate(err)
	}

	return retry.Retry(func() error {
		got, exists, verr := rw.peekManifest(ctx, tag)
		if verr == nil {
			switch {
			case exists && got == wanted:
				// A configured post-commit policy failure (e.g. referrers
				// linkage) is surfaced even though the registry accepted the
				// manifest, so it cannot be hidden by a matching tag.
				if putErr != nil && errors.Is(putErr, errReferrersTagFallbackDisabled) {
					return &terminalCommitError{err: putErr}
				}
				rw.confirms.mark(wanted)
				return nil
			case exists:
				// Tag points at some other complete graph.
				if putErr != nil {
					// Our PUT failed; the tag holds its previous (or another
					// publisher's) value. Report the actual write failure.
					return &terminalCommitError{err: putErr}
				}
				return &terminalCommitError{err: fmt.Errorf("%w: %s is at %s, wanted %s", ErrTagCommitConflict, tag.Identifier(), got, wanted)}
			default:
				// 404 at the tag.
				if putErr != nil {
					// The write failed and nothing moved: atomic failure.
					return &terminalCommitError{err: putErr}
				}
				return tagNotVisibleError{}
			}
		}

		if errors.Is(verr, errManifestVerifyForbidden) {
			// Cannot verify after the fact on this registry.
			if putErr != nil {
				return &terminalCommitError{err: putErr}
			}
			logs.Debug.Printf("tag %q accepted the manifest but verification is forbidden (403); trusting accepted response", tag)
			rw.confirms.mark(wanted)
			return nil
		}
		// Verification request itself failed (timeout, reset, ...). The commit
		// outcome is undecidable, so probe again; make sure transport-level
		// failures remain retryable. If probing can never succeed and the PUT
		// failed, surface the original write error to the caller.
		if putErr != nil {
			return fmt.Errorf("%w; unable to verify commit: %w", putErr, verr)
		}
		return verr
	}, predicate, rw.w.backoff)
}
