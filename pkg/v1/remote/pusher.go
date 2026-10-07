// Copyright 2023 Google LLC All Rights Reserved.
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
	"net/url"
	"sync"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

type manifest interface {
	Taggable
	partial.Describable
}

// key is either v1.Hash or v1.Layer (for stream.Layer)
type workers struct {
	// map[v1.Hash|v1.Layer]*sync.Once
	onces sync.Map

	// map[v1.Hash|v1.Layer]error
	errors sync.Map
}

func nop() error {
	return nil
}

func (w *workers) err(digest v1.Hash) error {
	v, ok := w.errors.Load(digest)
	if !ok || v == nil {
		return nil
	}
	return v.(error)
}

func (w *workers) Do(digest v1.Hash, f func() error) error {
	// We don't care if it was loaded or not because the sync.Once will do it for us.
	once, _ := w.onces.LoadOrStore(digest, &sync.Once{})

	once.(*sync.Once).Do(func() {
		w.errors.Store(digest, f())
	})

	err := w.err(digest)
	if err != nil {
		// Allow this to be retried by another caller.
		w.onces.Delete(digest)
	}
	return err
}

func (w *workers) Stream(layer v1.Layer, f func() error) error {
	// We don't care if it was loaded or not because the sync.Once will do it for us.
	once, _ := w.onces.LoadOrStore(layer, &sync.Once{})

	once.(*sync.Once).Do(func() {
		w.errors.Store(layer, f())
	})

	v, ok := w.errors.Load(layer)
	if !ok || v == nil {
		return nil
	}

	return v.(error)
}

type Pusher struct {
	o *options

	// map[name.Repository]*repoWriter
	writers sync.Map
}

func NewPusher(options ...Option) (*Pusher, error) {
	o, err := makeOptions(options...)
	if err != nil {
		return nil, err
	}

	return newPusher(o), nil
}

func newPusher(o *options) *Pusher {
	if o.pusher != nil {
		return o.pusher
	}
	return &Pusher{
		o: o,
	}
}

func (p *Pusher) writer(ctx context.Context, repo name.Repository, o *options) (*repoWriter, error) {
	v, _ := p.writers.LoadOrStore(repo, &repoWriter{
		repo: repo,
		o:    o,
	})
	rw := v.(*repoWriter)
	if err := rw.init(ctx); err != nil {
		p.writers.CompareAndDelete(repo, rw)
		return nil, err
	}
	return rw, nil
}

func (p *Pusher) Put(ctx context.Context, ref name.Reference, t Taggable) error {
	w, err := p.writer(ctx, ref.Context(), p.o)
	if err != nil {
		return err
	}

	m, err := taggableToManifest(t)
	if err != nil {
		return err
	}

	return w.commitManifest(ctx, ref, m)
}

func (p *Pusher) Push(ctx context.Context, ref name.Reference, t Taggable) error {
	w, err := p.writer(ctx, ref.Context(), p.o)
	if err != nil {
		return err
	}
	return w.writeManifest(ctx, ref, t)
}

func (p *Pusher) Upload(ctx context.Context, repo name.Repository, l v1.Layer) error {
	w, err := p.writer(ctx, repo, p.o)
	if err != nil {
		return err
	}
	return w.writeLayer(ctx, l)
}

func (p *Pusher) Delete(ctx context.Context, ref name.Reference) error {
	// Use a transport scoped for delete. Requesting DeleteScope (which
	// includes the "delete" action) allows registries that require an
	// explicit delete permission—such as IBM Cloud Container Registry—to
	// grant access.
	client, err := makeDeleteClient(ctx, ref.Context(), p.o)
	if err != nil {
		return err
	}

	u := url.URL{
		Scheme: ref.Context().Scheme(),
		Host:   ref.Context().RegistryStr(),
		Path:   fmt.Sprintf("/v2/%s/manifests/%s", ref.Context().RepositoryStr(), ref.Identifier()),
	}

	req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return transport.CheckError(resp, http.StatusOK, http.StatusAccepted)

	// TODO(jason): If the manifest had a `subject`, and if the registry
	// doesn't support Referrers, update the index pointed to by the
	// subject's fallback tag to remove the descriptor for this manifest.
}

type repoWriter struct {
	repo name.Repository
	o    *options
	once sync.Once

	w   *writer
	err error

	work *workers

	// confirms records digests verified present in the destination, so a tag
	// move can be gated on the complete graph and so retries reuse blobs and
	// manifests instead of uploading them again.
	confirms *confirmations

	// tagLocks holds one mutex per tag identifier so concurrent publishes of
	// the same tag within this Pusher serialize their commit decisions.
	tagLocks sync.Map // map[string]*sync.Mutex
}

// this will run once per repoWriter instance
func (rw *repoWriter) init(ctx context.Context) error {
	rw.once.Do(func() {
		rw.work = &workers{}
		rw.confirms = newConfirmations()
		rw.w, rw.err = makeWriter(ctx, rw.repo, nil, rw.o)
	})
	return rw.err
}

func (rw *repoWriter) writeDeps(ctx context.Context, m manifest) error {
	if img, ok := m.(v1.Image); ok {
		return rw.writeLayers(ctx, img)
	}

	if idx, ok := m.(v1.ImageIndex); ok {
		return rw.writeChildren(ctx, idx)
	}

	// This has no deps, not an error (e.g. something you want to just PUT).
	return nil
}

type describable struct {
	desc v1.Descriptor
}

func (d describable) Digest() (v1.Hash, error) {
	return d.desc.Digest, nil
}

func (d describable) Size() (int64, error) {
	return d.desc.Size, nil
}

func (d describable) MediaType() (types.MediaType, error) {
	return d.desc.MediaType, nil
}

type tagManifest struct {
	Taggable
	partial.Describable
}

func taggableToManifest(t Taggable) (manifest, error) {
	if m, ok := t.(manifest); ok {
		return m, nil
	}

	if d, ok := t.(*Descriptor); ok {
		if d.MediaType.IsIndex() {
			return d.ImageIndex()
		}

		if d.MediaType.IsImage() {
			return d.Image()
		}

		if d.MediaType.IsSchema1() {
			return d.Schema1()
		}

		return tagManifest{t, describable{d.toDesc()}}, nil
	}

	desc := v1.Descriptor{
		// A reasonable default if Taggable doesn't implement MediaType.
		MediaType: types.DockerManifestSchema2,
	}

	b, err := t.RawManifest()
	if err != nil {
		return nil, err
	}

	if wmt, ok := t.(withMediaType); ok {
		desc.MediaType, err = wmt.MediaType()
		if err != nil {
			return nil, err
		}
	}

	desc.Digest, desc.Size, err = v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	return tagManifest{t, describable{desc}}, nil
}

func (rw *repoWriter) writeManifest(ctx context.Context, ref name.Reference, t Taggable) error {
	m, err := taggableToManifest(t)
	if err != nil {
		return err
	}

	needDeps := true

	digest, err := m.Digest()
	if errors.Is(err, stream.ErrNotComputed) {
		// Streaming layers cannot be described until they are consumed, so
		// upload them first and derive the digest afterwards. The tag is still
		// only moved after every upload has completed.
		if err := rw.writeDeps(ctx, m); err != nil {
			return err
		}

		needDeps = false

		digest, err = m.Digest()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	// This may be a lazy child where we have no ref until digest is computed.
	isRoot := ref != nil
	if ref == nil {
		ref = rw.repo.Digest(digest.String())
	}

	if tag, ok := ref.(name.Tag); ok {
		return rw.writeTagged(ctx, tag, m, needDeps)
	}
	return rw.writeDigestRef(ctx, ref, m, needDeps, isRoot)
}

// writeTagged publishes to a tag in two non-overlapping phases:
//
//  1. every referenced blob, config and child manifest is uploaded by digest
//     (deduped through workers) and recorded in confirms;
//  2. the tag is moved exactly once via finalizeTag, which verifies the
//     resulting tag digest and converges retries and concurrent publishes.
//
// The tag is therefore untouched until the complete graph is confirmed: any
// failure, cancellation or process exit during phase 1 leaves the tag at its
// previous value, while already-confirmed content stays reusable for the next
// attempt.
func (rw *repoWriter) writeTagged(ctx context.Context, tag name.Tag, m manifest, needDeps bool) error {
	// Serialize same-tag publishers across this Pusher: only one commit
	// decision runs at a time, and followers observe a converged result.
	tagMu := rw.tagLock(tag.Identifier())
	tagMu.Lock()
	defer tagMu.Unlock()

	digest, err := m.Digest()
	if err != nil {
		return err
	}

	// Fast path: the tag already points at exactly this graph; do no uploads.
	if exists, err := rw.manifestExists(ctx, tag, m); err != nil {
		return err
	} else if exists {
		rw.confirms.mark(digest)
		return nil
	}

	// Fix and validate the descriptor graph before mutating the repository.
	// Graphs containing streamed layers cannot be frozen; the ordered upload
	// below provides the same tag-last guarantee without up-front digests.
	var graph *frozenGraph
	if needDeps {
		graph, err = freezeManifest(m, rw.o.allowNondistributableArtifacts)
		if err != nil {
			return err
		}
	}

	// This mirrors the dedupe bookkeeping in writeDigestRef: when our closure
	// is deduped against an in-flight identical digest, the tag still has to
	// be moved by this caller after phase 1 completes.
	moveTag := true
	if err := rw.work.Do(digest, func() error {
		if needDeps {
			if err := rw.writeDeps(ctx, m); err != nil {
				return err
			}
		}
		if graph != nil {
			if err := graph.gate(rw.confirms); err != nil {
				return err
			}
		}
		moveTag = false
		return rw.finalizeTag(ctx, tag, m)
	}); err != nil {
		return err
	}

	if !moveTag {
		return nil
	}

	// The digest closure was run by another caller (a child manifest upload or
	// a different tag); ensure this tag converges onto the confirmed content.
	if graph != nil {
		if err := graph.gate(rw.confirms); err != nil {
			return err
		}
	}
	return rw.finalizeTag(ctx, tag, m)
}

// writeDigestRef publishes content addressed only by its digest; there is no
// tag that could be left pointing at a partial graph. Uploads are deduped by
// digest and retried safely because storing content by digest is idempotent.
func (rw *repoWriter) writeDigestRef(ctx context.Context, ref name.Reference, m manifest, needDeps, isRoot bool) error {
	digest, err := m.Digest()
	if err != nil {
		return err
	}

	// Entry-point digest pushes still fix and validate the complete graph
	// before mutating anything; child manifest writes are covered by their
	// root's freeze. Graphs with streamed layers cannot be frozen.
	if isRoot && needDeps {
		if _, err := freezeManifest(m, rw.o.allowNondistributableArtifacts); err != nil {
			return err
		}
	}

	return rw.work.Do(digest, func() error {
		if exists, err := rw.manifestExists(ctx, ref, m); err != nil {
			return err
		} else if exists {
			return nil
		}

		if needDeps {
			if err := rw.writeDeps(ctx, m); err != nil {
				return err
			}
		}

		if err := rw.commitManifest(ctx, ref, m); err != nil {
			return err
		}
		rw.confirms.mark(digest)
		return nil
	})
}

func (rw *repoWriter) writeChildren(ctx context.Context, idx v1.ImageIndex) error {
	children, err := partial.Manifests(idx)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(rw.o.jobs)

	for _, child := range children {
		child := child
		if err := rw.writeChild(ctx, child, g); err != nil {
			return err
		}
	}

	return g.Wait()
}

func (rw *repoWriter) writeChild(ctx context.Context, child partial.Describable, g *errgroup.Group) error {
	switch child := child.(type) {
	case v1.ImageIndex:
		// For recursive index, we want to do a depth-first launching of goroutines
		// to avoid deadlocking.
		//
		// Note that this is rare, so the impact of this should be really small.
		return rw.writeManifest(ctx, nil, child)
	case v1.Image:
		g.Go(func() error {
			return rw.writeManifest(ctx, nil, child)
		})
	case v1.Layer:
		g.Go(func() error {
			return rw.writeLayer(ctx, child)
		})
	default:
		// This can't happen.
		return fmt.Errorf("encountered unknown child: %T", child)
	}
	return nil
}

// TODO: Consider caching some representation of the tags/digests in the destination
// repository as a hint to avoid this optimistic check in cases where we will most
// likely have to do a PUT anyway, e.g. if we are overwriting a tag we just wrote.
func (rw *repoWriter) manifestExists(ctx context.Context, ref name.Reference, t Taggable) (bool, error) {
	f := &fetcher{
		target: ref.Context(),
		client: rw.w.getClient(),
	}

	m, err := taggableToManifest(t)
	if err != nil {
		return false, err
	}

	digest, err := m.Digest()
	if err != nil {
		// Possibly due to streaming layers.
		return false, nil
	}
	got, err := f.headManifest(ctx, ref, allManifestMediaTypes)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) {
			if terr.StatusCode == http.StatusNotFound {
				return false, nil
			}

			// We treat a 403 here as non-fatal because this existence check is an optimization and
			// some registries will return a 403 instead of a 404 in certain situations.
			// E.g. https://jfrog.atlassian.net/browse/RTFACT-13797
			if terr.StatusCode == http.StatusForbidden {
				logs.Debug.Printf("manifestExists unexpected 403: %v", err)
				return false, nil
			}
		}

		return false, err
	}

	if digest != got.Digest {
		// Mark that we saw this digest in the registry so we don't have to check it again.
		rw.work.Do(got.Digest, nop)
		// The observed digest is confirmed present (it is not the content we
		// are about to upload, but it can still be referenced safely).
		rw.confirms.mark(got.Digest)

		return false, nil
	}

	if tag, ok := ref.(name.Tag); ok {
		logs.Progress.Printf("existing manifest: %s@%s", tag.Identifier(), got.Digest)
	} else {
		logs.Progress.Print("existing manifest: ", got.Digest)
	}

	// The exact manifest we wanted is already present; it is confirmed and
	// must never be uploaded again.
	rw.confirms.mark(got.Digest)

	return true, nil
}

func (rw *repoWriter) commitManifest(ctx context.Context, ref name.Reference, m manifest) error {
	if rw.o.progress != nil {
		size, err := m.Size()
		if err != nil {
			return err
		}
		rw.o.progress.total(size)
	}

	return rw.w.commitManifest(ctx, m, ref)
}

func (rw *repoWriter) writeLayers(pctx context.Context, img v1.Image) error {
	ls, err := img.Layers()
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(pctx)
	g.SetLimit(rw.o.jobs)

	for _, l := range ls {
		l := l

		g.Go(func() error {
			return rw.writeLayer(ctx, l)
		})
	}

	mt, err := img.MediaType()
	if err != nil {
		return err
	}

	if mt.IsSchema1() {
		return g.Wait()
	}

	cl, err := partial.ConfigLayer(img)
	if errors.Is(err, stream.ErrNotComputed) {
		if err := g.Wait(); err != nil {
			return err
		}

		cl, err := partial.ConfigLayer(img)
		if err != nil {
			return err
		}

		return rw.writeLayer(pctx, cl)
	} else if err != nil {
		return err
	}

	g.Go(func() error {
		return rw.writeLayer(ctx, cl)
	})

	return g.Wait()
}

func (rw *repoWriter) writeLayer(ctx context.Context, l v1.Layer) error {
	// Skip any non-distributable things.
	mt, err := l.MediaType()
	if err != nil {
		return err
	}
	if !mt.IsDistributable() && !rw.o.allowNondistributableArtifacts {
		return nil
	}

	digest, err := l.Digest()
	if err != nil {
		if errors.Is(err, stream.ErrNotComputed) {
			return rw.lazyWriteLayer(ctx, l)
		}
		return err
	}

	return rw.work.Do(digest, func() error {
		if rw.o.progress != nil {
			size, err := l.Size()
			if err != nil {
				return err
			}
			rw.o.progress.total(size)
		}
		if err := rw.w.uploadOne(ctx, l); err != nil {
			return err
		}
		// Existing (HEAD), mounted or freshly committed: the blob is confirmed
		// present by digest and safe to reuse on any later retry.
		rw.confirms.mark(digest)
		return nil
	})
}

func (rw *repoWriter) lazyWriteLayer(ctx context.Context, l v1.Layer) error {
	return rw.work.Stream(l, func() error {
		if err := rw.w.uploadOne(ctx, l); err != nil {
			return err
		}

		// Mark this upload completed.
		digest, err := l.Digest()
		if err != nil {
			return err
		}

		rw.work.Do(digest, nop)
		// Streaming blobs are only known after upload; the commit means they
		// are confirmed and reusable on retry.
		rw.confirms.mark(digest)

		if rw.o.progress != nil {
			size, err := l.Size()
			if err != nil {
				return err
			}
			rw.o.progress.total(size)
		}

		return nil
	})
}
