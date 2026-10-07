// Copyright 2018 Google LLC All Rights Reserved.
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
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// WriteToFile writes in the compressed format to a tarball, on disk.
// This is just syntactic sugar wrapping tarball.Write with a new file.
//
// The archive is built in an isolated, hidden candidate file in the same
// directory and only replaces the destination once the full tarball
// (manifest.json, config and every layer) has been written, synced and
// re-read successfully. The replacement is atomic, so a failed, canceled or
// interrupted export leaves any previously confirmed archive at p untouched.
func WriteToFile(p string, ref name.Reference, img v1.Image, opts ...WriteOption) error {
	return writeArchiveToFile(p, func(w io.Writer) error {
		return Write(ref, img, w, opts...)
	})
}

// MultiWriteToFile writes in the compressed format to a tarball, on disk.
// This is just syntactic sugar wrapping tarball.MultiWrite with a new file.
func MultiWriteToFile(p string, tagToImage map[name.Tag]v1.Image, opts ...WriteOption) error {
	refToImage := make(map[name.Reference]v1.Image, len(tagToImage))
	for i, d := range tagToImage {
		refToImage[i] = d
	}
	return MultiRefWriteToFile(p, refToImage, opts...)
}

// MultiRefWriteToFile writes in the compressed format to a tarball, on disk.
// This is just syntactic sugar wrapping tarball.MultiRefWrite with a new file.
//
// As with WriteToFile, the destination is replaced atomically: it never
// observes a partially written archive.
func MultiRefWriteToFile(p string, refToImage map[name.Reference]v1.Image, opts ...WriteOption) error {
	return writeArchiveToFile(p, func(w io.Writer) error {
		return MultiRefWrite(refToImage, w, opts...)
	})
}

// Write is a wrapper to write a single image and tag to a tarball.
func Write(ref name.Reference, img v1.Image, w io.Writer, opts ...WriteOption) error {
	return MultiRefWrite(map[name.Reference]v1.Image{ref: img}, w, opts...)
}

// MultiWrite writes the contents of each image to the provided writer, in the compressed format.
// The contents are written in the following format:
// One manifest.json file at the top level containing information about several images.
// One file for each layer, named after the layer's SHA.
// One file for the config blob, named after its SHA.
func MultiWrite(tagToImage map[name.Tag]v1.Image, w io.Writer, opts ...WriteOption) error {
	refToImage := make(map[name.Reference]v1.Image, len(tagToImage))
	for i, d := range tagToImage {
		refToImage[i] = d
	}
	return MultiRefWrite(refToImage, w, opts...)
}

// MultiRefWrite writes the contents of each image to the provided writer, in the compressed format.
// The contents are written in the following format:
// One manifest.json file at the top level containing information about several images.
// One file for each layer, named after the layer's SHA.
// One file for the config blob, named after its SHA.
func MultiRefWrite(refToImage map[name.Reference]v1.Image, w io.Writer, opts ...WriteOption) error {
	// process options
	o := &writeOptions{
		updates: nil,
	}
	for _, option := range opts {
		if err := option(o); err != nil {
			return err
		}
	}

	imageToTags := dedupRefToImage(refToImage)
	size, mBytes, err := getSizeAndManifest(imageToTags)
	if err != nil {
		return sendUpdateReturn(o, err)
	}

	return writeImagesToTar(imageToTags, mBytes, size, w, o)
}

// sendUpdateReturn return the passed in error message, also sending on update channel, if it exists
func sendUpdateReturn(o *writeOptions, err error) error {
	if o != nil && o.updates != nil {
		o.updates <- v1.Update{
			Error: err,
		}
	}
	return err
}

// sendProgressWriterReturn return the passed in error message, also sending on update channel, if it exists, along with downloaded information
func sendProgressWriterReturn(pw *progressWriter, err error) error {
	if pw != nil {
		return pw.Error(err)
	}
	return err
}

// writeImagesToTar writes the images to the tarball
func writeImagesToTar(imageToTags map[v1.Image][]string, m []byte, size int64, w io.Writer, o *writeOptions) (err error) {
	if w == nil {
		return sendUpdateReturn(o, errors.New("must pass valid writer"))
	}

	tw := w
	var pw *progressWriter

	// we only calculate the sizes and use a progressWriter if we were provided
	// an option with a progress channel
	if o != nil && o.updates != nil {
		pw = &progressWriter{
			w:       w,
			updates: o.updates,
			size:    size,
		}
		tw = pw
	}

	tf := tar.NewWriter(tw)
	defer tf.Close()

	seenLayerDigests := make(map[string]struct{})

	for img := range imageToTags {
		// Write the config.
		cfgName, err := img.ConfigName()
		if err != nil {
			return sendProgressWriterReturn(pw, err)
		}
		cfgBlob, err := img.RawConfigFile()
		if err != nil {
			return sendProgressWriterReturn(pw, err)
		}
		if err := writeTarEntry(tf, cfgName.String(), bytes.NewReader(cfgBlob), int64(len(cfgBlob))); err != nil {
			return sendProgressWriterReturn(pw, err)
		}

		// Write the layers.
		layers, err := img.Layers()
		if err != nil {
			return sendProgressWriterReturn(pw, err)
		}
		layerFiles := make([]string, len(layers))
		for i, l := range layers {
			d, err := l.Digest()
			if err != nil {
				return sendProgressWriterReturn(pw, err)
			}
			// Munge the file name to appease ancient technology.
			//
			// tar assumes anything with a colon is a remote tape drive:
			// https://www.gnu.org/software/tar/manual/html_section/tar_45.html
			// Drop the algorithm prefix, e.g. "sha256:"
			hex := d.Hex

			// gunzip expects certain file extensions:
			// https://www.gnu.org/software/gzip/manual/html_node/Overview.html
			layerFiles[i] = hex + layerExtension(l)

			if _, ok := seenLayerDigests[hex]; ok {
				continue
			}
			seenLayerDigests[hex] = struct{}{}

			if err := writeLayer(tf, layerFiles[i], l); err != nil {
				return sendProgressWriterReturn(pw, err)
			}
		}
	}
	if err := writeTarEntry(tf, "manifest.json", bytes.NewReader(m), int64(len(m))); err != nil {
		return sendProgressWriterReturn(pw, err)
	}

	// be sure to close the tar writer so everything is flushed out before we send our EOF
	if err := tf.Close(); err != nil {
		return sendProgressWriterReturn(pw, err)
	}
	// send an EOF to indicate finished on the channel, but nil as our return error
	_ = sendProgressWriterReturn(pw, io.EOF)
	return nil
}

// calculateManifest calculates the manifest and optionally the size of the tar file
func calculateManifest(imageToTags map[v1.Image][]string) (m Manifest, err error) {
	if len(imageToTags) == 0 {
		return nil, errors.New("set of images is empty")
	}

	for img, tags := range imageToTags {
		cfgName, err := img.ConfigName()
		if err != nil {
			return nil, err
		}

		// Store foreign layer info.
		layerSources := make(map[v1.Hash]v1.Descriptor)

		// Write the layers.
		layers, err := img.Layers()
		if err != nil {
			return nil, err
		}
		layerFiles := make([]string, len(layers))
		for i, l := range layers {
			d, err := l.Digest()
			if err != nil {
				return nil, err
			}
			// Munge the file name to appease ancient technology.
			//
			// tar assumes anything with a colon is a remote tape drive:
			// https://www.gnu.org/software/tar/manual/html_section/tar_45.html
			// Drop the algorithm prefix, e.g. "sha256:"
			hex := d.Hex

			// gunzip expects certain file extensions:
			// https://www.gnu.org/software/gzip/manual/html_node/Overview.html
			layerFiles[i] = hex + layerExtension(l)

			// Add to LayerSources if it's a foreign layer.
			desc, err := partial.BlobDescriptor(img, d)
			if err != nil {
				return nil, err
			}
			if !desc.MediaType.IsDistributable() {
				diffid, err := partial.BlobToDiffID(img, d)
				if err != nil {
					return nil, err
				}
				layerSources[diffid] = *desc
			}
		}

		// Generate the tar descriptor and write it.
		m = append(m, Descriptor{
			Config:       cfgName.String(),
			RepoTags:     tags,
			Layers:       layerFiles,
			LayerSources: layerSources,
		})
	}
	// sort by name of the repotags so it is consistent. Alternatively, we could sort by hash of the
	// descriptor, but that would make it hard for humans to process
	sort.Slice(m, func(i, j int) bool {
		return strings.Join(m[i].RepoTags, ",") < strings.Join(m[j].RepoTags, ",")
	})

	return m, nil
}

// CalculateSize calculates the expected complete size of the output tar file
func CalculateSize(refToImage map[name.Reference]v1.Image) (size int64, err error) {
	imageToTags := dedupRefToImage(refToImage)
	size, _, err = getSizeAndManifest(imageToTags)
	return size, err
}

func getSizeAndManifest(imageToTags map[v1.Image][]string) (int64, []byte, error) {
	m, err := calculateManifest(imageToTags)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to calculate manifest: %w", err)
	}
	mBytes, err := json.Marshal(m)
	if err != nil {
		return 0, nil, fmt.Errorf("could not marshall manifest to bytes: %w", err)
	}

	size, err := calculateTarballSize(imageToTags, mBytes)
	if err != nil {
		return 0, nil, fmt.Errorf("error calculating tarball size: %w", err)
	}
	return size, mBytes, nil
}

// calculateTarballSize calculates the size of the tar file
func calculateTarballSize(imageToTags map[v1.Image][]string, mBytes []byte) (size int64, err error) {
	seenLayerDigests := make(map[string]struct{})
	for img, name := range imageToTags {
		manifest, err := img.Manifest()
		if err != nil {
			return size, fmt.Errorf("unable to get manifest for img %s: %w", name, err)
		}
		size += calculateSingleFileInTarSize(manifest.Config.Size)
		for _, l := range manifest.Layers {
			hex := l.Digest.Hex
			if _, ok := seenLayerDigests[hex]; ok {
				continue
			}
			seenLayerDigests[hex] = struct{}{}
			size += calculateSingleFileInTarSize(l.Size)
		}
	}
	// add the manifest
	size += calculateSingleFileInTarSize(int64(len(mBytes)))

	// add the two padding blocks that indicate end of a tar file
	size += 1024
	return size, nil
}

func dedupRefToImage(refToImage map[name.Reference]v1.Image) map[v1.Image][]string {
	imageToTags := make(map[v1.Image][]string)

	for ref, img := range refToImage {
		if tag, ok := ref.(name.Tag); ok {
			if tags, ok := imageToTags[img]; !ok || tags == nil {
				imageToTags[img] = []string{}
			}
			// Docker cannot load tarballs without an explicit tag:
			// https://github.com/google/go-containerregistry/issues/890
			//
			// We can't use the fully qualified tag.Name() because of rules_docker:
			// https://github.com/google/go-containerregistry/issues/527
			//
			// If the tag is "latest", but tag.String() doesn't end in ":latest",
			// just append it. Kind of gross, but should work for now.
			ts := tag.String()
			if tag.Identifier() == name.DefaultTag && !strings.HasSuffix(ts, ":"+name.DefaultTag) {
				ts = fmt.Sprintf("%s:%s", ts, name.DefaultTag)
			}
			imageToTags[img] = append(imageToTags[img], ts)
		} else if _, ok := imageToTags[img]; !ok {
			imageToTags[img] = nil
		}
	}

	return imageToTags
}

// writeTarEntry writes a file to the provided writer with a corresponding tar header
func writeTarEntry(tf *tar.Writer, path string, r io.Reader, size int64) error {
	hdr := &tar.Header{
		Mode:     0644,
		Typeflag: tar.TypeReg,
		Size:     size,
		Name:     path,
	}
	if err := tf.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := io.Copy(tf, r)
	return err
}

// writeLayer streams a layer's compressed blob into the tar writer and closes
// the reader before returning. The close releases any pull-limiter slot held
// by a remote-backed layer (remote.WithJobs); leaving it open would deadlock
// the write loop after defaultJobs layers.
func writeLayer(tf *tar.Writer, name string, l v1.Layer) error {
	r, err := l.Compressed()
	if err != nil {
		return err
	}
	defer r.Close()
	blobSize, err := l.Size()
	if err != nil {
		return err
	}
	return writeTarEntry(tf, name, r, blobSize)
}

// ComputeManifest get the manifest.json that will be written to the tarball
// for multiple references
func ComputeManifest(refToImage map[name.Reference]v1.Image) (Manifest, error) {
	imageToTags := dedupRefToImage(refToImage)
	return calculateManifest(imageToTags)
}

// WriteOption a function option to pass to Write()
type WriteOption func(*writeOptions) error
type writeOptions struct {
	updates chan<- v1.Update
}

// WithProgress create a WriteOption for passing to Write() that enables
// a channel to receive updates as they are downloaded and written to disk.
func WithProgress(updates chan<- v1.Update) WriteOption {
	return func(o *writeOptions) error {
		o.updates = updates
		return nil
	}
}

// progressWriter is a writer which will send the download progress
type progressWriter struct {
	w              io.Writer
	updates        chan<- v1.Update
	size, complete int64
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	if err != nil {
		return n, err
	}

	pw.complete += int64(n)

	pw.updates <- v1.Update{
		Total:    pw.size,
		Complete: pw.complete,
	}

	return n, err
}

func (pw *progressWriter) Error(err error) error {
	pw.updates <- v1.Update{
		Total:    pw.size,
		Complete: pw.complete,
		Error:    err,
	}
	return err
}

func (pw *progressWriter) Close() error {
	pw.updates <- v1.Update{
		Total:    pw.size,
		Complete: pw.complete,
		Error:    io.EOF,
	}
	return io.EOF
}

// calculateSingleFileInTarSize calculate the size a file will take up in a tar archive,
// given the input data. Provided by rounding up to nearest whole block (512)
// and adding header 512
func calculateSingleFileInTarSize(in int64) (out int64) {
	// doing this manually, because math.Round() works with float64
	out += in
	if remainder := out % 512; remainder != 0 {
		out += (512 - remainder)
	}
	out += 512
	return out
}

func layerExtension(l v1.Layer) string {
	mt, _ := l.MediaType()
	switch mt {
	case types.OCILayerZStd:
		return ".tar.zst"
	case types.OCIUncompressedLayer, types.OCIUncompressedRestrictedLayer, types.DockerUncompressedLayer:
		return ".tar"
	default:
		// historically, only gzip compressed tar was supported, so this is the fallback
		return ".tar.gz"
	}
}

// candidatePrefix returns the name prefix used for unconfirmed candidate
// archives. Candidates are hidden dotfiles in the destination directory so
// they never collide with the confirmed archive or with unrelated files.
func candidatePrefix(base string) string {
	return "." + base + ".tmp-"
}

// lockName returns the name of the file used to serialize concurrent exports
// targeting the same destination. It must never match candidatePrefix.
func lockName(base string) string {
	return "." + base + ".lock"
}

// writeArchiveToFile runs write against an isolated candidate file in the
// destination directory, verifies the resulting archive is fully readable,
// syncs it to stable storage and only then atomically replaces p.
//
// On any failure (including a write error, a short write reported by the
// compression layer, a Close error, or ENOSPC surfaced by Sync) the candidate
// is removed and p is left untouched, so callers keep observing the previous
// complete archive. Unconfirmed candidates abandoned by crashed or killed
// processes are recovered or removed before writing. Exports to the same
// destination are serialized with an advisory lock so concurrent runs never
// delete each other's candidates or confirmed archives.
func writeArchiveToFile(p string, write func(io.Writer) error) error {
	dir := filepath.Dir(p)
	base := filepath.Base(p)

	lock, err := acquireTargetLock(filepath.Join(dir, lockName(base)))
	if err != nil {
		return err
	}
	defer lock.Unlock()

	// The lock guarantees no other live export to p owns a candidate, so any
	// matching file was abandoned by a process that died mid-write.
	if err := recoverOrRemoveStaleCandidates(dir, base, p); err != nil {
		return err
	}

	candidate, candidateName, err := createCandidateFile(dir, base)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			// Closing twice (after the explicit Close below) is harmless.
			_ = candidate.Close()
			_ = os.Remove(candidateName)
		}
	}()

	if err := write(candidate); err != nil {
		return err
	}
	// Make sure data hit stable storage before we trust it, surfacing errors
	// (e.g. ENOSPC) that a deferred Close might otherwise swallow.
	if err := candidate.Sync(); err != nil {
		return fmt.Errorf("syncing image tarball: %w", err)
	}
	if err := verifyTarball(candidateName); err != nil {
		return fmt.Errorf("unverified image tarball: %w", err)
	}

	// Preserve the permission bits of the archive being replaced, matching
	// the behavior os.Create had when it truncated an existing file in
	// place. A brand-new file already carries 0666 modified by the umask.
	if fi, statErr := os.Stat(p); statErr == nil {
		mode := fi.Mode().Perm() | (fi.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
		if err := candidate.Chmod(mode); err != nil {
			return fmt.Errorf("preserving permissions of %q: %w", p, err)
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	if err := candidate.Close(); err != nil {
		return err
	}
	// Same directory, so this rename is atomic and never leaves p missing.
	if err := os.Rename(candidateName, p); err != nil {
		return fmt.Errorf("replacing %q: %w", p, err)
	}
	committed = true

	// Persist the rename itself across a crash.
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("syncing archive directory: %w", err)
	}
	return nil
}

// createCandidateFile creates a fresh, uniquely named candidate with O_EXCL
// so concurrent exports cannot share or steal one another's files.
func createCandidateFile(dir, base string) (*os.File, string, error) {
	var random [8]byte
	for range 128 {
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generating candidate file name: %w", err)
		}
		name := filepath.Join(dir, fmt.Sprintf("%s%x", candidatePrefix(base), random[:]))
		// 0666 matches os.Create's requested mode (the process umask still
		// applies); when replacing an archive we restore its recorded mode
		// before the atomic rename.
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666) //nolint:gosec // G302: permissions intentionally match os.Create
		if err == nil {
			return f, name, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("could not create candidate file in %q", dir)
}

// recoverOrRemoveStaleCandidates disposes of candidate files left behind by
// exports that did not finish (process exit, SIGKILL, crash, power loss).
// Complete candidates are promoted to the destination; incomplete ones are
// deleted. Any recovery or cleanup error is returned to the caller. The
// destination itself and any unrelated files are never touched.
func recoverOrRemoveStaleCandidates(dir, base, target string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("scanning stale archive candidates: %w", err)
	}
	prefix := candidatePrefix(base)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		candidate := filepath.Join(dir, entry.Name())
		if verifyTarball(candidate) != nil {
			if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing incomplete archive candidate %q: %w", candidate, err)
			}
			continue
		}
		// The candidate is complete but was never renamed to the destination.
		// Recover it; our own export replaces it immediately afterwards, and
		// if that export fails, the destination still holds this archive.
		if err := os.Rename(candidate, target); err != nil {
			return fmt.Errorf("recovering complete archive candidate %q: %w", candidate, err)
		}
	}
	return nil
}

// syncDirectory flushes directory metadata (including renames) to disk.
// Errors are returned so the caller can report that the rename was not
// durably synchronized, even though the rename itself is atomic.
func syncDirectory(dir string) error {
	if d, err := os.Open(dir); err == nil {
		syncErr := d.Sync()
		closeErr := d.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	} else {
		return err
	}
}

// verifyTarball reopens the candidate independently of the writer and checks
// that it is a complete, readable image tarball: the tar stream terminates
// cleanly, every member is present in full, manifest.json parses, and every
// config and layer referenced by the manifest is a member of the archive.
func verifyTarball(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyArchive(f)
}

func verifyArchive(r io.Reader) error {
	tr := tar.NewReader(r)
	members := make(map[string]struct{})
	var manifest []byte
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		// Consume the whole entry so a truncated archive (missing blocks, a
		// cut-off layer or a short write padded by the tar writer) is caught.
		var n int64
		if path.Clean(hdr.Name) == "manifest.json" {
			manifest, err = io.ReadAll(tr)
			n = int64(len(manifest))
		} else {
			n, err = io.Copy(io.Discard, tr)
		}
		if err != nil {
			return fmt.Errorf("reading tar member %q: %w", hdr.Name, err)
		}
		if n != hdr.Size {
			return fmt.Errorf("tar member %q is truncated: read %d of %d bytes", hdr.Name, n, hdr.Size)
		}
		members[path.Clean(hdr.Name)] = struct{}{}
	}

	if len(manifest) == 0 {
		return errors.New("manifest.json is missing or empty")
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return fmt.Errorf("parsing manifest.json: %w", err)
	}
	if len(m) == 0 {
		return errors.New("manifest.json contains no images")
	}
	for i, d := range m {
		if d.Config == "" {
			return fmt.Errorf("manifest entry %d has no config", i)
		}
		if _, ok := members[path.Clean(d.Config)]; !ok {
			return fmt.Errorf("config %q referenced by manifest.json is missing", d.Config)
		}
		for _, l := range d.Layers {
			if _, ok := members[path.Clean(l)]; !ok {
				return fmt.Errorf("layer %q referenced by manifest.json is missing", l)
			}
		}
	}
	return nil
}
