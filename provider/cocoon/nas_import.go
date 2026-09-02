package cocoon

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/cocoonstack/cocoon-common/ociutil"

	"github.com/cocoonstack/vk-cocoon/nasimage"
	"github.com/cocoonstack/vk-cocoon/provider"
	"github.com/cocoonstack/vk-cocoon/vm"
)

const (
	defaultMacosStateDir = "/var/lib/cocoon-macos"
	macosOSName          = "macos"
)

func (p *Provider) resolveRunImageFromNAS(ctx context.Context, image string, force bool) (string, bool, error) {
	if p.ImageNAS == nil || isHTTPURL(image) {
		return "", false, nil
	}
	repository, tag := ociutil.ParseRef(image)
	localName := repository + ":" + tag
	found, err := p.ImageNAS.WithPublication(ctx, image, nasimage.ModeRun, func(publication *nasimage.Publication) error {
		if !force {
			local, inspectErr := p.Runtime.ImageInspect(ctx, localName)
			if inspectErr == nil && local.ID == publication.Manifest.Artifact.Digest {
				return nil
			}
		}
		return p.importNASRunImage(ctx, publication, localName)
	})
	if err != nil {
		return "", true, fmt.Errorf("materialize image %s from NAS: %w", image, err)
	}
	return localName, found, nil
}

func (p *Provider) importNASRunImage(ctx context.Context, publication *nasimage.Publication, localName string) error {
	if publication.Manifest.OS == macosOSName {
		return errors.New("macOS NAS image cannot be imported by the cocoon runtime")
	}
	if err := p.admitNASImport(ctx, publication, nil, false); err != nil {
		return err
	}
	if err := publication.VerifyArtifact(); err != nil {
		return fmt.Errorf("verify NAS run image: %w", err)
	}
	if err := importFile(ctx, publication.ArtifactPath, func() (io.WriteCloser, func() error, error) {
		return p.Runtime.ImageImport(ctx, localName)
	}); err != nil {
		return fmt.Errorf("import NAS run image %s: %w", localName, err)
	}
	image, err := p.Runtime.ImageInspect(ctx, localName)
	if err != nil {
		return fmt.Errorf("inspect NAS run image alias %s after import: %w", localName, err)
	}
	if image.ID != publication.Manifest.Artifact.Digest {
		return fmt.Errorf("NAS run image %s digest mismatch after import: got %s, want %s", localName, image.ID, publication.Manifest.Artifact.Digest)
	}
	return nil
}

func (p *Provider) importNASClone(ctx context.Context, publication *nasimage.Publication, localName string) (*vm.Snapshot, error) {
	if publication.Manifest.OS == macosOSName {
		return nil, errors.New("macOS publications do not support mode=clone")
	}
	dependencies, resolveErr := publication.ImageArtifacts()
	if resolveErr != nil {
		return nil, fmt.Errorf("resolve NAS snapshot dependencies: %w", resolveErr)
	}
	if admitErr := p.admitNASImport(ctx, publication, dependencies, false); admitErr != nil {
		return nil, admitErr
	}
	if verifyErr := publication.VerifyArtifact(); verifyErr != nil {
		return nil, fmt.Errorf("verify NAS snapshot bundle: %w", verifyErr)
	}
	for _, dependency := range dependencies {
		if p.imagePresent(ctx, dependency.Digest) {
			continue
		}
		if verifyErr := nasimage.VerifyImageArtifact(dependency); verifyErr != nil {
			return nil, fmt.Errorf("verify NAS snapshot dependency %s: %w", dependency.Digest, verifyErr)
		}
		dependency := dependency
		if err := importFile(ctx, dependency.Path, func() (io.WriteCloser, func() error, error) {
			return p.Runtime.ImageImport(ctx, dependency.Name)
		}); err != nil {
			return nil, fmt.Errorf("import NAS snapshot dependency %s: %w", dependency.Digest, err)
		}
		image, err := p.Runtime.ImageInspect(ctx, dependency.Name)
		if err != nil {
			return nil, fmt.Errorf("inspect snapshot dependency %s after import: %w", dependency.Digest, err)
		}
		if image.ID != dependency.Digest {
			return nil, fmt.Errorf("snapshot dependency %s digest mismatch after import: got %s", dependency.Name, image.ID)
		}
	}
	if err := importFile(ctx, publication.ArtifactPath, func() (io.WriteCloser, func() error, error) {
		return p.Runtime.SnapshotImport(ctx, localName)
	}); err != nil {
		return nil, fmt.Errorf("import NAS snapshot %s: %w", localName, err)
	}
	snapshot, err := p.Runtime.Snapshot(ctx, localName)
	if err != nil {
		return nil, fmt.Errorf("inspect NAS snapshot %s after import: %w", localName, err)
	}
	if err := validateImportedSnapshot(snapshot, publication.Manifest); err != nil {
		return nil, fmt.Errorf("validate NAS snapshot %s after import: %w", localName, err)
	}
	return snapshot, nil
}

func (p *Provider) importNASMacosImage(ctx context.Context, publication *nasimage.Publication, image string) error {
	if publication.Manifest.OS != macosOSName {
		return fmt.Errorf("NAS image %s has os=%s, want macos", image, publication.Manifest.OS)
	}
	if err := p.admitNASImport(ctx, publication, nil, true); err != nil {
		return err
	}
	if err := publication.VerifyArtifact(); err != nil {
		return fmt.Errorf("verify NAS macOS image: %w", err)
	}
	if output, err := p.macosExec(ctx, "image", "import", image, publication.ArtifactPath); err != nil {
		return fmt.Errorf("import NAS macOS image %s: %w: %s", image, err, strings.TrimSpace(output))
	}
	digest, err := p.macosImageDigest(ctx, image)
	if err != nil {
		return fmt.Errorf("inspect NAS macOS image %s after import: %w", image, err)
	}
	if digest != publication.Manifest.Artifact.Digest {
		return fmt.Errorf("NAS macOS image %s digest mismatch after import: got %s, want %s", image, digest, publication.Manifest.Artifact.Digest)
	}
	return nil
}

func (p *Provider) macosImageDigest(ctx context.Context, image string) (string, error) {
	output, err := p.macosExec(ctx, "image", "inspect", image)
	if err != nil {
		return "", err
	}
	var metadata struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(output), &metadata); err != nil {
		return "", err
	}
	if metadata.ID == "" {
		return "", errors.New("image inspect returned an empty digest")
	}
	return metadata.ID, nil
}

func importFile(ctx context.Context, filename string, openImporter func() (io.WriteCloser, func() error, error)) error {
	source, err := os.Open(filename) //nolint:gosec // filename is containment-checked by nasimage.Store
	if err != nil {
		return err
	}
	defer source.Close() //nolint:errcheck
	importer, wait, err := openImporter()
	if err != nil {
		return err
	}
	_, copyErr := copyWithContext(ctx, importer, source)
	if copyErr != nil {
		_ = importer.Close()
		_ = wait()
		return copyErr
	}
	if err := importer.Close(); err != nil {
		_ = wait()
		return err
	}
	return wait()
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 1024*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := src.Read(buffer)
		if read > 0 {
			count, writeErr := dst.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func validateImportedSnapshot(snapshot *vm.Snapshot, manifest nasimage.Manifest) error {
	if snapshot == nil || manifest.Base == nil {
		return errors.New("snapshot metadata is missing")
	}
	if snapshot.Image != manifest.Base.Image || snapshot.ImageDigest != manifest.Base.Digest || snapshot.ImageType != "cloudimg" || snapshot.Hypervisor != manifest.Hypervisor {
		return fmt.Errorf("snapshot identity mismatch: id=%q image=%q image_digest=%q image_type=%q hypervisor=%q", snapshot.ID, snapshot.Image, snapshot.ImageDigest, snapshot.ImageType, snapshot.Hypervisor)
	}
	want := slices.Clone(manifest.ImageBlobIDs)
	got := make([]string, 0, len(snapshot.ImageBlobIDs))
	for digest := range snapshot.ImageBlobIDs {
		if !strings.HasPrefix(digest, "sha256:") {
			digest = "sha256:" + digest
		}
		got = append(got, digest)
	}
	if !slices.Contains(got, manifest.Base.Digest) {
		got = append(got, manifest.Base.Digest)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !slices.Equal(want, got) {
		return fmt.Errorf("snapshot dependencies %v do not match %v", got, want)
	}
	return nil
}

func (p *Provider) admitNASImport(ctx context.Context, publication *nasimage.Publication, dependencies []nasimage.ImageArtifact, macos bool) error {
	required := publication.Manifest.Artifact.SizeBytes
	if publication.Manifest.Mode == nasimage.ModeClone {
		required = publication.Manifest.Artifact.UnpackedSizeBytes
		for _, dependency := range dependencies {
			if !p.imagePresent(ctx, dependency.Digest) {
				var ok bool
				if required, ok = safeAdd(required, dependency.SizeBytes); !ok {
					return errors.New("NAS import size estimate overflows")
				}
			}
		}
	}
	if required <= 0 {
		return errors.New("NAS import has no conservative size estimate")
	}
	if p.NASImportOverheadPercent > 0 {
		if required > (1<<63-1)/int64(p.NASImportOverheadPercent) {
			return errors.New("NAS import overhead estimate overflows")
		}
		overhead := required * int64(p.NASImportOverheadPercent) / 100
		var ok bool
		if required, ok = safeAdd(required, overhead); !ok {
			return errors.New("NAS import size estimate overflows")
		}
	}
	root := p.NASCacheRoot
	if root == "" {
		if macos {
			root = cmp.Or(os.Getenv("COCOON_MACOS_HOME"), defaultMacosStateDir)
		} else {
			root = provider.CocoonRootDir()
		}
	}
	total, available, err := provider.StorageBytesAt(root)
	if err != nil {
		return fmt.Errorf("inspect local image cache filesystem %s: %w", root, err)
	}
	reserve := max(p.NASMinFreeBytes, total*int64(p.NASMinFreePercent)/100)
	if required > available || available-required < reserve {
		return fmt.Errorf("insufficient local image cache space: available=%d required=%d reserve=%d", available, required, reserve)
	}
	return nil
}

func safeAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || right > (1<<63-1)-left {
		return 0, false
	}
	return left + right, true
}
