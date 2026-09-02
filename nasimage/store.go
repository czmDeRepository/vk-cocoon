// Package nasimage resolves and validates immutable image publications from a
// locally mounted NAS. The on-disk protocol is shared with Cocoon Console's
// image-export runner.
package nasimage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cocoonstack/cocoon-common/ociutil"
)

const (
	maxMetadataBytes = 1 << 20
	maxImageBlobIDs  = 256
	lockRetryDelay   = 50 * time.Millisecond
)

var (
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	publicationIDPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)
)

// Mode selects the mutable ref namespace and artifact validation rules.
type Mode string

const (
	ModeRun   Mode = "run"
	ModeClone Mode = "clone"
)

// ArtifactFile describes an immutable NAS artifact.
type ArtifactFile struct {
	Digest            string `json:"digest"`
	Path              string `json:"path"`
	SizeBytes         int64  `json:"size_bytes"`
	VirtualSizeBytes  int64  `json:"virtual_size_bytes,omitempty"`
	UnpackedSizeBytes int64  `json:"unpacked_size_bytes,omitempty"`
}

// ArtifactBase describes the pinned cloud image required by a Clone artifact.
type ArtifactBase struct {
	Image     string `json:"image"`
	Digest    string `json:"digest"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
}

// Manifest is the immutable publication manifest written by Cocoon Console.
type Manifest struct {
	SchemaVersion              int           `json:"schema_version"`
	PublicationID              string        `json:"publication_id"`
	Cluster                    string        `json:"cluster"`
	OS                         string        `json:"os"`
	Mode                       Mode          `json:"mode"`
	Image                      string        `json:"image"`
	Artifact                   ArtifactFile  `json:"artifact"`
	Base                       *ArtifactBase `json:"base,omitempty"`
	ImageBlobIDs               []string      `json:"image_blob_ids,omitempty"`
	SourceSnapshotID           string        `json:"snapshot_id,omitempty"`
	SnapshotCompatibilityClass string        `json:"snapshot_cpu_class"`
	Hypervisor                 string        `json:"hypervisor,omitempty"`
	SnapshotABI                string        `json:"snapshot_abi,omitempty"`
	CreatedAt                  string        `json:"created_at"`
}

type artifactRef struct {
	SchemaVersion int    `json:"schema_version"`
	PublicationID string `json:"publication_id"`
	Cluster       string `json:"cluster"`
	Image         string `json:"image"`
	Mode          Mode   `json:"mode"`
	Digest        string `json:"digest"`
	ManifestPath  string `json:"manifest_path"`
	CreatedAt     string `json:"created_at"`
}

// ImageArtifact is one cloud-image blob required by a publication. Name is
// the alias passed to cocoon image import; dependency-only blobs use their
// digest as the alias.
type ImageArtifact struct {
	Name      string
	Digest    string
	Path      string
	SizeBytes int64
}

// Publication is a fully cross-checked ref and immutable manifest. Paths are
// canonical existing files contained by Store.Root.
type Publication struct {
	RefPath          string
	ManifestPath     string
	ArtifactPath     string
	SnapshotJSONPath string
	ChecksumsPath    string
	Manifest         Manifest
	root             string
	realRoot         string
}

// Store reads publications from one cluster-specific NAS root.
type Store struct {
	Root                       string
	Cluster                    string
	SnapshotCompatibilityClass string
	realRoot                   string
	requireMounted             bool
	mountValidator             func(string) error
}

func sha256DigestParts(digest string) (string, string, error) {
	if !digestPattern.MatchString(digest) {
		return "", "", fmt.Errorf("invalid SHA256 digest %q", digest)
	}
	digestHex := strings.TrimPrefix(digest, "sha256:")
	return digestHex, digestHex[:2], nil
}

func imageBlobRelativePath(digest string) (string, error) {
	digestHex, shard, err := sha256DigestParts(digest)
	if err != nil {
		return "", err
	}
	return path.Join("images", "blobs", "sha256", shard, digestHex+".qcow2"), nil
}

func imageManifestRelativePath(digest, publicationID string) (string, error) {
	digestHex, shard, err := sha256DigestParts(digest)
	if err != nil {
		return "", err
	}
	return path.Join("images", "manifests", "sha256", shard, digestHex, publicationID+".json"), nil
}

func snapshotArtifactDirRelativePath(digest string) (string, error) {
	digestHex, shard, err := sha256DigestParts(digest)
	if err != nil {
		return "", err
	}
	return path.Join("snapshots", "sha256", shard, digestHex), nil
}

func digestLockRelativePath(digest string) (string, error) {
	digestHex, shard, err := sha256DigestParts(digest)
	if err != nil {
		return "", err
	}
	return path.Join("locks", "sha256", shard, digestHex+".lock"), nil
}

// New validates an explicitly configured NAS root for publication parsing.
// Production startup should use NewMounted to additionally require ByteNAS.
func New(root, snapshotCompatibilityClass string) (*Store, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("NAS root is empty")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("NAS root %q must be absolute", root)
	}
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat NAS root %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("NAS root %s is not a directory", root)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve NAS root %s: %w", root, err)
	}
	return &Store{
		Root:                       root,
		SnapshotCompatibilityClass: strings.TrimSpace(snapshotCompatibilityClass),
		realRoot:                   filepath.Clean(realRoot),
	}, nil
}

// NewMounted validates the publication root and verifies that the resolved
// path is currently backed by ByteFuse/virtio-pfs. This prevents an empty
// mountpoint directory from silently enabling OCI fallback after mount loss.
func NewMounted(root, cluster, snapshotCompatibilityClass string) (*Store, error) {
	cluster = strings.TrimSpace(cluster)
	if cluster == "" {
		return nil, errors.New("NAS cluster is empty")
	}
	store, err := New(root, snapshotCompatibilityClass)
	if err != nil {
		return nil, err
	}
	if err := validateNASMount(store.realRoot); err != nil {
		return nil, err
	}
	store.Cluster = cluster
	store.requireMounted = true
	return store, nil
}

func (s *Store) validateMounted() error {
	if !s.requireMounted {
		return nil
	}
	validator := s.mountValidator
	if validator == nil {
		validator = validateNASMount
	}
	return validator(s.realRoot)
}

// WithPublication resolves image in the requested namespace and keeps shared
// ref/digest locks for the callback. found=false means neither a managed ref
// nor a wrong-mode ref exists, so callers may retain their OCI/HTTP fallback.
func (s *Store) WithPublication(ctx context.Context, image string, mode Mode, fn func(*Publication) error) (found bool, err error) {
	if err := s.validateMounted(); err != nil {
		return true, fmt.Errorf("validate mounted NAS before resolving image %s: %w", image, err)
	}
	refRelative, ok := referencePath(image, mode)
	if !ok {
		return false, nil
	}
	exists, presenceErr := s.publicationRefExists(image, mode, refRelative)
	if presenceErr != nil {
		return true, presenceErr
	}
	if !exists {
		return false, nil
	}

	// The ref may move between the optimistic read and lock acquisition. Retry
	// with the new digest set rather than importing bytes not protected from GC.
	for range 4 {
		publication, loadErr := s.loadPublication(image, mode, refRelative)
		if loadErr != nil {
			return true, loadErr
		}
		primaryLockPaths, pathErr := publication.primaryLockPaths()
		if pathErr != nil {
			return true, pathErr
		}
		releasePrimary, lockErr := acquireSharedLocks(ctx, primaryLockPaths)
		if lockErr != nil {
			return true, lockErr
		}
		lockedPublication, reloadErr := s.loadPublication(image, mode, refRelative)
		if reloadErr != nil {
			releasePrimary()
			return true, reloadErr
		}
		lockedPrimaryLockPaths, pathErr := lockedPublication.primaryLockPaths()
		if pathErr != nil {
			releasePrimary()
			return true, pathErr
		}
		if !slices.Equal(primaryLockPaths, lockedPrimaryLockPaths) {
			releasePrimary()
			continue
		}
		// Console's clone publisher takes the mutable ref and snapshot digest
		// locks first, then the dependency digest locks. Mirror that order to
		// avoid a cycle where an importer holds a dependency while a publisher
		// holds the snapshot lock and each waits for the other.
		dependencyLockPaths, pathErr := lockedPublication.dependencyLockPaths()
		if pathErr != nil {
			releasePrimary()
			return true, pathErr
		}
		releaseDependencies, lockErr := acquireSharedLocks(ctx, dependencyLockPaths)
		if lockErr != nil {
			releasePrimary()
			return true, lockErr
		}
		callbackErr := fn(lockedPublication)
		releaseDependencies()
		releasePrimary()
		return true, callbackErr
	}
	return true, fmt.Errorf("NAS ref %s changed repeatedly while acquiring locks", refRelative)
}

func (s *Store) publicationRefExists(image string, mode Mode, refRelative string) (bool, error) {
	refPath := filepath.Join(s.Root, filepath.FromSlash(refRelative))
	if _, err := os.Stat(refPath); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat NAS ref %s: %w", refRelative, err)
	}

	otherMode := ModeRun
	if mode == ModeRun {
		otherMode = ModeClone
	}
	otherRelative, _ := referencePath(image, otherMode)
	if _, err := os.Stat(filepath.Join(s.Root, filepath.FromSlash(otherRelative))); err == nil {
		return false, fmt.Errorf("NAS image %s is published as mode=%s, requested mode=%s", image, otherMode, mode)
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat alternate NAS ref %s: %w", otherRelative, err)
	}

	// A lost mount can make both managed refs appear absent. Revalidate at the
	// exact fallback boundary so a mid-resolution outage cannot turn a NAS
	// publication into an unintended OCI pull.
	if err := s.validateMounted(); err != nil {
		return false, fmt.Errorf("validate mounted NAS after resolving image %s: %w", image, err)
	}
	return false, nil
}

func (s *Store) loadPublication(image string, mode Mode, refRelative string) (*Publication, error) {
	refPath, err := s.secureExistingPath(refRelative)
	if err != nil {
		return nil, fmt.Errorf("resolve NAS ref %s: %w", refRelative, err)
	}
	var ref artifactRef
	if readErr := readJSONFile(refPath, &ref); readErr != nil {
		return nil, fmt.Errorf("read NAS ref %s: %w", refRelative, readErr)
	}
	if validateErr := validateRef(ref, image, mode); validateErr != nil {
		return nil, fmt.Errorf("validate NAS ref %s: %w", refRelative, validateErr)
	}
	if s.Cluster != "" && ref.Cluster != s.Cluster {
		return nil, fmt.Errorf("validate NAS ref %s: cluster %q does not match configured cluster %q", refRelative, ref.Cluster, s.Cluster)
	}
	manifestPath, err := s.secureExistingPath(ref.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("resolve NAS manifest %s: %w", ref.ManifestPath, err)
	}
	var manifest Manifest
	if readErr := readJSONFile(manifestPath, &manifest); readErr != nil {
		return nil, fmt.Errorf("read NAS manifest %s: %w", ref.ManifestPath, readErr)
	}
	if validateErr := s.validateManifest(ref, manifest); validateErr != nil {
		return nil, fmt.Errorf("validate NAS manifest %s: %w", ref.ManifestPath, validateErr)
	}
	artifactPath, err := s.secureExistingPath(manifest.Artifact.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve NAS artifact %s: %w", manifest.Artifact.Path, err)
	}
	publication := &Publication{
		RefPath:      refPath,
		ManifestPath: manifestPath,
		ArtifactPath: artifactPath,
		Manifest:     manifest,
		root:         s.Root,
		realRoot:     s.realRoot,
	}
	if mode == ModeClone {
		artifactDir := path.Dir(manifest.Artifact.Path)
		publication.SnapshotJSONPath, err = s.secureExistingPath(path.Join(artifactDir, "snapshot.json"))
		if err != nil {
			return nil, fmt.Errorf("resolve NAS snapshot metadata: %w", err)
		}
		publication.ChecksumsPath, err = s.secureExistingPath(path.Join(artifactDir, "SHA256SUMS"))
		if err != nil {
			return nil, fmt.Errorf("resolve NAS snapshot checksums: %w", err)
		}
	}
	return publication, nil
}

func validateRef(ref artifactRef, image string, mode Mode) error {
	if ref.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", ref.SchemaVersion)
	}
	if !publicationIDPattern.MatchString(ref.PublicationID) {
		return fmt.Errorf("invalid publication_id %q", ref.PublicationID)
	}
	if ref.Cluster == "" || ref.Image != image || ref.Mode != mode {
		return fmt.Errorf("identity mismatch: cluster=%q image=%q mode=%q", ref.Cluster, ref.Image, ref.Mode)
	}
	if !digestPattern.MatchString(ref.Digest) {
		return fmt.Errorf("invalid digest %q", ref.Digest)
	}
	if _, err := time.Parse(time.RFC3339Nano, ref.CreatedAt); err != nil {
		return fmt.Errorf("invalid created_at: %w", err)
	}
	return validateRelativePath(ref.ManifestPath)
}

func (s *Store) validateManifest(ref artifactRef, manifest Manifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", manifest.SchemaVersion)
	}
	if manifest.PublicationID != ref.PublicationID || manifest.Cluster != ref.Cluster || manifest.Image != ref.Image || manifest.Mode != ref.Mode {
		return errors.New("manifest identity does not match ref")
	}
	if manifest.OS != "linux" && manifest.OS != "windows" && manifest.OS != "macos" {
		return fmt.Errorf("invalid OS %q", manifest.OS)
	}
	if manifest.Artifact.Digest != ref.Digest || !digestPattern.MatchString(manifest.Artifact.Digest) {
		return fmt.Errorf("artifact digest %q does not match ref %q", manifest.Artifact.Digest, ref.Digest)
	}
	if manifest.Artifact.SizeBytes <= 0 {
		return errors.New("artifact size_bytes must be positive")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return fmt.Errorf("invalid created_at: %w", err)
	}
	expectedArtifact, err := imageBlobRelativePath(manifest.Artifact.Digest)
	if err != nil {
		return err
	}
	expectedManifest, err := imageManifestRelativePath(manifest.Artifact.Digest, manifest.PublicationID)
	if err != nil {
		return err
	}
	if manifest.Mode == ModeClone {
		artifactDir, pathErr := snapshotArtifactDirRelativePath(manifest.Artifact.Digest)
		if pathErr != nil {
			return pathErr
		}
		expectedArtifact = path.Join(artifactDir, "snapshot.tar.gz")
		expectedManifest = path.Join(artifactDir, "manifests", manifest.PublicationID+".json")
	}
	if manifest.Artifact.Path != expectedArtifact {
		return fmt.Errorf("artifact path %q does not match %q", manifest.Artifact.Path, expectedArtifact)
	}
	if ref.ManifestPath != expectedManifest {
		return fmt.Errorf("manifest path %q does not match %q", ref.ManifestPath, expectedManifest)
	}
	if manifest.Mode == ModeRun {
		return validateRunManifest(manifest)
	}
	return s.validateCloneManifest(manifest)
}

func validateRunManifest(manifest Manifest) error {
	if manifest.Artifact.VirtualSizeBytes <= 0 {
		return errors.New("run artifact virtual_size_bytes must be positive")
	}
	if manifest.SnapshotCompatibilityClass != "" || manifest.Base != nil || len(manifest.ImageBlobIDs) != 0 {
		return errors.New("run artifact contains clone-only metadata")
	}
	return nil
}

func (s *Store) validateCloneManifest(manifest Manifest) error {
	if manifest.Base == nil || manifest.Base.Image == "" || !digestPattern.MatchString(manifest.Base.Digest) || manifest.Base.SizeBytes <= 0 {
		return errors.New("clone base metadata is incomplete")
	}
	expectedBasePath, err := imageBlobRelativePath(manifest.Base.Digest)
	if err != nil {
		return err
	}
	if manifest.Base.Path != expectedBasePath {
		return fmt.Errorf("base path %q does not match %q", manifest.Base.Path, expectedBasePath)
	}
	if manifest.SourceSnapshotID == "" || manifest.Artifact.UnpackedSizeBytes <= 0 || manifest.Hypervisor == "" || manifest.SnapshotCompatibilityClass == "" {
		return errors.New("clone compatibility metadata is incomplete")
	}
	if s.SnapshotCompatibilityClass == "" || manifest.SnapshotCompatibilityClass != s.SnapshotCompatibilityClass {
		return fmt.Errorf("snapshot CPU class %q does not match node class %q", manifest.SnapshotCompatibilityClass, s.SnapshotCompatibilityClass)
	}
	if manifest.SnapshotABI == "" || manifest.SnapshotABI != snapshotABI(manifest.SnapshotCompatibilityClass) {
		return fmt.Errorf("snapshot ABI %q is inconsistent with CPU class %q", manifest.SnapshotABI, manifest.SnapshotCompatibilityClass)
	}
	if len(manifest.ImageBlobIDs) == 0 || len(manifest.ImageBlobIDs) > maxImageBlobIDs {
		return fmt.Errorf("clone image dependency count %d is invalid", len(manifest.ImageBlobIDs))
	}
	seen := make(map[string]struct{}, len(manifest.ImageBlobIDs))
	for _, digest := range manifest.ImageBlobIDs {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("invalid image dependency %q", digest)
		}
		if _, exists := seen[digest]; exists {
			return fmt.Errorf("duplicate image dependency %q", digest)
		}
		seen[digest] = struct{}{}
	}
	if _, ok := seen[manifest.Base.Digest]; !ok {
		return errors.New("clone dependencies do not include the base digest")
	}
	return nil
}

func (s *Store) secureExistingPath(relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	full := filepath.Join(s.Root, filepath.FromSlash(relative))
	realPath, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", err
	}
	realPath = filepath.Clean(realPath)
	expectedPath := filepath.Join(s.realRoot, filepath.FromSlash(relative))
	if realPath != expectedPath {
		return "", fmt.Errorf("path %q traverses a symlink", relative)
	}
	inside, err := filepath.Rel(s.realRoot, realPath)
	if err != nil || inside == ".." || filepath.IsAbs(inside) || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes NAS root", relative)
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path %q is not a regular file", relative)
	}
	return filepath.Clean(full), nil
}

func validateRelativePath(relative string) error {
	if relative == "" || strings.Contains(relative, `\`) || path.IsAbs(relative) || path.Clean(relative) != relative || relative == "." || strings.HasPrefix(relative, "../") {
		return fmt.Errorf("unsafe relative path %q", relative)
	}
	return nil
}

func referencePath(image string, mode Mode) (string, bool) {
	if !ociutil.IsRelativeRef(image) {
		return "", false
	}
	repository, tag := ociutil.ParseRef(image)
	root := "images"
	if mode == ModeClone {
		root = "snapshots"
	}
	return path.Join(root, "refs", repository, tag+".json"), true
}

func readJSONFile(filename string, target any) error {
	raw, err := readSmallFile(filename)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JSON document has trailing data")
	}
	return nil
}

func readSmallFile(filename string) ([]byte, error) {
	f, err := os.Open(filename) //nolint:gosec // filename is rooted and containment-checked by Store
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(f, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxMetadataBytes {
		return nil, fmt.Errorf("metadata exceeds %d bytes", maxMetadataBytes)
	}
	return raw, nil
}

func (p *Publication) primaryLockPaths() ([]string, error) {
	digestLock, err := digestLockRelativePath(p.Manifest.Artifact.Digest)
	if err != nil {
		return nil, err
	}
	paths := []string{
		p.RefPath + ".lock",
		filepath.Join(p.root, filepath.FromSlash(digestLock)),
	}
	sort.Strings(paths)
	return slices.Compact(paths), nil
}

func (p *Publication) dependencyLockPaths() ([]string, error) {
	paths := make([]string, 0, len(p.Manifest.ImageBlobIDs))
	for _, digest := range p.Manifest.ImageBlobIDs {
		if digest == p.Manifest.Artifact.Digest {
			continue
		}
		lockPath, err := digestLockRelativePath(digest)
		if err != nil {
			return nil, err
		}
		paths = append(paths, filepath.Join(p.root, filepath.FromSlash(lockPath)))
	}
	sort.Strings(paths)
	return slices.Compact(paths), nil
}

func acquireSharedLocks(ctx context.Context, paths []string) (func(), error) {
	files := make([]*os.File, 0, len(paths))
	release := func() {
		for _, file := range slices.Backward(files) {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
		}
	}
	for _, lockPath := range paths {
		if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
			release()
			return nil, fmt.Errorf("create NAS lock directory: %w", err)
		}
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path is derived from validated NAS metadata
		if err != nil {
			release()
			return nil, fmt.Errorf("open NAS lock %s: %w", lockPath, err)
		}
		for {
			err = unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB)
			if err == nil {
				break
			}
			if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
				_ = file.Close()
				release()
				return nil, fmt.Errorf("lock NAS path %s: %w", lockPath, err)
			}
			timer := time.NewTimer(lockRetryDelay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				_ = file.Close()
				release()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		files = append(files, file)
	}
	return release, nil
}

// VerifyArtifact verifies the immutable run image or clone snapshot bundle.
func (p *Publication) VerifyArtifact() error {
	if p.Manifest.Mode == ModeRun {
		return verifyDigestFile(p.ArtifactPath, p.Manifest.Artifact.Digest, p.Manifest.Artifact.SizeBytes)
	}
	if err := verifyDigestFile(p.ArtifactPath, p.Manifest.Artifact.Digest, p.Manifest.Artifact.SizeBytes); err != nil {
		return err
	}
	checksums, err := parseChecksums(p.ChecksumsPath)
	if err != nil {
		return err
	}
	for name, filename := range map[string]string{
		"snapshot.tar.gz": p.ArtifactPath,
		"snapshot.json":   p.SnapshotJSONPath,
	} {
		digest, ok := checksums[name]
		if !ok {
			return fmt.Errorf("snapshot checksums omit %s", name)
		}
		if err := verifyDigestFile(filename, "sha256:"+digest, 0); err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
	}
	if len(checksums) != 2 {
		entries := mapsKeys(checksums)
		sort.Strings(entries)
		return fmt.Errorf("snapshot checksums contain unexpected entries: %v", entries)
	}
	return p.verifySnapshotMetadata()
}

// ImageArtifacts returns the base and dependency cloud-image blobs required
// before importing a Clone snapshot.
func (p *Publication) ImageArtifacts() ([]ImageArtifact, error) {
	if p.Manifest.Mode != ModeClone || p.Manifest.Base == nil {
		return nil, nil
	}
	result := []ImageArtifact{{
		Name:      p.Manifest.Base.Image,
		Digest:    p.Manifest.Base.Digest,
		SizeBytes: p.Manifest.Base.SizeBytes,
	}}
	result[0].Path = filepath.Join(p.root, filepath.FromSlash(p.Manifest.Base.Path))
	for _, digest := range p.Manifest.ImageBlobIDs {
		if digest == p.Manifest.Base.Digest {
			continue
		}
		relativePath, err := imageBlobRelativePath(digest)
		if err != nil {
			return nil, err
		}
		result = append(result, ImageArtifact{
			Name:   digest,
			Digest: digest,
			Path:   filepath.Join(p.root, filepath.FromSlash(relativePath)),
		})
	}
	for i := range result {
		relative, err := filepath.Rel(p.root, result[i].Path)
		if err != nil {
			return nil, err
		}
		securePath, err := (&Store{Root: p.root, realRoot: p.realRoot}).secureExistingPath(filepath.ToSlash(relative))
		if err != nil {
			return nil, fmt.Errorf("resolve image dependency %s: %w", result[i].Digest, err)
		}
		result[i].Path = securePath
		if result[i].SizeBytes == 0 {
			info, err := os.Stat(securePath)
			if err != nil {
				return nil, err
			}
			result[i].SizeBytes = info.Size()
		}
	}
	return result, nil
}

// VerifyImageArtifact verifies one pinned cloud-image blob before import.
func VerifyImageArtifact(artifact ImageArtifact) error {
	return verifyDigestFile(artifact.Path, artifact.Digest, artifact.SizeBytes)
}

func (p *Publication) verifySnapshotMetadata() error {
	var metadata struct {
		ID           string              `json:"id"`
		Image        string              `json:"image"`
		ImageDigest  string              `json:"image_digest"`
		ImageType    string              `json:"image_type"`
		ImageBlobIDs map[string]struct{} `json:"image_blob_ids"`
		Hypervisor   string              `json:"hypervisor"`
	}
	if err := readJSONFile(p.SnapshotJSONPath, &metadata); err != nil {
		return fmt.Errorf("read snapshot metadata: %w", err)
	}
	if p.Manifest.Base == nil || metadata.ID != p.Manifest.SourceSnapshotID || metadata.Image != p.Manifest.Base.Image || metadata.ImageDigest != p.Manifest.Base.Digest || metadata.Hypervisor != p.Manifest.Hypervisor {
		return errors.New("snapshot metadata does not match publication manifest")
	}
	if metadata.ImageType != "cloudimg" {
		return fmt.Errorf("snapshot image_type %q is not cloudimg", metadata.ImageType)
	}
	want := slices.Clone(p.Manifest.ImageBlobIDs)
	got := make([]string, 0, len(metadata.ImageBlobIDs))
	for digest := range metadata.ImageBlobIDs {
		if !strings.HasPrefix(digest, "sha256:") {
			digest = "sha256:" + digest
		}
		got = append(got, digest)
	}
	got = appendMissingDigest(got, p.Manifest.Base.Digest)
	sort.Strings(want)
	sort.Strings(got)
	if !slices.Equal(want, got) {
		return fmt.Errorf("snapshot image dependencies %v do not match manifest %v", got, want)
	}
	return nil
}

func parseChecksums(filename string) (map[string]string, error) {
	raw, err := readSmallFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read snapshot checksums: %w", err)
	}
	result := make(map[string]string, 2)
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid checksum line %q", line)
		}
		digest := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*")
		if len(digest) != 64 {
			return nil, fmt.Errorf("invalid checksum digest %q", fields[0])
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("invalid checksum digest %q", fields[0])
		}
		if name != "snapshot.tar.gz" && name != "snapshot.json" {
			return nil, fmt.Errorf("invalid checksum filename %q", name)
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate checksum filename %q", name)
		}
		result[name] = digest
	}
	return result, nil
}

func verifyDigestFile(filename, digest string, expectedSize int64) error {
	if !digestPattern.MatchString(digest) {
		return fmt.Errorf("invalid expected digest %q", digest)
	}
	if err := verifyFileSize(filename, expectedSize); err != nil {
		return err
	}
	f, err := os.Open(filename) //nolint:gosec // filename comes from a containment-checked publication
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}
	got := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if got != digest {
		return fmt.Errorf("digest mismatch: got %s, want %s", got, digest)
	}
	return nil
}

func verifyFileSize(filename string, expectedSize int64) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return fmt.Errorf("artifact %s is not a non-empty regular file", filename)
	}
	if expectedSize > 0 && info.Size() != expectedSize {
		return fmt.Errorf("artifact size mismatch: got %d, want %d", info.Size(), expectedSize)
	}
	return nil
}

func snapshotABI(cpuClass string) string {
	parts := strings.Split(strings.TrimSpace(cpuClass), "-")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], "-")
}

func appendMissingDigest(values []string, digest string) []string {
	if !slices.Contains(values, digest) {
		return append(values, digest)
	}
	return values
}

func mapsKeys[K comparable, V any](values map[K]V) []K {
	result := make([]K, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	return result
}
