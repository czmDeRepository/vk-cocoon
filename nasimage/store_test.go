package nasimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testCPUClass = "intel-cascadelake-ch-v1"

func TestRunPublication(t *testing.T) {
	root := t.TempDir()
	image := "team/run-image:v1"
	artifact := []byte("qcow2-run-image")
	publication := writeRunPublication(t, root, image, "linux", artifact)
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), image, ModeRun, func(got *Publication) error {
		if got.Manifest.Artifact.Digest != publication.Manifest.Artifact.Digest {
			t.Fatalf("digest = %q, want %q", got.Manifest.Artifact.Digest, publication.Manifest.Artifact.Digest)
		}
		return got.VerifyArtifact()
	})
	if err != nil {
		t.Fatalf("WithPublication: %v", err)
	}
	if !found {
		t.Fatal("publication not found")
	}
}

func TestAbsentPublicationAllowsFallback(t *testing.T) {
	store, err := New(t.TempDir(), testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), "ubuntu:v1", ModeRun, func(*Publication) error {
		t.Fatal("callback must not run")
		return nil
	})
	if err != nil || found {
		t.Fatalf("WithPublication = found=%v err=%v, want false,nil", found, err)
	}
}

func TestMountedStoreFailsClosedWhenMountIsUnavailable(t *testing.T) {
	store, err := New(t.TempDir(), testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	store.Cluster = "cocoon-jj"
	store.requireMounted = true
	found, err := store.WithPublication(t.Context(), "ubuntu:v1", ModeRun, func(*Publication) error {
		t.Fatal("callback must not run")
		return nil
	})
	if !found || err == nil || !strings.Contains(err.Error(), "validate mounted NAS") {
		t.Fatalf("WithPublication = found=%v err=%v, want fail-closed mount error", found, err)
	}
}

func TestMountedStoreRevalidatesBeforeFallback(t *testing.T) {
	store, err := New(t.TempDir(), testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	store.Cluster = "cocoon-jj"
	store.requireMounted = true
	validations := 0
	store.mountValidator = func(string) error {
		validations++
		if validations == 1 {
			return nil
		}
		return errors.New("mount disappeared")
	}
	found, err := store.WithPublication(t.Context(), "ubuntu:v1", ModeRun, func(*Publication) error {
		t.Fatal("callback must not run")
		return nil
	})
	if !found || err == nil || !strings.Contains(err.Error(), "validate mounted NAS after resolving image") {
		t.Fatalf("WithPublication = found=%v err=%v, want fail-closed revalidation error", found, err)
	}
	if validations != 2 {
		t.Fatalf("mount validations = %d, want 2", validations)
	}
}

func TestPublicationClusterMustMatchConfiguredCluster(t *testing.T) {
	root := t.TempDir()
	writeRunPublication(t, root, "team/image:v1", "linux", []byte("image"))
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	store.Cluster = "another-cluster"
	found, err := store.WithPublication(t.Context(), "team/image:v1", ModeRun, func(*Publication) error {
		t.Fatal("callback must not run")
		return nil
	})
	if !found || err == nil || !strings.Contains(err.Error(), "does not match configured cluster") {
		t.Fatalf("WithPublication = found=%v err=%v, want cluster mismatch", found, err)
	}
}

func TestWrongModeDoesNotFallBack(t *testing.T) {
	root := t.TempDir()
	writeRunPublication(t, root, "team/image:v1", "linux", []byte("image"))
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), "team/image:v1", ModeClone, func(*Publication) error { return nil })
	if !found || err == nil || !strings.Contains(err.Error(), "published as mode=run") {
		t.Fatalf("WithPublication = found=%v err=%v", found, err)
	}
}

func TestCorruptManagedPublicationFailsClosed(t *testing.T) {
	root := t.TempDir()
	publication := writeRunPublication(t, root, "team/image:v1", "linux", []byte("image"))
	publication.Manifest.Artifact.Path = "../escape.qcow2"
	writeJSON(t, publication.ManifestPath, publication.Manifest)
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), "team/image:v1", ModeRun, func(*Publication) error { return nil })
	if !found || err == nil || !strings.Contains(err.Error(), "artifact path") {
		t.Fatalf("WithPublication = found=%v err=%v", found, err)
	}
}

func TestFlatDigestPathIsRejected(t *testing.T) {
	root := t.TempDir()
	publication := writeRunPublication(t, root, "team/image:v1", "linux", []byte("image"))
	digestHex := strings.TrimPrefix(publication.Manifest.Artifact.Digest, "sha256:")
	publication.Manifest.Artifact.Path = filepath.ToSlash(filepath.Join("images", "blobs", "sha256", digestHex+".qcow2"))
	writeJSON(t, publication.ManifestPath, publication.Manifest)
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), publication.Manifest.Image, ModeRun, func(*Publication) error { return nil })
	if !found || err == nil || !strings.Contains(err.Error(), "artifact path") {
		t.Fatalf("WithPublication = found=%v err=%v, want flat digest path rejection", found, err)
	}
}

func TestArtifactSymlinkIsRejected(t *testing.T) {
	root := t.TempDir()
	publication := writeRunPublication(t, root, "team/image:v1", "linux", []byte("image"))
	artifactPath := filepath.Join(root, filepath.FromSlash(publication.Manifest.Artifact.Path))
	outside := filepath.Join(t.TempDir(), "outside.qcow2")
	writeFile(t, outside, []byte("image"))
	if err := os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, artifactPath); err != nil {
		t.Fatal(err)
	}
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), publication.Manifest.Image, ModeRun, func(*Publication) error { return nil })
	if !found || err == nil || !strings.Contains(err.Error(), "traverses a symlink") {
		t.Fatalf("WithPublication = found=%v err=%v", found, err)
	}
}

func TestClonePublication(t *testing.T) {
	root := t.TempDir()
	publication := writeClonePublication(t, root, "team/clone:v1")
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), publication.Manifest.Image, ModeClone, func(got *Publication) error {
		if err := got.VerifyArtifact(); err != nil {
			return err
		}
		dependencies, err := got.ImageArtifacts()
		if err != nil {
			return err
		}
		if len(dependencies) != 2 {
			t.Fatalf("dependencies = %v, want base + one extra", dependencies)
		}
		for _, dependency := range dependencies {
			if err := VerifyImageArtifact(dependency); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithPublication: %v", err)
	}
	if !found {
		t.Fatal("publication not found")
	}
}

func TestClonePublicationRejectsArchiveDigestMismatch(t *testing.T) {
	root := t.TempDir()
	publication := writeClonePublication(t, root, "team/clone:v1")
	artifactPath := filepath.Join(root, filepath.FromSlash(publication.Manifest.Artifact.Path))
	corrupt := []byte("snapshot-tar-gziq")
	if int64(len(corrupt)) != publication.Manifest.Artifact.SizeBytes {
		t.Fatalf("test corruption size = %d, want %d", len(corrupt), publication.Manifest.Artifact.SizeBytes)
	}
	writeFile(t, artifactPath, corrupt)
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), publication.Manifest.Image, ModeClone, func(got *Publication) error {
		return got.VerifyArtifact()
	})
	if !found || err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("WithPublication = found=%v err=%v", found, err)
	}
}

func TestCloneCPUClassMismatch(t *testing.T) {
	root := t.TempDir()
	publication := writeClonePublication(t, root, "team/clone:v1")
	store, err := New(root, "amd-genoa-ch-v1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	found, err := store.WithPublication(t.Context(), publication.Manifest.Image, ModeClone, func(*Publication) error { return nil })
	if !found || err == nil || !strings.Contains(err.Error(), "snapshot CPU class") {
		t.Fatalf("WithPublication = found=%v err=%v", found, err)
	}
}

func TestCloneLockOrderMatchesPublisher(t *testing.T) {
	root := t.TempDir()
	publication := writeClonePublication(t, root, "team/clone:v1")
	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	loaded, err := store.loadPublication(publication.Manifest.Image, ModeClone,
		filepath.ToSlash(filepath.Join("snapshots", "refs", "team/clone", "v1.json")))
	if err != nil {
		t.Fatalf("loadPublication: %v", err)
	}
	primary, err := loaded.primaryLockPaths()
	if err != nil {
		t.Fatalf("primaryLockPaths: %v", err)
	}
	dependencies, err := loaded.dependencyLockPaths()
	if err != nil {
		t.Fatalf("dependencyLockPaths: %v", err)
	}
	if len(primary) != 2 {
		t.Fatalf("primary locks = %v, want ref + snapshot digest", primary)
	}
	if len(dependencies) != len(publication.Manifest.ImageBlobIDs) {
		t.Fatalf("dependency locks = %v, want %d", dependencies, len(publication.Manifest.ImageBlobIDs))
	}
	for _, dependency := range dependencies {
		if slices.Contains(primary, dependency) {
			t.Fatalf("dependency lock %q duplicated in primary locks", dependency)
		}
	}
}

func TestSharedLockHonorsContext(t *testing.T) {
	root := t.TempDir()
	publication := writeRunPublication(t, root, "team/image:v1", "linux", []byte("image"))
	lockRelative, err := digestLockRelativePath(publication.Manifest.Artifact.Digest)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, filepath.FromSlash(lockRelative))
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close() //nolint:errcheck
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck

	store, err := New(root, testCPUClass)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	found, err := store.WithPublication(ctx, publication.Manifest.Image, ModeRun, func(*Publication) error { return nil })
	if !found || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WithPublication = found=%v err=%v, want context deadline", found, err)
	}
}

func writeRunPublication(t *testing.T, root, image, osName string, artifact []byte) *Publication {
	t.Helper()
	digest := sha256Digest(artifact)
	publicationID := "image-export-run-v1"
	repository, tag := splitRef(t, image)
	artifactRelative, err := imageBlobRelativePath(digest)
	if err != nil {
		t.Fatal(err)
	}
	manifestRelative, err := imageManifestRelativePath(digest, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	refRelative := filepath.ToSlash(filepath.Join("images", "refs", repository, tag+".json"))
	writeFile(t, filepath.Join(root, filepath.FromSlash(artifactRelative)), artifact)
	manifest := Manifest{
		SchemaVersion: 1, PublicationID: publicationID, Cluster: "cocoon-jj", OS: osName,
		Mode: ModeRun, Image: image, Artifact: ArtifactFile{
			Digest: digest, Path: artifactRelative, SizeBytes: int64(len(artifact)), VirtualSizeBytes: int64(len(artifact)) * 2,
		}, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ref := artifactRef{
		SchemaVersion: 1, PublicationID: publicationID, Cluster: manifest.Cluster, Image: image,
		Mode: ModeRun, Digest: digest, ManifestPath: manifestRelative, CreatedAt: manifest.CreatedAt,
	}
	manifestPath := filepath.Join(root, filepath.FromSlash(manifestRelative))
	writeJSON(t, manifestPath, manifest)
	writeJSON(t, filepath.Join(root, filepath.FromSlash(refRelative)), ref)
	return &Publication{Manifest: manifest, ManifestPath: manifestPath}
}

func writeClonePublication(t *testing.T, root, image string) *Publication {
	t.Helper()
	snapshotID := "SNAPSHOTTESTIDENTIFIER00001"
	base := []byte("base-image")
	extra := []byte("extra-image")
	baseDigest := sha256Digest(base)
	extraDigest := sha256Digest(extra)
	snapshot := []byte("snapshot-tar-gzip")
	artifactDigest := sha256Digest(snapshot)
	metadata := map[string]any{
		"id": snapshotID, "image": "base:v1", "image_digest": baseDigest, "image_type": "cloudimg",
		"image_blob_ids": map[string]struct{}{strings.TrimPrefix(extraDigest, "sha256:"): {}},
		"hypervisor":     "cloud-hypervisor",
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	publicationID := "image-export-clone-v1"
	repository, tag := splitRef(t, image)
	artifactDir, err := snapshotArtifactDirRelativePath(artifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	artifactRelative := filepath.ToSlash(filepath.Join(artifactDir, "snapshot.tar.gz"))
	manifestRelative := filepath.ToSlash(filepath.Join(artifactDir, "manifests", publicationID+".json"))
	refRelative := filepath.ToSlash(filepath.Join("snapshots", "refs", repository, tag+".json"))
	baseRelative, err := imageBlobRelativePath(baseDigest)
	if err != nil {
		t.Fatal(err)
	}
	extraRelative, err := imageBlobRelativePath(extraDigest)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(artifactRelative)), snapshot)
	writeFile(t, filepath.Join(root, filepath.FromSlash(artifactDir), "snapshot.json"), metadataRaw)
	checksums := strings.TrimPrefix(sha256Digest(snapshot), "sha256:") + "  snapshot.tar.gz\n" +
		strings.TrimPrefix(sha256Digest(metadataRaw), "sha256:") + "  snapshot.json\n"
	writeFile(t, filepath.Join(root, filepath.FromSlash(artifactDir), "SHA256SUMS"), []byte(checksums))
	writeFile(t, filepath.Join(root, filepath.FromSlash(baseRelative)), base)
	writeFile(t, filepath.Join(root, filepath.FromSlash(extraRelative)), extra)
	manifest := Manifest{
		SchemaVersion: 1, PublicationID: publicationID, Cluster: "cocoon-jj", OS: "linux",
		Mode: ModeClone, Image: image, Artifact: ArtifactFile{
			Digest: artifactDigest, Path: artifactRelative, SizeBytes: int64(len(snapshot)), UnpackedSizeBytes: int64(len(snapshot)) * 4,
		}, Base: &ArtifactBase{Image: "base:v1", Digest: baseDigest, Path: baseRelative, SizeBytes: int64(len(base))},
		ImageBlobIDs: []string{baseDigest, extraDigest}, SourceSnapshotID: snapshotID, SnapshotCompatibilityClass: testCPUClass,
		Hypervisor: "cloud-hypervisor", SnapshotABI: "ch-v1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ref := artifactRef{
		SchemaVersion: 1, PublicationID: publicationID, Cluster: manifest.Cluster, Image: image,
		Mode: ModeClone, Digest: artifactDigest, ManifestPath: manifestRelative, CreatedAt: manifest.CreatedAt,
	}
	manifestPath := filepath.Join(root, filepath.FromSlash(manifestRelative))
	writeJSON(t, manifestPath, manifest)
	writeJSON(t, filepath.Join(root, filepath.FromSlash(refRelative)), ref)
	return &Publication{Manifest: manifest, ManifestPath: manifestPath}
}

func writeJSON(t *testing.T, filename string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filename, raw)
}

func writeFile(t *testing.T, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func splitRef(t *testing.T, image string) (string, string) {
	t.Helper()
	repository, tag, ok := strings.Cut(image, ":")
	if !ok {
		t.Fatalf("image %q has no tag", image)
	}
	return repository, tag
}

func sha256Digest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
