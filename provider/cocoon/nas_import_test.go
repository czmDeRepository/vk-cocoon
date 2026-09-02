package cocoon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cocoonstack/vk-cocoon/nasimage"
	"github.com/cocoonstack/vk-cocoon/vm"
)

const nasTestCPUClass = "intel-cascadelake-ch-v1"

func TestEnsureRunImageImportsFromNAS(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/run:v1"
	digest := writeNASRun(t, root, image, "linux", []byte("run-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{imageImportDigests: map[string]string{image: digest}}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)

	got, err := p.ensureRunImage(t.Context(), image, false)
	if err != nil {
		t.Fatalf("ensureRunImage: %v", err)
	}
	if got != image {
		t.Fatalf("ensureRunImage = %q, want %q", got, image)
	}
	if len(runtime.imageImports) != 1 || runtime.imageImports[0] != image {
		t.Fatalf("image imports = %v, want [%s]", runtime.imageImports, image)
	}
	if len(runtime.ensuredImages) != 0 {
		t.Fatalf("OCI fallback unexpectedly used: %v", runtime.ensuredImages)
	}
}

func TestEnsureRunImageReusesMatchingNASAlias(t *testing.T) {
	root := t.TempDir()
	image := "team/run:v1"
	digest := writeNASRun(t, root, image, "linux", []byte("run-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{
		imagesPresent: map[string]bool{image: true},
		imageDigests:  map[string]string{image: digest},
	}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store

	got, err := p.ensureRunImage(t.Context(), image, false)
	if err != nil {
		t.Fatalf("ensureRunImage: %v", err)
	}
	if got != image || len(runtime.imageImports) != 0 || len(runtime.ensuredImages) != 0 {
		t.Fatalf("ensureRunImage = %q imports=%v fallback=%v", got, runtime.imageImports, runtime.ensuredImages)
	}
}

func TestEnsureRunImageReplacesWrongNASAlias(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/run:v1"
	digest := writeNASRun(t, root, image, "linux", []byte("run-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{
		imagesPresent:      map[string]bool{image: true},
		imageDigests:       map[string]string{image: "sha256:" + strings.Repeat("e", 64)},
		imageImportDigests: map[string]string{image: digest},
	}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)

	if _, err := p.ensureRunImage(t.Context(), image, false); err != nil {
		t.Fatalf("ensureRunImage: %v", err)
	}
	if len(runtime.imageImports) != 1 || runtime.imageImports[0] != image {
		t.Fatalf("image imports = %v, want replacement import", runtime.imageImports)
	}
	if len(runtime.ensuredImages) != 0 {
		t.Fatalf("wrong NAS alias fell back to OCI: %v", runtime.ensuredImages)
	}
}

func TestEnsureRunImageNASCorruptionFailsClosed(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/run:v1"
	digest := writeNASRun(t, root, image, "linux", []byte("run-image"))
	digestHex := strings.TrimPrefix(digest, "sha256:")
	artifactPath := filepath.Join(root, "images", "blobs", "sha256", digestHex[:2], digestHex+".qcow2")
	if err := os.WriteFile(artifactPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)

	_, err = p.ensureRunImage(t.Context(), image, false)
	if err == nil || !strings.Contains(err.Error(), "verify NAS run image") {
		t.Fatalf("ensureRunImage error = %v", err)
	}
	if len(runtime.ensuredImages) != 0 {
		t.Fatalf("corrupt managed publication fell back to OCI: %v", runtime.ensuredImages)
	}
}

func TestEnsureRunImageRejectsWrongImportedAliasDigest(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/run:v1"
	writeNASRun(t, root, image, "linux", []byte("run-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{imageImportDigests: map[string]string{image: "sha256:" + strings.Repeat("f", 64)}}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)

	_, err = p.ensureRunImage(t.Context(), image, false)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch after import") {
		t.Fatalf("ensureRunImage error = %v", err)
	}
	if len(runtime.ensuredImages) != 0 {
		t.Fatalf("wrong NAS alias digest fell back to OCI: %v", runtime.ensuredImages)
	}
}

func TestEnsureRunImageAbsentNASRefFallsBack(t *testing.T) {
	store, err := nasimage.New(t.TempDir(), nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store

	got, err := p.ensureRunImage(t.Context(), "ubuntu:v1", false)
	if err != nil {
		t.Fatalf("ensureRunImage: %v", err)
	}
	if got != "ubuntu:v1" || len(runtime.ensuredImages) != 1 {
		t.Fatalf("fallback result=%q calls=%v", got, runtime.ensuredImages)
	}
}

func TestEnsureSnapshotImportsDependenciesFromNAS(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/clone:v1"
	publication := writeNASClone(t, root, image)
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	imageDigests := map[string]string{publication.Manifest.Base.Image: publication.Manifest.Base.Digest}
	for _, digest := range publication.Manifest.ImageBlobIDs {
		imageDigests[digest] = digest
	}
	runtime := &fakeRuntime{
		imageImportDigests: imageDigests,
		snapshotImportResult: &vm.Snapshot{
			ID: "IMPORTEDSNAPSHOTIDENTIFIER001", Image: publication.Manifest.Base.Image,
			ImageDigest: publication.Manifest.Base.Digest, ImageType: "cloudimg",
			ImageBlobIDs: map[string]struct{}{strings.TrimPrefix(publication.Manifest.ImageBlobIDs[1], "sha256:"): {}}, Hypervisor: publication.Manifest.Hypervisor,
		},
	}
	p := newTestProvider(t)
	p.Runtime = runtime
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)

	snapshot, err := p.ensureSnapshot(t.Context(), "team/clone", "v1", image)
	if err != nil {
		t.Fatalf("ensureSnapshot: %v", err)
	}
	if snapshot == nil || snapshot.ID != "IMPORTEDSNAPSHOTIDENTIFIER001" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if len(runtime.imageImports) != len(publication.Manifest.ImageBlobIDs) {
		t.Fatalf("image imports = %v, want %d dependencies", runtime.imageImports, len(publication.Manifest.ImageBlobIDs))
	}
	if len(runtime.snapshotImports) != 1 || runtime.snapshotImports[0] != image {
		t.Fatalf("snapshot imports = %v", runtime.snapshotImports)
	}
}

func TestEnsureMacosImageImportsFromNAS(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/macos:v1"
	digest := writeNASRun(t, root, image, "macos", []byte("macos-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProvider(t)
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)
	imported := false
	calls := stubMacosExec(p, func(args []string) (string, error) {
		switch {
		case macosCallIs(args, "image", "inspect") && !imported:
			return "", errors.New("not found")
		case macosCallIs(args, "image", "import"):
			if len(args) != 4 || args[2] != image {
				t.Fatalf("image import args = %v", args)
			}
			imported = true
			return "", nil
		case macosCallIs(args, "image", "inspect"):
			return `{"id":"` + digest + `"}`, nil
		default:
			return "", nil
		}
	})

	if err := p.ensureMacosImage(t.Context(), image); err != nil {
		t.Fatalf("ensureMacosImage: %v", err)
	}
	if !imported {
		t.Fatal("NAS macOS image was not imported")
	}
	for _, call := range calls() {
		if macosCallIs(call, "image", "pull") {
			t.Fatalf("OCI pull unexpectedly used: %v", call)
		}
	}
}

func TestEnsureMacosImageReusesMatchingNASAlias(t *testing.T) {
	root := t.TempDir()
	image := "team/macos:v1"
	digest := writeNASRun(t, root, image, "macos", []byte("macos-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProvider(t)
	p.ImageNAS = store
	calls := stubMacosExec(p, func(args []string) (string, error) {
		switch {
		case macosCallIs(args, "image", "inspect"):
			return `{"id":"` + digest + `"}`, nil
		case macosCallIs(args, "image", "import"), macosCallIs(args, "image", "pull"):
			t.Fatalf("matching NAS alias performed mutation: %v", args)
		}
		return "", nil
	})

	if err := p.ensureMacosImage(t.Context(), image); err != nil {
		t.Fatalf("ensureMacosImage: %v", err)
	}
	if got := len(calls()); got != 1 {
		t.Fatalf("macOS calls = %v, want one inspect", calls())
	}
}

func TestEnsureMacosImageReplacesWrongNASAlias(t *testing.T) {
	root := t.TempDir()
	cacheRoot := t.TempDir()
	image := "team/macos:v1"
	digest := writeNASRun(t, root, image, "macos", []byte("macos-image"))
	store, err := nasimage.New(root, nasTestCPUClass)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProvider(t)
	p.ImageNAS = store
	disableNASReserve(p, cacheRoot)
	currentDigest := "sha256:" + strings.Repeat("e", 64)
	imports := 0
	calls := stubMacosExec(p, func(args []string) (string, error) {
		switch {
		case macosCallIs(args, "image", "inspect"):
			return `{"id":"` + currentDigest + `"}`, nil
		case macosCallIs(args, "image", "import"):
			imports++
			currentDigest = digest
			return "", nil
		case macosCallIs(args, "image", "pull"):
			t.Fatalf("wrong NAS alias fell back to OCI: %v", args)
		}
		return "", nil
	})

	if err := p.ensureMacosImage(t.Context(), image); err != nil {
		t.Fatalf("ensureMacosImage: %v", err)
	}
	if imports != 1 {
		t.Fatalf("macOS imports = %d, calls=%v", imports, calls())
	}
}

func disableNASReserve(p *Provider, cacheRoot string) {
	p.NASCacheRoot = cacheRoot
	p.NASMinFreeBytes = 0
	p.NASMinFreePercent = 0
	p.NASImportOverheadPercent = 0
}

func writeNASRun(t *testing.T, root, image, osName string, content []byte) string {
	t.Helper()
	digest := testDigest(content)
	digestHex := strings.TrimPrefix(digest, "sha256:")
	publicationID := "image-export-run-v1"
	repository, tag := splitNASTestRef(t, image)
	artifactRelative := filepath.ToSlash(filepath.Join("images", "blobs", "sha256", digestHex[:2], digestHex+".qcow2"))
	manifestRelative := filepath.ToSlash(filepath.Join("images", "manifests", "sha256", digestHex[:2], digestHex, publicationID+".json"))
	manifest := nasimage.Manifest{
		SchemaVersion: 1, PublicationID: publicationID, Cluster: "cocoon-jj", OS: osName,
		Mode: nasimage.ModeRun, Image: image, Artifact: nasimage.ArtifactFile{
			Digest: digest, Path: artifactRelative, SizeBytes: int64(len(content)), VirtualSizeBytes: int64(len(content)) * 2,
		}, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ref := map[string]any{
		"schema_version": 1, "publication_id": publicationID, "cluster": "cocoon-jj", "image": image,
		"mode": "run", "digest": digest, "manifest_path": manifestRelative, "created_at": manifest.CreatedAt,
	}
	writeNASTestFile(t, filepath.Join(root, filepath.FromSlash(artifactRelative)), content)
	writeNASTestJSON(t, filepath.Join(root, filepath.FromSlash(manifestRelative)), manifest)
	writeNASTestJSON(t, filepath.Join(root, "images", "refs", filepath.FromSlash(repository), tag+".json"), ref)
	return digest
}

func writeNASClone(t *testing.T, root, image string) *nasimage.Publication {
	t.Helper()
	snapshotID := "SNAPSHOTTESTIDENTIFIER00002"
	base := []byte("clone-base")
	extra := []byte("clone-extra")
	snapshotArchive := []byte("snapshot-archive")
	artifactDigest := testDigest(snapshotArchive)
	baseDigest := testDigest(base)
	extraDigest := testDigest(extra)
	publicationID := "image-export-clone-v1"
	digestHex := strings.TrimPrefix(artifactDigest, "sha256:")
	repository, tag := splitNASTestRef(t, image)
	artifactDir := filepath.ToSlash(filepath.Join("snapshots", "sha256", digestHex[:2], digestHex))
	artifactRelative := filepath.ToSlash(filepath.Join(artifactDir, "snapshot.tar.gz"))
	manifestRelative := filepath.ToSlash(filepath.Join(artifactDir, "manifests", publicationID+".json"))
	baseHex := strings.TrimPrefix(baseDigest, "sha256:")
	extraHex := strings.TrimPrefix(extraDigest, "sha256:")
	baseRelative := filepath.ToSlash(filepath.Join("images", "blobs", "sha256", baseHex[:2], baseHex+".qcow2"))
	extraRelative := filepath.ToSlash(filepath.Join("images", "blobs", "sha256", extraHex[:2], extraHex+".qcow2"))
	metadata := map[string]any{
		"id": snapshotID, "image": "base:v1", "image_digest": baseDigest, "image_type": "cloudimg",
		"image_blob_ids": map[string]struct{}{strings.TrimPrefix(extraDigest, "sha256:"): {}},
		"hypervisor":     "cloud-hypervisor",
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	manifest := nasimage.Manifest{
		SchemaVersion: 1, PublicationID: publicationID, Cluster: "cocoon-jj", OS: "linux",
		Mode: nasimage.ModeClone, Image: image, Artifact: nasimage.ArtifactFile{
			Digest: artifactDigest, Path: artifactRelative, SizeBytes: int64(len(snapshotArchive)), UnpackedSizeBytes: int64(len(snapshotArchive)) * 4,
		}, Base: &nasimage.ArtifactBase{Image: "base:v1", Digest: baseDigest, Path: baseRelative, SizeBytes: int64(len(base))},
		ImageBlobIDs: []string{baseDigest, extraDigest}, SourceSnapshotID: snapshotID, SnapshotCompatibilityClass: nasTestCPUClass,
		Hypervisor: "cloud-hypervisor", SnapshotABI: "ch-v1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ref := map[string]any{
		"schema_version": 1, "publication_id": publicationID, "cluster": "cocoon-jj", "image": image,
		"mode": "clone", "digest": artifactDigest, "manifest_path": manifestRelative, "created_at": manifest.CreatedAt,
	}
	writeNASTestFile(t, filepath.Join(root, filepath.FromSlash(artifactRelative)), snapshotArchive)
	writeNASTestFile(t, filepath.Join(root, filepath.FromSlash(artifactDir), "snapshot.json"), metadataRaw)
	checksums := strings.TrimPrefix(testDigest(snapshotArchive), "sha256:") + "  snapshot.tar.gz\n" +
		strings.TrimPrefix(testDigest(metadataRaw), "sha256:") + "  snapshot.json\n"
	writeNASTestFile(t, filepath.Join(root, filepath.FromSlash(artifactDir), "SHA256SUMS"), []byte(checksums))
	writeNASTestFile(t, filepath.Join(root, filepath.FromSlash(baseRelative)), base)
	writeNASTestFile(t, filepath.Join(root, filepath.FromSlash(extraRelative)), extra)
	writeNASTestJSON(t, filepath.Join(root, filepath.FromSlash(manifestRelative)), manifest)
	writeNASTestJSON(t, filepath.Join(root, "snapshots", "refs", filepath.FromSlash(repository), tag+".json"), ref)
	return &nasimage.Publication{Manifest: manifest}
}

func writeNASTestJSON(t *testing.T, filename string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeNASTestFile(t, filename, raw)
}

func writeNASTestFile(t *testing.T, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func splitNASTestRef(t *testing.T, image string) (string, string) {
	t.Helper()
	repository, tag, ok := strings.Cut(image, ":")
	if !ok {
		t.Fatalf("image %q has no tag", image)
	}
	return repository, tag
}

func testDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
