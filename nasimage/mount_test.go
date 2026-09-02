package nasimage

import "testing"

func TestMountFilesystemUsesDeepestCoveringMount(t *testing.T) {
	mountInfo := "36 25 0:32 / / rw - apfs disk rw\n" +
		"50 36 0:50 / /mnt/bytenas rw - fuse.bytefuse bytefuse rw\n" +
		"51 50 0:51 / /mnt/bytenas/cocoon\\040data rw - virtio_pfs cocoon rw\n"
	filesystem, found, err := mountFilesystem(mountInfo, "/mnt/bytenas/cocoon data/clusters/cocoon-jj")
	if err != nil {
		t.Fatalf("mountFilesystem: %v", err)
	}
	if !found || filesystem != "virtio_pfs" {
		t.Fatalf("mountFilesystem = %q,%v, want virtio_pfs,true", filesystem, found)
	}
}

func TestMountFilesystemRejectsMalformedEscape(t *testing.T) {
	_, _, err := mountFilesystem("50 36 0:50 / /mnt/bad\\xx rw - fuse.bytefuse bytefuse rw\n", "/mnt/bad")
	if err == nil {
		t.Fatal("mountFilesystem accepted malformed mountinfo escape")
	}
}
