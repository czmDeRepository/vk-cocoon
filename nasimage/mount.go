package nasimage

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

func validateNASMount(root string) error {
	mountInfo, err := readMountInfo()
	if err != nil {
		return fmt.Errorf("read mount table for NAS root %s: %w", root, err)
	}
	filesystem, found, err := mountFilesystem(mountInfo, root)
	if err != nil {
		return fmt.Errorf("parse mount table for NAS root %s: %w", root, err)
	}
	if !found {
		return fmt.Errorf("NAS root %s is not covered by a mounted filesystem", root)
	}
	lower := strings.ToLower(filesystem)
	if !strings.Contains(lower, "bytefuse") && !strings.Contains(lower, "virtio_pfs") {
		return fmt.Errorf("NAS root %s is mounted as %s, want bytefuse or virtio_pfs", root, filesystem)
	}
	return nil
}

func mountFilesystem(mountInfo, target string) (string, bool, error) {
	target = filepath.Clean(target)
	bestMount := ""
	bestFilesystem := ""
	scanner := bufio.NewScanner(strings.NewReader(mountInfo))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 6 || separator < 0 || separator+1 >= len(fields) {
			continue
		}
		mountPoint, err := decodeMountInfoPath(fields[4])
		if err != nil {
			return "", false, err
		}
		mountPoint = filepath.Clean(mountPoint)
		relative, err := filepath.Rel(mountPoint, target)
		if err != nil || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if len(mountPoint) > len(bestMount) {
			bestMount = mountPoint
			bestFilesystem = fields[separator+1]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", false, err
	}
	return bestFilesystem, bestMount != "", nil
}

func decodeMountInfoPath(value string) (string, error) {
	var decoded strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			index++
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("invalid mountinfo escape in %q", value)
		}
		octal := value[index+1 : index+4]
		parsed, err := strconv.ParseUint(octal, 8, 8)
		if err != nil {
			return "", fmt.Errorf("invalid mountinfo escape \\%s in %q", octal, value)
		}
		decoded.WriteByte(byte(parsed))
		index += 4
	}
	return decoded.String(), nil
}
