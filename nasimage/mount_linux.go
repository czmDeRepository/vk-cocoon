//go:build linux

package nasimage

import (
	"os"
)

func readMountInfo() (string, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
