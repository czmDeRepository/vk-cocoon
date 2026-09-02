//go:build !linux

package nasimage

import "errors"

func readMountInfo() (string, error) {
	return "", errors.New("linux mountinfo is unavailable")
}
