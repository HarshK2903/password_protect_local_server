//go:build unix

package files

import (
	"golang.org/x/sys/unix"
	"os"
)

// O_NONBLOCK prevents a FIFO replacement race from blocking an HTTP goroutine.
// O_NOFOLLOW also rejects a last-component symlink swap before descriptor checks.
func openRead(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
}
