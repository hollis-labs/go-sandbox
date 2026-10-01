//go:build unix

package sandbox

import (
	"os"
	"syscall"
)

// uidCanWrite reports whether the current uid may write dir (create, rename or
// remove entries in it) now or after a chmod: a directory the uid owns counts
// as writable even at 0555, because its owner can make it writable again.
func uidCanWrite(dir string) bool {
	const wOK = 0x2
	if syscall.Access(dir, wOK) == nil {
		return true
	}
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
