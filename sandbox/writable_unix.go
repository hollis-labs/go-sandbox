//go:build unix

package sandbox

import "syscall"

// uidCanWrite reports whether the current uid may write dir: create, rename or
// remove entries in it.
func uidCanWrite(dir string) bool {
	const wOK = 0x2
	return syscall.Access(dir, wOK) == nil
}
