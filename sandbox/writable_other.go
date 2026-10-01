//go:build !unix

package sandbox

// uidCanWrite assumes a directory is writable where it cannot ask, so a
// protected path is never trusted through a symlink there.
func uidCanWrite(string) bool { return true }
