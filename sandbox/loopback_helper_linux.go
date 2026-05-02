//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	loopbackHelperEnv = "__GO_SANDBOX_LOOPBACK_HELPER"
	loopbackHelperArg = "__go_sandbox_loopback_helper__"
)

// Linux loopback note: bwrap's --unshare-net leaves the namespace-local
// lo device present but DOWN. Reusing the importing binary as a one-shot
// trampoline keeps the public API additive: the library's init() runs
// before main(), raises lo inside the unshared netns, and then execs the
// original target argv. This avoids a caller-visible helper binary.
func init() {
	if os.Getenv(loopbackHelperEnv) != "1" {
		return
	}
	if len(os.Args) < 3 || os.Args[1] != loopbackHelperArg {
		fatalLoopbackHelper("invalid helper invocation")
	}
	if err := bringInterfaceUp("lo"); err != nil {
		fatalLoopbackHelper(fmt.Sprintf("bring up loopback: %v", err))
	}

	targetPath := os.Args[2]
	targetArgs := append([]string{targetPath}, os.Args[3:]...)
	if err := syscall.Exec(targetPath, targetArgs, filteredHelperEnv()); err != nil {
		fatalLoopbackHelper(fmt.Sprintf("exec target %q: %v", targetPath, err))
	}
}

type ifreq struct {
	name [syscall.IFNAMSIZ]byte
	data [24]byte
}

func bringInterfaceUp(name string) error {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)

	var ifr ifreq
	copy(ifr.name[:], name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}

	flags := *(*uint16)(unsafe.Pointer(&ifr.data[0]))
	flags |= uint16(syscall.IFF_UP)
	*(*uint16)(unsafe.Pointer(&ifr.data[0])) = flags

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

func filteredHelperEnv() []string {
	prefix := loopbackHelperEnv + "="
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		filtered = append(filtered, kv)
	}
	return filtered
}

func fatalLoopbackHelper(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, "go-sandbox loopback helper:", msg)
	os.Exit(125)
}
