//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	loopbackHelperEnv             = "__GO_SANDBOX_LOOPBACK_HELPER"
	loopbackHelperArg             = "__go_sandbox_loopback_helper__"
	loopbackHelperForwardDirEnv   = "__GO_SANDBOX_LOOPBACK_FORWARD_DIR"
	loopbackHelperForwardPortsEnv = "__GO_SANDBOX_LOOPBACK_FORWARD_PORTS"
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
	os.Exit(runLoopbackHelper())
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
	prefixes := []string{
		loopbackHelperEnv + "=",
		loopbackHelperForwardDirEnv + "=",
		loopbackHelperForwardPortsEnv + "=",
	}
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, kv := range env {
		skip := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(kv, prefix) {
				skip = true
				break
			}
		}
		if skip {
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

func runLoopbackHelper() int {
	if len(os.Args) < 3 || os.Args[1] != loopbackHelperArg {
		fatalLoopbackHelper("invalid helper invocation")
	}
	if err := bringInterfaceUp("lo"); err != nil {
		fatalLoopbackHelper(fmt.Sprintf("bring up loopback: %v", err))
	}

	targetPath := os.Args[2]
	targetArgs := append([]string{targetPath}, os.Args[3:]...)

	ports, err := parseLoopbackPorts(os.Getenv(loopbackHelperForwardPortsEnv))
	if err != nil {
		fatalLoopbackHelper(fmt.Sprintf("parse loopback forward ports: %v", err))
	}
	forwardDir := os.Getenv(loopbackHelperForwardDirEnv)

	if len(ports) == 0 {
		if err := syscall.Exec(targetPath, targetArgs, filteredHelperEnv()); err != nil {
			fatalLoopbackHelper(fmt.Sprintf("exec target %q: %v", targetPath, err))
		}
		return 0
	}
	if forwardDir == "" {
		fatalLoopbackHelper("missing loopback forward dir")
	}

	listeners, err := startSandboxLoopbackBridges(forwardDir, ports)
	if err != nil {
		fatalLoopbackHelper(fmt.Sprintf("start loopback bridges: %v", err))
	}
	defer closeListeners(listeners)

	child := exec.Command(targetPath, os.Args[3:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = filteredHelperEnv()

	if err := child.Start(); err != nil {
		fatalLoopbackHelper(fmt.Sprintf("start target %q: %v", targetPath, err))
	}
	forwardSignals(child.Process)

	if err := child.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fatalLoopbackHelper(fmt.Sprintf("wait for target %q: %v", targetPath, err))
	}
	return 0
}

func parseLoopbackPorts(raw string) ([]int, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func startSandboxLoopbackBridges(forwardDir string, ports []int) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(ports)*2)
	for _, port := range ports {
		socketPath := filepath.Join(forwardDir, loopbackSocketName(port))

		v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			closeListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, v4)
		go serveSandboxLoopbackBridge(v4, socketPath)

		if v6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port))); err == nil {
			listeners = append(listeners, v6)
			go serveSandboxLoopbackBridge(v6, socketPath)
		}
	}
	return listeners, nil
}

func serveSandboxLoopbackBridge(listener net.Listener, socketPath string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedNetworkError(err) {
				return
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()

			target, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("unix", socketPath)
			if err != nil {
				return
			}
			defer target.Close()

			proxyConns(c, target)
		}(conn)
	}
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

func forwardSignals(process *os.Process) {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for sig := range signals {
			if process != nil {
				_ = process.Signal(sig)
			}
		}
	}()
}
