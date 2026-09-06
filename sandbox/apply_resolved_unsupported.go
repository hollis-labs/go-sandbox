//go:build !darwin && !linux && !linux

package sandbox

import (
	"fmt"
	"os/exec"
	"runtime"
)

func applyResolved(cmd *exec.Cmd, p ResolvedAccessPolicy) (func(), error) {
	_ = cmd
	return nil, fmt.Errorf("sandbox: resolved policy application for backend %s is not implemented on %s", p.Backend, runtime.GOOS)
}
