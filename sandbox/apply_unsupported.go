//go:build !darwin && !linux

package sandbox

import (
	"fmt"
	"os/exec"
)

// Apply returns an error on unsupported platforms. A non-empty profile on
// an unsupported platform is a hard launch failure — no silent downgrade.
func Apply(cmd *exec.Cmd, p Profile, workspace string) (cleanup func(), err error) {
	_ = cmd
	_ = workspace
	return nil, fmt.Errorf("sandboxing not supported on this platform (profile %q requested)", p.ID)
}
