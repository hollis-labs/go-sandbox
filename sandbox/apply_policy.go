package sandbox

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrBackendUnavailable marks a host/runtime prerequisite that prevents the
// selected backend from enforcing a policy on this machine.
var ErrBackendUnavailable = errors.New("sandbox: backend unavailable")

// ErrUnsupportedPolicy marks a resolved policy shape the selected backend cannot
// faithfully enforce.
var ErrUnsupportedPolicy = errors.New("sandbox: unsupported policy")

// ApplyResolved wraps cmd with the backend selected by a ResolvedAccessPolicy.
// It checks backend capabilities before changing the command, returns disabled
// outcomes without wrapping, and marks enforcement as applied only after the
// platform backend has successfully prepared the exact process about to start.
func ApplyResolved(cmd *exec.Cmd, p ResolvedAccessPolicy) (EnforcementOutcome, func(), error) {
	caps := ResolveBackendCapabilities("", p.Backend)
	out := AssessEnforcement(p, caps)
	if out.State == EnforcementDisabled {
		return out, func() {}, nil
	}
	if out.State != EnforcementConfigured {
		return out, nil, fmt.Errorf("sandbox: cannot enforce policy %q with backend %s: %s", p.ID, caps.Backend, strings.Join(out.Diagnostics, "; "))
	}

	cleanup, err := applyResolved(cmd, p)
	if err != nil {
		if errors.Is(err, ErrBackendUnavailable) || errors.Is(err, ErrUnsupportedPolicy) {
			out.State = EnforcementUnsupported
		} else {
			out.State = EnforcementFailed
		}
		out.Diagnostics = append(out.Diagnostics, err.Error())
		return out, nil, err
	}
	return AppliedOutcome(out), cleanup, nil
}
