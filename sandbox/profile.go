package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FSSpec describes the filesystem scope for a sandbox profile.
type FSSpec struct {
	// Read lists paths the session may read. "workspace" is a magic token
	// that resolves to the session's workspace root at Apply time.
	Read []string `yaml:"read"`
	// Write lists paths the session may write. Same token semantics as Read.
	Write []string `yaml:"write"`
	// Deny lists paths explicitly blocked even if covered by a Read allow.
	// Deny entries take precedence over Read allows.
	Deny []string `yaml:"deny"`
	// Protect lists paths the session must never write, even inside the
	// workspace or a Write path: control-plane state such as a host's
	// database, config or allow-lists (CW-20260930-0237). A protected path
	// stays readable where a grant covers it, and protection grants nothing.
	// Linux protects paths that exist at Apply time and refuses one that does
	// not exist where the session could create it; macOS protects by path.
	Protect []string `yaml:"protect"`
}

// Profile is a named sandbox configuration. Profiles are typically loaded
// from a directory of YAML files via LoadProfiles, but may also be
// constructed programmatically.
type Profile struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	FS          FSSpec `yaml:"fs"`
	// Net controls outbound network access. false = deny all outbound.
	Net bool `yaml:"net"`
	// AllowLoopback permits loopback traffic to 127.0.0.0/8 and ::1 even
	// when Net is false. It is a no-op when Net is true.
	AllowLoopback bool `yaml:"allow_loopback"`
	// LoopbackForwardPorts exposes selected host 127.0.0.1 TCP ports inside
	// the Linux sandbox namespace while Net is false. It is currently a
	// Linux-only bridge mechanism and a no-op on other platforms.
	LoopbackForwardPorts []int `yaml:"loopback_forward_ports"`
	// Subprocess controls whether the session may spawn child processes
	// beyond the agent binary itself. macOS enforces this via SBPL
	// process-fork / process-exec* denies; Linux bwrap does not directly
	// gate subprocess spawning (use namespace isolation instead).
	Subprocess bool `yaml:"subprocess"`
	// DenyGUILaunch blocks launching GUI applications, for example a CLI that
	// falls back to opening a browser for an interactive sign-in. macOS
	// enforces it via SBPL (exec of /usr/bin/open and Mach lookups of
	// LaunchServices); Linux bwrap does not enforce it, and a resolved policy
	// that requires it is refused there (see CapGUILaunchDeny).
	DenyGUILaunch bool `yaml:"deny_gui_launch"`
	// DenyUserServiceManager stops the session reaching the user service
	// manager, which would otherwise run a command for it outside the
	// sandbox (`systemd-run --user`): a write delegated past FS.Protect, for
	// one. Linux hides $XDG_RUNTIME_DIR/systemd/ and the session bus, which
	// also breaks the Secret Service keyring and everything else on the
	// session bus; macOS refuses it. See AccessPolicy.DenyUserServiceManager.
	DenyUserServiceManager bool `yaml:"deny_user_service_manager"`
	// HostFilesystem gives the session the host filesystem as the parent sees
	// it, writable, instead of Linux bwrap's narrowed system mounts; only
	// FS.Protect narrows it. It is the minimal sandbox for a host whose agents
	// otherwise run unconfined and only need control-plane protection. On
	// Linux it binds / (with devices), leaves the pid, ipc and uts namespaces
	// and the session (so a PTY keeps its controlling terminal) shared, and
	// unshares the network only when Net is false. FS.Read and FS.Write add
	// nothing in this mode, and Linux refuses FS.Deny in it rather than
	// ignore it. macOS legacy profiles are already default-allow, so it
	// changes nothing there.
	HostFilesystem bool `yaml:"host_filesystem"`
}

// LoadProfile reads and parses a single profile YAML file.
func LoadProfile(path string) (Profile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: catalog-sourced path, not untrusted input
	if err != nil {
		return Profile{}, fmt.Errorf("read profile %s: %w", path, err)
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("parse profile %s: %w", path, err)
	}
	if p.ID == "" {
		return Profile{}, fmt.Errorf("profile %s: missing id field", path)
	}
	return p, nil
}

// LoadProfiles reads all *.yaml files in dir and returns them keyed by ID.
// A missing directory is not an error — it returns an empty map, matching
// the expected behavior when no sandbox-profiles dir is configured.
func LoadProfiles(dir string) (map[string]Profile, error) {
	out := map[string]Profile{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		return nil, fmt.Errorf("read sandbox-profiles dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		p, err := LoadProfile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[p.ID] = p
	}
	return out, nil
}
