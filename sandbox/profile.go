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
	// Subprocess controls whether the session may spawn child processes
	// beyond the agent binary itself. macOS enforces this via SBPL
	// process-fork / process-exec* denies; Linux bwrap does not directly
	// gate subprocess spawning (use namespace isolation instead).
	Subprocess bool `yaml:"subprocess"`
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
