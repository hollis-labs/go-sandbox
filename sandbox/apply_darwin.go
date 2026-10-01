//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// seatbeltUnsafeRuneError is returned when a string destined for a seatbelt
// profile literal contains a byte the profile syntax cannot quote safely.
type seatbeltUnsafeRuneError struct {
	field  string
	value  string
	reason string
}

func (e *seatbeltUnsafeRuneError) Error() string {
	return fmt.Sprintf("sandbox: seatbelt: %s contains unsafe value: %s", e.field, e.reason)
}

// validateSeatbeltLiteral rejects strings that cannot be embedded in a
// TinyScheme string literal without changing the meaning of the profile.
// The seatbelt/TinyScheme parser treats `"`, `\`, parens, semicolons, and
// whitespace as structural; even backslash-escaping is unreliable across
// macOS releases, so we fail closed on any of these bytes. ASCII control
// chars (< 0x20) are always rejected.
//
// SBPL profile-string injection is a real CVE shape — before the fix,
// `fmt.Fprintf(&b, "(subpath \"%s\")", absDir)` let a crafted directory
// name inject arbitrary seatbelt rules. The validator is non-optional.
func validateSeatbeltLiteral(field, value string) error {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x20 || c == 0x7f {
			return &seatbeltUnsafeRuneError{
				field:  field,
				value:  value,
				reason: fmt.Sprintf("control byte 0x%02x at offset %d", c, i),
			}
		}
		switch c {
		case '"', '\\', '(', ')', ';', '\'':
			return &seatbeltUnsafeRuneError{
				field:  field,
				value:  value,
				reason: fmt.Sprintf("forbidden byte %q at offset %d", c, i),
			}
		}
	}
	return nil
}

// BuildSBPL generates a macOS sandbox-exec seatbelt profile string from a
// Profile and a workspace root.
//
// Strategy: default-allow with selective denies. Default-deny on macOS
// requires enumerating a large (and OS-version-dependent) allowlist of
// system paths, dyld caches, Mach services, and XPC endpoints that every
// modern process implicitly needs. Tightening to default-deny is left for
// a future sprint.
//
// Every interpolated value (workspace, FS.Read/Write/Deny entries) is
// validated via validateSeatbeltLiteral before being written to the
// profile. An invalid value returns a non-nil error and the caller must
// refuse to spawn the sandbox.
func BuildSBPL(p Profile, workspace string) (string, error) {
	if p.DenyUserServiceManager {
		return "", errDarwinUserServiceManager(p.ID)
	}
	absWS, err := filepath.Abs(workspace)
	if err != nil {
		absWS = workspace
	}
	if err := validateSeatbeltLiteral("workspace", absWS); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("\n")
	b.WriteString("; Default-allow posture — selective denies below constrain the\n")
	b.WriteString("; principal areas of concern (sensitive FS paths, network, subprocess).\n")
	b.WriteString("(allow default)\n\n")

	// Workspace is always writable, regardless of FS.Write contents.
	b.WriteString("; Workspace is the writable root.\n")
	fmt.Fprintf(&b, "(allow file-write* (subpath \"%s\"))\n\n", absWS)

	// Additional Write paths beyond the workspace.
	wroteAny := false
	for i, raw := range p.FS.Write {
		path, err := expandAndValidate(fmt.Sprintf("FS.Write[%d]", i), raw, absWS)
		if err != nil {
			return "", err
		}
		if path == absWS {
			continue
		}
		if !wroteAny {
			b.WriteString("; Additional writable paths.\n")
			wroteAny = true
		}
		fmt.Fprintf(&b, "(allow file-write* (subpath \"%s\"))\n", path)
	}
	if wroteAny {
		b.WriteString("\n")
	}

	// Read paths are no-ops under default-allow but validated to keep the
	// validator's coverage uniform — a future tighter posture will use them.
	for i, raw := range p.FS.Read {
		if _, err := expandAndValidate(fmt.Sprintf("FS.Read[%d]", i), raw, absWS); err != nil {
			return "", err
		}
	}

	// Explicit FS denies — take precedence over default allow.
	if len(p.FS.Deny) > 0 {
		b.WriteString("; Explicit FS denies.\n")
		for i, raw := range p.FS.Deny {
			path, err := expandAndValidate(fmt.Sprintf("FS.Deny[%d]", i), raw, absWS)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "(deny file-read* (subpath \"%s\"))\n", path)
			fmt.Fprintf(&b, "(deny file-write* (subpath \"%s\"))\n", path)
		}
		b.WriteString("\n")
	}

	// Write-protected paths: after every write allow, so they win. Seatbelt
	// matches real paths, so each is canonicalized (/tmp/x is
	// /private/tmp/x) and writeProtectDenies adds the alias back.
	protected := make([]string, 0, len(p.FS.Protect))
	for i, raw := range p.FS.Protect {
		path, err := expandAndValidate(fmt.Sprintf("FS.Protect[%d]", i), raw, absWS)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("%w: protected path %q must be absolute (or ~/..., or workspace)", ErrUnsupportedPolicy, raw)
		}
		if err := validateProtectPath(path); err != nil {
			return "", err
		}
		canonical, err := canonicalPath(path)
		if err != nil {
			return "", fmt.Errorf("sandbox: resolve protected path %q: %w", raw, err)
		}
		protected = append(protected, canonical)
	}
	if err := validateProtectSet(protected); err != nil {
		return "", err
	}
	writes := []string{absWS}
	for _, raw := range p.FS.Write {
		if path := expandPath(raw, absWS); filepath.IsAbs(path) {
			if canonical, err := canonicalPath(path); err == nil {
				writes = append(writes, canonical)
			}
		}
	}
	if canonical, err := canonicalPath(absWS); err == nil {
		writes = append(writes, canonical)
	}
	if err := validateWritesOutsideProtect(writes, protected); err != nil {
		return "", err
	}
	if err := writeProtectDenies(&b, protected); err != nil {
		return "", err
	}

	if !p.Net {
		if p.AllowLoopback {
			if err := writeLoopbackAllows(&b); err != nil {
				return "", err
			}
		}
		b.WriteString("; Block all network traffic beyond the loopback allowlist above.\n")
		b.WriteString("(deny network*)\n\n")
	}

	if !p.Subprocess {
		b.WriteString("; Block subprocess spawning beyond the initial binary.\n")
		b.WriteString("(deny process-fork)\n")
		b.WriteString("(deny process-exec*)\n\n")
	}

	if p.DenyGUILaunch {
		writeGUILaunchDenies(&b)
	}

	return b.String(), nil
}

// BuildResolvedSBPL generates a macOS sandbox-exec seatbelt profile for an
// already-resolved access policy. Unlike BuildSBPL's legacy compatibility
// posture, this emitter uses default-deny plus Apple's system.sb import for
// baseline OS services, then grants only resolved filesystem/runtime paths.
// Explicit denies still take precedence beneath allowed parents.
func BuildResolvedSBPL(p ResolvedAccessPolicy) (string, error) {
	if p.Mode == ConfinementDisabled {
		return "", fmt.Errorf("sandbox: disabled policy %q has no SBPL profile", p.ID)
	}
	if p.Subprocess == SubprocessDeny {
		return "", fmt.Errorf("sandbox: subprocess deny is unsupported by resolved darwin pre-spawn enforcement")
	}
	if p.DenyUserServiceManager {
		return "", errDarwinUserServiceManager(p.ID)
	}

	var b strings.Builder
	b.WriteString("(version 1)\n\n")
	b.WriteString("; Resolved access policy: default deny with system service support and explicit grants.\n")
	b.WriteString("(deny default)\n")
	b.WriteString("(import \"system.sb\")\n\n")
	b.WriteString("; Process control for the initial sandboxed payload.\n")
	b.WriteString("(allow process*)\n\n")
	b.WriteString("; Metadata reads let the runtime traverse parent directories without exposing file contents.\n")
	b.WriteString("(allow file-read-metadata)\n\n")

	readable := append(darwinSystemReadPaths(), resolvedPathStrings(p.allReads())...)
	readable = append(readable, resolvedPathStrings(p.allWrites())...)
	writable := resolvedPathStrings(p.allWrites())
	if err := writeResolvedReadAllows(&b, readable); err != nil {
		return "", err
	}
	if err := writeResolvedWriteAllows(&b, writable); err != nil {
		return "", err
	}
	if err := writeResolvedDenies(&b, resolvedPathStrings(p.allDenies())); err != nil {
		return "", err
	}
	if err := writeProtectDenies(&b, resolvedPathStrings(p.FS.Protect)); err != nil {
		return "", err
	}

	switch p.Network.Mode {
	case NetworkFull:
		b.WriteString("; Full network was explicitly requested.\n")
		b.WriteString("(allow network*)\n\n")
	case NetworkLoopback:
		if err := writeLoopbackAllows(&b); err != nil {
			return "", err
		}
		b.WriteString("; Block all network traffic beyond the loopback allowlist above.\n")
		b.WriteString("(deny network*)\n\n")
	default:
		b.WriteString("; Network denied by policy and default-deny posture.\n\n")
	}

	// Last, so the denies follow the system.sb and process* allows above.
	if p.DenyGUILaunch {
		writeGUILaunchDenies(&b)
	}

	return b.String(), nil
}

// writeGUILaunchDenies emits the two rules that stop a child from launching
// GUI applications, for example a CLI whose sign-in fallback opens a browser:
// exec of /usr/bin/open, and Mach lookups of LaunchServices (launchservicesd
// and the lsd.* services), which also blocks a copy of open or any other
// client of LaunchServices. Verified with sandbox-exec on macOS 15.7: exec of
// /usr/bin/open fails with EPERM, and `lsappinfo list` returns nothing under
// the lookup deny while returning the running apps without it.
// errDarwinUserServiceManager refuses DenyUserServiceManager: launchd would
// still run a job for the child (launchctl submit / bootstrap), and seatbelt
// here does not cut that path off.
func errDarwinUserServiceManager(id string) error {
	return fmt.Errorf("%w: profile %q: DenyUserServiceManager is not enforced on darwin (launchd user agents)", ErrUnsupportedPolicy, id)
}

func writeGUILaunchDenies(b *strings.Builder) {
	b.WriteString("; Deny GUI launch: no open(1), no LaunchServices.\n")
	b.WriteString("(deny process-exec (literal \"/usr/bin/open\"))\n")
	b.WriteString("(deny mach-lookup (global-name \"com.apple.coreservices.launchservicesd\") (global-name-regex #\"^com\\.apple\\.lsd\\.\"))\n\n")
}

func darwinSystemReadPaths() []string {
	paths := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/lib",
		"/usr/share",
		"/System/Library",
		"/Library/Apple",
		"/private/var/db/timezone",
		"/etc/localtime",
		"/dev/null",
	}
	return existingDarwinPaths(paths)
}

func existingDarwinPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			if resolved, err := filepath.EvalSymlinks(path); err == nil {
				path = resolved
			}
			out = append(out, filepath.Clean(path))
		}
	}
	return out
}

func writeResolvedReadAllows(b *strings.Builder, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	b.WriteString("; Read-only filesystem grants.\n")
	for _, path := range paths {
		if err := writeSeatbeltPathRule(b, "allow", "file-read*", path); err != nil {
			return err
		}
		if err := writeSeatbeltPathRule(b, "allow", "file-map-executable", path); err != nil {
			return err
		}
	}
	b.WriteString("\n")
	return nil
}

func writeResolvedWriteAllows(b *strings.Builder, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	b.WriteString("; Writable filesystem grants.\n")
	for _, path := range paths {
		if err := writeSeatbeltPathRule(b, "allow", "file-read*", path); err != nil {
			return err
		}
		if err := writeSeatbeltPathRule(b, "allow", "file-write*", path); err != nil {
			return err
		}
		if err := writeSeatbeltPathRule(b, "allow", "file-map-executable", path); err != nil {
			return err
		}
	}
	b.WriteString("\n")
	return nil
}

func writeResolvedDenies(b *strings.Builder, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	b.WriteString("; Explicit deny grants override enclosing allows.\n")
	for _, path := range paths {
		if err := writeSeatbeltPathRule(b, "deny", "file-read*", path); err != nil {
			return err
		}
		if err := writeSeatbeltPathRule(b, "deny", "file-write*", path); err != nil {
			return err
		}
	}
	b.WriteString("\n")
	return nil
}

// writeProtectDenies emits the write denies for write-protected paths
// (FilesystemAccess.Protect, Profile.FS.Protect). They must follow every
// write allow so they take precedence; they leave reads to the rules above.
// Seatbelt matches by path, so a protected path that does not exist yet is
// protected too, unlike Linux bwrap.
//
// Each ancestor is also denied writes by literal: the entry itself, not its
// contents. Without it the child could rename an ancestor away and put a
// symlink to its own directory in its place, so the protected path resolves
// somewhere writable (the macOS form of the rename the Linux backend blocks by
// pinning ancestors).
func writeProtectDenies(b *strings.Builder, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	b.WriteString("; Write-protected paths: never writable, whatever allows them above.\n")
	seen := map[string]bool{}
	for _, path := range paths {
		if err := writeSeatbeltPathRule(b, "deny", "file-write*", path); err != nil {
			return err
		}
		// Hard links: a link to a protected file from a writable directory
		// would be a second, unprotected name for the same file. Seatbelt
		// may check link creation as its own operation, separate from
		// file-write* on the new name, so deny it explicitly. (Linux refuses
		// it with EXDEV across the bind.) Not yet run on a Mac.
		if err := writeSeatbeltPathRule(b, "deny", "file-link", path); err != nil {
			return err
		}
		for dir := filepath.Dir(path); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
			if seen[dir] {
				continue
			}
			seen[dir] = true
			aliases, err := seatbeltAliases([]string{dir})
			if err != nil {
				return err
			}
			for _, alias := range aliases {
				fmt.Fprintf(b, "(deny file-write* (literal \"%s\"))\n", alias)
			}
		}
	}
	b.WriteString("\n")
	return nil
}

func writeSeatbeltPathRule(b *strings.Builder, action, operation, path string) error {
	aliases, err := seatbeltAliases([]string{path})
	if err != nil {
		return err
	}
	for _, candidate := range aliases {
		fmt.Fprintf(b, "(%s %s (literal \"%s\"))\n", action, operation, candidate)
		fmt.Fprintf(b, "(%s %s (subpath \"%s\"))\n", action, operation, candidate)
	}
	return nil
}

func seatbeltAliases(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, path := range paths {
		for _, candidate := range seatbeltPathAliases(path) {
			if err := validateSeatbeltLiteral("path", candidate); err != nil {
				return nil, err
			}
			if !seen[candidate] {
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	return out, nil
}

func seatbeltPathAliases(path string) []string {
	path = filepath.Clean(path)
	seen := map[string]bool{}
	var out []string
	add := func(candidate string) {
		candidate = filepath.Clean(candidate)
		if !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	add(path)
	const privateTmp = "/private/tmp"
	if path == privateTmp {
		add("/tmp")
	} else if strings.HasPrefix(path, privateTmp+"/") {
		add("/tmp/" + strings.TrimPrefix(path, privateTmp+"/"))
	}
	const privateVar = "/private/var"
	if path == privateVar {
		add("/var")
	} else if strings.HasPrefix(path, privateVar+"/") {
		add("/var/" + strings.TrimPrefix(path, privateVar+"/"))
	}
	return out
}

func writeLoopbackAllows(b *strings.Builder) error {
	for _, literal := range []struct {
		field string
		value string
	}{
		{field: "network localhost local", value: "localhost:*"},
		{field: "network localhost remote", value: "localhost:*"},
	} {
		if err := validateSeatbeltLiteral(literal.field, literal.value); err != nil {
			return err
		}
	}

	// Seatbelt's host-filter grammar only accepts "localhost" or "*" here,
	// so localhost is the narrowest allowlist form that preserves tested
	// 127.0.0.1 and ::1 reachability without broadening non-loopback egress.
	b.WriteString("; Preserve localhost traffic while keeping non-loopback network denied.\n")
	b.WriteString("(allow network-bind (local ip \"localhost:*\"))\n")
	b.WriteString("(allow network-inbound (local ip \"localhost:*\"))\n")
	b.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n\n")
	return nil
}

// expandAndValidate resolves the "workspace", "${HOME}", and "~" tokens in
// raw, then runs the resulting path through validateSeatbeltLiteral.
func expandAndValidate(field, raw, workspace string) (string, error) {
	path := expandPath(raw, workspace)
	if err := validateSeatbeltLiteral(field, path); err != nil {
		return "", err
	}
	return path, nil
}

// expandPath resolves the "workspace", "${HOME}", and leading "~" tokens.
// Only a bare "~" or a "~/" prefix is expanded — "~" mid-path (e.g.
// "/cache/foo~2") is intentionally left untouched to avoid corrupting
// filenames that happen to contain a tilde. Empty paths are returned
// as-is; the validator catches them downstream.
func expandPath(raw, workspace string) string {
	if raw == "workspace" {
		return workspace
	}
	home, _ := os.UserHomeDir()
	raw = strings.ReplaceAll(raw, "${HOME}", home)
	if raw == "~" {
		return home
	}
	if strings.HasPrefix(raw, "~/") {
		raw = home + raw[1:]
	}
	return raw
}

// Apply wraps cmd to run under macOS sandbox-exec with a profile generated
// from p and workspace. It returns a cleanup function that removes the
// temporary profile file; callers MUST call cleanup after the command
// finishes (defer cleanup() works). Returns an error if sandbox-exec is
// unavailable or profile generation fails.
//
// Cleanup pattern lineage: extracted from nanite's applyOSSandbox. The
// earlier mux Apply leaked the temp profile file; do not regress.
func Apply(cmd *exec.Cmd, p Profile, workspace string) (cleanup func(), err error) {
	sbplBin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, fmt.Errorf("sandbox-exec not found: cannot enforce profile %q on this system", p.ID)
	}

	sbpl, err := BuildSBPL(p, workspace)
	if err != nil {
		return nil, err
	}

	f, err := os.CreateTemp("", "go-sandbox-*.sb")
	if err != nil {
		return nil, fmt.Errorf("create sandbox profile temp file: %w", err)
	}
	profilePath := f.Name()
	if _, err := f.WriteString(sbpl); err != nil {
		_ = f.Close()
		_ = os.Remove(profilePath)
		return nil, fmt.Errorf("write sandbox profile: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(profilePath)
		return nil, fmt.Errorf("close sandbox profile: %w", err)
	}

	origPath := cmd.Path
	origArgs := cmd.Args[1:]
	cmd.Path = sbplBin
	newArgs := make([]string, 0, 4+len(origArgs))
	newArgs = append(newArgs, "sandbox-exec", "-f", profilePath, origPath)
	newArgs = append(newArgs, origArgs...)
	cmd.Args = newArgs

	return func() { _ = os.Remove(profilePath) }, nil
}

func applyResolved(cmd *exec.Cmd, p ResolvedAccessPolicy) (func(), error) {
	sbplBin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, fmt.Errorf("sandbox-exec not found: cannot enforce policy %q on this system", p.ID)
	}

	sbpl, err := BuildResolvedSBPL(p)
	if err != nil {
		return nil, err
	}

	f, err := os.CreateTemp("", "go-sandbox-*.sb")
	if err != nil {
		return nil, fmt.Errorf("create sandbox profile temp file: %w", err)
	}
	profilePath := f.Name()
	if _, err := f.WriteString(sbpl); err != nil {
		_ = f.Close()
		_ = os.Remove(profilePath)
		return nil, fmt.Errorf("write sandbox profile: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(profilePath)
		return nil, fmt.Errorf("close sandbox profile: %w", err)
	}

	origPath := cmd.Path
	origArgs := cmd.Args[1:]
	cmd.Path = sbplBin
	newArgs := make([]string, 0, 4+len(origArgs))
	newArgs = append(newArgs, "sandbox-exec", "-f", profilePath, origPath)
	newArgs = append(newArgs, origArgs...)
	cmd.Args = newArgs

	return func() { _ = os.Remove(profilePath) }, nil
}
