package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/hollis-labs/go-safefs/pathsafe"
)

// ConfinementMode declares whether OS confinement is mandatory or explicitly
// disabled for a launch.
type ConfinementMode string

const (
	// ConfinementRequired means the child must not start unless the selected
	// backend can enforce every requested capability.
	ConfinementRequired ConfinementMode = "required"
	// ConfinementDisabled is an explicit unconfined launch. It is represented
	// in outcomes so callers do not mistake it for applied enforcement.
	ConfinementDisabled ConfinementMode = "disabled"
)

// RootName identifies one of the concrete launch roots used by access policy.
type RootName string

const (
	ProjectRoot RootName = "project"
	BootRoot    RootName = "boot"
	StateRoot   RootName = "state"
	ScratchRoot RootName = "scratch"
	CWDRoot     RootName = "cwd"
)

// Roots names concrete filesystem roots independently from the process cwd.
// Empty optional roots may not be referenced by PathRef.
type Roots struct {
	Project string
	Boot    string
	State   string
	Scratch string
	CWD     string
}

// PathRef names either an absolute path (when Root is empty) or a path under
// one of Roots. Relative defaults to ".".
type PathRef struct {
	Root     RootName
	Relative string
	Path     string
}

// FilesystemAccess is the child process filesystem policy. Deny rules always
// take precedence over read and write grants. SourceRead entries are resolved
// and recorded for provenance, but are not child execution grants.
//
// Protect lists paths the child must never write, even inside a Write grant:
// control-plane state such as a host's database, config or allow-lists, which
// a same-uid agent could otherwise rewrite to grant itself authority
// (CW-20260930-0237). Protection is narrower than Deny (the child may still
// read a protected path that a grant covers) and grants nothing: a protected
// path outside every grant stays invisible. Deny overrides Protect.
type FilesystemAccess struct {
	Read       []PathRef
	Write      []PathRef
	Deny       []PathRef
	SourceRead []PathRef
	Protect    []PathRef
}

// RuntimeAccess declares host runtime files the backend must make readable,
// such as an executable, dynamic loader support files or language runtimes.
type RuntimeAccess struct {
	Executable PathRef
	Read       []PathRef
}

// ProviderStateAccess declares provider-owned mutable state needed at runtime.
type ProviderStateAccess struct {
	Read  []PathRef
	Write []PathRef
}

// ScratchAccess declares whether the private scratch root is writable inside
// the sandbox. The root itself is Roots.Scratch.
type ScratchAccess struct {
	Writable bool
}

// NetworkMode declares the requested network shape.
type NetworkMode string

const (
	NetworkDeny     NetworkMode = "deny"
	NetworkLoopback NetworkMode = "loopback"
	NetworkFull     NetworkMode = "full"
)

// NetworkAccess declares network requirements. LoopbackPorts are host
// localhost TCP ports that must be bridged when the backend uses a private
// network namespace.
type NetworkAccess struct {
	Mode          NetworkMode
	LoopbackPorts []int
}

// SubprocessMode declares child process spawning behavior after the initial
// sandboxed process starts.
type SubprocessMode string

const (
	SubprocessAllow SubprocessMode = "allow"
	SubprocessDeny  SubprocessMode = "deny"
)

// BackendName identifies an enforcement backend.
type BackendName string

const (
	BackendAuto           BackendName = "auto"
	BackendNone           BackendName = "none"
	BackendDarwinSeatbelt BackendName = "darwin-seatbelt"
	BackendLinuxBwrap     BackendName = "linux-bwrap"
)

// LegacyCompatibility records that a policy came from the legacy Profile /
// SandboxProfile shape. Legacy profiles are default-allow with selective
// denies on some backends; callers must not label them workspace-confined.
type LegacyCompatibility struct {
	Enabled      bool
	Source       string
	DefaultAllow bool
}

// AccessPolicy is the caller-authored sandbox request.
type AccessPolicy struct {
	ID            string
	Mode          ConfinementMode
	Backend       BackendName
	Roots         Roots
	FS            FilesystemAccess
	Runtime       RuntimeAccess
	ProviderState ProviderStateAccess
	Scratch       ScratchAccess
	Network       NetworkAccess
	Subprocess    SubprocessMode
	// DenyGUILaunch requests that the child cannot launch GUI applications
	// (open(1), LaunchServices). Backends that cannot enforce it report
	// CapGUILaunchDeny as unsupported.
	DenyGUILaunch bool
	// DenyUserServiceManager requests that the child cannot reach the user
	// service manager, which would run a command for it outside the sandbox
	// (`systemd-run --user`) and so write a protected path on its behalf.
	// Linux bwrap hides the manager's sockets ($XDG_RUNTIME_DIR/systemd/)
	// and the session bus, where the manager also answers: that also cuts
	// the child off from everything else on the session bus, including the
	// Secret Service keyring, notifications and portals. Backends that cannot
	// enforce it report CapUserServiceManagerDeny as unsupported.
	DenyUserServiceManager bool
	Legacy                 LegacyCompatibility
}

// ResolvedRoots contains absolute, symlink-normalized root paths.
type ResolvedRoots struct {
	Project string
	Boot    string
	State   string
	Scratch string
	CWD     string
}

// AccessKind identifies why a path is visible to the child.
type AccessKind string

const (
	AccessRead        AccessKind = "read"
	AccessWrite       AccessKind = "write"
	AccessDeny        AccessKind = "deny"
	AccessSourceRead  AccessKind = "source-read"
	AccessRuntimeRead AccessKind = "runtime-read"
	AccessProtect     AccessKind = "protect"
)

// ResolvedPath is a normalized access rule.
type ResolvedPath struct {
	Kind   AccessKind
	Root   RootName
	Path   string
	Source string
}

// ResolvedFilesystemAccess is the concrete filesystem policy. Write grants
// imply read access. Deny grants override both read and write. Protect
// overrides write: a protected path is at most read-only (see
// FilesystemAccess.Protect).
type ResolvedFilesystemAccess struct {
	Read       []ResolvedPath
	Write      []ResolvedPath
	Deny       []ResolvedPath
	SourceRead []ResolvedPath
	Protect    []ResolvedPath
}

// ResolvedAccessPolicy is the normalized sandbox request consumed by backend
// capability checks and later backend emitters.
type ResolvedAccessPolicy struct {
	ID            string
	Mode          ConfinementMode
	Backend       BackendName
	Roots         ResolvedRoots
	FS            ResolvedFilesystemAccess
	Runtime       []ResolvedPath
	ProviderState ResolvedFilesystemAccess
	Scratch       []ResolvedPath
	Network       NetworkAccess
	Subprocess    SubprocessMode
	DenyGUILaunch bool
	// DenyUserServiceManager: see AccessPolicy.DenyUserServiceManager.
	DenyUserServiceManager bool
	Legacy                 LegacyCompatibility
}

// AccessDecision is the effective child access for a path after deny
// precedence and write-implies-read rules are applied.
type AccessDecision string

const (
	AccessDenied    AccessDecision = "denied"
	AccessReadOnly  AccessDecision = "read-only"
	AccessReadWrite AccessDecision = "read-write"
	AccessNoGrant   AccessDecision = "no-grant"
)

// ResolveAccessPolicy validates and normalizes an AccessPolicy without
// consulting the host backend. It never converts SourceRead into execution
// grants and never derives roots from the process cwd.
func ResolveAccessPolicy(p AccessPolicy) (ResolvedAccessPolicy, error) {
	if p.ID == "" {
		return ResolvedAccessPolicy{}, errors.New("sandbox: access policy id is required")
	}
	if p.Mode == "" {
		p.Mode = ConfinementRequired
	}
	if p.Mode != ConfinementRequired && p.Mode != ConfinementDisabled {
		return ResolvedAccessPolicy{}, fmt.Errorf("sandbox: unsupported confinement mode %q", p.Mode)
	}
	if p.Backend == "" {
		p.Backend = BackendAuto
	}
	switch p.Backend {
	case BackendAuto, BackendNone, BackendDarwinSeatbelt, BackendLinuxBwrap:
	default:
		return ResolvedAccessPolicy{}, fmt.Errorf("sandbox: unsupported backend %q", p.Backend)
	}
	if p.Network.Mode == "" {
		p.Network.Mode = NetworkDeny
	}
	switch p.Network.Mode {
	case NetworkDeny, NetworkLoopback, NetworkFull:
	default:
		return ResolvedAccessPolicy{}, fmt.Errorf("sandbox: unsupported network mode %q", p.Network.Mode)
	}
	if p.Subprocess == "" {
		p.Subprocess = SubprocessAllow
	}
	switch p.Subprocess {
	case SubprocessAllow, SubprocessDeny:
	default:
		return ResolvedAccessPolicy{}, fmt.Errorf("sandbox: unsupported subprocess mode %q", p.Subprocess)
	}
	if err := validateLoopbackPortSet(p.Network.LoopbackPorts); err != nil {
		return ResolvedAccessPolicy{}, err
	}

	roots, err := resolveRoots(p.Roots)
	if err != nil {
		return ResolvedAccessPolicy{}, err
	}
	resolved := ResolvedAccessPolicy{
		ID:         p.ID,
		Mode:       p.Mode,
		Backend:    p.Backend,
		Roots:      roots,
		Network:    NetworkAccess{Mode: p.Network.Mode, LoopbackPorts: slices.Clone(p.Network.LoopbackPorts)},
		Subprocess: p.Subprocess,
		Legacy:     p.Legacy,

		DenyGUILaunch:          p.DenyGUILaunch,
		DenyUserServiceManager: p.DenyUserServiceManager,
	}

	if resolved.FS.Read, err = resolvePathRefs(AccessRead, p.FS.Read, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if resolved.FS.Write, err = resolvePathRefs(AccessWrite, p.FS.Write, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if resolved.FS.Deny, err = resolvePathRefs(AccessDeny, p.FS.Deny, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if resolved.FS.SourceRead, err = resolvePathRefs(AccessSourceRead, p.FS.SourceRead, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if resolved.FS.Protect, err = resolvePathRefs(AccessProtect, p.FS.Protect, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if err := validateProtectSet(resolvedPathStrings(resolved.FS.Protect)); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if err := validateWritesOutsideProtect(resolvedPathStrings(resolved.allWrites()), resolvedPathStrings(resolved.FS.Protect)); err != nil {
		return ResolvedAccessPolicy{}, err
	}

	if p.Runtime.Executable != (PathRef{}) {
		exe, err := resolvePathRef(AccessRuntimeRead, p.Runtime.Executable, roots)
		if err != nil {
			return ResolvedAccessPolicy{}, err
		}
		resolved.Runtime = append(resolved.Runtime, exe)
	}
	runtimeReads, err := resolvePathRefs(AccessRuntimeRead, p.Runtime.Read, roots)
	if err != nil {
		return ResolvedAccessPolicy{}, err
	}
	resolved.Runtime = append(resolved.Runtime, runtimeReads...)

	if resolved.ProviderState.Read, err = resolvePathRefs(AccessRead, p.ProviderState.Read, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if resolved.ProviderState.Write, err = resolvePathRefs(AccessWrite, p.ProviderState.Write, roots); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if p.Scratch.Writable {
		if roots.Scratch == "" {
			return ResolvedAccessPolicy{}, errors.New("sandbox: scratch access requested without scratch root")
		}
		resolved.Scratch = []ResolvedPath{{
			Kind:   AccessWrite,
			Root:   ScratchRoot,
			Path:   roots.Scratch,
			Source: "scratch",
		}}
	}

	sortResolvedPolicy(&resolved)
	return resolved, nil
}

// AccessFor returns the effective child filesystem access for path. It is a
// policy decision helper; actual OS enforcement is backend-specific.
func (p ResolvedAccessPolicy) AccessFor(path string) AccessDecision {
	resolved, err := canonicalPath(path)
	if err != nil {
		return AccessNoGrant
	}
	if containsPath(p.allDenies(), resolved) {
		return AccessDenied
	}
	if containsPath(p.FS.Protect, resolved) {
		if containsPath(p.allWrites(), resolved) || containsPath(p.allReads(), resolved) {
			return AccessReadOnly
		}
		return AccessNoGrant
	}
	if containsPath(p.allWrites(), resolved) {
		return AccessReadWrite
	}
	if containsPath(p.allReads(), resolved) {
		return AccessReadOnly
	}
	return AccessNoGrant
}

// WithProtected returns a copy of p that also write-protects paths (see
// FilesystemAccess.Protect). Each path must be absolute; it is canonicalized
// the way ResolveAccessPolicy canonicalizes absolute refs. It is how a host
// adds its control-plane paths to a policy that was resolved elsewhere.
func (p ResolvedAccessPolicy) WithProtected(paths ...string) (ResolvedAccessPolicy, error) {
	out := p
	out.FS.Protect = slices.Clone(p.FS.Protect)
	for _, raw := range paths {
		if !filepath.IsAbs(raw) {
			return ResolvedAccessPolicy{}, fmt.Errorf("sandbox: protected path %q must be absolute", raw)
		}
		resolved, err := resolvePathRef(AccessProtect, PathRef{Path: raw}, ResolvedRoots{})
		if err != nil {
			return ResolvedAccessPolicy{}, err
		}
		if !slices.ContainsFunc(out.FS.Protect, func(r ResolvedPath) bool { return r.Path == resolved.Path }) {
			out.FS.Protect = append(out.FS.Protect, resolved)
		}
	}
	if err := validateProtectSet(resolvedPathStrings(out.FS.Protect)); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	if err := validateWritesOutsideProtect(resolvedPathStrings(out.allWrites()), resolvedPathStrings(out.FS.Protect)); err != nil {
		return ResolvedAccessPolicy{}, err
	}
	sortResolvedPolicy(&out)
	return out, nil
}

// LegacyProfile converts a resolved policy into the legacy Profile shape. This
// is a compatibility bridge for existing Apply callers and may lose future
// policy detail; new code should pass the resolved policy to backend-aware
// launch plumbing once available.
func (p ResolvedAccessPolicy) LegacyProfile() Profile {
	profile := Profile{
		ID:                   p.ID,
		Description:          "generated from resolved access policy",
		Net:                  p.Network.Mode == NetworkFull,
		AllowLoopback:        p.Network.Mode == NetworkLoopback,
		LoopbackForwardPorts: slices.Clone(p.Network.LoopbackPorts),
		Subprocess:           p.Subprocess != SubprocessDeny,
		DenyGUILaunch:        p.DenyGUILaunch,

		DenyUserServiceManager: p.DenyUserServiceManager,
	}
	for _, item := range p.allReads() {
		profile.FS.Read = append(profile.FS.Read, item.Path)
	}
	for _, item := range p.allWrites() {
		profile.FS.Write = append(profile.FS.Write, item.Path)
	}
	for _, item := range p.allDenies() {
		profile.FS.Deny = append(profile.FS.Deny, item.Path)
	}
	for _, item := range p.FS.Protect {
		profile.FS.Protect = append(profile.FS.Protect, item.Path)
	}
	return profile
}

// PolicyFromProfile adapts the legacy Profile / SandboxProfile shape. The
// workspace token becomes Project, Boot, State, Scratch and CWD only because
// the old API had one root parameter. Legacy.DefaultAllow marks the semantic
// gap so callers do not describe this as strict workspace confinement.
func PolicyFromProfile(p Profile, workspace string) AccessPolicy {
	roots := Roots{
		Project: workspace,
		Boot:    workspace,
		State:   workspace,
		Scratch: workspace,
		CWD:     workspace,
	}
	return AccessPolicy{
		ID:      p.ID,
		Mode:    ConfinementRequired,
		Backend: BackendAuto,
		Roots:   roots,
		FS: FilesystemAccess{
			Read:    pathRefsFromLegacy(p.FS.Read),
			Write:   pathRefsFromLegacy(p.FS.Write),
			Deny:    pathRefsFromLegacy(p.FS.Deny),
			Protect: pathRefsFromLegacy(p.FS.Protect),
		},
		Network: NetworkAccess{
			Mode:          legacyNetworkMode(p),
			LoopbackPorts: slices.Clone(p.LoopbackForwardPorts),
		},
		Subprocess:             legacySubprocessMode(p),
		DenyGUILaunch:          p.DenyGUILaunch,
		DenyUserServiceManager: p.DenyUserServiceManager,
		Legacy: LegacyCompatibility{
			Enabled:      true,
			Source:       "Profile",
			DefaultAllow: true,
		},
	}
}

// Capability identifies an enforcement capability a backend may provide.
type Capability string

const (
	CapFilesystemAllowlist Capability = "filesystem-allowlist"
	CapDenyPrecedence      Capability = "deny-precedence"
	CapRuntimeReads        Capability = "runtime-reads"
	CapProviderState       Capability = "provider-state"
	CapScratch             Capability = "scratch"
	CapNetworkDeny         Capability = "network-deny"
	CapLoopback            Capability = "loopback"
	CapLoopbackForward     Capability = "loopback-forward"
	CapSubprocessDeny      Capability = "subprocess-deny"
	CapGUILaunchDeny       Capability = "gui-launch-deny"
	CapWriteProtect        Capability = "write-protect"
	// CapUserServiceManagerDeny is AccessPolicy.DenyUserServiceManager.
	CapUserServiceManagerDeny Capability = "user-service-manager-deny"
	CapDisabledMode           Capability = "disabled-mode"
)

// BackendCapabilities reports what a selected backend can honestly enforce.
type BackendCapabilities struct {
	Backend      BackendName
	GOOS         string
	Supported    bool
	Capabilities []Capability
	Reason       string
}

// ResolveBackendCapabilities selects a backend for goos and reports known
// capabilities. Pass goos="" to use runtime.GOOS.
func ResolveBackendCapabilities(goos string, requested BackendName) BackendCapabilities {
	if goos == "" {
		goos = runtime.GOOS
	}
	if requested == "" || requested == BackendAuto {
		switch goos {
		case "darwin":
			requested = BackendDarwinSeatbelt
		case "linux":
			requested = BackendLinuxBwrap
		default:
			requested = BackendNone
		}
	}
	caps := BackendCapabilities{Backend: requested, GOOS: goos}
	switch requested {
	case BackendNone:
		caps.Supported = true
		caps.Capabilities = []Capability{CapDisabledMode}
	case BackendDarwinSeatbelt:
		caps.Supported = goos == "darwin"
		caps.Capabilities = []Capability{
			CapFilesystemAllowlist,
			CapDenyPrecedence,
			CapRuntimeReads,
			CapProviderState,
			CapScratch,
			CapNetworkDeny,
			CapLoopback,
			CapGUILaunchDeny,
			CapWriteProtect,
		}
	case BackendLinuxBwrap:
		caps.Supported = goos == "linux"
		caps.Capabilities = []Capability{
			CapFilesystemAllowlist,
			CapDenyPrecedence,
			CapRuntimeReads,
			CapProviderState,
			CapScratch,
			CapNetworkDeny,
			CapLoopback,
			CapLoopbackForward,
			CapWriteProtect,
			CapUserServiceManagerDeny,
		}
	default:
		caps.Supported = false
		caps.Reason = "unknown backend"
	}
	if !caps.Supported && caps.Reason == "" {
		caps.Reason = fmt.Sprintf("%s is unsupported on %s", requested, goos)
	}
	return caps
}

// EnforcementState summarizes the actual enforcement status of a launch.
type EnforcementState string

const (
	EnforcementConfigured  EnforcementState = "configured"
	EnforcementDisabled    EnforcementState = "disabled"
	EnforcementUnsupported EnforcementState = "unsupported"
	EnforcementApplied     EnforcementState = "applied"
	EnforcementFailed      EnforcementState = "failed"
)

// EnforcementOutcome distinguishes requested policy, selected backend and
// actual launch status. Applied should be used only after backend wrapping has
// succeeded for the child process about to start.
type EnforcementOutcome struct {
	PolicyID     string
	Mode         ConfinementMode
	Backend      BackendName
	State        EnforcementState
	Enforced     bool
	Disabled     bool
	Unsupported  []Capability
	Diagnostics  []string
	BackendGOOS  string
	BackendReady bool
}

// AssessEnforcement checks whether caps can enforce p. It fails closed for
// required confinement and reports disabled mode honestly.
func AssessEnforcement(p ResolvedAccessPolicy, caps BackendCapabilities) EnforcementOutcome {
	out := EnforcementOutcome{
		PolicyID:     p.ID,
		Mode:         p.Mode,
		Backend:      caps.Backend,
		BackendGOOS:  caps.GOOS,
		BackendReady: caps.Supported,
	}
	if p.Mode == ConfinementDisabled {
		out.State = EnforcementDisabled
		out.Disabled = true
		out.Diagnostics = append(out.Diagnostics, "confinement explicitly disabled")
		return out
	}
	if !caps.Supported {
		out.State = EnforcementUnsupported
		out.Diagnostics = append(out.Diagnostics, caps.Reason)
		return out
	}

	required := requiredCapabilities(p)
	if len(required) == 0 {
		out.State = EnforcementUnsupported
		out.Diagnostics = append(out.Diagnostics, "required confinement has no enforceable requirements")
		return out
	}
	for _, cap := range required {
		if !slices.Contains(caps.Capabilities, cap) {
			out.Unsupported = append(out.Unsupported, cap)
		}
	}
	if len(out.Unsupported) > 0 {
		out.State = EnforcementUnsupported
		for _, cap := range out.Unsupported {
			out.Diagnostics = append(out.Diagnostics, fmt.Sprintf("backend %s lacks %s", caps.Backend, cap))
		}
		return out
	}
	out.State = EnforcementConfigured
	return out
}

// AppliedOutcome marks a configured outcome as applied after backend wrapping
// succeeds. It never upgrades disabled or unsupported outcomes.
func AppliedOutcome(out EnforcementOutcome) EnforcementOutcome {
	if out.State == EnforcementConfigured {
		out.State = EnforcementApplied
		out.Enforced = true
	}
	return out
}

func resolveRoots(roots Roots) (ResolvedRoots, error) {
	project, err := requiredRoot(ProjectRoot, roots.Project)
	if err != nil {
		return ResolvedRoots{}, err
	}
	cwdRaw := roots.CWD
	if cwdRaw == "" {
		cwdRaw = roots.Project
	}
	cwd, err := canonicalPath(cwdRaw)
	if err != nil {
		return ResolvedRoots{}, fmt.Errorf("sandbox: resolve cwd root: %w", err)
	}
	out := ResolvedRoots{Project: project, CWD: cwd}
	if roots.Boot != "" {
		if out.Boot, err = canonicalPath(roots.Boot); err != nil {
			return ResolvedRoots{}, fmt.Errorf("sandbox: resolve boot root: %w", err)
		}
	}
	if roots.State != "" {
		if out.State, err = canonicalPath(roots.State); err != nil {
			return ResolvedRoots{}, fmt.Errorf("sandbox: resolve state root: %w", err)
		}
	}
	if roots.Scratch != "" {
		if out.Scratch, err = canonicalPath(roots.Scratch); err != nil {
			return ResolvedRoots{}, fmt.Errorf("sandbox: resolve scratch root: %w", err)
		}
	}
	return out, nil
}

func requiredRoot(name RootName, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("sandbox: %s root is required", name)
	}
	root, err := canonicalPath(path)
	if err != nil {
		return "", fmt.Errorf("sandbox: resolve %s root: %w", name, err)
	}
	return root, nil
}

func resolvePathRefs(kind AccessKind, refs []PathRef, roots ResolvedRoots) ([]ResolvedPath, error) {
	out := make([]ResolvedPath, 0, len(refs))
	for _, ref := range refs {
		resolved, err := resolvePathRef(kind, ref, roots)
		if err != nil {
			return nil, err
		}
		out = append(out, resolved)
	}
	return out, nil
}

func resolvePathRef(kind AccessKind, ref PathRef, roots ResolvedRoots) (ResolvedPath, error) {
	if ref.Root == "" {
		if ref.Path == "" {
			return ResolvedPath{}, fmt.Errorf("sandbox: %s path ref needs root or path", kind)
		}
		if kind == AccessProtect {
			if !filepath.IsAbs(ref.Path) {
				return ResolvedPath{}, fmt.Errorf("sandbox: protected path %q must be absolute or under a root", ref.Path)
			}
			if err := validateProtectPath(ref.Path); err != nil {
				return ResolvedPath{}, err
			}
		}
		path, err := canonicalPath(ref.Path)
		if err != nil {
			return ResolvedPath{}, fmt.Errorf("sandbox: resolve %s path %q: %w", kind, ref.Path, err)
		}
		return ResolvedPath{Kind: kind, Path: path, Source: ref.Path}, nil
	}
	root, err := rootPath(roots, ref.Root)
	if err != nil {
		return ResolvedPath{}, err
	}
	rel := ref.Relative
	if rel == "" {
		rel = "."
	}
	if kind == AccessProtect {
		if err := validateProtectPath(filepath.Join(root, rel)); err != nil {
			return ResolvedPath{}, err
		}
	}
	path, err := pathsafe.ResolveUnder(root, rel)
	if err != nil {
		return ResolvedPath{}, fmt.Errorf("sandbox: resolve %s under %s: %w", kind, ref.Root, err)
	}
	return ResolvedPath{Kind: kind, Root: ref.Root, Path: path, Source: rel}, nil
}

// validateProtectPath refuses a protected path the child could re-point: one
// with a symlink component in a directory the current uid can write. The
// backends protect the path the symlink resolves to at launch; the child
// could then swap the link (`ln -s evil x.new && mv -T x.new x`) and the
// host would follow it somewhere writable. Symlinks in directories the uid
// cannot write (/var -> /private/var on macOS) are fixed and allowed. A
// host passes the real path instead.
//
// It follows the whole resolution, not just the path as written: a fixed
// symlink whose target goes through a re-pointable one is refused too.
func validateProtectPath(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("sandbox: protected path %q must be absolute", path)
	}
	walk := path
	for hops := 0; ; hops++ {
		if hops > maxPolicySymlinkFollow {
			return fmt.Errorf("sandbox: too many symlinks resolving protected path %q", path)
		}
		next, err := protectWalkStep(path, walk)
		if err != nil || next == "" {
			return err
		}
		walk = next
	}
}

// protectDirWritable is uidCanWrite, a variable so a test can mark a
// directory fixed: a non-root test cannot make one the uid neither owns nor
// can write.
var protectDirWritable = uidCanWrite

// protectWalkStep walks walk component by component until the first
// symlink. It refuses that symlink if the uid can write its directory, and
// otherwise returns the path with the link replaced by its target, to walk
// again. It returns "" once walk has no symlink left (or stops existing).
func protectWalkStep(path, walk string) (string, error) {
	sep := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(walk, sep), sep)
	prefix := sep
	for i, part := range parts {
		if part == "" {
			continue
		}
		parent := prefix
		prefix = filepath.Join(prefix, part)
		info, err := os.Lstat(prefix)
		if err != nil {
			if os.IsNotExist(err) {
				return "", nil
			}
			return "", fmt.Errorf("sandbox: inspect protected path %q: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if protectDirWritable(parent) {
			return "", fmt.Errorf("%w: protected path %q goes through symlink %q in writable directory %q, which the sandboxed process could re-point; protect the real path", ErrUnsupportedPolicy, path, prefix, parent)
		}
		target, err := os.Readlink(prefix)
		if err != nil {
			return "", fmt.Errorf("sandbox: inspect protected path %q: %w", path, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(parent, target)
		}
		return filepath.Join(append([]string{target}, parts[i+1:]...)...), nil
	}
	return "", nil
}

// validateProtectSet refuses protected paths that are not directories (unless
// a protected directory already covers them). A file's directory stays
// writable, which defeats file-level protection: the host's own atomic save
// (write a temp file, rename it over the original) replaces the file the
// sandbox protected, and a database's sidecar (SQLite's -wal, -journal) can
// be planted beside it and read by the host. Protect the directory. paths are
// canonical.
func validateProtectSet(paths []string) error {
	var dirs []string
	type entry struct {
		path string
		dir  bool
	}
	var entries []entry
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("sandbox: inspect protected path %q: %w", path, err)
		}
		entries = append(entries, entry{path, info.IsDir()})
		if info.IsDir() {
			dirs = append(dirs, path)
		}
	}
	for _, e := range entries {
		if e.dir {
			continue
		}
		if slices.ContainsFunc(dirs, func(dir string) bool { return dir != e.path && pathContains(dir, e.path) }) {
			continue
		}
		return fmt.Errorf("%w: protected path %q is not a directory; protect its directory (a file's directory stays writable, so an atomic save or a database sidecar beside it defeats file-level protection)", ErrUnsupportedPolicy, e.path)
	}
	return nil
}

// validateWritesOutsideProtect refuses a write grant (or workspace) at or
// inside a protected directory. Protect wins over write on macOS, where the
// write deny follows the allow, but on Linux a writable mount inside a
// protected directory would stay writable, so the platforms would disagree;
// the policy is refused instead of guessing which the host meant. writes and
// protected are canonical.
func validateWritesOutsideProtect(writes, protected []string) error {
	for _, write := range writes {
		for _, dir := range protected {
			if pathContains(dir, write) {
				return fmt.Errorf("%w: write grant %q is inside protected path %q; a protected tree cannot also be granted writes", ErrUnsupportedPolicy, write, dir)
			}
		}
	}
	return nil
}

func resolvedPathStrings(paths []ResolvedPath) []string {
	out := make([]string, 0, len(paths))
	for _, item := range paths {
		out = append(out, item.Path)
	}
	return out
}

func rootPath(roots ResolvedRoots, name RootName) (string, error) {
	switch name {
	case ProjectRoot:
		return roots.Project, nil
	case BootRoot:
		if roots.Boot == "" {
			return "", errors.New("sandbox: boot root is not configured")
		}
		return roots.Boot, nil
	case StateRoot:
		if roots.State == "" {
			return "", errors.New("sandbox: state root is not configured")
		}
		return roots.State, nil
	case ScratchRoot:
		if roots.Scratch == "" {
			return "", errors.New("sandbox: scratch root is not configured")
		}
		return roots.Scratch, nil
	case CWDRoot:
		return roots.CWD, nil
	default:
		return "", fmt.Errorf("sandbox: unknown root %q", name)
	}
}

func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(path, 0) {
		return "", errors.New("null byte in path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveSymlinksBestEffortPolicy(abs)
}

// maxPolicySymlinkFollow bounds how many dangling links
// resolveSymlinksBestEffortPolicy follows by hand, so a chain of dangling
// links cannot loop. It matches go-safefs/pathsafe.
const maxPolicySymlinkFollow = 40

// resolveSymlinksBestEffortPolicy resolves path's symlinks, rejoining any
// suffix that does not exist yet onto its longest existing ancestor. A
// dangling symlink is followed by hand and judged by where it points: a
// caller that creates the returned path writes through the link, so
// reporting the link's own path (what EvalSymlinks' not-exist would leave)
// let a link inside a granted root stand for a target outside it. This is
// the fix go-safefs/pathsafe carries for ResolveUnder.
func resolveSymlinksBestEffortPolicy(path string) (string, error) {
	return resolveSymlinksPolicyDepth(filepath.Clean(path), 0)
}

func resolveSymlinksPolicyDepth(path string, depth int) (string, error) {
	if evald, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(evald), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if depth >= maxPolicySymlinkFollow {
			return "", fmt.Errorf("too many symlinks resolving %q", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			// A relative target is relative to the link's real directory.
			realDir, err := filepath.EvalSymlinks(filepath.Dir(path))
			if err != nil {
				return "", err
			}
			target = filepath.Join(realDir, target)
		}
		return resolveSymlinksPolicyDepth(filepath.Clean(target), depth+1)
	}

	dir := path
	var suffix []string
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return path, nil
		}
		suffix = append([]string{filepath.Base(dir)}, suffix...)
		dir = parent
		if info, err := os.Lstat(dir); err == nil {
			if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				return "", fmt.Errorf("ancestor %q is not a directory", dir)
			}
			evald, err := filepath.EvalSymlinks(dir)
			if err != nil {
				return "", err
			}
			return filepath.Join(append([]string{evald}, suffix...)...), nil
		}
	}
}

func containsPath(paths []ResolvedPath, target string) bool {
	for _, item := range paths {
		if pathContains(item.Path, target) {
			return true
		}
	}
	return false
}

func pathContains(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == child {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (p ResolvedAccessPolicy) allReads() []ResolvedPath {
	out := append([]ResolvedPath{}, p.FS.Read...)
	out = append(out, p.Runtime...)
	out = append(out, p.ProviderState.Read...)
	return out
}

func (p ResolvedAccessPolicy) allWrites() []ResolvedPath {
	out := append([]ResolvedPath{}, p.FS.Write...)
	out = append(out, p.ProviderState.Write...)
	out = append(out, p.Scratch...)
	return out
}

func (p ResolvedAccessPolicy) allDenies() []ResolvedPath {
	return append([]ResolvedPath{}, p.FS.Deny...)
}

func sortResolvedPolicy(p *ResolvedAccessPolicy) {
	sortPaths := func(paths []ResolvedPath) {
		slices.SortFunc(paths, func(a, b ResolvedPath) int {
			if a.Path < b.Path {
				return -1
			}
			if a.Path > b.Path {
				return 1
			}
			if a.Kind < b.Kind {
				return -1
			}
			if a.Kind > b.Kind {
				return 1
			}
			return 0
		})
	}
	sortPaths(p.FS.Read)
	sortPaths(p.FS.Write)
	sortPaths(p.FS.Deny)
	sortPaths(p.FS.SourceRead)
	sortPaths(p.FS.Protect)
	sortPaths(p.Runtime)
	sortPaths(p.ProviderState.Read)
	sortPaths(p.ProviderState.Write)
	sortPaths(p.Scratch)
	slices.Sort(p.Network.LoopbackPorts)
}

func validateLoopbackPortSet(ports []int) error {
	seen := map[int]struct{}{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("sandbox: invalid loopback port %d", port)
		}
		if _, ok := seen[port]; ok {
			return fmt.Errorf("sandbox: duplicate loopback port %d", port)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func requiredCapabilities(p ResolvedAccessPolicy) []Capability {
	var caps []Capability
	add := func(cap Capability) {
		if !slices.Contains(caps, cap) {
			caps = append(caps, cap)
		}
	}
	if len(p.FS.Read) > 0 || len(p.FS.Write) > 0 {
		add(CapFilesystemAllowlist)
	}
	if len(p.FS.Deny) > 0 {
		add(CapDenyPrecedence)
	}
	if len(p.FS.Protect) > 0 {
		add(CapWriteProtect)
	}
	if len(p.Runtime) > 0 {
		add(CapRuntimeReads)
		add(CapFilesystemAllowlist)
	}
	if len(p.ProviderState.Read) > 0 || len(p.ProviderState.Write) > 0 {
		add(CapProviderState)
		add(CapFilesystemAllowlist)
	}
	if len(p.Scratch) > 0 {
		add(CapScratch)
		add(CapFilesystemAllowlist)
	}
	switch p.Network.Mode {
	case NetworkDeny:
		add(CapNetworkDeny)
	case NetworkLoopback:
		add(CapNetworkDeny)
		add(CapLoopback)
		if len(p.Network.LoopbackPorts) > 0 {
			add(CapLoopbackForward)
		}
	}
	if p.Subprocess == SubprocessDeny {
		add(CapSubprocessDeny)
	}
	if p.DenyGUILaunch {
		add(CapGUILaunchDeny)
	}
	if p.DenyUserServiceManager {
		add(CapUserServiceManagerDeny)
	}
	return caps
}

func pathRefsFromLegacy(paths []string) []PathRef {
	refs := make([]PathRef, 0, len(paths))
	for _, path := range paths {
		if path == "workspace" {
			refs = append(refs, PathRef{Root: ProjectRoot})
			continue
		}
		refs = append(refs, PathRef{Path: expandLegacyPath(path)})
	}
	return refs
}

func expandLegacyPath(raw string) string {
	home, _ := os.UserHomeDir()
	raw = strings.ReplaceAll(raw, "${HOME}", home)
	if raw == "~" {
		return home
	}
	if strings.HasPrefix(raw, "~/") {
		return home + raw[1:]
	}
	return raw
}

func legacyNetworkMode(p Profile) NetworkMode {
	if p.Net {
		return NetworkFull
	}
	if p.AllowLoopback || len(p.LoopbackForwardPorts) > 0 {
		return NetworkLoopback
	}
	return NetworkDeny
}

func legacySubprocessMode(p Profile) SubprocessMode {
	if p.Subprocess {
		return SubprocessAllow
	}
	return SubprocessDeny
}
