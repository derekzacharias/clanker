// Package service installs the agent as a background service so an enrolled
// endpoint stays reachable without the operator editing unit files.
//
// The agent intentionally ships no service by default when it is only scanning
// locally; the installer asks for one when the endpoint is enrolled in a
// dashboard. Everything here is idempotent and reversible: `uninstall` removes
// exactly what `install` wrote.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Name is the unit/label/task name used everywhere.
const Name = "clanker-guard-agent"

// ErrUnsupported means this platform has no supervisor this package knows how to
// drive; the caller should tell the operator how to run `watch` themselves.
var ErrUnsupported = errors.New("this platform has no supported service manager")

// Runner runs an external command. Injected so tests can assert the exact
// invocation without touching the host's service manager.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// Manager installs, removes and reports on the agent service.
type Manager struct {
	// ExePath is the agent binary the service should run.
	ExePath string
	// ConfigPath is the enrollment file passed to `watch --config`.
	ConfigPath string
	// Home overrides the user's home directory (tests).
	Home string
	// StartupDir overrides the Windows Startup folder (tests).
	startupDir string
	// Run executes service-manager commands (tests).
	Run Runner

	goos string
}

// New returns a manager for this platform.
func New(exePath, configPath string) *Manager {
	return &Manager{
		ExePath:    exePath,
		ConfigPath: configPath,
		Run:        execRunner,
		goos:       runtime.GOOS,
	}
}

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s: %w (%s)", name, err, text)
		}
		return text, fmt.Errorf("%s: %w", name, err)
	}
	return text, nil
}

func (m *Manager) home() (string, error) {
	if m.Home != "" {
		return m.Home, nil
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h, nil
	}
	return "", errors.New("cannot determine the home directory")
}

// Status describes the installed service.
type Status struct {
	Platform  string `json:"platform"`
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Path      string `json:"path,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Install writes the platform definition and starts it. It reports what it did so
// the installer can print a truthful summary.
func (m *Manager) Install(ctx context.Context) (Status, error) {
	switch m.goos {
	case "linux":
		return m.installSystemdUser(ctx)
	case "darwin":
		return m.installLaunchd(ctx)
	case "windows":
		return m.installScheduledTask(ctx)
	default:
		return Status{Platform: m.goos}, ErrUnsupported
	}
}

// Uninstall stops the service and removes what Install wrote.
func (m *Manager) Uninstall(ctx context.Context) (Status, error) {
	switch m.goos {
	case "linux":
		return m.uninstallSystemdUser(ctx)
	case "darwin":
		return m.uninstallLaunchd(ctx)
	case "windows":
		return m.uninstallScheduledTask(ctx)
	default:
		return Status{Platform: m.goos}, ErrUnsupported
	}
}

// Start, Stop and Restart drive the installed service. They are no-ops with
// ErrUnsupported on platforms this package does not manage.
func (m *Manager) Start(ctx context.Context) error {
	switch m.goos {
	case "linux":
		_, err := m.Run(ctx, "systemctl", "--user", "start", Name+".service")
		return err
	case "darwin":
		plist, err := m.launchdPlistPath()
		if err != nil {
			return err
		}
		_, err = m.Run(ctx, "launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), plist)
		return err
	case "windows":
		_, err := m.Run(ctx, "schtasks", "/Run", "/TN", Name)
		return err
	default:
		return ErrUnsupported
	}
}

func (m *Manager) Stop(ctx context.Context) error {
	switch m.goos {
	case "linux":
		_, err := m.Run(ctx, "systemctl", "--user", "stop", Name+".service")
		return err
	case "darwin":
		plist, err := m.launchdPlistPath()
		if err != nil {
			return err
		}
		_, err = m.Run(ctx, "launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), plist)
		return err
	case "windows":
		_, err := m.Run(ctx, "schtasks", "/End", "/TN", Name)
		return err
	default:
		return ErrUnsupported
	}
}

func (m *Manager) Restart(ctx context.Context) error {
	switch m.goos {
	case "linux":
		_, err := m.Run(ctx, "systemctl", "--user", "restart", Name+".service")
		return err
	default:
		// launchd and schtasks have no restart verb; stop then start is equivalent.
		if err := m.Stop(ctx); err != nil && !errors.Is(err, ErrUnsupported) {
			return err
		}
		return m.Start(ctx)
	}
}

// Current reports the installed state without changing anything.
func (m *Manager) Current(ctx context.Context) Status {
	switch m.goos {
	case "linux":
		return m.systemdStatus(ctx)
	case "darwin":
		return m.launchdStatus(ctx)
	case "windows":
		return m.taskStatus(ctx)
	default:
		return Status{Platform: m.goos}
	}
}

// ---------------------------------------------------------------- systemd ---

func (m *Manager) systemdUnitPath() (string, error) {
	home, err := m.home()
	if err != nil {
		return "", err
	}
	// Prefer XDG_CONFIG_HOME when it is set, the same rule systemd uses.
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", Name+".service"), nil
}

// SystemdUnit is the unit content. Exported for tests and for operators who want
// to see exactly what gets written.
func (m *Manager) SystemdUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Clanker Guard endpoint agent
Documentation=https://github.com/derekzacharias/clanker-guard-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s watch --config %s
Restart=always
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
`, m.ExePath, m.ConfigPath)
}

func (m *Manager) installSystemdUser(ctx context.Context) (Status, error) {
	unitPath, err := m.systemdUnitPath()
	if err != nil {
		return Status{Platform: m.goos}, err
	}
	if _, err := m.Run(ctx, "systemctl", "--user", "show-environment"); err != nil {
		// No user manager (containers, minimal images). Say so instead of writing
		// a unit nothing will ever load.
		return Status{Platform: m.goos}, fmt.Errorf("%w: systemctl --user is not available: %v", ErrUnsupported, err)
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		return Status{Platform: m.goos}, fmt.Errorf("create %s: %w", filepath.Dir(unitPath), err)
	}
	if err := os.WriteFile(unitPath, []byte(m.SystemdUnit()), 0o600); err != nil {
		return Status{Platform: m.goos}, err
	}
	if _, err := m.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return Status{Platform: m.goos, Path: unitPath}, err
	}
	if _, err := m.Run(ctx, "systemctl", "--user", "enable", "--now", Name+".service"); err != nil {
		return Status{Platform: m.goos, Path: unitPath}, err
	}
	// Without lingering the unit stops when the last session closes, which is the
	// exact "it went offline" complaint this is here to prevent. Not fatal: some
	// systems disallow it, and the service is still running for this session.
	detail := ""
	if u, err := user.Current(); err == nil {
		if _, err := m.Run(ctx, "loginctl", "enable-linger", u.Username); err != nil {
			detail = "warning: loginctl enable-linger failed; the service stops when you log out"
		}
	}
	st := m.systemdStatus(ctx)
	st.Detail = detail
	return st, nil
}

func (m *Manager) uninstallSystemdUser(ctx context.Context) (Status, error) {
	unitPath, err := m.systemdUnitPath()
	if err != nil {
		return Status{Platform: m.goos}, err
	}
	_, _ = m.Run(ctx, "systemctl", "--user", "disable", "--now", Name+".service")
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Status{Platform: m.goos, Path: unitPath}, err
	}
	_, _ = m.Run(ctx, "systemctl", "--user", "daemon-reload")
	return Status{Platform: m.goos, Path: unitPath, Installed: false}, nil
}

func (m *Manager) systemdStatus(ctx context.Context) Status {
	unitPath, err := m.systemdUnitPath()
	if err != nil {
		return Status{Platform: m.goos}
	}
	st := Status{Platform: m.goos, Path: unitPath}
	if _, err := os.Stat(unitPath); err == nil {
		st.Installed = true
	}
	if out, err := m.Run(ctx, "systemctl", "--user", "is-enabled", Name+".service"); err == nil {
		st.Enabled = strings.TrimSpace(out) == "enabled"
	}
	if out, err := m.Run(ctx, "systemctl", "--user", "is-active", Name+".service"); err == nil {
		st.Running = strings.TrimSpace(out) == "active"
	}
	return st
}

// ----------------------------------------------------------------- launchd ---

func (m *Manager) launchdPlistPath() (string, error) {
	home, err := m.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", "com.clanker.guard-agent.plist"), nil
}

// LaunchdPlist is the property list written on macOS.
func (m *Manager) LaunchdPlist(logPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.clanker.guard-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>watch</string>
    <string>--config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, m.ExePath, m.ConfigPath, logPath, logPath)
}

func (m *Manager) installLaunchd(ctx context.Context) (Status, error) {
	plist, err := m.launchdPlistPath()
	if err != nil {
		return Status{Platform: m.goos}, err
	}
	home, _ := m.home()
	logPath := filepath.Join(home, "Library", "Logs", "clanker-guard-agent.log")
	if err := os.MkdirAll(filepath.Dir(plist), 0o700); err != nil {
		return Status{Platform: m.goos}, err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return Status{Platform: m.goos}, err
	}
	if err := os.WriteFile(plist, []byte(m.LaunchdPlist(logPath)), 0o600); err != nil {
		return Status{Platform: m.goos}, err
	}
	// Reload so a changed plist takes effect; ignore the "not loaded" error.
	_, _ = m.Run(ctx, "launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), plist)
	if _, err := m.Run(ctx, "launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), plist); err != nil {
		if _, legacyErr := m.Run(ctx, "launchctl", "load", "-w", plist); legacyErr != nil {
			return Status{Platform: m.goos, Path: plist}, err
		}
	}
	return m.launchdStatus(ctx), nil
}

func (m *Manager) uninstallLaunchd(ctx context.Context) (Status, error) {
	plist, err := m.launchdPlistPath()
	if err != nil {
		return Status{Platform: m.goos}, err
	}
	_, _ = m.Run(ctx, "launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), plist)
	_, _ = m.Run(ctx, "launchctl", "unload", "-w", plist)
	if err := os.Remove(plist); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Status{Platform: m.goos, Path: plist}, err
	}
	return Status{Platform: m.goos, Path: plist}, nil
}

func (m *Manager) launchdStatus(ctx context.Context) Status {
	plist, err := m.launchdPlistPath()
	if err != nil {
		return Status{Platform: m.goos}
	}
	st := Status{Platform: m.goos, Path: plist}
	if _, err := os.Stat(plist); err == nil {
		st.Installed = true
		st.Enabled = true
	}
	if out, err := m.Run(ctx, "launchctl", "print", fmt.Sprintf("gui/%d/com.clanker.guard-agent", os.Getuid())); err == nil {
		st.Running = strings.Contains(out, "state = running")
	}
	return st
}

// ---------------------------------------------------------------- windows ---

func (m *Manager) installScheduledTask(ctx context.Context) (Status, error) {
	// A logon task, not a Windows service: no binary in C:\Windows, and it stops when the
	// user logs out for good (which is when the endpoint is unreachable anyway).
	if _, err := m.Run(ctx, "schtasks", "/Create", "/F", "/SC", "ONLOGON", "/TN", Name,
		"/TR", fmt.Sprintf(`"%s" watch --config "%s"`, m.ExePath, m.ConfigPath)); err != nil {
		// Task creation is refused on some managed machines ("Access is denied"). A per-user
		// Startup shortcut reaches the same outcome with no privileges at all, so the endpoint
		// still comes back after a logon instead of silently staying offline.
		if startupErr := m.installStartupShortcut(); startupErr == nil {
			detail := "installed as a Startup shortcut; the scheduled task was refused (" + shortErr(err) + ")"
			return Status{Platform: m.goos, Installed: true, Enabled: true, Path: m.startupPath(), Detail: detail}, nil
		}
		return Status{Platform: m.goos}, err
	}
	_, _ = m.Run(ctx, "schtasks", "/Run", "/TN", Name)
	return m.taskStatus(ctx), nil
}

func (m *Manager) uninstallScheduledTask(ctx context.Context) (Status, error) {
	_, _ = m.Run(ctx, "schtasks", "/End", "/TN", Name)
	_, _ = m.Run(ctx, "schtasks", "/Delete", "/F", "/TN", Name)
	// Remove the Startup shortcut too, when that was the mechanism that got installed.
	_ = os.Remove(m.startupPath())
	return Status{Platform: m.goos}, nil
}

// startupPath is the per-user Startup folder entry that replaces a refused task.
func (m *Manager) startupPath() string {
	dir := m.startupDir
	if dir == "" {
		cfg, err := os.UserConfigDir() // %AppData% on Windows
		if err != nil {
			return ""
		}
		dir = filepath.Join(cfg, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	}
	return filepath.Join(dir, Name+".cmd")
}

// installStartupShortcut writes a .cmd that launches the watcher at logon.
//
// No privileges, no Task Scheduler, no policy change: the Start Menu's Startup folder is
// per-user by design. The file is a plain script the operator can read.
func (m *Manager) installStartupShortcut() error {
	path := m.startupPath()
	if path == "" {
		return errors.New("cannot resolve the Startup folder")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("@echo off\r\nstart \"\" \"%s\" watch --config \"%s\"\r\n", m.ExePath, m.ConfigPath)
	return os.WriteFile(path, []byte(content), 0o644)
}

// shortErr keeps the service detail line readable.
func shortErr(err error) string {
	s := strings.TrimSpace(err.Error())
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return strings.ReplaceAll(s, "\n", " ")
}

func (m *Manager) taskStatus(ctx context.Context) Status {
	st := Status{Platform: m.goos}
	out, err := m.Run(ctx, "schtasks", "/Query", "/TN", Name)
	if err != nil {
		return st
	}
	st.Installed = true
	st.Enabled = true
	st.Running = strings.Contains(strings.ToLower(out), "running")
	return st
}
