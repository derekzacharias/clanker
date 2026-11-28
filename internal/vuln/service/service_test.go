package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records service-manager calls instead of touching the host.
type fakeRunner struct {
	calls [][]string
	// fail maps a command name to the error it should return.
	fail map[string]bool
	out  map[string]string
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail[name] {
		return "", errFake
	}
	if out, ok := f.out[name]; ok {
		return out, nil
	}
	return "", nil
}

var errFake = os.ErrInvalid

func newManager(t *testing.T, goos string) (*Manager, *fakeRunner, string) {
	t.Helper()
	home := t.TempDir()
	f := &fakeRunner{fail: map[string]bool{}, out: map[string]string{}}
	m := &Manager{
		ExePath:    "/usr/local/bin/clanker-guard-agent",
		ConfigPath: filepath.Join(home, ".config/clanker-guard/agent.json"),
		Home:       home,
		Run:        f.run,
		goos:       goos,
	}
	return m, f, home
}

func TestSystemdUnitNamesTheWatchLoop(t *testing.T) {
	m, _, _ := newManager(t, "linux")
	unit := m.SystemdUnit()
	for _, want := range []string{
		"ExecStart=/usr/local/bin/clanker-guard-agent watch --config ",
		"Restart=always",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit is missing %q:\n%s", want, unit)
		}
	}
}

func TestInstallSystemdWritesAndEnablesTheUnit(t *testing.T) {
	m, f, home := newManager(t, "linux")
	status, err := m.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	unitPath := filepath.Join(home, ".config/systemd/user/clanker-guard-agent.service")
	if _, err := os.Stat(unitPath); err != nil {
		t.Fatalf("unit not written: %v", err)
	}
	// Enabling is what makes it start at boot; lingering is what keeps it alive
	// after logout. Both must be attempted.
	joined := ""
	for _, c := range f.calls {
		joined += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{
		"systemctl --user daemon-reload",
		"systemctl --user enable --now clanker-guard-agent.service",
		"loginctl enable-linger",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing call %q in:\n%s", want, joined)
		}
	}
	if status.Path != unitPath {
		t.Fatalf("status path = %q", status.Path)
	}
}

func TestInstallSystemdReportsMissingUserManager(t *testing.T) {
	m, f, _ := newManager(t, "linux")
	f.fail["systemctl"] = true
	_, err := m.Install(context.Background())
	if err == nil {
		t.Fatal("expected an error when there is no user systemd")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("error should explain the platform limit: %v", err)
	}
	// It must not write a unit nothing would load.
	if _, statErr := os.Stat(filepath.Join(m.Home, ".config/systemd/user/clanker-guard-agent.service")); statErr == nil {
		t.Fatal("a unit was written even though systemd is unavailable")
	}
}

func TestUninstallSystemdRemovesTheUnit(t *testing.T) {
	m, f, home := newManager(t, "linux")
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(home, ".config/systemd/user/clanker-guard-agent.service")
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatal("unit file survived uninstall")
	}
	joined := ""
	for _, c := range f.calls {
		joined += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(joined, "disable --now") {
		t.Fatalf("uninstall did not stop the service:\n%s", joined)
	}
}

func TestLaunchdPlistKeepsTheAgentAlive(t *testing.T) {
	m, f, home := newManager(t, "darwin")
	status, err := m.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	plistPath := filepath.Join(home, "Library/LaunchAgents/com.clanker.guard-agent.plist")
	body, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	for _, want := range []string{"<key>KeepAlive</key><true/>", "<string>watch</string>", "<key>RunAtLoad</key><true/>"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("plist is missing %q:\n%s", want, body)
		}
	}
	joined := ""
	for _, c := range f.calls {
		joined += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(joined, "launchctl bootstrap gui/") {
		t.Fatalf("plist was not loaded:\n%s", joined)
	}
	if status.Path != plistPath {
		t.Fatalf("status path = %q", status.Path)
	}
}

func TestScheduledTaskOnWindows(t *testing.T) {
	m, f, _ := newManager(t, "windows")
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	joined := ""
	for _, c := range f.calls {
		joined += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{"schtasks /Create", "/SC ONLOGON", "watch --config"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if _, err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	m, _, _ := newManager(t, "plan9")
	if _, err := m.Install(context.Background()); err == nil {
		t.Fatal("an unknown platform must not claim success")
	}
	if st := m.Current(context.Background()); st.Installed {
		t.Fatal("status claims an installed service on an unsupported platform")
	}
}

// Some managed Windows machines refuse task creation ("Access is denied"). The endpoint must
// still come back after a logon, and a per-user Startup shortcut does that with no privileges.
func TestWindowsInstallFallsBackToStartupShortcut(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{
		ExePath:    `C:\Users\student\AppData\Local\clanker-guard\bin\clanker-guard-agent.exe`,
		ConfigPath: `C:\Users\student\AppData\Roaming\clanker-guard\agent.json`,
		goos:       "windows",
		startupDir: dir,
		Run:        nil, // filled below so the test can record both calls
	}
	var calls []string
	m.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "schtasks" {
			return "", errors.New("schtasks: exit status 1 (ERROR: Access is denied.)")
		}
		return "", nil
	}
	var started []string
	m.StartWatcher = func(exePath, configPath string) error {
		started = append(started, exePath+"|"+configPath)
		return nil
	}
	st, err := m.installScheduledTask(context.Background())
	if err != nil {
		t.Fatalf("install should fall back, got %v", err)
	}
	if !st.Installed || !st.Enabled {
		t.Fatalf("status = %+v", st)
	}
	// The watcher has to be started now, not only at the next logon, or the endpoint shows
	// offline until someone signs out and back in.
	if len(started) != 1 {
		t.Fatalf("watcher start calls = %v, want exactly one", started)
	}
	if want := m.ExePath + "|" + m.ConfigPath; started[0] != want {
		t.Fatalf("watcher started with %q, want %q", started[0], want)
	}
	// A terminal window the installer leaves behind is the bug this replaced: `cmd /c start`
	// gave the watcher its own console, which stayed open for as long as the watcher ran.
	for _, c := range calls {
		if strings.HasPrefix(c, "cmd ") {
			t.Fatalf("the fallback must not launch the watcher through a shell: %v", calls)
		}
	}
	if !st.Running {
		t.Fatalf("status should report it running: %+v", st)
	}
	if !strings.Contains(st.Detail, "Startup shortcut") {
		t.Fatalf("detail does not explain the fallback: %q", st.Detail)
	}
	body, err := os.ReadFile(filepath.Join(dir, Name+".cmd"))
	if err != nil {
		t.Fatalf("startup shortcut missing: %v", err)
	}
	for _, want := range []string{"watch --config", "clanker-guard-agent.exe"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("shortcut is missing %q:\n%s", want, body)
		}
	}
	// Uninstalling removes it.
	if _, err := m.uninstallScheduledTask(context.Background()); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Name+".cmd")); !os.IsNotExist(err) {
		t.Fatal("startup shortcut survived uninstall")
	}
}

// A watcher that could not be started must be reported honestly: the endpoint is installed and
// returns at the next logon, but it is offline right now, and the installer should say so rather
// than show a green running state that will not answer a scan.
func TestWindowsFallbackReportsAWatcherThatDidNotStart(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{
		ExePath:    `C:\agent\clanker-guard-agent.exe`,
		ConfigPath: `C:\agent\agent.json`,
		goos:       "windows",
		startupDir: dir,
		Run: func(context.Context, string, ...string) (string, error) {
			return "", errors.New("ERROR: Access is denied.")
		},
		StartWatcher: func(string, string) error {
			return errors.New("the file is locked by another process")
		},
	}
	st, err := m.installScheduledTask(context.Background())
	if err != nil {
		t.Fatalf("a refused task with a workable shortcut is still an install, got %v", err)
	}
	if !st.Installed || st.Running {
		t.Fatalf("status should be installed but not running: %+v", st)
	}
	if !strings.Contains(st.Detail, "watcher did not start") {
		t.Fatalf("detail does not name the failed start: %q", st.Detail)
	}
}

// Installing over an existing install must take effect. `enable --now` does nothing to a running
// unit, so an upgraded binary would sit on disk while the old build kept the connection — which is
// what made an agent upgrade look like "not reporting".
func TestLinuxInstallRestartsAnExistingUnit(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	m := &Manager{
		ExePath: "/usr/local/bin/clanker-guard-agent", ConfigPath: dir + "/agent.json",
		Home: dir, goos: "linux", Run: func(ctx context.Context, name string, args ...string) (string, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "systemctl" && len(args) > 1 && args[1] == "show-environment" {
				return "VAR=value", nil
			}
			return "", nil
		},
	}
	if _, err := m.installSystemdUser(context.Background()); err != nil && !errors.Is(err, ErrUnsupported) {
		t.Fatalf("installSystemdUser: %v", err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "systemctl --user enable --now") {
		t.Fatalf("enable missing:\n%s", joined)
	}
	if !strings.Contains(joined, "systemctl --user restart "+Name+".service") {
		t.Fatalf("install does not restart an existing unit:\n%s", joined)
	}
}
