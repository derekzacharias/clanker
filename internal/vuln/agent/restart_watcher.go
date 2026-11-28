package agent

import (
	"os/exec"
)

// RestartWatcherDetached starts the (possibly just replaced) binary in watch
// mode, detached from the process that performed the update. The updater is
// usually the watcher itself, so the new watcher must not die with it.
func RestartWatcherDetached(exePath, configPath string) error {
	cmd := exec.Command(exePath, "watch", "--config", configPath)
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
