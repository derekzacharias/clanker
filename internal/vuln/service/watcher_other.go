//go:build !windows

package service

import (
	"os/exec"
	"syscall"
)

// startWatcherDetached launches `watch` in its own session.
//
// Linux and macOS start the watcher through their service manager instead; this exists so a
// Windows install path compiled or tested on another platform still detaches rather than
// leaving a child attached to the installer. There is no console window to suppress here.
func startWatcherDetached(exePath, configPath string) error {
	cmd := exec.Command(exePath, "watch", "--config", configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
