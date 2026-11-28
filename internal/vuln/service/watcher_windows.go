//go:build windows

package service

import (
	"os/exec"
	"syscall"
)

// DETACHED_PROCESS is not exported by the syscall package; it is the flag that matters
// here, so it is named instead of passing a bare 0x8.
const detachedProcess = 0x00000008

// startWatcherDetached launches `watch` with no console window of its own.
//
// Starting the watcher through `cmd /c start` created a new console for it: the installer
// finished, but the operator was left looking at a terminal window running the watcher, and
// every retry added another one. DETACHED_PROCESS gives the child no console at all — there
// is nothing to show and nothing to close — while CREATE_NEW_PROCESS_GROUP keeps it
// independent of the installer's console, so closing that terminal cannot take the endpoint
// offline. The child outlives this process, so it is deliberately not tied to a context.
func startWatcherDetached(exePath, configPath string) error {
	cmd := exec.Command(exePath, "watch", "--config", configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
