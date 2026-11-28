//go:build windows

package agent

import (
	"fmt"
	"os/exec"
	"syscall"
)

// defaultSwapper replaces the running binary on Windows.
//
// Windows locks an executable while it runs, so the rename cannot happen
// from inside the process that will be replaced. The staged file IS the new
// binary, so it is launched detached as a swap helper: the helper waits for
// the current process to exit (the rename starts succeeding the moment the
// file is unlocked), swaps the binary and restarts the watcher. The helper
// has no console window and is not tied to the current console's lifetime.
func defaultSwapper(temp, target string) error {
	cmd := exec.Command(temp, "update-swap", "--from", temp, "--to", target)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 /* DETACHED_PROCESS */ | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start swap helper: %w", err)
	}
	// The helper must outlive this process; releasing the handle is enough.
	return cmd.Process.Release()
}
