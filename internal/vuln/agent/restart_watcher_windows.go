//go:build windows

package agent

import "syscall"

func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: 0x00000008 /* DETACHED_PROCESS */ | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}
