//go:build !windows

package agent

import "syscall"

func detachedProcAttr() *syscall.SysProcAttr {
	return nil
}
