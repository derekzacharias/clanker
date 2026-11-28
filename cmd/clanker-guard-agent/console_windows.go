//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// hideOwnedConsoleWindow removes the console window that a background start gives this
// process, without touching the console of a person running the command by hand.
//
// The watcher is long-lived, so any console window it owns stays on screen for as long as the
// agent runs: the logon task and the Startup shortcut both start it outside an interactive
// shell, and that window is the "terminal that never closes" after an install. Hiding it keeps
// the endpoint running while leaving the desktop clean.
//
// A console shared with another process (cmd.exe, PowerShell, Windows Terminal) belongs to the
// operator, so the process count is the guard: only a console this process owns on its own is
// hidden. Nothing else about the console changes; writes still go to the same device.
func hideOwnedConsoleWindow() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	user32 := syscall.NewLazyDLL("user32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	consoleProcesses := kernel32.NewProc("GetConsoleProcessList")
	showWindow := user32.NewProc("ShowWindow")

	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 {
		return // started detached: there is no console window to hide
	}
	var pids [2]uint32
	count, _, _ := consoleProcesses.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if count != 1 {
		return // shared console, or a count this call did not fit; leave it alone
	}
	const swHide = 0
	_, _, _ = showWindow.Call(hwnd, swHide)
}
