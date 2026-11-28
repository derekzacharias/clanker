//go:build !windows

package main

// hideOwnedConsoleWindow is a no-op: the service managers on Linux and macOS already start the
// watcher without a terminal attached, and a person running `watch` by hand wants to see it.
func hideOwnedConsoleWindow() {}
