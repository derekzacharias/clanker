//go:build !windows

package agent

import "os"

// defaultSwapper replaces the running binary. On non-Windows platforms the
// kernel allows renaming over a file that is still executing, so the swap is
// immediate and atomic from the next start.
func defaultSwapper(temp, target string) error {
	return os.Rename(temp, target)
}
