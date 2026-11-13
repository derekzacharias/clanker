package main

import (
	"fmt"
	"os"

	"github.com/bgdnvk/clanker/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// A subcommand may already have set a more specific exit code (for
		// example 3 for a configuration error, 2 for policy findings).
		if code := cmd.ExitCode(); code != 0 {
			os.Exit(code)
		}
		os.Exit(1)
	}
	// Honour the documented assessment exit codes (2 findings, 4 incomplete).
	if code := cmd.ExitCode(); code != 0 {
		os.Exit(code)
	}
}
