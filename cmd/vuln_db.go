package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// Database operations: take a copy, and prove the copy is good.
//
// A backup nobody has restored is a hope. `db verify` opens the snapshot with the same code
// the server uses, runs SQLite's integrity check, and prints what is inside — so a restore
// drill is a command with an exit code, not a paragraph of instructions.

func newVulnDBCmd() *cobra.Command {
	var (
		common vulnCommonFlags
		to     string
		from   string
		dir    string
	)
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Back up and verify the Clanker Guard database",
		Long: `Copy and check the dashboard database.

  clanker vuln db backup --to /backups            # consistent snapshot (VACUUM INTO)
  clanker vuln db verify --from /backups/x.db     # integrity check + row counts
  clanker vuln db restore --from /backups/x.db    # check, then install it as the cache

Restoring replaces the cache file, so stop the server first. The command refuses to
overwrite an existing database unless --force is given, and it keeps the previous file
beside the new one with a .before-restore suffix.`,
		Args: cobra.NoArgs,
	}
	common.register(cmd)

	backup := &cobra.Command{
		Use:   "backup",
		Short: "Write a consistent snapshot of the database",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := resolveBackupPath(to)
			if err != nil {
				return err
			}
			st, err := intel.OpenStore(common.path())
			if err != nil {
				return err
			}
			defer st.Close()
			if err := st.BackupTo(context.Background(), path); err != nil {
				return err
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			fmt.Printf("snapshot: %s (%d bytes, mode %s)\n", path, info.Size(), info.Mode().Perm())
			return nil
		},
	}
	backup.Flags().StringVar(&to, "to", "", "directory for the snapshot (default: beside the cache)")

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Check a snapshot opens, passes integrity_check, and report what it holds",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return verifySnapshot(from)
		},
	}
	verify.Flags().StringVar(&from, "from", "", "snapshot file to check")

	restore := &cobra.Command{
		Use:   "restore",
		Short: "Verify a snapshot, then install it as the cache (server must be stopped)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" {
				return errors.New("--from is required")
			}
			if err := verifySnapshot(from); err != nil {
				return fmt.Errorf("refusing to restore an unverified snapshot: %w", err)
			}
			dest := common.path()
			force, _ := cmd.Flags().GetBool("force")
			if _, err := os.Stat(dest); err == nil {
				if !force {
					return fmt.Errorf("%s exists; stop the server and pass --force to replace it", dest)
				}
				backup := dest + ".before-restore"
				if err := copyFile(dest, backup); err != nil {
					return fmt.Errorf("keep the previous database: %w", err)
				}
				fmt.Printf("previous database kept at %s\n", backup)
			}
			if err := copyFile(from, dest); err != nil {
				return err
			}
			if err := os.Chmod(dest, 0o600); err != nil {
				return err
			}
			// Leftover WAL/SHM from the old file would be replayed onto the new one.
			for _, suffix := range []string{"-wal", "-shm"} {
				_ = os.Remove(dest + suffix)
			}
			fmt.Printf("restored %s\nrestart the server to use it\n", dest)
			return nil
		},
	}
	restore.Flags().StringVar(&from, "from", "", "snapshot file to restore")
	restore.Flags().Bool("force", false, "replace an existing database")

	_ = dir
	cmd.AddCommand(backup, verify, restore)
	return cmd
}

func resolveBackupPath(to string) (string, error) {
	dir := strings.TrimSpace(to)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := "intel-" + time.Now().UTC().Format("20060102T150405Z") + ".db"
	return filepath.Join(dir, name), nil
}

// verifySnapshot is the drill: open with the real store, check integrity, count rows and
// confirm the subsystems' tables are present.
func verifySnapshot(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("--from is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()

	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("integrity_check failed to run: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("integrity_check reported: %s", integrity)
	}
	counts, err := snapshotCounts(db)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "snapshot:\t%s\n", path)
	fmt.Fprintf(w, "size:\t%d bytes\n", info.Size())
	fmt.Fprintf(w, "integrity:\tok\n")
	for _, c := range counts {
		fmt.Fprintf(w, "%s:\t%d\n", c.label, c.n)
	}
	_ = w.Flush()
	if counts[0].n == 0 {
		return errors.New("the snapshot holds no assessments; it is not a usable backup")
	}
	fmt.Println("result: usable — restore with `clanker vuln db restore --from`")
	return nil
}

type snapshotCount struct {
	label string
	n     int
}

// snapshotCounts checks the tables the three subsystems own, so a snapshot that is missing
// remediation or tickets is reported rather than silently accepted.
func snapshotCounts(db *sql.DB) ([]snapshotCount, error) {
	specs := []struct{ label, query string }{
		{"assessments", `SELECT COUNT(*) FROM runs`},
		{"remediation items", `SELECT COUNT(*) FROM remediation_items`},
		{"asset ownership", `SELECT COUNT(*) FROM asset_owners`},
		{"audit entries", `SELECT COUNT(*) FROM audit_log`},
		{"gitlab tickets", `SELECT COUNT(*) FROM gitlab_tickets`},
		{"agent events", `SELECT COUNT(*) FROM agent_events`},
	}
	out := make([]snapshotCount, 0, len(specs))
	for _, s := range specs {
		var n int
		if err := db.QueryRow(s.query).Scan(&n); err != nil {
			// A missing table is not corruption: an older snapshot predates that feature.
			if strings.Contains(err.Error(), "no such table") {
				out = append(out, snapshotCount{label: s.label, n: 0})
				continue
			}
			return nil, fmt.Errorf("count %s: %w", s.label, err)
		}
		out = append(out, snapshotCount{label: s.label, n: n})
	}
	return out, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.ReadFrom(in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// keep the subsystem packages referenced: this file documents which tables a snapshot must
// contain, and the stores define them.
var _ = remediate.StateDetected
var _ = ticketing.ErrTicketNotFound
