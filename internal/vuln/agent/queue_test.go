package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueueRoundTripKeepsOrderAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	q, err := OpenQueue(dir)
	if err != nil {
		t.Fatalf("OpenQueue: %v", err)
	}
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for i, id := range []string{"SCAN-A", "SCAN-B", "SCAN-C"} {
		if err := q.Enqueue([]byte(`{"report_id":"`+id+`"}`), int64(i+1), id, now); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	if q.Len() != 3 {
		t.Fatalf("Len = %d", q.Len())
	}
	items, err := q.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || items[0].ReportID != "SCAN-A" || items[2].ReportID != "SCAN-C" {
		t.Fatalf("order = %v", []string{items[0].ReportID, items[1].ReportID, items[2].ReportID})
	}
	if items[1].Sequence != 2 {
		t.Fatalf("sequence = %d", items[1].Sequence)
	}
	// A queued report is the host's software inventory: 0600, never world readable.
	info, err := os.Stat(items[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("queue file mode = %o, want 600", perm)
	}
	if err := q.Remove(items[0].Path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if q.Len() != 2 {
		t.Fatalf("Len after remove = %d", q.Len())
	}
}

func TestQueueIsBounded(t *testing.T) {
	q, err := OpenQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 1; i <= queueMaxEntries+5; i++ {
		if err := q.Enqueue([]byte(`{"n":`+string(rune('0'+i%10))+`}`), int64(i), "SCAN", now); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if q.Len() > queueMaxEntries {
		t.Fatalf("queue kept %d entries, want at most %d", q.Len(), queueMaxEntries)
	}
	// The newest reports survive: they describe the current state of the host.
	items, _ := q.List()
	last := items[len(items)-1]
	if last.Sequence != int64(queueMaxEntries+5) {
		t.Fatalf("newest entry sequence = %d, want %d", last.Sequence, queueMaxEntries+5)
	}
}

func TestQueueRejectsEmptyAndHandlesCorruptEntries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	q, err := OpenQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(nil, 1, "SCAN", time.Now()); err == nil {
		t.Fatal("an empty report must not be queued")
	}
	// A truncated file from a crash must be skipped, not block the queue.
	if err := os.WriteFile(filepath.Join(dir, "report-000000000000000009.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := q.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("corrupt entry survived List: %v", items)
	}
	// Remove refuses paths that are not queue files.
	if err := q.Remove(filepath.Join(dir, "..", "agent.json")); err == nil {
		t.Fatal("Remove accepted a path outside the queue")
	}
}
