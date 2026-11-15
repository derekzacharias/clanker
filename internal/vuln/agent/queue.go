package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Offline report queue.
//
// A scan's result must not be lost because the dashboard was unreachable for a
// minute: the report is spooled to disk, retried in order, and only deleted once
// the server acknowledges it. The queue is bounded in count and bytes so a long
// outage cannot fill the endpoint's disk, and files are 0600 because a report
// contains the host's complete software inventory.
const (
	queueMaxEntries = 25
	queueMaxBytes   = 64 << 20
	queueFilePrefix = "report-"
	queueFileSuffix = ".json"
)

// Queued is one spooled report awaiting upload.
type Queued struct {
	Path       string
	Sequence   int64
	EnqueuedAt time.Time
	Payload    []byte
	ReportID   string
}

type queueEnvelope struct {
	Sequence   int64     `json:"sequence"`
	EnqueuedAt time.Time `json:"enqueued_at"`
	ReportID   string    `json:"report_id"`
	Payload    []byte    `json:"payload"`
}

// Queue is a directory of pending reports.
type Queue struct{ dir string }

// QueuePath is where reports are spooled for a given config file: beside it, so a
// config move takes the queue with it.
func QueuePath(configPath string) string {
	if configPath == "" {
		configPath = ConfigPath()
	}
	return filepath.Join(filepath.Dir(configPath), "queue")
}

// OpenQueue creates (if needed) and returns the queue in dir.
func OpenQueue(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create queue %s: %w", dir, err)
	}
	return &Queue{dir: dir}, nil
}

// Len reports how many reports are waiting.
func (q *Queue) Len() int { return len(q.entries()) }

func (q *Queue) entries() []string {
	items, err := filepath.Glob(filepath.Join(q.dir, queueFilePrefix+"*"+queueFileSuffix))
	if err != nil {
		return nil
	}
	sort.Strings(items) // zero-padded sequence in the name keeps order
	return items
}

// Enqueue spools a report. Older entries are dropped when the queue is full: the
// newest assessment is the one an operator needs.
func (q *Queue) Enqueue(payload []byte, sequence int64, reportID string, now time.Time) error {
	if len(payload) == 0 {
		return fmt.Errorf("refusing to queue an empty report")
	}
	if len(payload) > queueMaxBytes {
		return fmt.Errorf("report is %d bytes, over the %d byte queue limit", len(payload), queueMaxBytes)
	}
	env := queueEnvelope{Sequence: sequence, EnqueuedAt: now.UTC(), ReportID: reportID, Payload: payload}
	blob, err := json.Marshal(env)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s%018d%s", queueFilePrefix, sequence, queueFileSuffix)
	final := filepath.Join(q.dir, name)
	tmp, err := os.CreateTemp(q.dir, ".queue-*")
	if err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	q.trim()
	return nil
}

// trim enforces the count and byte bounds by dropping the oldest entries.
func (q *Queue) trim() {
	items := q.entries()
	for len(items) > queueMaxEntries {
		_ = os.Remove(items[0])
		items = items[1:]
	}
	total := int64(0)
	for _, item := range items {
		if info, err := os.Stat(item); err == nil {
			total += info.Size()
		}
	}
	for total > queueMaxBytes && len(items) > 1 {
		info, err := os.Stat(items[0])
		_ = os.Remove(items[0])
		if err == nil {
			total -= info.Size()
		}
		items = items[1:]
	}
}

// List returns the queued reports in upload order.
func (q *Queue) List() ([]Queued, error) {
	out := []Queued{}
	for _, item := range q.entries() {
		raw, err := os.ReadFile(item)
		if err != nil {
			continue
		}
		var env queueEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			// A corrupt entry must not block the queue forever.
			_ = os.Remove(item)
			continue
		}
		out = append(out, Queued{
			Path: item, Sequence: env.Sequence, EnqueuedAt: env.EnqueuedAt,
			Payload: env.Payload, ReportID: env.ReportID,
		})
	}
	return out, nil
}

// Remove deletes an acknowledged entry.
func (q *Queue) Remove(path string) error {
	if !strings.HasPrefix(filepath.Base(path), queueFilePrefix) {
		return fmt.Errorf("refusing to remove %q: not a queued report", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
