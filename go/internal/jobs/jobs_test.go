package jobs

import (
	"strings"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

func shell(script string) Command {
	return func(kind string, payload []byte) ([]string, []byte, error) {
		return []string{"/bin/sh", "-c", script}, payload, nil
	}
}

func field(o *ojson.Object, k string) ojson.Value { v, _ := o.Get(k); return v }

func waitState(t *testing.T, r *Runner, id string) *ojson.Object {
	t.Helper()
	v := r.Wait(id, 10)
	if v == nil {
		t.Fatalf("job %s vanished", id)
	}
	return v
}

// C15: at most two run and four wait; the seventh is refused at once, and nothing blocks on a worker.
func TestAdmissionCancelAndShutdown(t *testing.T) {
	r, err := New(shell("sleep 30"), 2, 4, 60*time.Second, 32, 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 6; i++ {
		job, err := r.Submit("analyze", nil)
		if err != nil {
			t.Fatalf("job %d refused: %v", i, err)
		}
		ids = append(ids, field(job, "id").(string))
	}
	started := time.Now()
	if _, err := r.Submit("analyze", nil); err == nil || err.Error() != "Too many analyses in progress; retry in a moment." {
		t.Fatalf("seventh job: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("admission waited for a worker")
	}
	status := ojson.MustDumps(r.Status())
	if !strings.Contains(status, `"running": 2, "queued": 4`) || !strings.Contains(status, `"rejected": 1`) {
		t.Fatal(status)
	}
	// Cancelling a running job kills its worker and frees the slot for the first queued one.
	view := r.Cancel(ids[0])
	if field(view, "state") != "cancelled" || field(view, "reason") != "cancelled by the operator" {
		t.Fatal(ojson.MustDumps(view))
	}
	if again := r.Cancel(ids[0]); ojson.MustDumps(again) != ojson.MustDumps(view) {
		t.Fatal("cancel is not idempotent")
	}
	if r.Cancel("unknown") != nil {
		t.Fatal("an unknown job was cancelled")
	}
	if s := field(r.Get(ids[2], false), "state"); s != "running" {
		t.Fatalf("the first queued job did not start: %v", s)
	}
	r.Shutdown()
	for i, id := range ids[1:] {
		v := r.Get(id, false)
		reason, _ := field(v, "reason").(string)
		if field(v, "state") != "cancelled" || !strings.HasPrefix(reason, "server shut down") {
			t.Fatalf("job %d after shutdown: %s", i+1, ojson.MustDumps(v))
		}
	}
	if _, err := r.Submit("analyze", nil); err == nil || err.Error() != "The server is shutting down." {
		t.Fatalf("submit after shutdown: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.running) != 0 || len(r.queue) != 0 {
		t.Fatal("work left after shutdown")
	}
}

func TestOutcomesCarryTheReferenceReasons(t *testing.T) {
	cases := []struct{ script, state, reason, result string }{
		{`printf '{"a": [1, 2.5]}'`, "done", "", `{"a": [1, 2.5]}`},
		{`printf '{"error": "Capture could not be analyzed: x"}'`, "failed", "Capture could not be analyzed: x", ""},
		{`printf 'not json'`, "failed", "worker returned no readable result", ""},
		{`exit 3`, "failed", "worker exited with status 3", ""},
		{`kill -9 $$`, "failed", "worker exited with status -9", ""},
		{`cat`, "done", "", `[1]`},
	}
	for _, c := range cases {
		r, _ := New(shell(c.script), 2, 4, 10*time.Second, 32, 300, nil)
		job, err := r.Submit("analyze", []byte("[1]"))
		if err != nil {
			t.Fatal(err)
		}
		v := waitState(t, r, field(job, "id").(string))
		reason, _ := field(v, "reason").(string)
		if field(v, "state") != c.state || reason != c.reason {
			t.Errorf("%s: %s", c.script, ojson.MustDumps(v))
		}
		if c.result != "" && ojson.MustDumps(field(v, "result")) != c.result {
			t.Errorf("%s: result %s", c.script, ojson.MustDumps(field(v, "result")))
		}
	}
}

func TestLifetimeExpiresAndRetentionIsBounded(t *testing.T) {
	r, _ := New(shell("sleep 30"), 1, 0, 300*time.Millisecond, 2, 300, nil)
	job, _ := r.Submit("analyze", nil)
	v := waitState(t, r, field(job, "id").(string))
	if field(v, "state") != "expired" || field(v, "reason") != "worker exceeded its 0 second lifetime" {
		t.Fatal(ojson.MustDumps(v))
	}
	q, _ := New(shell("true"), 1, 4, 10*time.Second, 2, 300, nil)
	var ids []string
	for i := 0; i < 4; i++ {
		job, err := q.Submit("analyze", nil)
		if err != nil {
			t.Fatal(err)
		}
		id := field(job, "id").(string)
		waitState(t, q, id)
		ids = append(ids, id)
	}
	if q.Get(ids[0], false) != nil || q.Get(ids[1], false) != nil || q.Get(ids[3], false) == nil {
		t.Fatal("finished outcomes are not bounded to the retained number, oldest first")
	}
}
