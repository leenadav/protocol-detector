package livectl

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/events"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// Limits audit (PRO-477): see go/internal/analyze/limits_gap_test.go for the convention.

func limitGap(t *testing.T, id string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now reports its limit (docs/security/LIMITS-AUDIT-PRO-477.md): remove limitGap() and assert it plainly", id)
	}
	t.Skipf("%s (docs/security/LIMITS-AUDIT-PRO-477.md): limit hit silently, fix owned by the engine lane; today %s", id, today)
}

// SEC-LIM-10: the versioned log keeps the last 4096 envelopes (events.DefaultRetention) and its view is reduced
// from the retained envelopes only. A capture gap marks the run degraded; once 4096 later events push the gap
// envelope out, /api/live/events reports "quality": "intact" again, and the view says nothing about the envelopes
// it no longer covers. A later result silently replaces the earlier, worse one.
func TestLimitGapEventViewQualityOutlivesRetention(t *testing.T) {
	s := NewState(nil)
	s.Begin("00112233aabbccdd", "lo", "running")
	ingestText(t, s, `{"type": "capture_gap", "scope": "all_observations_this_capture", "reason": "packet loss"}`)
	quality := func() string {
		page, err := s.EventsSince(0, 1)
		if err != nil {
			t.Fatal(err)
		}
		view, _ := page.Get("view")
		q, _ := view.(*ojson.Object).Get("quality")
		text, _ := q.(string)
		return text
	}
	if quality() != "degraded" {
		t.Fatalf("reproducer drifted: a capture gap reads %q", quality())
	}
	for i := 0; i < events.DefaultRetention; i++ {
		ingestText(t, s, fmt.Sprintf(`{"type": "classification", "source": ["192.0.2.10", %d], "destination": ["198.51.100.53", 53], `+
			`"transport": "udp", "status": "identified", "protocol": "dns"}`, 1024+i%60000))
	}
	page, err := s.EventsSince(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	text := ojson.MustDumps(page)
	if !strings.Contains(text, `"start": 2`) {
		t.Fatalf("reproducer drifted: the gap envelope was not dropped: %.200s", text)
	}
	limitGap(t, "SEC-LIM-10", quality() == "degraded", "after 4096 later events the view reads quality "+quality())
}
