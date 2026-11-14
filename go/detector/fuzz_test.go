package detector

import (
	"testing"
)

// FuzzFlowInvariants drives one flow with arbitrary bytes for both directions, split at arbitrary points,
// with ends and expiry interleaved, and checks the facade's invariants: the engine never panics on input,
// every outcome and reason is in its vocabulary, inspected bytes stay within the budget, a done direction
// never changes again, revisions never decrease, Close releases everything, and a withheld value is empty.
func FuzzFlowInvariants(f *testing.F) {
	f.Add(httpRequest, httpResponse, uint8(5), uint8(0))
	f.Add(sshBanner, smtpEHLO, uint8(1), uint8(3))
	f.Add(http2Preface, postgres, uint8(9), uint8(1))
	f.Add(junk, []byte("HTTP/1.1 200 OK\r\n\r\n"), uint8(2), uint8(2))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}, []byte{0x16, 0x03, 0x03}, uint8(3), uint8(0))
	c := allFamilies()
	c.MaxBytesPerDirection, c.MaxFeedsPerDirection = 4096, 64
	e, err := New(c)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, client, server []byte, step, ops uint8) {
		flow, err := e.NewFlow("fuzz")
		if err != nil {
			t.Fatal(err)
		}
		size := int(step%31) + 1
		var prev [2]DirectionSnapshot
		check := func() {
			s := flow.Snapshot()
			for _, d := range AllDirections() {
				ds := s.Direction(d)
				if !ds.Outcome.Valid() || !ds.Reason.Valid() {
					t.Fatalf("%s: outcome %q reason %q", d, ds.Outcome, ds.Reason)
				}
				if ds.BytesInspected > c.MaxBytesPerDirection {
					t.Fatalf("%s: inspected %d bytes over the budget", d, ds.BytesInspected)
				}
				if ds.Revision < prev[d].Revision {
					t.Fatalf("%s: revision went back from %d to %d", d, prev[d].Revision, ds.Revision)
				}
				if prev[d].Done && (ds.Outcome != prev[d].Outcome || !ds.Done) {
					t.Fatalf("%s: done direction changed from %s to %s", d, prev[d].Outcome, ds.Outcome)
				}
				offers := 0
				for _, ev := range ds.Evidence {
					if ev.Class == ClassWithheld && ev.Value != "" {
						t.Fatalf("withheld value kept: %+v", ev)
					}
					if ev.Field == "offered_alpn" {
						offers++
					}
				}
				if len(ds.OfferedALPN) > MaxOfferedALPN || offers > MaxOfferedALPN || len(ds.Evidence) > MaxEvidence {
					t.Fatalf("%s: export bounds exceeded: %d ALPN, %d offered_alpn rows, %d evidence", d, len(ds.OfferedALPN), offers, len(ds.Evidence))
				}
				prev[d] = ds
			}
		}
		for i := 0; i < len(client) || i < len(server); i += size {
			if i < len(client) {
				flow.Feed(ClientToServer, client[i:minInt(i+size, len(client))])
			}
			if i < len(server) {
				flow.Feed(ServerToClient, server[i:minInt(i+size, len(server))])
			}
			check()
		}
		if ops&1 != 0 {
			flow.EndDirection(ClientToServer, EndEOF)
		}
		if ops&2 != 0 {
			flow.Expire()
		}
		check()
		final := flow.Close()
		if !final.Closed || !final.Direction(ClientToServer).Done || !final.Direction(ServerToClient).Done {
			t.Fatalf("close left a direction open: %+v", final)
		}
		if flow.dirs[ClientToServer].in != nil || flow.dirs[ServerToClient].in != nil {
			t.Fatal("close kept an inspector")
		}
		if st := e.Stats(); st.Panics != 0 {
			t.Fatalf("the engine panicked on input (recovered %d)", st.Panics)
		}
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
