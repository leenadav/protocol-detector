package detector

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// deepCopy returns a Snapshot whose every string and slice is a fresh copy, so a later comparison with
// reflect.DeepEqual compares contents only.
func deepCopy(s Snapshot) Snapshot {
	c := s
	c.ID = strings.Clone(s.ID)
	for i, d := range s.Directions {
		d.Detail, d.Family, d.ApplicationProtocol = strings.Clone(d.Detail), strings.Clone(d.Family), strings.Clone(d.ApplicationProtocol)
		d.Encryption, d.Scope, d.Hostname = strings.Clone(d.Encryption), strings.Clone(d.Scope), Hostname(strings.Clone(string(d.Hostname)))
		if d.OfferedALPN != nil {
			alpn := make([]string, len(d.OfferedALPN))
			for j, a := range d.OfferedALPN {
				alpn[j] = strings.Clone(a)
			}
			d.OfferedALPN = alpn
		}
		if d.Evidence != nil {
			ev := make([]Evidence, len(d.Evidence))
			for j, e := range d.Evidence {
				ev[j] = Evidence{Field: strings.Clone(e.Field), Value: strings.Clone(e.Value), Source: strings.Clone(e.Source),
					Strength: strings.Clone(e.Strength), Class: e.Class}
			}
			d.Evidence = ev
		}
		c.Directions[i] = d
	}
	return c
}

// A held Snapshot is detached from the flow (PRO-148). The package no longer copies closed-vocabulary strings,
// reuses a copy while the engine reports the same text, and reuses the snapshot's internal evidence and ALPN
// slices in place across revisions. None of that may change a Snapshot the host already holds:
//   - a snapshot taken in the middle of a flow stays the same while the flow goes on publishing revisions;
//   - after Close, overwriting every input buffer the flow was fed changes no string of any held snapshot;
//   - the same holds while other goroutines run flows through the same engine with the reused, overwritten
//     buffers (run under -race in make go-check).
func TestHeldSnapshotsStayDetached(t *testing.T) {
	client, server := tlsFlights(t, "detach.example.test", []string{"h2", "http/1.1"}, nil)
	flows := map[string][2][]byte{
		"tls":  {client, server},
		"http": {append([]byte(nil), httpRequest...), append([]byte(nil), httpResponse...)},
		"ssh":  {append([]byte(nil), sshBanner...), []byte("SSH-2.0-Server_1.0\r\n")},
	}
	e := mustEngine(t, allFamilies())
	for name, in := range flows {
		f := mustFlow(t, e)
		half := len(in[0]) / 2
		f.Feed(ClientToServer, in[0][:half])
		early := f.Snapshot()
		earlyWant := deepCopy(early)
		f.Feed(ClientToServer, in[0][half:]) // more revisions: the internal slices are rewritten in place
		mid := f.Snapshot()
		midWant := deepCopy(mid)
		f.Feed(ServerToClient, in[1])
		closed := f.Close()
		closedWant := deepCopy(closed)
		if len(closed.Direction(ClientToServer).Evidence) == 0 {
			t.Fatalf("%s: the client direction carries no evidence; the test would check nothing", name)
		}
		// Overwrite every byte the flow was fed, and run new flows over the same buffers while the held snapshots
		// are read concurrently.
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			buf := append([]byte(nil), in[0]...) // each worker's own buffer, taken before the originals are overwritten
			wg.Add(1)
			go func(w int, buf []byte) {
				defer wg.Done()
				for i := 0; i < 50; i++ {
					g, err := e.NewFlow(fmt.Sprint(w))
					if err != nil {
						continue
					}
					g.Feed(ClientToServer, buf)
					g.Close()
					for j := range buf { // reuse: overwrite, then restore for the next flow
						buf[j] ^= 0xFF
					}
					for j := range buf {
						buf[j] ^= 0xFF
					}
				}
			}(w, buf)
		}
		for _, buf := range in {
			for i := range buf {
				buf[i] = 0xAA
			}
		}
		for i := 0; i < 50; i++ {
			for _, held := range []struct {
				got, want Snapshot
				what      string
			}{{early, earlyWant, "early"}, {mid, midWant, "mid-flow"}, {closed, closedWant, "closed"}} {
				if !reflect.DeepEqual(held.got, held.want) {
					t.Fatalf("%s: the %s snapshot changed after the flow went on, closed and its input was overwritten:\n got  %+v\n want %+v",
						name, held.what, held.got, held.want)
				}
			}
		}
		wg.Wait()
		// A caller writing into its own snapshot reaches nothing the engine holds.
		if ev := closed.Directions[ClientToServer].Evidence; len(ev) > 0 {
			ev[0].Value = "changed by the caller"
		}
		if again := f.Snapshot(); !reflect.DeepEqual(again, closedWant) {
			t.Fatalf("%s: writing into a returned snapshot changed the flow's own record", name)
		}
	}
}
