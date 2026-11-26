package keylogcap

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

func testOwner(t *testing.T) (*content.Pack, *coordinator) {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newCoordinator(pack, Budget{PerDirection: decrypt.MaxStream, Aggregate: 4 * 1024 * 1024, Connections: MaxConnections, Pending: 8192}, MaxConnections)
	if err != nil {
		t.Fatal(err)
	}
	return pack, owner
}

func feed(t *testing.T, owner *coordinator, frames [][]byte) {
	t.Helper()
	for i, f := range frames {
		packet, err := transport.Decode(f, 1, transport.Ignore)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.accept(packet.(*transport.TCP), 1700000000+float64(i)); err != nil {
			t.Fatal(err)
		}
	}
}

// SEC-KEY-1: a connection that failed at the capture level (a gap) never reached a decoder verdict; once it is
// closed it keeps its settled row and drops its decoder, and a later report neither rebuilds nor changes it.
func TestCaptureFailedConnectionDropsItsDecoder(t *testing.T) {
	pack, owner := testOwner(t)
	keys := decrypt.NewKeyProvider()
	defer keys.Release()
	client, server, keylog := exchange()
	if _, err := keys.Append(keylog); err != nil {
		t.Fatal(err)
	}
	frames := conversation(client, server)
	d := newDecryptor(pack, owner.Tier, keys)
	feed(t, owner, append(append([][]byte{}, frames[:3]...), frames[4:]...)) // one client segment missing
	if err := owner.end("Capture input EOF"); err != nil {
		t.Fatal(err)
	}
	if err := d.pump(); err != nil {
		t.Fatal(err)
	}
	if len(d.finished) != 1 {
		t.Fatalf("finished: %d", len(d.finished))
	}
	c := d.finished[0]
	if !c.failed || c.tls != nil || c.row == nil {
		t.Fatalf("failed=%v tls=%v row=%v: a capture-failed connection keeps its decoder", c.failed, c.tls != nil, c.row != nil)
	}
	first := d.report(0, 0, "")
	settled := c.row
	c.dirty = true // even if something marked it dirty, a released connection is not rebuilt
	if second := d.report(0, 0, ""); c.row != settled || !containsAll(second, `"status": "unavailable"`, `"reason_code": "gap"`, `"reason": "TCP capture has missing bytes."`) {
		t.Fatalf("row rebuilt or changed:\n%s\n%s", first, second)
	}
}

// SEC-KEY-1: every closed connection, decrypted ones included, releases its decoder after the row is settled.
func TestDecryptedClosedConnectionReleasesItsDecoder(t *testing.T) {
	pack, owner := testOwner(t)
	keys := decrypt.NewKeyProvider()
	defer keys.Release()
	client, server, keylog := exchange()
	if _, err := keys.Append(keylog); err != nil {
		t.Fatal(err)
	}
	d := newDecryptor(pack, owner.Tier, keys)
	feed(t, owner, conversation(client, server))
	if err := owner.end("Capture input EOF"); err != nil {
		t.Fatal(err)
	}
	if err := d.pump(); err != nil {
		t.Fatal(err)
	}
	if len(d.finished) != 1 || d.finished[0].tls != nil {
		t.Fatalf("finished %d, decoder kept", len(d.finished))
	}
	if text := d.report(0, 0, ""); !containsAll(text, `"status": "decrypted"`, `"authenticated_records": 5`) {
		t.Fatalf("report: %s", text)
	}
}

// SEC-KEY-1: the closed-connection window holds at most maxFinished, in close order, and the slot of the one
// it drops is cleared so the shared backing array does not keep that connection reachable.
func TestFinishedWindowIsBoundedAndForgetsTheOldest(t *testing.T) {
	pack, owner := testOwner(t)
	d := newDecryptor(pack, owner.Tier, decrypt.Index{})
	server := transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	closeOne := func(i int) {
		client := transport.Endpoint{Addr: "192.0.2.10", Port: uint16(1024 + i)}
		key := session.KeyOf(client, server)
		owner.pending = append(owner.pending, queued{event: event{kind: "open", key: key, client: client, server: server}},
			queued{event: event{kind: "close", key: key, reason: "test"}})
		if err := d.pump(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxFinished; i++ {
		closeOne(i)
	}
	window := d.finished
	if len(window) != maxFinished || window[0].client.Port != 1024 {
		t.Fatalf("window %d", len(window))
	}
	closeOne(maxFinished)
	if window[0] != nil {
		t.Error("the dropped connection is still reachable through the backing array")
	}
	if len(d.finished) != maxFinished || d.finished[0].client.Port != 1025 || d.finished[maxFinished-1].client.Port != uint16(1024+maxFinished) {
		t.Fatalf("window %d: %d..%d", len(d.finished), d.finished[0].client.Port, d.finished[len(d.finished)-1].client.Port)
	}
	if d.closedCount != maxFinished+1 || len(d.rows()) != maxFinished {
		t.Fatalf("closed %d rows %d", d.closedCount, len(d.rows()))
	}
}

// SEC-KEY-1: the key-log path publishes each analyzer record's generation and then drops the record, so a long
// capture retains no per-session record; tuple reuse still starts a new generation.
func TestKeyLogPathDropsPublishedAnalyzerRecords(t *testing.T) {
	_, owner := testOwner(t)
	client, server, _ := exchange()
	frames := conversation(client, server)
	again := [][]byte{frame(clientEnd, serverEnd, 500000, 2, nil), frame(serverEnd, clientEnd, 600000, 18, nil)}
	feed(t, owner, append(append([][]byte{}, frames...), again...))
	if owner.an.Sessions == 0 {
		t.Fatal("no session was finalized")
	}
	if len(owner.an.Records) != 0 || owner.records != 0 {
		t.Fatalf("records retained: %d (cursor %d)", len(owner.an.Records), owner.records)
	}
	if err := owner.end("Capture input EOF"); err != nil {
		t.Fatal(err)
	}
	items := owner.drain()
	generations := []int{}
	for _, e := range items {
		if e.kind == "open" {
			generations = append(generations, e.generation)
		}
	}
	if len(generations) != 2 || generations[0] != 0 || generations[1] != 1 {
		t.Fatalf("generations %v", generations)
	}
}

func containsAll(text string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(text, p) {
			return false
		}
	}
	return true
}
