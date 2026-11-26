package decrypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// tls13Material is every derived secret and IV the directions hold, and the client random.
func tls13Material(c *Connection) [][]byte {
	out := [][]byte{c.random}
	for _, dir := range c.dirs {
		d := dir.(*tls13Direction)
		for _, b := range d.secrets {
			out = append(out, b)
		}
		for _, b := range d.ivs {
			out = append(out, b)
		}
	}
	return out
}

// SEC-KEY-1: a terminal TLS 1.3 connection zeroes its derived traffic secrets, IVs and client random before
// dropping them, on both the complete and the failed path, and never writes the KeyProvider's own secrets.
func TestReleaseZeroesTLS13SecretsButNotTheKeyProvider(t *testing.T) {
	s := tls13Session(0x1301)
	random := bytes.Repeat([]byte{0x5a}, 32)
	tampered := append([]byte{}, s.server...)
	tampered[len(tampered)-3] ^= 1
	for _, tc := range []struct {
		name, state string
		server      []byte
	}{{"complete", StateComplete, s.server}, {"failed", StateFailed, tampered}} {
		keys := NewKeyProvider()
		if _, err := keys.Append(s.keylog); err != nil {
			t.Fatal(err)
		}
		conn := NewConnection(keys, "c", "s")
		conn.Feed("c", s.client)
		conn.Feed("s", tc.server)
		conn.Advance(1) // directions installed, records still queued
		if conn.dirs[0] == nil {
			t.Fatalf("%s: directions not started (%s %s)", tc.name, conn.State, conn.Reason)
		}
		material := tls13Material(conn)
		for conn.HasWork() {
			conn.Advance(64)
		}
		if conn.Finish() != tc.state {
			t.Fatalf("%s: %s %s", tc.name, conn.State, conn.Reason)
		}
		for i, b := range material {
			if len(b) == 0 || !allZero(b) {
				t.Errorf("%s: material %d not zeroed: %x", tc.name, i, b)
			}
		}
		for i, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
			got, err := keys.Lookup(label, random)
			if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{byte(i + 1)}, 32)) {
				t.Errorf("%s: KeyProvider secret %s changed: %x %v", tc.name, label, got, err)
			}
		}
		keys.Release()
	}
}

// SEC-KEY-1: TLS 1.2 zeroes the derived key block (both directions' keys and IVs), not the master secret the
// KeyProvider indexes; Discard (a capture-level failure) zeroes the same material and changes no state.
func TestReleaseZeroesTLS12KeyBlockAndDiscardKeepsState(t *testing.T) {
	random := bytes.Repeat([]byte{0x33}, 32)
	master := bytes.Repeat([]byte{0x07}, 48)
	hello := append(append([]byte{3, 3}, random...), 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
	sh := append(append([]byte{3, 3}, bytes.Repeat([]byte{0x44}, 32)...), 0, 0xc0, 0x2f, 0, 0, 0)
	for _, end := range []string{"fail", "discard"} {
		keys := NewKeyProvider()
		if _, err := keys.Append("CLIENT_RANDOM " + hex.EncodeToString(random) + " " + hex.EncodeToString(master) + "\n"); err != nil {
			t.Fatal(err)
		}
		conn := NewConnection(keys, "c", "s")
		conn.Feed("c", plainRecord(22, handshake(1, hello)))
		conn.Feed("s", plainRecord(22, handshake(2, sh)))
		conn.Advance(64)
		if conn.Version != "TLS 1.2" || conn.dirs[0] == nil {
			t.Fatalf("%s: TLS 1.2 directions not started: %s %s", end, conn.State, conn.Reason)
		}
		block, clientRandom := conn.dirs[0].(*tls12Direction).block, conn.random
		if conn.dirs[1].(*tls12Direction).block == nil || len(block) != 2*16+8 {
			t.Fatalf("%s: key block not kept: %d", end, len(block))
		}
		before := conn.Metadata()
		if end == "fail" {
			conn.Fail("TCP capture has missing bytes.", "gap")
		} else {
			conn.Discard()
			if after := conn.Metadata(); after["state"] != before["state"] || after["version"] != "TLS 1.2" || conn.Reason != "" {
				t.Errorf("discard changed state: %v -> %v", before, after)
			}
		}
		if !allZero(block) || !allZero(clientRandom) || conn.dirs != [2]direction{} || conn.random != nil || conn.keys != nil {
			t.Errorf("%s: TLS 1.2 key material retained: block %x random %x", end, block, clientRandom)
		}
		if got, err := keys.Lookup("CLIENT_RANDOM", random); err != nil || !bytes.Equal(got, master) {
			t.Errorf("%s: KeyProvider master secret changed: %x %v", end, got, err)
		}
		keys.Release()
	}
}
