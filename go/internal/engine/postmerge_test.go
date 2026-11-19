package engine

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"strconv"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Post-merge detection items (migration/POST-MERGE-BACKLOG.md), prepared before the merge (2026-11-19). Each test
// asserts the behaviour the item asks for. While today's behaviour persists it is skipped with the item's reason;
// once the Go fix makes it pass, pending fails, so the marker is removed and the test becomes a plain assertion.
// The reproducers are synthetic: no captured bytes (AGENTS.md). Nothing here changes detection code.

func pendingItem(t *testing.T, item string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now behaves as POST-MERGE-BACKLOG.md asks: remove pending() and assert it plainly", item)
	}
	t.Skipf("%s (migration/POST-MERGE-BACKLOG.md): post-merge, Go-only fix; today %s", item, today)
}

func inspectDatagram(t *testing.T, payload string) contracts.Observation {
	t.Helper()
	data, err := hex.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDatagram(contracts.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	o, err := d.Inspect(data, "")
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// PM-1 and PM-2(a) are flow-level under the decided UDP flow rule (first datagram per direction, two agreeing
// datagrams for CoAP and OpenVPN): go/internal/analyzer/postmerge_udp_test.go.

// PM-2(b): a random datagram that the CoAP first-byte probe selected and the profile then refused (F-ADV-1's
// reproducer) is unknown with code profile-unsupported, blaming CoAP; the D09 run saw 1,736 such UDP sessions. The
// item asks for no-dispatch: no supported structure was there.
func TestPM2_RefusedWeakProbeIsNoDispatch(t *testing.T) {
	o := inspectDatagram(t, "655085b84e0ec69b50164b0c53833c26")
	explained := appid.Explain(&o, appid.DirectionFacts{})
	code, _ := explained["code"].(string)
	pendingItem(t, "PM-2(b)", code == "no-dispatch", "the code is "+code+" ("+o.Reason+")")
}

// PM-6: gQUIC (pre-RFC 9000) packets, a Q043 public header and a Q046 long header, end as no-dispatch today, like
// arbitrary bytes. The item asks for an honest reason that names QUIC (a version outside the profile), whether or
// not a gQUIC profile is added.
func TestPM6_GoogleQUICIsReportedAsQUICOutsideTheProfile(t *testing.T) {
	q043 := "0d010203040506070851303433019a687f9bff49" + strings.Repeat("00", 56)
	q046 := "c35130343650010203040506070800000001" + strings.Repeat("9e", 60)
	named := 0
	for _, p := range []string{q043, q046} {
		o := inspectDatagram(t, p)
		if o.Status == contracts.Identified || strings.Contains(o.Reason, "QUIC") {
			named++
		}
	}
	pendingItem(t, "PM-6", named == 2, strconv.Itoa(named)+" of 2 gQUIC packets name QUIC")
}

// PM-8: Telegram MTProto over TCP (research/protocol/telegram-mtproto.md), a new client-direction profile, post-merge
// and Go-only. The positive vectors are the spec's P1 to P5 and are pending; the negatives must never identify,
// today or after, and are asserted plainly. P5's CRC is CRC-32/ISO-HDLC (Go's crc32.ChecksumIEEE, zlib's crc32)
// written little-endian, as MadelineProto's Full transport computes it (crc32b with the digest reversed); Telegram's
// transport page names only "CRC32", and current tdlib no longer implements the Full transport.
func mtprotoFinal(t *testing.T, payload string) contracts.Observation {
	t.Helper()
	data, err := hex.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	in, err := New(contracts.DefaultConfig(), "")
	if err != nil {
		t.Fatal(err)
	}
	events := append(in.Feed(data), in.End("fin")...)
	if len(events) == 0 {
		t.Fatalf("no event for %s", payload)
	}
	return events[len(events)-1].Observation
}

func TestPM8_TelegramMTProtoVectors(t *testing.T) {
	full := "1c00000000000000000102030405060708090a0b0c0d0e0f21bed445"
	b, _ := hex.DecodeString(full)
	if crc := crc32.ChecksumIEEE(b[:24]); binary.LittleEndian.Uint32(b[24:]) != crc {
		t.Fatalf("P5 CRC: computed %08x, the vector carries %x", crc, b[24:])
	}
	for name, payload := range map[string]string{
		"N1 CRC mismatch":             full[:len(full)-2] + "44",
		"N3 length 0x7fffffff":        "eeeeeeeeffffff7f" + strings.Repeat("00", 16),
		"N4 abridged, 3 bytes, end":   "ef02000102",
		"N5 obfuscated-like 64 bytes": "a1b2c3d4e5f60718" + strings.Repeat("5a", 56),
		"N6 abridged long header":     "ef7fffff00" + strings.Repeat("01", 8),
	} {
		o := mtprotoFinal(t, payload)
		if strings.HasPrefix(deref(o.ApplicationProtocol), "telegram") {
			t.Errorf("%s: identified as Telegram: %+v", name, o)
		}
	}
	positives := map[string]string{
		"P1 abridged":            "ef020001020304050607",
		"P2 abridged long":       "ef7f800000" + strings.Repeat("ab", 512),
		"P3 intermediate":        "eeeeeeee10000000000102030405060708090a0b0c0d0e0f",
		"P4 padded intermediate": "dddddddd13000000000102030405060708090a0b0c0d0e0faabbcc",
		"P5 full":                full,
	}
	identified := 0
	for _, payload := range positives {
		if strings.HasPrefix(deref(mtprotoFinal(t, payload).ApplicationProtocol), "telegram") {
			identified++
		}
	}
	pendingItem(t, "PM-8", identified == len(positives), strconv.Itoa(identified)+" of 5 MTProto vectors are identified (no profile yet)")
}
