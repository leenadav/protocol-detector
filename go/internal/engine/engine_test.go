package engine

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

func TestInputBufferIsNotRetainedByTheInspector(t *testing.T) {
	in, err := New(contracts.DefaultConfig(), "")
	if err != nil {
		t.Fatal(err)
	}
	buf := []byte("GET /a HTTP/1.1\r\nHost: a.example\r\n")
	in.Feed(buf)
	for i := range buf {
		buf[i] = 'z'
	}
	events := in.Feed([]byte("\r\n"))
	if len(events) != 1 || events[0].Observation.Status != contracts.Identified || *events[0].Observation.Hostname != "a.example" {
		t.Fatalf("identification after the caller reused its buffer: %+v", events)
	}
}

func TestHintSelectsButNeverEstablishes(t *testing.T) {
	in, _ := New(contracts.DefaultConfig(), "dns")
	events := in.Feed([]byte("GET / HTTP/1.1\r\n\r\n"))
	events = append(events, in.End("fin")...)
	if len(events) != 1 || events[0].Observation.Status != contracts.Incomplete {
		t.Fatalf("a dns hint on HTTP bytes: %+v", events)
	}
	in2, _ := New(contracts.DefaultConfig(), "tls")
	if ev := in2.Feed([]byte("GET / HTTP/1.1\r\n\r\n")); len(ev) != 1 || ev[0].Observation.Status != contracts.Malformed {
		t.Fatalf("a tls hint on HTTP bytes: %+v", ev)
	}
	if _, err := New(contracts.DefaultConfig(), "mqtt"); err == nil {
		t.Fatal("unported hint accepted")
	}
}

func TestOptionsTheBackendLacksAreRefusedUpFront(t *testing.T) {
	cfg := contracts.DefaultConfig()
	cfg.Heuristics = true
	if _, err := New(cfg, ""); err == nil {
		t.Fatal("heuristics accepted")
	}
	cfg = contracts.DefaultConfig()
	cfg.Fingerprints = true
	in, _ := New(cfg, "")
	in.Feed([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01})
	if in.NotPorted == nil {
		t.Fatal("fingerprints on TLS not reported as unsupported")
	}
}

func FuzzInspectorNeverPanics(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), uint8(3))
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x2a, 0x01}, uint8(1))
	f.Add([]byte{0x00, 0x1d, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01}, uint8(7))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		cfg := contracts.DefaultConfig()
		cfg.MaxBytes = 4096
		in, err := New(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		step := int(chunk%16) + 1
		total := 0
		for i := 0; i < len(data); i += step {
			end := i + step
			if end > len(data) {
				end = len(data)
			}
			total += len(in.Feed(data[i:end]))
			if in.NotPorted != nil {
				return
			}
		}
		in.End("fin")
		if in.Metrics.BytesInspected > cfg.MaxBytes || in.Metrics.BytesReceived != len(data) {
			t.Fatalf("metrics out of bounds: %+v", in.Metrics)
		}
		if !in.terminal && in.Observation.Status != contracts.Detecting {
			t.Fatal("non-terminal inspector with a decided observation")
		}
		d, _ := NewDatagram(cfg)
		d.Inspect(data, "")
	})
}
