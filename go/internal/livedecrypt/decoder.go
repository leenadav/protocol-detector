package livedecrypt

import (
	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
	"github.com/leenadav/protocol-detector/go/internal/keylogcap"
	"github.com/leenadav/protocol-detector/go/internal/live"
)

const snapshotProfile = "Live TLS 1.2/1.3 POC; incremental record authentication; capture quality provisional until stop."

// Decoder is LiveDecoder: it owns the pcap stream decoder and the decryptor; the monitor's tier owns the bytes.
type Decoder struct {
	Monitor   *live.Monitor
	keys      *decrypt.KeyProvider
	decryptor *keylogcap.Decryptor
	stream    *capture.Decoder
	Frames    int
	consumed  int
}

// NewDecoder builds the worker's monitor (64 connections, 16 KiB windows, every event, a retained tier of
// 256 KiB per direction) and its decoder.
func NewDecoder(pack *content.Pack, captureID string, emit func(live.Event)) (*Decoder, error) {
	monitor, err := live.NewMonitor(pack, live.Options{MaxConnections: MaxConnections, ByteLimit: 16384, IdleTimeout: 60, AllEvents: true,
		CRC32CByteLimit: 4096, Observation: "handshake", Checksums: "ignore"}, captureID, emit)
	if err != nil {
		return nil, err
	}
	tier := monitor.Retain(keylogcap.Budget{PerDirection: decrypt.MaxStream, Aggregate: 4 * 1024 * 1024, Connections: MaxConnections, Pending: 8192})
	keys := decrypt.NewKeyProvider()
	return &Decoder{Monitor: monitor, keys: keys, decryptor: keylogcap.NewDecryptor(pack, tier, keys), stream: capture.NewDecoder()}, nil
}

func budget(message string) error {
	return &decrypt.Error{Message: message, Code: decrypt.BudgetExhausted}
}

// Feed takes one chunk of the pcap stream at the clock value now.
func (d *Decoder) Feed(chunk []byte, now float64) error {
	d.consumed += len(chunk)
	if d.consumed > Limit {
		return budget("Live decryption reached its 2 MiB capture budget; restart for a new sample.")
	}
	records, err := d.stream.Feed(chunk)
	if err != nil {
		return err
	}
	d.Frames += len(records)
	if d.Frames > MaxFrames {
		return budget("Live decryption reached 20,000 frames.")
	}
	for _, record := range records {
		if err := d.Monitor.Accept(record, now); err != nil {
			return err
		}
	}
	return d.decryptor.Pump()
}

// Advance appends new key-log lines (if any) and does one bounded slice of decoding work.
func (d *Decoder) Advance(keylog string) error {
	if keylog != "" {
		if _, err := d.keys.Append(keylog); err != nil {
			return err
		}
	}
	if err := d.decryptor.Pump(); err != nil {
		return err
	}
	return d.decryptor.Work(WorkQuantum, 16)
}

// End finalizes every connection still tracked, exactly once, before the final report.
func (d *Decoder) End(reason string) error {
	if err := d.stream.End(); err != nil {
		return err
	}
	if err := d.Monitor.End(reason); err != nil {
		return err
	}
	if err := d.decryptor.Pump(); err != nil {
		return err
	}
	return d.decryptor.Work(1<<20, 1)
}

// Snapshot is a status read as JSON text: cached rows, no parsing and no cryptography.
func (d *Decoder) Snapshot() string { return d.decryptor.Report(d.Frames, 0, snapshotProfile) }

// Release ends the run's secret references.
func (d *Decoder) Release() { d.keys.Release() }
