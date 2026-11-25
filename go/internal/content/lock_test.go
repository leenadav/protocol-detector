package content

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// lock.json is the append-only ledger of every published content release (tools/content_pack.py, PRO-411). The
// tests read the current release's pins from its last entry, so a batch added with the tool needs no Go edit,
// while the Go loader still has to reproduce, independently of the tool, every digest the ledger records.
type lockEntry struct {
	Version     string            `json:"version"`
	Digest      string            `json:"digest"`
	Released    string            `json:"released"`
	Reviewed    string            `json:"reviewed"`
	Components  map[string]string `json:"components"`
	HostEntries int               `json:"host_entries"`
	PackDigest  *string           `json:"pack_digest"`
	Note        string            `json:"note"`
	Review      string            `json:"review"`
}

func loadLock() ([]lockEntry, error) {
	data, err := os.ReadFile("lock.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Schema   int         `json:"schema"`
		Releases []lockEntry `json:"releases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Schema != 1 || len(doc.Releases) == 0 {
		return nil, fmt.Errorf("lock.json: schema %d with %d releases", doc.Schema, len(doc.Releases))
	}
	return doc.Releases, nil
}

func readLock(t *testing.T) []lockEntry {
	t.Helper()
	lock, err := loadLock()
	if err != nil {
		t.Fatal(err)
	}
	return lock
}

// currentPins are the version, release digest and pack digest of the committed pack, as the lock records them.
func currentPins() (version, release, pack string) {
	lock, err := loadLock()
	if err != nil {
		panic(err)
	}
	last := lock[len(lock)-1]
	if last.PackDigest == nil {
		panic("lock.json: the current release has no pack_digest")
	}
	return last.Version, last.Digest, *last.PackDigest
}
