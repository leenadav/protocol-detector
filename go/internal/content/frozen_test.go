package content

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// The frozen copy of release FrozenVersion (PRO-428) is that release's content, not the current pack with its
// version string changed: its pack digest, release digest, components and host-entry count are the lock's entry for
// FrozenVersion, its history lists exactly the releases before it, each as the lock records it, and a later
// release keeps FrozenVersion's release block and server-name catalog in history.json unchanged (C11).
func TestFrozenReleaseIsTheLockedRelease(t *testing.T) {
	packData, err := os.ReadFile(FrozenPackFile)
	if err != nil {
		t.Fatal(err)
	}
	historyData, err := os.ReadFile(FrozenHistoryFile)
	if err != nil {
		t.Fatal(err)
	}
	lock := readLock(t)
	index := -1
	for k, entry := range lock {
		if entry.Version == FrozenVersion {
			index = k
		}
	}
	if index < 0 {
		t.Fatalf("lock.json has no entry for the frozen release %s", FrozenVersion)
	}
	entry := lock[index]
	if entry.PackDigest == nil {
		t.Fatalf("lock.json entry %s has no pack_digest", FrozenVersion)
	}
	pack, err := Parse(packData)
	if err != nil {
		t.Fatal(err)
	}
	digests, err := ComputeDigests(packData)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Release.Version != FrozenVersion || digests.Release != entry.Digest || digests.Pack != *entry.PackDigest {
		t.Fatalf("frozen pack is release %s digest %s pack digest %s; lock.json %s: %s, %s",
			pack.Release.Version, digests.Release, digests.Pack, FrozenVersion, entry.Digest, *entry.PackDigest)
	}
	for name, want := range entry.Components {
		if digests.Components[name] != want {
			t.Errorf("frozen pack component %s: %s, lock.json %s", name, digests.Components[name], want)
		}
	}
	if got := len(pack.AppDomains); got != entry.HostEntries {
		t.Errorf("frozen pack has %d host entries, lock.json %d", got, entry.HostEntries)
	}

	var history struct {
		Current  string                     `json:"current"`
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(historyData, &history); err != nil {
		t.Fatal(err)
	}
	if history.Current != FrozenVersion {
		t.Fatalf("frozen history's current release is %s, want %s", history.Current, FrozenVersion)
	}
	releases := releasesOf(historyData)
	if len(releases) != index+1 {
		t.Fatalf("frozen history runs %v, lock.json has %d releases up to %s", releases, index+1, FrozenVersion)
	}
	for k, v := range releases {
		if lock[k].Version != v {
			t.Fatalf("frozen history release %d is %s, lock.json %s", k, v, lock[k].Version)
		}
	}

	// The releases before FrozenVersion are the same bytes in the current history (it is append-only), and if a
	// later release is current, FrozenVersion's own block is in the current history as the frozen pack states it.
	var current struct {
		Current  string                     `json:"current"`
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(embeddedHistoryCurrent(t), &current); err != nil {
		t.Fatal(err)
	}
	for v, block := range history.Releases {
		if !bytes.Equal(compact(t, block), compact(t, current.Releases[v])) {
			t.Errorf("release %s differs between the frozen history and history.json", v)
		}
	}
	if current.Current != FrozenVersion {
		block, ok := current.Releases[FrozenVersion]
		if !ok {
			t.Fatalf("history.json (current %s) has no block for %s", current.Current, FrozenVersion)
		}
		var frozenPack map[string]json.RawMessage
		if err := json.Unmarshal(packData, &frozenPack); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(map[string]json.RawMessage{"release": frozenPack["release"], "host_catalog": frozenPack["host_catalog"]})
		if !bytes.Equal(compact(t, want), compact(t, block)) {
			t.Errorf("history.json's block for %s is not the frozen pack's release and server-name catalog", FrozenVersion)
		}
	} else if !bytes.Equal(packData, readFile(t, "pack.json")) || !bytes.Equal(historyData, readFile(t, "history.json")) {
		t.Errorf("%s is still the current release, so the frozen copies must equal pack.json and history.json", FrozenVersion)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// embeddedHistoryCurrent is history.json as committed (not the embedded copy, which is the frozen one in a
// frozencontent build).
func embeddedHistoryCurrent(t *testing.T) []byte { return readFile(t, "history.json") }

func compact(t *testing.T, raw []byte) []byte {
	t.Helper()
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(value) // object keys sorted, insignificant layout dropped
	return out
}
