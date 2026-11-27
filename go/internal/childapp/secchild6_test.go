package childapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// SEC-CHILD-6: the component's SHA-256 is pinned per release by lock.json, the built-in component refuses to
// load unless it is the lock's in-force release byte for byte, and the release number N may have many digits.

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func loadWith(t *testing.T, data, lock []byte) (*Set, error) {
	t.Helper()
	p := pack(t)
	return loadPinned(data, lock, Options{}, func(d []byte, o Options) (*Set, error) { return Load(d, p, o) })
}

func TestBuiltinComponentIsTheLockedRelease(t *testing.T) {
	l, err := ParseLock(embeddedLock)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Builtin(Options{})
	if err != nil {
		t.Fatal(err)
	}
	cur := l.Current()
	if s.Release.Version != cur.Version || s.Digest != cur.SHA256 || s.Digest != sha(EmbeddedBytes()) {
		t.Fatalf("built-in %s %s, locked %s %s", s.Release.Version, s.Digest, cur.Version, cur.SHA256)
	}
	if !l.Pinned(cur.Version, cur.SHA256) || l.Pinned(cur.Version, strings.Repeat("0", 64)) || l.Pinned("2099.01.1", cur.SHA256) {
		t.Fatal("Pinned does not answer by version and digest")
	}
	if _, err := Embedded(pack(t)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(EmbeddedLockBytes(), embeddedLock) {
		t.Fatal("EmbeddedLockBytes is not the built-in lock")
	}
}

// TestLockHistoryKeepsPublishedReleases pins the releases published before the lock existed (their bytes are
// those of commits e75e4a8, dadc6bd and bce8743): the history is append-only, so these entries never change.
func TestLockHistoryKeepsPublishedReleases(t *testing.T) {
	l, err := ParseLock(embeddedLock)
	if err != nil {
		t.Fatal(err)
	}
	published := []LockEntry{
		{"2026.11.0", "b0494abe884cd092ace09790439d2688197f24ed8c7994035c618951550544f3"},
		{"2026.11.1", "e5c63e57aec019af2091a2b960ddff35eaada005c260fa6958a9c237f56b0dc6"},
		{"2026.11.2", "8fcfa58fb0911186aa244d71e9d32c022a2e1c097c1f76835117c3ee5119a311"},
	}
	if len(l.Releases) < len(published) {
		t.Fatalf("lock has %d releases, %d were published", len(l.Releases), len(published))
	}
	for i, want := range published {
		if l.Releases[i] != want {
			t.Errorf("release %d is %+v, published %+v", i, l.Releases[i], want)
		}
	}
}

func TestBuiltinRefusesAnUnpinnedComponent(t *testing.T) {
	cur, _ := ParseLock(embeddedLock)
	version := cur.Current().Version
	edited := bytes.Replace(EmbeddedBytes(), []byte(`"review": "`), []byte(`"review": "edited `), 1)
	if bytes.Equal(edited, EmbeddedBytes()) {
		t.Fatal("the edit did not apply")
	}
	if _, err := loadWith(t, edited, embeddedLock); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("an edit without a new pin loaded: %v", err)
	}
	bumped := bytes.Replace(EmbeddedBytes(), []byte(`"version": "`+version+`"`), []byte(`"version": "2026.12.10"`), 1)
	if _, err := loadWith(t, bumped, embeddedLock); err == nil || !strings.Contains(err.Error(), "not the locked release") {
		t.Fatalf("a release bump without a pin loaded: %v", err)
	}
	// Pinned as the next release, the bumped file loads (multi-digit N included).
	lock := strings.Replace(string(embeddedLock), "\n ]", `,
  {"version": "2026.12.10", "sha256": "`+sha(bumped)+`"}
 ]`, 1)
	s, err := loadWith(t, bumped, []byte(lock))
	if err != nil || s.Release.Version != "2026.12.10" || s.Digest != sha(bumped) {
		t.Fatalf("a pinned release did not load: %v", err)
	}
	// An older pinned release is not the in-force one.
	if _, err := loadWith(t, EmbeddedBytes(), []byte(lock)); err == nil {
		t.Fatal("a superseded release loaded")
	}
	if _, err := loadWith(t, EmbeddedBytes(), []byte(`{"schema": 1, "releases": []}`)); err == nil {
		t.Fatal("an empty lock was accepted")
	}
}

func TestParseLockRefuses(t *testing.T) {
	d1, d2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	entry := func(v, d string) string { return `{"version": "` + v + `", "sha256": "` + d + `"}` }
	lock := func(entries ...string) []byte {
		return []byte(`{"schema": 1, "releases": [` + strings.Join(entries, ", ") + `]}`)
	}
	if _, err := ParseLock(lock(entry("2026.11.9", d1), entry("2026.11.10", d2))); err != nil {
		t.Fatalf("numeric order 9 < 10 refused: %v", err)
	}
	bad := map[string][]byte{
		"schema 2":           []byte(`{"schema": 2, "releases": [` + entry("2026.11.0", d1) + `]}`),
		"no releases":        lock(),
		"unknown key":        []byte(`{"schema": 1, "releases": [{"version": "2026.11.0", "sha256": "` + d1 + `", "x": 1}]}`),
		"repeated key":       []byte(`{"schema": 1, "releases": [{"version": "2026.11.0", "version": "2026.11.1", "sha256": "` + d1 + `"}]}`),
		"missing digest":     []byte(`{"schema": 1, "releases": [{"version": "2026.11.0"}]}`),
		"short digest":       lock(entry("2026.11.0", d1[:63])),
		"upper-case digest":  lock(entry("2026.11.0", strings.ToUpper(d1))),
		"bad version":        lock(entry("2026.13.0", d1)),
		"lexical order":      lock(entry("2026.11.10", d1), entry("2026.11.9", d2)),
		"repeated version":   lock(entry("2026.11.1", d1), entry("2026.11.1", d2)),
		"repeated digest":    lock(entry("2026.11.1", d1), entry("2026.11.2", d1)),
		"older year":         lock(entry("2026.11.1", d1), entry("2025.12.2", d2)),
		"trailing data":      append(lock(entry("2026.11.0", d1)), []byte(` {}`)...),
		"releases not list":  []byte(`{"schema": 1, "releases": {}}`),
		"version not string": []byte(`{"schema": 1, "releases": [{"version": 1, "sha256": "` + d1 + `"}]}`),
	}
	for name, data := range bad {
		if _, err := ParseLock(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReleaseNumberMayHaveManyDigits(t *testing.T) {
	for v, want := range map[string]bool{
		"2026.11.0": true, "2026.11.9": true, "2026.11.10": true, "2026.11.123456": true,
		"2026.11.1234567": false, "2026.11.01": false, "2026.11.00": false, "2026.11.": false, "2026.1.1": false,
		"2026.00.1": false, "2026.11.1a": false, "2026.11.-1": false, "26.11.1": false,
	} {
		if got := validVersion(v); got != want {
			t.Errorf("validVersion(%q) = %v, want %v", v, got, want)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"2026.11.9", "2026.11.10", -1}, {"2026.11.10", "2026.11.9", 1}, {"2026.12.1", "2027.01.0", -1}, {"2026.11.10", "2026.11.10", 0}} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	data := strings.Replace(child(`{"hosts": ["content.dropboxapi.com"], "methods": ["POST"]}`), `"2026.11.0"`, `"2026.11.10"`, 1)
	s, err := Load([]byte(data), pack(t), Options{})
	if err != nil || s.Release.Version != "2026.11.10" {
		t.Fatalf("release 2026.11.10 refused: %v", err)
	}
	if got := s.Classify(Request{Host: "content.dropboxapi.com", Method: "POST", Path: "/"}); got.Digest != sha([]byte(data)) || got.Release != "2026.11.10" {
		t.Fatalf("result names %s %s", got.Release, got.Digest)
	}
}
