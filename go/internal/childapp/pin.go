package childapp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

// The release-to-digest lock of the child-app component (SEC-CHILD-6). lock.json lists every published
// release of childapps.json, oldest first, with the SHA-256 of the exact file bytes; the history is append-only
// and its last entry pins the built-in file. The built-in component refuses to load unless its release and
// digest are that last entry, so a rule edit without a release bump and a new pin fails the build's tests and
// every Builtin call, and a verdict's child_digest names the bytes it was classified with.

//go:embed lock.json
var embeddedLock []byte

// LockEntry is one published release of the component.
type LockEntry struct {
	Version string
	SHA256  string
}

// Lock is the parsed, validated release history of the component.
type Lock struct {
	Releases []LockEntry
}

// EmbeddedLockBytes is a copy of the built-in lock file.
func EmbeddedLockBytes() []byte { return append([]byte(nil), embeddedLock...) }

// ParseLock decodes and validates a lock: schema 1, at least one release, each version YYYY.MM.N with releases
// in strictly increasing version order (numeric N), each digest 64 lower-case hex characters and no digest
// published twice (a release whose bytes did not change needs no new entry).
func ParseLock(data []byte) (*Lock, error) {
	top, err := object(data, []string{"schema", "releases"}, "schema", "releases")
	if err != nil {
		return nil, invalid("lock: %v", err)
	}
	if string(bytes.TrimSpace(top["schema"])) != "1" {
		return nil, invalid("lock: unsupported schema")
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(top["releases"], &raws); err != nil || len(raws) == 0 {
		return nil, invalid("lock: releases must be a non-empty list")
	}
	l := &Lock{}
	seen := map[string]bool{}
	for i, raw := range raws {
		doc, err := object(raw, []string{"version", "sha256"}, "version", "sha256")
		if err != nil {
			return nil, invalid("lock: release %d: %v", i, err)
		}
		var e LockEntry
		if e.Version, err = str(doc["version"]); err != nil || !validVersion(e.Version) {
			return nil, invalid("lock: release %d: version must be YYYY.MM.N", i)
		}
		if e.SHA256, err = str(doc["sha256"]); err != nil || !validDigest(e.SHA256) {
			return nil, invalid("lock: release %s: sha256 must be 64 lower-case hex characters", e.Version)
		}
		if i > 0 && compareVersions(l.Releases[i-1].Version, e.Version) >= 0 {
			return nil, invalid("lock: release %s does not follow %s", e.Version, l.Releases[i-1].Version)
		}
		if seen[e.SHA256] {
			return nil, invalid("lock: release %s repeats a published digest", e.Version)
		}
		seen[e.SHA256] = true
		l.Releases = append(l.Releases, e)
	}
	return l, nil
}

// Current is the last, in-force release of the lock.
func (l *Lock) Current() LockEntry { return l.Releases[len(l.Releases)-1] }

// Pinned reports whether version was published with digest.
func (l *Lock) Pinned(version, digest string) bool {
	for _, e := range l.Releases {
		if e.Version == version {
			return e.SHA256 == digest
		}
	}
	return false
}

// verifyCurrent refuses a set that is not the lock's in-force release byte for byte.
func (l *Lock) verifyCurrent(s *Set) error {
	cur := l.Current()
	if s.Release.Version != cur.Version {
		return invalid("component release %s is not the locked release %s (bump the release and pin it in lock.json)",
			s.Release.Version, cur.Version)
	}
	if s.Digest != cur.SHA256 {
		return invalid("component release %s has digest %s, locked %s (an edit needs a new release and pin)",
			s.Release.Version, s.Digest, cur.SHA256)
	}
	return nil
}

// loadPinned loads the built-in component and checks it against the built-in lock.
func loadPinned(data, lock []byte, opts Options, load func([]byte, Options) (*Set, error)) (*Set, error) {
	l, err := ParseLock(lock)
	if err != nil {
		return nil, err
	}
	s, err := load(data, opts)
	if err != nil {
		return nil, err
	}
	if err := l.verifyCurrent(s); err != nil {
		return nil, err
	}
	return s, nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

// compareVersions orders two valid YYYY.MM.N versions numerically.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range pa {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
