package content

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

const fixturePath = "../../../migration/fixtures/content.json"

// The built-in pack must be the fixture, byte for byte (work item #16).
func TestEmbeddedPackEqualsTheFixture(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixture, packJSONBytes) {
		t.Fatalf("go/internal/content/pack.json (%d bytes) differs from %s (%d bytes); copy the fixture over it",
			len(packJSONBytes), fixturePath, len(fixture))
	}
	built, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(built, loaded) {
		t.Fatal("the built-in pack and the loaded fixture parse to different packs")
	}
	if built.Release.Version == "" || len(built.Applications) == 0 {
		t.Fatalf("built-in pack looks empty: %+v", built.Release)
	}
}

func TestEmbeddedBytesAreACopy(t *testing.T) {
	a := EmbeddedBytes()
	a[0] ^= 0xff
	if bytes.Equal(a, packJSONBytes) || !bytes.Equal(EmbeddedBytes(), packJSONBytes) {
		t.Fatal("EmbeddedBytes exposes the built-in bytes")
	}
}

// Host-supplied bytes get the same validation, including the stated digests.
func TestSuppliedPackIsValidatedAndItsStatedDigestsAreChecked(t *testing.T) {
	good := EmbeddedBytes()
	if _, err := ParseSupplied(good); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"empty":     nil,
		"oversize":  make([]byte, MaxPackBytes+1),
		"not json":  []byte("{"),
		"truncated": good[:len(good)/2],
		"no digest": bytes.Replace(good, []byte(`"digest"`), []byte(`"digesx"`), 1),
	} {
		if _, err := ParseSupplied(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Tampered content that keeps the stated digests is refused: the loader recomputes the application
	// component (migration/CONTENT-DIGEST.md). That is self-consistency; the pin is tested in pin_test.go.
	original, _ := Embedded()
	app := ""
	for name := range original.Applications {
		if app == "" || name < app {
			app = name
		}
	}
	tampered := bytes.Replace(good, []byte(`"`+app+`"`), []byte(`"`+app+`-x"`), 1)
	if bytes.Equal(tampered, good) {
		t.Fatal("could not build a tampered pack")
	}
	if _, err := ParseSupplied(tampered); err == nil {
		t.Fatal("a pack whose application table no longer matches its stated component was accepted")
	}
}
