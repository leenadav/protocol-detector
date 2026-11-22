package content

import (
	"bytes"
	"os"
	"testing"
)

func TestEmbeddedPackIsTheSharedPack(t *testing.T) {
	shared, err := os.ReadFile("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, embedded) {
		t.Fatal("go/internal/content/pack.json differs from migration/fixtures/content.json; copy the exported pack (make content-pack)")
	}
	if _, err := Embedded(); err != nil {
		t.Fatal(err)
	}
}
