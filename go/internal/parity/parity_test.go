package parity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

const casesPath = "../../../migration/fixtures/cases.json"

func TestCommittedCasesDecodeAndReEncodeIdentically(t *testing.T) {
	doc, err := Load(context.Background(), casesPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 1000 {
		t.Fatalf("only %d cases", len(doc.Cases))
	}
	kinds := map[string]int{}
	for i := range doc.Cases {
		c := &doc.Cases[i]
		kinds[c.Kind]++
		var typed interface{}
		switch c.Kind {
		case "stream":
			e, err := c.Stream()
			if err != nil {
				t.Fatal(c.ID, err)
			}
			typed = e
		case "datagram":
			e, err := c.Datagram()
			if err != nil {
				t.Fatal(c.ID, err)
			}
			typed = e
		default:
			continue
		}
		// The typed Go contracts must re-encode to exactly the Python expectation (structural equality).
		out, err := json.Marshal(typed)
		if err != nil {
			t.Fatal(c.ID, err)
		}
		var want, got interface{}
		json.Unmarshal(c.Expected, &want)
		json.Unmarshal(out, &got)
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s re-encodes differently:\n%s\n%s", c.ID, c.Expected, out)
		}
	}
	if kinds["stream"] == 0 || kinds["datagram"] == 0 || kinds["session"] == 0 {
		t.Fatalf("kinds %v", kinds)
	}
}

func TestLoadHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Load(ctx, casesPath)
	if !errors.Is(err, errs.Cancelled.Err()) {
		t.Fatalf("cancelled load returned %v", err)
	}
}

func TestLoadFailsClosed(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(text), 0o600)
		return p
	}
	if _, err := Load(context.Background(), filepath.Join(dir, "missing.json")); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), write("schema.json", `{"schema": 2, "cases": []}`)); !errors.Is(err, errs.Unsupported.Err()) {
		t.Fatal(err)
	}
	dup := `{"schema":1,"cases":[{"id":"a","kind":"session","expected":{}},{"id":"a","kind":"session","expected":{}}]}`
	if _, err := Load(context.Background(), write("dup.json", dup)); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal(err)
	}
	bad := `{"schema":1,"cases":[{"id":"a","kind":"stream","expected":{"events":[],"final":{"status":"maybe"},"metrics":{}}}]}`
	if _, err := Load(context.Background(), write("bad.json", bad)); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), write("kind.json", `{"schema":1,"cases":[{"id":"a","kind":"other","expected":{}}]}`)); !errors.Is(err, errs.Unsupported.Err()) {
		t.Fatal(err)
	}
}
