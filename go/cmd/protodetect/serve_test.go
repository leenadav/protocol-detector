package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// PRO-402: the service selects no interpreter. --python is no longer an option, and the usage does not offer it.
func TestServeHasNoPythonOption(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runServe(context.Background(), []string{"--python", "python3"}, &stdout, &stderr); code != 2 {
		t.Fatalf("serve --python: exit %d, want the usage error 2", code)
	}
	if strings.Contains(stderr.String(), "python") || !strings.Contains(stderr.String(), "usage: protodetect serve") {
		t.Fatalf("serve usage: %q", stderr.String())
	}
}
