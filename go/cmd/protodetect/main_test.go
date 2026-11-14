package main

import "testing"

func TestCommands(t *testing.T) {
	if run(nil) != 2 || run([]string{"nope"}) != 2 || run([]string{"version"}) != 0 {
		t.Fatal("usage handling")
	}
	if run([]string{"cases", "--file", "../../../migration/fixtures/cases.json"}) != 0 {
		t.Fatal("committed cases rejected")
	}
	if run([]string{"cases", "--file", "/nonexistent/cases.json"}) != 1 {
		t.Fatal("missing file accepted")
	}
}
