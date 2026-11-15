package analyzer

import (
	"reflect"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// continuationSummary keeps only continuation-sourced summary fields, per direction, with the message count as a
// number and the end reason under "ended" (continuation.continuation_summary).
func TestContinuationSummaryPerDirection(t *testing.T) {
	client := &contracts.Observation{Evidence: []contracts.Evidence{
		{Field: "http_method", Value: "GET", Source: "wire:request_line"},
		{Field: "http_messages", Value: "3", Source: "wire:continuation"},
		{Field: "http_methods", Value: "POST", Source: "wire:continuation"},
		{Field: "continuation", Value: "budget", Source: "wire:continuation"},
		{Field: "http_messages", Value: "9", Source: "wire:headers"}, // not a continuation source
	}}
	server := &contracts.Observation{Evidence: []contracts.Evidence{{Field: "http_status", Value: "200", Source: "wire:status_line"}}}
	got := continuationSummary(client, server, nil)
	want := map[string]interface{}{"client": map[string]interface{}{"http_messages": 3, "http_methods": "POST", "ended": "budget"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary %v, want %v", got, want)
	}
	if len(continuationSummary(nil, server, nil)) != 0 {
		t.Fatal("summary without continuation evidence")
	}
}
