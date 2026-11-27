package engine

import "sync/atomic"

// PRO-596: an identified observation labels each evidence row with its byte source and the parser's provenance
// ("wire:client_hello"). Both halves are engine constants (a closed vocabulary), so building the label afresh for
// every row of every flow only allocated the same few strings again: 11 allocations per TLS flow. sourceLabel
// returns one shared copy per pair instead.
//
// The cache is copy-on-write behind an atomic pointer: a hit is a lock-free load and a map lookup with no
// allocation, so concurrent flows never contend; a miss copies the map once per new pair. It is bounded by
// maxSourceLabels, past which a label is built as before, so it can never grow with traffic.

type sourcePair struct{ source, provenance string }

const maxSourceLabels = 256

var sourceLabels atomic.Pointer[map[sourcePair]string]

func init() { sourceLabels.Store(&map[sourcePair]string{}) }

func sourceLabel(source, provenance string) string {
	key := sourcePair{source, provenance}
	for {
		current := sourceLabels.Load()
		if label, ok := (*current)[key]; ok {
			return label
		}
		label := source + ":" + provenance
		if len(*current) >= maxSourceLabels {
			return label
		}
		next := make(map[sourcePair]string, len(*current)+1)
		for k, v := range *current {
			next[k] = v
		}
		next[key] = label
		if sourceLabels.CompareAndSwap(current, &next) {
			return label
		}
	}
}
