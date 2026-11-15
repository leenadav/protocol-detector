// Command protodetect is the Go replay and diagnostic CLI.
//
//	protodetect version
//	protodetect cases  --file migration/fixtures/cases.json           validate and count the differential cases
//	protodetect replay --cases migration/fixtures/cases.json --out go-results.json
//
// replay writes the Go backend's results for migration/parity/compare.py --results. Cases the backend
// cannot answer are written as {"unsupported": reason}; the comparator never counts them as matches.
// Capture files (pcap/pcapng) are not read yet; the families the backend identifies are listed by
// `protodetect version`.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/bench"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/parity"
	"github.com/leenadav/protocol-detector/go/internal/replay"
)

const version = "0.0.0-m4"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: protodetect version | cases --file PATH | replay --cases PATH --out PATH")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "version":
		fmt.Printf("protodetect %s (go backend; experimental families: %s; no production use)\n", version, strings.Join(engine.Families, ", "))
		return 0
	case "cases":
		fs := flag.NewFlagSet("cases", flag.ContinueOnError)
		file := fs.String("file", "migration/fixtures/cases.json", "the differential cases file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		doc, err := parity.Load(ctx, *file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cases:", err)
			return 1
		}
		counts := map[string]int{}
		for _, c := range doc.Cases {
			counts[c.Kind]++
		}
		names := make([]string, 0, len(counts))
		for k := range counts {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Printf("cases ok: %d total", len(doc.Cases))
		for _, k := range names {
			fmt.Printf(", %s %d", k, counts[k])
		}
		fmt.Println()
		return 0
	case "replay":
		fs := flag.NewFlagSet("replay", flag.ContinueOnError)
		cases := fs.String("cases", "migration/fixtures/cases.json", "the differential cases file")
		out := fs.String("out", "", "where to write the results (required)")
		if err := fs.Parse(args[1:]); err != nil || *out == "" {
			fmt.Fprintln(os.Stderr, "replay: --out is required")
			return 2
		}
		doc, err := parity.Load(ctx, *cases)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		results, err := replay.Run(ctx, doc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		data, _ := json.MarshalIndent(results, "", " ")
		if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			return 1
		}
		unsupported := 0
		for _, raw := range results.Results {
			var m replay.Unsupported
			if json.Unmarshal(raw, &m) == nil && m.Unsupported != "" {
				unsupported++
			}
		}
		fmt.Printf("replay: %d cases, %d answered, %d unsupported -> %s\n", len(doc.Cases), len(doc.Cases)-unsupported, unsupported, *out)
		return 0
	case "bench":
		fs := flag.NewFlagSet("bench", flag.ContinueOnError)
		workloads := fs.String("workloads", "migration/benchmarks/workloads.json", "shared benchmark workloads")
		iterations := fs.Int("iterations", 300, "timed flows per round")
		rounds := fs.Int("rounds", 5, "rounds")
		warmup := fs.Int("warmup", 50, "untimed flows per workload")
		only := fs.String("only", "", "run one workload")
		if err := fs.Parse(args[1:]); err != nil || *iterations < 10 || *iterations > 10000 || *rounds < 1 || *rounds > 20 {
			fmt.Fprintln(os.Stderr, "bench: use 10..10000 iterations and 1..20 rounds")
			return 2
		}
		list, err := bench.Load(*workloads)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bench:", err)
			return 1
		}
		if *only != "" {
			var kept []bench.Workload
			for _, w := range list {
				if w.Name == *only {
					kept = append(kept, w)
				}
			}
			list = kept
		}
		results, err := bench.Run(list, *iterations, *rounds, *warmup)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bench:", err)
			return 1
		}
		doc := map[string]interface{}{"backend": "go", "go": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
			"iterations_per_round": *iterations, "rounds": *rounds, "warmup": *warmup,
			"scope": "Feed loop including events; excludes Inspector construction, capture, TCP, output and concurrency", "cases": results}
		data, _ := json.MarshalIndent(doc, "", " ")
		fmt.Println(string(data))
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown command", args[0])
	return 2
}
