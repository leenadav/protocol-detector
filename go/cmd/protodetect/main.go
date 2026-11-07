// Command protodetect is the Go replay and diagnostic CLI (migration M2: skeleton).
//
//	protodetect version
//	protodetect cases --file migration/fixtures/cases.json   validate and count the differential cases
//
// Replay (`protodetect replay`) arrives with the M4 vertical slice; until then the command never
// claims a detection capability.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"

	"github.com/leenadav/protocol-detector/go/internal/parity"
)

const version = "0.0.0-m2"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: protodetect version | cases --file PATH")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "version":
		fmt.Println("protodetect " + version + " (go backend: no detection capability yet)")
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
	}
	fmt.Fprintln(os.Stderr, "unknown command", args[0])
	return 2
}
