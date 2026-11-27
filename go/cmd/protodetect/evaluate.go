package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/corpus"
)

const evaluateUsage = "usage: protodetect evaluate-corpus CORPUS [--write REPORT.md] [--json REPORT.json] [--min-accuracy FRACTION] [--max-wrong COUNT]"

// writeReport writes one report file. It opens the named file's directory as an os.Root, so the write
// cannot follow a symbolic link or a ".." out of the directory the operator named.
func writeReport(path string, data []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close() //nolint:errcheck // the write's own error is the one reported
	return root.WriteFile(filepath.Base(path), data, 0o600)
}

// runEvaluateCorpus scores the engine against an independently labelled corpus (D09, SR-67). Exit 0 when the
// thresholds hold, 1 when they do not, 2 for a refused corpus or bad arguments.
func runEvaluateCorpus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evaluate-corpus", flag.ContinueOnError)
	fs.SetOutput(stderr)
	write := fs.String("write", "", "write the Markdown report here")
	jsonOut := fs.String("json", "", "write the JSON report here")
	minAccuracy := fs.Float64("min-accuracy", -1, "exit 1 when family accuracy is below this fraction")
	maxWrong := fs.Int("max-wrong", -1, "exit 1 when wrong-family identifications exceed this count")
	var dir string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil || dir == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, evaluateUsage)
		return 2
	}
	pack, err := content.Embedded()
	if err != nil {
		fmt.Fprintln(stderr, "content error:", err)
		return 2
	}
	manifest, err := corpus.Load(dir)
	var report *corpus.Report
	if err == nil {
		report, err = corpus.Evaluate(manifest, pack)
	}
	var refused *corpus.Error
	if errors.As(err, &refused) {
		fmt.Fprintln(stdout, "corpus error:", refused.Message)
		return 2
	} else if err != nil {
		fmt.Fprintln(stderr, "corpus error:", err)
		return 2
	}
	text := corpus.Render(report)
	if *write != "" {
		if err := writeReport(*write, []byte(text)); err != nil {
			fmt.Fprintln(stderr, "write error:", err)
			return 2
		}
	}
	if *jsonOut != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = writeReport(*jsonOut, append(data, '\n'))
		}
		if err != nil {
			fmt.Fprintln(stderr, "write error:", err)
			return 2
		}
	}
	if *write == "" && *jsonOut == "" {
		fmt.Fprint(stdout, text)
	} else {
		fmt.Fprintln(stdout, corpus.IndependenceLine(report))
	}
	totals := report.Totals
	accuracy := 0.0
	if totals.FamilyAccuracy != nil {
		accuracy = *totals.FamilyAccuracy
	}
	if (*maxWrong >= 0 && totals.Wrong > *maxWrong) || (*minAccuracy >= 0 && accuracy < *minAccuracy) {
		fmt.Fprintf(stdout, "corpus evaluation FAILED thresholds: wrong %d accuracy %.1f%%\n", totals.Wrong, 100*accuracy)
		return 1
	}
	return 0
}
