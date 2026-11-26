package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/leenadav/protocol-detector/go/internal/serve"
)

const serveUsage = "usage: protodetect serve [--port N] [--root PRESENTATION_DIR] [--python INTERPRETER]"

// runServe is presentation/server.py's service: the dashboard and its API on 127.0.0.1 (contracts C14, C15).
// --root is the presentation directory (default: the checkout's, beside go/bin). --python is accepted and checked
// as before but no longer used: since PRO-401 the demo capture, the decryption showcase and the catalog are the
// service's own, and no interpreter is run.
func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	port, root, python := 8765, "", "python3"
	pythonSet := false
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			fmt.Fprintln(stderr, serveUsage)
			return 2
		}
		value := args[i+1]
		switch args[i] {
		case "--port":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 65535 {
				fmt.Fprintln(stderr, serveUsage)
				return 2
			}
			port = n
		case "--root":
			root = value
		case "--python":
			python, pythonSet = value, true
		default:
			fmt.Fprintln(stderr, serveUsage)
			return 2
		}
		i++
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "protodetect serve: cannot locate its own binary")
		return 1
	}
	if root == "" {
		root = filepath.Join(filepath.Dir(self), "..", "..", "presentation")
	}
	if _, err := os.Stat(filepath.Join(root, "web", "index.html")); err != nil {
		fmt.Fprintln(stderr, "protodetect serve: no presentation directory at "+root+" (use --root)")
		return 2
	}
	if python != "" {
		if resolved, err := exec.LookPath(python); err == nil {
			python = resolved
		} else if pythonSet {
			fmt.Fprintln(stderr, "protodetect serve: interpreter not found: "+python)
			return 2
		} else {
			python = ""
		}
	}
	server, err := serve.New(root, python, self)
	if err != nil {
		fmt.Fprintln(stderr, "protodetect serve:", err)
		return 1
	}
	bound, err := server.Listen(port)
	if err != nil {
		fmt.Fprintln(stderr, "protodetect serve:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Protocol Observatory: http://127.0.0.1:%d\n", bound)
	if f, ok := stdout.(*os.File); ok {
		_ = f.Sync()
	}
	go server.Serve()
	// SIGTERM (the launcher's terminate()) ends the service as SIGINT does: the live run's worker, which runs in
	// its own session, is stopped and the job runner shut down before the process exits.
	stop, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer cancel()
	<-stop.Done()
	server.Close()
	return 0
}

func runServeWorker(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "analyze" {
		return serve.AnalyzeWorker(stdin, stdout)
	}
	if len(args) == 1 && args[0] == "decrypt" {
		return serve.DecryptWorker(stdin, stdout)
	}
	if len(args) == 1 && args[0] == "decrypt-demo" {
		return serve.DecryptDemoWorker(stdout)
	}
	fmt.Fprintln(stderr, "usage: protodetect serve-worker analyze|decrypt|decrypt-demo < REQUEST")
	return 2
}
