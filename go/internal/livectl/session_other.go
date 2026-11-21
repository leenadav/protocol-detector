//go:build !unix

package livectl

import "os/exec"

// ownSession: no Unix sessions on this platform (the release builds for Windows; live capture is Unix-only).
func ownSession(process *exec.Cmd) {}

// killGroup kills the capture worker process itself.
func killGroup(process *exec.Cmd) { _ = process.Process.Kill() }
