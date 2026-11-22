//go:build !unix

package jobs

import "os/exec"

// ownProcessGroup: without Unix process groups, cancellation kills the worker process itself (the release builds
// for Windows; the reference's job runner is Unix-only).
func ownProcessGroup(process *exec.Cmd) {
	process.Cancel = func() error { return process.Process.Kill() }
}
