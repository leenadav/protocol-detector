//go:build unix

package livectl

import (
	"os/exec"
	"syscall"
)

// ownSession starts the capture worker in its own session, so its process group can be killed as a whole.
func ownSession(process *exec.Cmd) { process.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

// killGroup kills this run's process group, and only it.
func killGroup(process *exec.Cmd) { _ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL) }
