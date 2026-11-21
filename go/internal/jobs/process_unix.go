//go:build unix

package jobs

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts the worker in its own process group and makes cancellation kill the whole group.
func ownProcessGroup(process *exec.Cmd) {
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.Cancel = func() error { return syscall.Kill(-process.Process.Pid, syscall.SIGKILL) }
}
