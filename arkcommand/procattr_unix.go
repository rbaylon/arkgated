//go:build !windows

package Arkcommand

import (
	"os/exec"
	"syscall"
)

// newProcAttr puts a command in its own process group (Setpgid) rather than
// arkgated's, so killProcessGroup can kill the whole tree a command spawns -
// not just the direct child - with one signal. This matters for anything
// that isn't a single flat binary: "/bin/sh -c \"netstat -rn | grep UGHS\""
// (ActiveRoutes) forks a shell that itself forks netstat and grep, and
// killing only the shell would leave netstat/grep running as orphans,
// reparented to init, for as long as they'd otherwise take to finish or
// hang.
func newProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGKILL to cmd's whole process group (the negative
// PID convention for kill(2)). Called as cmd.Cancel by RunCtx/
// RunWithOutputCtx when their context is done, either from cmdTimeout
// elapsing or an admin's ClearActive - see registry.go.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
