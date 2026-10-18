//go:build windows

package Arkcommand

import (
	"os/exec"
	"syscall"
)

// This daemon only ever runs on OpenBSD (see CLAUDE.md) - this file exists
// purely so `go build`/`go vet` still work on a non-Unix development
// machine. newProcAttr/killProcessGroup here are stand-ins, not a real
// implementation: Windows has no equivalent of a POSIX process group to put
// a child in or to kill by PID sign, so a hung command's children (if any)
// are not reaped by this path on Windows the way procattr_unix.go reaps them
// on the real target platform. cmd.Cancel still falls through to killing the
// direct child process, which is exec.CommandContext's own default anyway.
func newProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
