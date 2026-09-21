package Arkcommand

import (
	"context"
	"log"
	"os/exec"
	"time"
)

// WantOutput, when set by the client, tells the connection handler in
// main.go to run this command via RunWithOutput and reply with the
// captured output (JSON {ok,output,error}) instead of the plain "OK"/"NOK"
// used for every other command - see main.go's worker(). It's
// omitempty so existing callers that don't set it produce byte-identical
// JSON to before this field existed.
type Arkcmd struct {
	Name       string   `json:"name"`
	Cmd        string   `json:"cmd"`
	Opts       []string `json:"opts"`
	WantOutput bool     `json:"want_output,omitempty"`
}

// quietCommands are periodic, high-frequency commands - gatewaymonitor's
// health-check ping (every pingInterval, per monitored gateway) and
// pfifaces' interface traffic-stats poll (netstat -ibn, hit by the UI
// dashboard on a short interval) - whose output isn't worth a log line on
// every single run; at that volume they drown out everything else in the
// log. Failures still surface through the caller's own handling
// (gatewaymonitor's success/failure history, the traffic-stats error
// response), just not as raw command output here.
var quietCommands = map[string]bool{
	"HealthPing": true,
	"Netstat":    true,
}

// IsQuiet reports whether name is a high-frequency command whose
// connection/output logging should be suppressed - see quietCommands.
func IsQuiet(name string) bool {
	return quietCommands[name]
}

// concurrentCommands are read-only, side-effect-free introspection commands
// (ping/traceroute/netstat/ifconfig) that main.go's connection handler runs
// immediately in their own connection's goroutine instead of handing off to
// the single serialized worker() queue. That queue exists to keep mutating
// commands (pf.conf/dhcpd.conf/unbound.conf/npppd.conf apply steps, route
// add/delete) strictly ordered - these commands touch no shared state, so
// running many of them at once is safe, and doing so matters in practice:
// gatewaymonitor fires one HealthPing per monitored gateway on every tick,
// all at once, and pfifaces polls Netstat/ListInterfaces on a short
// interval too. Funneling those through one serial worker alongside
// (potentially slow) mutating commands meant a burst of health checks - or
// even just one slow command in flight at the wrong moment - could blow
// past the caller's own timeout before ever being dequeued, producing
// falsely-"down" gateway statuses that reflected queueing delay, not
// reachability. Add a name here (and nowhere else) for any future
// read-only command that should get the same treatment; anything that
// writes a file, moves a file, or changes running state must NOT be added,
// since ordering among those is relied upon (e.g. pf.conf's
// check-then-backup-then-move-then-apply sequence).
var concurrentCommands = map[string]bool{
	"HealthPing":     true,
	"Ping":           true,
	"Traceroute":     true,
	"Netstat":        true,
	"ListInterfaces": true,
	"ActiveRoutes":   true,
	"SystemInfo":     true,
	"TunnelPs":       true,
	"FdSysctl":       true,
	"FdFstat":        true,
}

// IsConcurrent reports whether name is safe to run outside the serialized
// worker queue - see concurrentCommands.
func IsConcurrent(name string) bool {
	return concurrentCommands[name]
}

// newTrackedCmd builds the exec.Cmd for ac, bound to ctx so that whenever ctx
// is done - because parentCtx was cancelled (ClearActive, or the caller's own
// connection going away) or because RunCtx/RunWithOutputCtx's own cmdTimeout
// elapsed - the command's *whole process group* is killed, not just the
// direct child. exec.CommandContext's default Cancel behavior is a plain
// cmd.Process.Kill() on the immediate child only; for something like
// ActiveRoutes' "/bin/sh -c \"netstat -rn | grep UGHS\"", that kills the
// shell and leaves netstat/grep running as orphans. newProcAttr (see
// procattr_unix.go) puts the whole tree in one process group so
// killProcessGroup's -pid kill takes all of it at once. WaitDelay bounds how
// long Output/CombinedOutput will keep waiting after Cancel fires before
// giving up and returning anyway - defense in depth against a process that
// somehow ignores SIGKILL, so that case can't reintroduce the hang this
// whole mechanism exists to prevent.
func newTrackedCmd(ctx context.Context, ac *Arkcmd) *exec.Cmd {
	cmd := exec.CommandContext(ctx, ac.Cmd, ac.Opts...)
	cmd.SysProcAttr = newProcAttr()
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// Run is RunCtx against a background context - the command still gets
// cmdTimeout's automatic bound, it just isn't registered anywhere an admin
// could cancel it early or see it in a Snapshot. Prefer RunCtx with a
// context from Begin (see registry.go) for anything reached over IPC; this
// exists for callers (tests, anything run outside the connection-handling
// path) that don't need registry tracking.
func (ac *Arkcmd) Run() (int, error) {
	return ac.RunCtx(context.Background())
}

// RunCtx runs ac, killing it (whole process group) if parentCtx is
// cancelled or if cmdTimeout elapses first - see newTrackedCmd and the
// cmdTimeout doc comment in registry.go for why neither of those used to
// exist.
func (ac *Arkcmd) RunCtx(parentCtx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(parentCtx, cmdTimeout)
	defer cancel()
	cmd := newTrackedCmd(ctx, ac)
	out, err := cmd.Output()
	if !quietCommands[ac.Name] {
		log.Println(string(out))
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// RunWithOutput is RunWithOutputCtx against a background context - see Run's
// comment for why you'd want RunWithOutputCtx instead over IPC.
func (ac *Arkcmd) RunWithOutput() (int, []byte) {
	return ac.RunWithOutputCtx(context.Background())
}

// RunWithOutputCtx runs the command and always returns its captured output
// (stdout+stderr combined), even when it exits non-zero - callers like
// diagnostics (ping to an unreachable host, e.g.) need the output text
// precisely in that case, not just a bare failure code. Exit code is the
// process's real exit code when available, 1 otherwise (e.g. the binary
// itself couldn't be started, or it was killed - see newTrackedCmd - because
// parentCtx was cancelled or cmdTimeout elapsed).
func (ac *Arkcmd) RunWithOutputCtx(parentCtx context.Context) (int, []byte) {
	quiet := quietCommands[ac.Name]
	if !quiet {
		log.Println("running:", ac.Cmd)
	}
	ctx, cancel := context.WithTimeout(parentCtx, cmdTimeout)
	defer cancel()
	cmd := newTrackedCmd(ctx, ac)
	out, err := cmd.CombinedOutput()
	if !quiet {
		log.Println(string(out))
	}
	if err != nil {
		code := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
		return code, out
	}
	return 0, out
}
