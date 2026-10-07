package Arkcommand

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// helperCmd builds an Arkcmd that, when run, re-invokes this same test
// binary as a subprocess restricted to TestHelperProcess (below) - the
// standard portable way to test exec/kill/timeout behavior without depending
// on an external binary like `sleep` that exists on Unix but not Windows;
// see the stdlib's own os/exec_test.go for the origin of this pattern. args
// are read back out of os.Args (after "--") by TestHelperProcess in the
// child.
func helperCmd(name string, args ...string) *Arkcmd {
	opts := append([]string{"-test.run=TestHelperProcess", "--"}, args...)
	return &Arkcmd{Name: name, Cmd: os.Args[0], Opts: opts}
}

// TestHelperProcess is not a real test - go test runs it like any other, but
// it does nothing unless ARKCOMMAND_WANT_HELPER_PROCESS=1 is set, which the
// tests below set via os.Setenv before calling RunCtx/RunWithOutputCtx;
// exec.CommandContext inherits the parent's environment by default, so the
// spawned child sees it without RunCtx needing to know anything about
// testing.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("ARKCOMMAND_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "sleep":
		ms, _ := strconv.Atoi(args[1])
		time.Sleep(time.Duration(ms) * time.Millisecond)
	case "echo":
		os.Stdout.WriteString(args[1])
	case "fail":
		os.Exit(3)
	}
}

func withHelperEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ARKCOMMAND_WANT_HELPER_PROCESS", "1")
}

// The whole point of cmdTimeout: a command that runs far longer than it is
// allowed to must actually be cut off, not merely time-box in theory. Before
// this existed, RunCtx's predecessor (plain exec.Command) would have blocked
// here for the full 5 seconds; this proves it returns close to the shrunk
// timeout instead.
func TestRunCtxKillsAHungCommand(t *testing.T) {
	withHelperEnv(t)
	old := cmdTimeout
	cmdTimeout = 100 * time.Millisecond
	t.Cleanup(func() { cmdTimeout = old })

	ac := helperCmd("TestSlow", "sleep", "5000")
	start := time.Now()
	code, err := ac.RunCtx(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want an error from a killed process, got nil")
	}
	if code == 0 {
		t.Error("want a non-zero code for a killed process")
	}
	// Generous upper bound (cmdTimeout + WaitDelay + scheduling slack), but
	// far short of the 5s the process would otherwise have run for.
	if elapsed > 2*time.Second {
		t.Errorf("RunCtx took %v to return after a 100ms timeout - the kill did not take effect promptly", elapsed)
	}
}

func TestRunWithOutputCtxKillsAHungCommand(t *testing.T) {
	withHelperEnv(t)
	old := cmdTimeout
	cmdTimeout = 100 * time.Millisecond
	t.Cleanup(func() { cmdTimeout = old })

	ac := helperCmd("TestSlow", "sleep", "5000")
	start := time.Now()
	code, _ := ac.RunWithOutputCtx(context.Background())
	elapsed := time.Since(start)

	if code == 0 {
		t.Error("want a non-zero code for a killed process")
	}
	if elapsed > 2*time.Second {
		t.Errorf("RunWithOutputCtx took %v to return after a 100ms timeout", elapsed)
	}
}

// A well-behaved, fast command must be completely unaffected by any of
// this - the whole point is "make it does not break" existing behavior.
func TestRunWithOutputCtxStillWorksForAFastCommand(t *testing.T) {
	withHelperEnv(t)
	ac := helperCmd("TestFast", "echo", "hello")
	code, out := ac.RunWithOutputCtx(context.Background())
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if string(out) != "hello" {
		t.Errorf("out = %q, want %q", out, "hello")
	}
}

// A command that exits non-zero on its own (not killed) must still report
// its real exit code, unchanged from before RunCtx existed.
func TestRunWithOutputCtxReportsRealExitCode(t *testing.T) {
	withHelperEnv(t)
	ac := helperCmd("TestFail", "fail")
	code, _ := ac.RunWithOutputCtx(context.Background())
	if code != 3 {
		t.Errorf("code = %d, want 3 (the helper's real exit code)", code)
	}
}

// Cancelling the parent context (what ClearActive does, via Begin's context)
// must stop the command the same way the timeout does - this is the
// mechanism the administrative "clear" action in main.go depends on.
func TestRunCtxStopsOnParentCancel(t *testing.T) {
	withHelperEnv(t)
	// A long cmdTimeout, so if cancellation did not work, the test would hang
	// for the timeout instead of failing fast - making a broken cancellation
	// path obvious rather than silently passing for the wrong reason.
	old := cmdTimeout
	cmdTimeout = 10 * time.Second
	t.Cleanup(func() { cmdTimeout = old })

	ctx, cancel := context.WithCancel(context.Background())
	ac := helperCmd("TestSlow", "sleep", "5000")

	done := make(chan struct{})
	go func() {
		ac.RunCtx(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // let the process actually start
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunCtx did not stop within 2s of its parent context being cancelled")
	}
}

// Run()/RunWithOutput() (the no-context convenience wrappers) must still
// apply cmdTimeout - they're not a bypass of it, just an unregistered path.
func TestRunWithoutContextStillTimesOut(t *testing.T) {
	withHelperEnv(t)
	old := cmdTimeout
	cmdTimeout = 100 * time.Millisecond
	t.Cleanup(func() { cmdTimeout = old })

	ac := helperCmd("TestSlow", "sleep", "5000")
	start := time.Now()
	_, err := ac.Run()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want an error from a killed process")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Run() took %v, want it bounded by cmdTimeout", elapsed)
	}
}

// quietCommands must still suppress logging the same way for a command run
// through RunCtx as it did through the old exec.Command-based Run - not
// something the timeout/context plumbing should have disturbed.
func TestQuietCommandsUnaffectedByCtxChange(t *testing.T) {
	if !IsQuiet("HealthPing") {
		t.Error("HealthPing should still be quiet")
	}
	if IsQuiet("Ping") {
		t.Error("Ping should not be quiet")
	}
}

// SyspatchCheck waits on a remote mirror and can run for minutes. If it went
// through the serialized worker queue it would hold up every pf/dhcpd/route
// apply behind it, so it has to take the concurrent path.
func TestSyspatchCheckRunsOutsideTheQueue(t *testing.T) {
	if !IsConcurrent("SyspatchCheck") {
		t.Error("SyspatchCheck must be a concurrent command, not queued behind mutating commands")
	}
}

func TestTimeoutFor(t *testing.T) {
	if got := TimeoutFor("Ping"); got != cmdTimeout {
		t.Errorf("TimeoutFor(Ping) = %v, want the default %v", got, cmdTimeout)
	}
	if got := TimeoutFor("SyspatchCheck"); got <= cmdTimeout {
		t.Errorf("TimeoutFor(SyspatchCheck) = %v, want longer than the default %v", got, cmdTimeout)
	}
}

// A command with its own longer limit must not be killed at cmdTimeout, and
// one without must still be.
func TestLongTimeoutCommandOutlivesCmdTimeout(t *testing.T) {
	withHelperEnv(t)
	old := cmdTimeout
	cmdTimeout = 100 * time.Millisecond
	t.Cleanup(func() { cmdTimeout = old })
	longTimeouts["TestLong"] = 5 * time.Second
	t.Cleanup(func() { delete(longTimeouts, "TestLong") })

	if _, err := helperCmd("TestLong", "sleep", "500").RunCtx(context.Background()); err != nil {
		t.Errorf("command with a 5s limit was cut off at the 100ms default: %v", err)
	}
	if _, err := helperCmd("TestDefault", "sleep", "500").RunCtx(context.Background()); err == nil {
		t.Error("command without its own limit outlived the 100ms default")
	}
}
