package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	Arkcommand "github.com/rbaylon/arkgated/arkcommand"
)

// --- acquireSlot: the connection-count cap's own logic, tested directly
// against a small channel rather than needing 1000 real connections to prove
// the 1001st is rejected. ---

func TestAcquireSlotEnforcesCapacity(t *testing.T) {
	sem := make(chan struct{}, 2)

	rel1, ok1 := acquireSlot(sem)
	rel2, ok2 := acquireSlot(sem)
	if !ok1 || !ok2 {
		t.Fatal("first two acquires within capacity 2 should succeed")
	}

	_, ok3 := acquireSlot(sem)
	if ok3 {
		t.Fatal("third acquire should fail at capacity 2")
	}

	// Releasing must free a slot for the next caller - the cap is a live
	// ceiling, not a one-shot latch.
	rel1()
	_, ok4 := acquireSlot(sem)
	if !ok4 {
		t.Fatal("acquire should succeed again after a release")
	}
	rel2()
}

func TestAcquireSlotNeverBlocks(t *testing.T) {
	sem := make(chan struct{}, 1)
	acquireSlot(sem) // fill it

	done := make(chan struct{})
	go func() {
		acquireSlot(sem) // must return immediately with ok=false, not block
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("acquireSlot blocked instead of returning immediately when full")
	}
}

// --- end-to-end: run() against a real listener, real connections ---

// startTestDaemon writes a minimal valid config.json into a temp rundir and
// starts run() against a single real TCP listener, returning its address and
// a cancel func. srvcurl points at a closed local port so Enroll/PfCreate
// fail fast (already-established nil-safety behavior, not something this
// change touches) instead of hanging the test on an unreachable network
// call.
func startTestDaemon(t *testing.T) (addr string, cancel context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	cfgJSON := `{
		"ifaces": [{"name":"wan","device":"em0","speed":"100M","default":true,"type":"external","gateway":"10.0.0.1","ip":"10.0.0.2","netmask":"255.255.255.0","lb_percentage":0}],
		"wifi_ip_list": "wifilist.txt", "subs_ip_list": "subslist.txt",
		"subs_portal_port": 4000, "captive_portal_port": 3000,
		"router": "testrouter", "load_balance": false,
		"dhcps": [], "dns": "8.8.8.8", "pflows": []
	}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0640); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	c := &config{
		maxbuff: 4096,
		srvcurl: "http://127.0.0.1:1/", // closed port: fails fast, not hangs
		rundir:  dir + string(os.PathSeparator),
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		run(c, io.Discard, []net.Listener{ln}, ctx)
		close(done)
	}()

	t.Cleanup(func() {
		cancelFn()
		ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("run() did not return after cancel")
		}
	})

	return ln.Addr().String(), cancelFn
}

func sendRaw(t *testing.T, addr string, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return out
}

func sendCmd(t *testing.T, addr string, cmd Arkcommand.Arkcmd) []byte {
	t.Helper()
	b, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return sendRaw(t, addr, b)
}

// A connection that never sends anything must be closed by connDeadline,
// not held open forever - this is the fix for the mTLS listener's lazy
// handshake issue (a bare TCP connect with no ClientHello used to block the
// same Read indefinitely) and for any client that stalls after connecting.
func TestSilentConnectionIsClosedByDeadline(t *testing.T) {
	old := connDeadline
	connDeadline = 200 * time.Millisecond
	t.Cleanup(func() { connDeadline = old })

	addr, _ := startTestDaemon(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send nothing. The server-side deadline should close its end well
	// within a couple of connDeadline windows; a Read on our side will
	// return (EOF or reset) once it does.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	start := time.Now()
	_, err = conn.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the server to close an idle connection, got data instead")
	}
	if elapsed > 2*time.Second {
		t.Errorf("server took %v to close a silent connection with a 200ms deadline", elapsed)
	}
}

// ActiveHealthChecks must report tracked HealthPing commands - the data
// source for the dashboard's count. Uses a slow-but-real HealthPing
// connection (left open deliberately) so there is something genuine to
// report, not a mocked registry.
func TestActiveHealthChecksReportsInFlightPings(t *testing.T) {
	addr, _ := startTestDaemon(t)

	// A HealthPing whose Cmd doesn't exist: it fails almost immediately (no
	// such binary), but that's fine - Begin still registers it for the brief
	// window it's in flight. To get a *sustained* entry to observe, dial and
	// hold the connection open without waiting for the reply, in a
	// goroutine, then poll ActiveHealthChecks while it's still running.
	//
	// This uses "sleep" via the shell where available; skipped with a clear
	// reason on platforms where that assumption doesn't hold, rather than
	// silently asserting nothing.
	sleepCmd, sleepOpts := longRunningProbe(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sendCmd(t, addr, Arkcommand.Arkcmd{Name: "HealthPing", Cmd: sleepCmd, Opts: sleepOpts})
	}()

	// Poll briefly for the entry to appear rather than sleeping a fixed
	// guess - avoids flakiness from scheduling variance.
	deadline := time.Now().Add(2 * time.Second)
	var snap Arkcommand.ActiveSnapshot
	for time.Now().Before(deadline) {
		out := sendCmd(t, addr, Arkcommand.Arkcmd{Name: "ActiveHealthChecks"})
		if err := json.Unmarshal(out, &snap); err != nil {
			t.Fatalf("ActiveHealthChecks did not return valid JSON: %v (%q)", err, out)
		}
		if snap.Count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if snap.Count == 0 {
		t.Fatal("ActiveHealthChecks never showed the in-flight HealthPing")
	}
	if snap.Commands[0].Name != "HealthPing" {
		t.Errorf("tracked command name = %q, want HealthPing", snap.Commands[0].Name)
	}

	<-done // let the background HealthPing finish before the test ends
}

// ClearHealthChecks must actually terminate a stuck HealthPing - the
// administrative action the dashboard's button performs - and
// ActiveHealthChecks must reflect that afterward.
func TestClearHealthChecksTerminatesInFlightPings(t *testing.T) {
	addr, _ := startTestDaemon(t)
	sleepCmd, sleepOpts := longRunningProbe(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sendCmd(t, addr, Arkcommand.Arkcmd{Name: "HealthPing", Cmd: sleepCmd, Opts: sleepOpts})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out := sendCmd(t, addr, Arkcommand.Arkcmd{Name: "ActiveHealthChecks"})
		var snap Arkcommand.ActiveSnapshot
		json.Unmarshal(out, &snap)
		if snap.Count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	clearOut := sendCmd(t, addr, Arkcommand.Arkcmd{Name: "ClearHealthChecks"})
	var cleared map[string]int
	if err := json.Unmarshal(clearOut, &cleared); err != nil {
		t.Fatalf("ClearHealthChecks did not return valid JSON: %v (%q)", err, clearOut)
	}
	if cleared["cleared"] < 1 {
		t.Errorf("cleared = %v, want at least 1", cleared)
	}

	// The killed HealthPing's own goroutine should finish promptly now
	// (proving the kill actually reached the process), not linger for
	// however long it would otherwise have slept.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the cleared HealthPing did not finish promptly after being cleared")
	}

	// And the registry should reflect it being gone (End runs after the
	// goroutine above returns, so poll briefly rather than asserting
	// instantly).
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		out := sendCmd(t, addr, Arkcommand.Arkcmd{Name: "ActiveHealthChecks"})
		var snap Arkcommand.ActiveSnapshot
		json.Unmarshal(out, &snap)
		if snap.Count == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("ActiveHealthChecks still shows an entry after it was cleared and finished")
}

// ClearHealthChecks against an idle daemon (nothing in flight) must be a
// harmless no-op, not an error.
func TestClearHealthChecksNoopWhenNothingRunning(t *testing.T) {
	addr, _ := startTestDaemon(t)
	out := sendCmd(t, addr, Arkcommand.Arkcmd{Name: "ClearHealthChecks"})
	var cleared map[string]int
	if err := json.Unmarshal(out, &cleared); err != nil {
		t.Fatalf("bad JSON: %v (%q)", err, out)
	}
	if cleared["cleared"] != 0 {
		t.Errorf("cleared = %v, want 0", cleared)
	}
}

// Regression: malformed input must still get NOK and close promptly - this
// existed before any of the current changes and must not have been
// disturbed by them.
func TestMalformedPayloadStillGetsNOK(t *testing.T) {
	addr, _ := startTestDaemon(t)
	out := sendRaw(t, addr, []byte("not json"))
	if strings.TrimSpace(string(out)) != "NOK" {
		t.Errorf("got %q, want NOK", out)
	}
}

// longRunningProbe returns a Cmd/Opts pair that runs for a few seconds on
// this platform, so tests have something genuine to observe as "in flight"
// and something genuine for ClearHealthChecks to kill - not a mock. Skips
// (rather than guessing) if this platform's shell-based sleep assumption
// doesn't hold.
func longRunningProbe(t *testing.T) (cmd string, opts []string) {
	t.Helper()
	switch {
	case fileExists("/bin/sleep"):
		return "/bin/sleep", []string{"5"}
	case fileExists("C:\\Windows\\System32\\timeout.exe"):
		return "C:\\Windows\\System32\\timeout.exe", []string{"/T", "5"}
	default:
		t.Skip("no known long-running probe binary on this platform")
		return "", nil
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
