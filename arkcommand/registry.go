package Arkcommand

import (
	"context"
	"sort"
	"sync"
	"time"
)

// cmdTimeout bounds how long any single Arkcmd's underlying process may run
// before arkgated force-kills it itself, rather than depending entirely on
// the caller having embedded a timeout/count flag in Opts. Before this,
// Run/RunWithOutput called plain exec.Command with no deadline at all: a
// command that hung - a ping to a blackholed host with no -w flag, a stalled
// DNS lookup, any caller that omitted its own bound - held its goroutine, its
// connection and its forked OS process open indefinitely. Concurrent
// commands (see concurrentCommands) are the sharpest edge of this, since
// gatewaymonitor fires one HealthPing per monitored gateway on every tick
// with no queueing to smooth out a pile of stuck ones - enough unreachable
// gateways over enough ticks exhausts file descriptors or the process table
// on the host, which takes down the whole daemon, not just health checks.
//
// 90s is chosen to be well above anything this daemon legitimately runs
// (pfctl -nf, dhcpd -nf, mv, rcctl, a bounded ping/traceroute) while still
// turning "hangs forever" into "fails after a bounded, bounded-annoying
// wait" for a genuinely stuck command.
var cmdTimeout = 90 * time.Second

// CmdTimeout exports cmdTimeout for callers (main.go's connection-level
// deadline, sized so it never cuts off a command that is still legitimately
// running out its own bound) that need to size something off it without
// duplicating the number. A var, not a const, purely so tests can shrink it
// (restoring the original afterward) rather than waiting out a real 90s
// timeout to prove a hung command actually gets killed.
var CmdTimeout = cmdTimeout

// maxActiveCmds caps how many Arkcmds - across both the serialized worker
// queue and the concurrent-command path - may have a process in flight at
// once. This is a second, independent line of defense from cmdTimeout: a
// timeout bounds how long any one stuck command lives, but says nothing
// about how many can pile up *before* they time out. A wide enough burst of
// simultaneously-stuck connections could still exhaust resources well within
// the 90s window each one is individually allowed. 500 is generous for what
// this daemon is - an OpenBSD gateway box's IPC listener, not a
// general-purpose job server - real traffic (dozens to low hundreds of
// monitored gateways, each opening one connection per pingInterval) sits far
// below it; hitting the cap means something is already wrong, in which case
// rejecting outright (see main.go's runJob) is the right response, not
// piling on further.
var maxActiveCmds = 500

// MaxActiveCmds exports maxActiveCmds for callers (main.go's log line when
// Begin refuses) that want to say what the cap actually is without
// duplicating the number. A var so tests can shrink it to exercise the cap
// without registering 500 real entries.
var MaxActiveCmds = maxActiveCmds

// activeCmd is one command with a process currently running (or about to
// start), tracked so it can be counted, listed, and administratively
// terminated - see Snapshot/ClearActive and main.go's
// "ActiveHealthChecks"/"ClearHealthChecks" special cases.
type activeCmd struct {
	id      uint64
	name    string
	cmd     string
	opts    []string
	remote  string
	started time.Time
	cancel  context.CancelFunc
}

var (
	activeMu   sync.Mutex
	activeNext uint64
	active     = map[uint64]*activeCmd{}
)

// Begin registers cmd as about to run and returns a context tied to it: the
// context is cancelled if something calls ClearActive against a matching
// entry, and is otherwise live until End is called. It does *not* carry
// cmdTimeout itself - RunCtx/RunWithOutputCtx layer that on separately - so
// Begin's only job is registry bookkeeping and admin-triggered
// cancellation, independent of the automatic timeout.
//
// ok is false once maxActiveCmds is already reached, in which case the
// caller must not run cmd at all: id and ctx are zero values, and there is
// nothing to End.
//
// Every successful Begin must be paired with exactly one End call, however
// cmd finishes (including a panic recovery path, if one is ever added) - use
// defer.
func Begin(cmd Arkcmd, remote string) (id uint64, ctx context.Context, ok bool) {
	activeMu.Lock()
	defer activeMu.Unlock()
	if len(active) >= maxActiveCmds {
		return 0, nil, false
	}
	activeNext++
	id = activeNext
	ctx, cancel := context.WithCancel(context.Background())
	active[id] = &activeCmd{
		id: id, name: cmd.Name, cmd: cmd.Cmd, opts: cmd.Opts,
		remote: remote, started: time.Now(), cancel: cancel,
	}
	return id, ctx, true
}

// End deregisters id and releases its context's resources. Safe to call even
// if id was already removed - a concurrent ClearActive only cancels the
// context and does not delete the map entry, precisely so there is a single
// owner of the delete (the command's own End, called once it actually
// finishes) and no risk of two callers racing to clean up the same entry.
func End(id uint64) {
	activeMu.Lock()
	a, ok := active[id]
	if ok {
		delete(active, id)
	}
	activeMu.Unlock()
	if ok {
		a.cancel()
	}
}

// ActiveInfo is one tracked command, as reported by Snapshot.
type ActiveInfo struct {
	ID        uint64 `json:"id"`
	Name      string `json:"name"`
	Cmd       string `json:"cmd"`
	Remote    string `json:"remote"`
	RunningMs int64  `json:"running_ms"`
}

// ActiveSnapshot is Snapshot's result: the commands matching its filter,
// longest-running first (that ordering is what matters when the question is
// "which of these is actually stuck"), plus two counts - Count for the
// filtered set and TotalCount across every tracked command regardless of
// filter, so a HealthPing-scoped dashboard can still show how much of the
// daemon's total in-flight budget health checks account for.
type ActiveSnapshot struct {
	Count      int          `json:"count"`
	TotalCount int          `json:"total_count"`
	Commands   []ActiveInfo `json:"commands"`
}

// Snapshot returns every currently-tracked command whose Name equals
// filterName, or every tracked command if filterName is "".
func Snapshot(filterName string) ActiveSnapshot {
	activeMu.Lock()
	defer activeMu.Unlock()
	snap := ActiveSnapshot{TotalCount: len(active)}
	for _, a := range active {
		if filterName != "" && a.name != filterName {
			continue
		}
		snap.Commands = append(snap.Commands, ActiveInfo{
			ID: a.id, Name: a.name, Cmd: a.cmd, Remote: a.remote,
			RunningMs: time.Since(a.started).Milliseconds(),
		})
	}
	sort.Slice(snap.Commands, func(i, j int) bool {
		return snap.Commands[i].RunningMs > snap.Commands[j].RunningMs
	})
	snap.Count = len(snap.Commands)
	return snap
}

// ClearActive cancels every currently-tracked command whose Name equals
// filterName ("" matches everything) and reports how many it cancelled -
// this is the administrative "terminate the stuck ones" action.
//
// Cancelling only requests it: RunCtx/RunWithOutputCtx's Cancel func (see
// procattr_unix.go) is what actually kills the command's whole process
// group once its context is done, and the owning goroutine's own deferred
// End call is what removes the entry from the registry once the process has
// actually exited - not this function, which only flips the context and
// returns immediately.
func ClearActive(filterName string) int {
	activeMu.Lock()
	defer activeMu.Unlock()
	n := 0
	for _, a := range active {
		if filterName != "" && a.name != filterName {
			continue
		}
		a.cancel()
		n++
	}
	return n
}
