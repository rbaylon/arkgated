package Arkcommand

import (
	"testing"
	"time"
)

// resetRegistry clears the package-level registry state between tests, since
// it's a shared global - without this, entries left behind by one test (or
// run order) would leak into another's Snapshot/ClearActive counts.
func resetRegistry(t *testing.T) {
	t.Helper()
	activeMu.Lock()
	for _, a := range active {
		a.cancel()
	}
	active = map[uint64]*activeCmd{}
	activeMu.Unlock()
}

func TestBeginEndLifecycle(t *testing.T) {
	resetRegistry(t)

	id, ctx, ok := Begin(Arkcmd{Name: "HealthPing", Cmd: "/sbin/ping"}, "10.0.0.1:1234")
	if !ok {
		t.Fatal("Begin refused with room available")
	}
	if id == 0 {
		t.Error("want a non-zero id")
	}
	select {
	case <-ctx.Done():
		t.Fatal("context should not be done yet")
	default:
	}

	snap := Snapshot("")
	if snap.Count != 1 || snap.TotalCount != 1 {
		t.Fatalf("snapshot = %+v, want count 1", snap)
	}
	if snap.Commands[0].Name != "HealthPing" || snap.Commands[0].Remote != "10.0.0.1:1234" {
		t.Errorf("tracked entry = %+v", snap.Commands[0])
	}

	End(id)
	if got := Snapshot("").Count; got != 0 {
		t.Errorf("after End, count = %d, want 0", got)
	}
	select {
	case <-ctx.Done():
	default:
		t.Error("End should cancel the context")
	}
}

// End must be safe against being effectively called twice - once by
// ClearActive's cancel (which does not delete), once by the owning
// goroutine's own End (which does) - see registry.go's comment on why
// ClearActive never deletes.
func TestEndAfterClearActiveIsSafe(t *testing.T) {
	resetRegistry(t)
	id, ctx, ok := Begin(Arkcmd{Name: "HealthPing"}, "")
	if !ok {
		t.Fatal("Begin refused")
	}

	n := ClearActive("HealthPing")
	if n != 1 {
		t.Fatalf("ClearActive cleared %d, want 1", n)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("ClearActive should have cancelled the context")
	}
	// The entry must still be visible until the owner's own End - ClearActive
	// only cancels, it does not remove.
	if got := Snapshot("").Count; got != 1 {
		t.Errorf("count after ClearActive = %d, want 1 (removal is End's job)", got)
	}

	End(id) // must not panic or double-decrement anything
	if got := Snapshot("").Count; got != 0 {
		t.Errorf("count after End = %d, want 0", got)
	}
}

func TestSnapshotFiltersByName(t *testing.T) {
	resetRegistry(t)
	id1, _, _ := Begin(Arkcmd{Name: "HealthPing"}, "a")
	id2, _, _ := Begin(Arkcmd{Name: "Ping"}, "b")
	id3, _, _ := Begin(Arkcmd{Name: "HealthPing"}, "c")
	defer End(id1)
	defer End(id2)
	defer End(id3)

	hp := Snapshot("HealthPing")
	if hp.Count != 2 {
		t.Errorf("HealthPing count = %d, want 2", hp.Count)
	}
	if hp.TotalCount != 3 {
		t.Errorf("TotalCount = %d, want 3 (unfiltered, for context)", hp.TotalCount)
	}
	for _, c := range hp.Commands {
		if c.Name != "HealthPing" {
			t.Errorf("filtered snapshot contained %q", c.Name)
		}
	}

	all := Snapshot("")
	if all.Count != 3 {
		t.Errorf("unfiltered count = %d, want 3", all.Count)
	}
}

func TestSnapshotOrdersLongestRunningFirst(t *testing.T) {
	resetRegistry(t)
	idOld, _, _ := Begin(Arkcmd{Name: "HealthPing"}, "old")
	defer End(idOld)
	time.Sleep(20 * time.Millisecond)
	idNew, _, _ := Begin(Arkcmd{Name: "HealthPing"}, "new")
	defer End(idNew)

	snap := Snapshot("HealthPing")
	if len(snap.Commands) != 2 {
		t.Fatalf("got %d entries, want 2", len(snap.Commands))
	}
	if snap.Commands[0].Remote != "old" {
		t.Errorf("first entry = %q, want the longer-running one (\"old\")", snap.Commands[0].Remote)
	}
	if snap.Commands[0].RunningMs < snap.Commands[1].RunningMs {
		t.Errorf("not sorted longest-first: %+v", snap.Commands)
	}
}

// The whole reason maxActiveCmds exists: past the cap, Begin must refuse
// rather than let registrations grow without bound.
func TestBeginRefusesAtCap(t *testing.T) {
	resetRegistry(t)
	old := maxActiveCmds
	maxActiveCmds = 2
	t.Cleanup(func() { maxActiveCmds = old })

	id1, _, ok1 := Begin(Arkcmd{Name: "HealthPing"}, "1")
	id2, _, ok2 := Begin(Arkcmd{Name: "HealthPing"}, "2")
	if !ok1 || !ok2 {
		t.Fatal("first two Begins within the cap should succeed")
	}

	id3, ctx3, ok3 := Begin(Arkcmd{Name: "HealthPing"}, "3")
	if ok3 {
		t.Fatal("third Begin should be refused at cap 2")
	}
	if id3 != 0 || ctx3 != nil {
		t.Errorf("refused Begin should return zero values, got id=%d ctx=%v", id3, ctx3)
	}

	// Freeing a slot must let the next Begin through - the cap is a live
	// ceiling, not a one-shot latch.
	End(id1)
	id4, _, ok4 := Begin(Arkcmd{Name: "HealthPing"}, "4")
	if !ok4 {
		t.Fatal("Begin should succeed again after a slot freed up")
	}
	End(id2)
	End(id4)
}

// ClearActive with no filter ("") must reach every tracked command,
// regardless of name - used nowhere in main.go today (which always filters
// to "HealthPing"), but Snapshot/ClearActive's filter semantics need to
// agree with each other, and an empty filter is the natural "everything"
// case both should honor.
func TestClearActiveEmptyFilterMatchesEverything(t *testing.T) {
	resetRegistry(t)
	id1, ctx1, _ := Begin(Arkcmd{Name: "HealthPing"}, "")
	id2, ctx2, _ := Begin(Arkcmd{Name: "Ping"}, "")
	defer End(id1)
	defer End(id2)

	n := ClearActive("")
	if n != 2 {
		t.Errorf("cleared %d, want 2", n)
	}
	for _, ctx := range []interface{ Done() <-chan struct{} }{ctx1, ctx2} {
		select {
		case <-ctx.Done():
		default:
			t.Error("expected context to be cancelled")
		}
	}
}

// ClearActive against a name with nothing tracked must be a no-op, not an
// error or a panic - the ordinary case for a healthy gateway fleet where an
// admin checks the dashboard and finds nothing stuck.
func TestClearActiveNoMatchesIsHarmless(t *testing.T) {
	resetRegistry(t)
	if n := ClearActive("HealthPing"); n != 0 {
		t.Errorf("cleared %d from an empty registry, want 0", n)
	}
}
