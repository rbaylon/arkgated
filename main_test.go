package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rbaylon/arkgated/config/webconf"
	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
)

// fakeSrvcman stands in for srvcman's enrollment endpoints. query404 makes it
// claim not to know the router (so Enroll POSTs a create), and createOK decides
// whether that create succeeds.
type fakeSrvcman struct {
	queries  atomic.Int32
	creates  atomic.Int32
	createOK atomic.Bool
	knows    atomic.Bool // once true, the router is already enrolled
}

func (f *fakeSrvcman) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/pfconfig/query/", func(w http.ResponseWriter, r *http.Request) {
		f.queries.Add(1)
		if f.knows.Load() {
			w.Write([]byte(`{"router":"r1"}`))
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	mux.HandleFunc("/pfconfig/create", func(w http.ResponseWriter, r *http.Request) {
		f.creates.Add(1)
		if !f.createOK.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		f.knows.Store(true)
		w.Write([]byte(`{"ok":true}`))
	})
	return httptest.NewServer(mux)
}

// storeAt builds a configured Store whose srvcurl points at the fake srvcman.
func storeAt(t *testing.T, base string) *webconf.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := webconf.Open(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := webconf.Defaults()
	s.SrvcURL = base + "/"
	s.RunDir = dir + "/"
	s.APIUser, s.APIPassword = "u", "p"
	s.WebCert = filepath.Join(dir, "w.crt")
	s.WebKey = filepath.Join(dir, "w.key")
	errs, _, err := store.Save(s)
	if err != nil || len(errs) > 0 {
		t.Fatalf("seeding settings: %v / %v", err, errs)
	}
	return store
}

func withToken(t *testing.T, tok string) {
	t.Helper()
	prev := apitoken
	t.Cleanup(func() { apitoken = prev })
	if tok == "" {
		apitoken = nil
		return
	}
	apitoken = &tok
}

// The point of the change: enrollment that fails at startup is retried, and
// stops being retried once it succeeds.
func TestEnrollmentIsRetriedUntilItSucceeds(t *testing.T) {
	f := &fakeSrvcman{}
	srv := f.server()
	defer srv.Close()
	store := storeAt(t, srv.URL)
	pfcfg := &pfconfigmodel.Pfconfig{Router: "r1"}

	// Startup: no token yet, which is exactly the boot-before-srvcman case.
	withToken(t, "")
	lastErr := ""
	enrolled := enrollOnce(store, pfcfg, false, &lastErr)
	if enrolled {
		t.Fatal("should not be enrolled without a token")
	}
	if f.queries.Load() != 0 {
		t.Errorf("no token should mean no request at all, got %d", f.queries.Load())
	}
	if !strings.Contains(lastErr, "no API token available") {
		t.Errorf("lastErr = %q", lastErr)
	}

	// Token arrives, but srvcman rejects the create.
	withToken(t, "tok")
	f.createOK.Store(false)
	enrolled = enrollOnce(store, pfcfg, enrolled, &lastErr)
	if enrolled {
		t.Fatal("a failed create must not count as enrolled")
	}
	if f.queries.Load() != 1 || f.creates.Load() != 1 {
		t.Errorf("want 1 query + 1 create, got %d/%d", f.queries.Load(), f.creates.Load())
	}

	// Next tick: srvcman is healthy, enrollment lands.
	f.createOK.Store(true)
	enrolled = enrollOnce(store, pfcfg, enrolled, &lastErr)
	if !enrolled {
		t.Fatalf("should be enrolled now; lastErr=%q", lastErr)
	}
	if lastErr != "" {
		t.Errorf("lastErr should be cleared on success, got %q", lastErr)
	}
	if f.creates.Load() != 2 {
		t.Errorf("want a second create attempt, got %d", f.creates.Load())
	}

	// And it must stop: no further requests once enrolled.
	q, c := f.queries.Load(), f.creates.Load()
	for i := 0; i < 5; i++ {
		if !enrollOnce(store, pfcfg, enrolled, &lastErr) {
			t.Fatal("enrolled state should be sticky")
		}
	}
	if f.queries.Load() != q || f.creates.Load() != c {
		t.Errorf("enrollment kept calling srvcman after success: %d/%d -> %d/%d",
			q, c, f.queries.Load(), f.creates.Load())
	}
}

// A router srvcman already knows about must not be re-created.
func TestAlreadyEnrolledRouterIsNotRecreated(t *testing.T) {
	f := &fakeSrvcman{}
	f.knows.Store(true)
	srv := f.server()
	defer srv.Close()
	store := storeAt(t, srv.URL)

	withToken(t, "tok")
	lastErr := ""
	if !enrollOnce(store, &pfconfigmodel.Pfconfig{Router: "r1"}, false, &lastErr) {
		t.Fatalf("a known router should enroll cleanly; lastErr=%q", lastErr)
	}
	if f.creates.Load() != 0 {
		t.Errorf("an already-enrolled router must not be POSTed to create, got %d", f.creates.Load())
	}
}

// The same failure repeating every 15s must not reprint every tick, but a
// changed failure must be reported.
func TestRepeatedEnrollFailureIsLoggedOnce(t *testing.T) {
	f := &fakeSrvcman{}
	srv := f.server()
	defer srv.Close()
	store := storeAt(t, srv.URL)
	pfcfg := &pfconfigmodel.Pfconfig{Router: "r1"}

	withToken(t, "")
	lastErr := ""
	enrollOnce(store, pfcfg, false, &lastErr)
	first := lastErr
	if first == "" {
		t.Fatal("expected a recorded failure")
	}
	// Same failure again: lastErr unchanged means the caller suppressed the log.
	enrollOnce(store, pfcfg, false, &lastErr)
	if lastErr != first {
		t.Errorf("identical failure changed lastErr: %q -> %q", first, lastErr)
	}

	// A different failure must replace it, so it does get logged.
	withToken(t, "tok")
	f.createOK.Store(false)
	enrollOnce(store, pfcfg, false, &lastErr)
	if lastErr == first {
		t.Error("a different failure should update lastErr so it is logged")
	}
}

// A nil pfcfg must be refused rather than panicking - run() would never pass
// one, but the loop keeps a reference for the life of the process.
func TestEnrollOnceRejectsNilConfig(t *testing.T) {
	f := &fakeSrvcman{}
	srv := f.server()
	defer srv.Close()
	store := storeAt(t, srv.URL)

	withToken(t, "tok")
	lastErr := ""
	if enrollOnce(store, nil, false, &lastErr) {
		t.Error("nil router config must not report success")
	}
	if !strings.Contains(lastErr, "no router config") {
		t.Errorf("lastErr = %q", lastErr)
	}
}
