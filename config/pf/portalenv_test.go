package pfconfig

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// stubOwnership replaces the user lookup and chown for one test and returns
// the calls chown received.
type chownCall struct {
	path     string
	uid, gid int
	existed  bool // whether the file was already on disk when chown ran
}

func stubOwnership(t *testing.T) *[]chownCall {
	t.Helper()
	oldLookup, oldChown := lookupPortalIDs, chownFile
	t.Cleanup(func() { lookupPortalIDs, chownFile = oldLookup, oldChown })
	var calls []chownCall
	lookupPortalIDs = func() (int, int, error) { return 1001, 1002, nil }
	chownFile = func(path string, uid, gid int) error {
		_, err := os.Stat(path)
		calls = append(calls, chownCall{path, uid, gid, err == nil})
		return nil
	}
	return &calls
}

func TestInstallPortalEnvWritesThenChownsToAdmin(t *testing.T) {
	calls := stubOwnership(t)
	path := filepath.Join(t.TempDir(), "app", ".env")

	if err := installPortalEnv("billportal", path, "A=1\n"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "A=1\n" {
		t.Errorf("file = %q", b)
	}
	if len(*calls) != 1 {
		t.Fatalf("chown called %d times, want 1", len(*calls))
	}
	c := (*calls)[0]
	if c.path != path || c.uid != 1001 || c.gid != 1002 {
		t.Errorf("chown(%q, %d, %d), want the .env with admin's uid and gid", c.path, c.uid, c.gid)
	}
	if !c.existed {
		t.Error("chown ran before the file was written")
	}
	if runtime.GOOS != "windows" { // Windows has no unix mode bits
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}

// An existing file keeps its old owner when rewritten, so ownership has to be
// set on every write, not only when the file is first created.
func TestInstallPortalEnvChownsAnExistingFileToo(t *testing.T) {
	calls := stubOwnership(t)
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("OLD=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installPortalEnv("captiveportal", path, "NEW=1\n"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Errorf("chown called %d times on rewrite, want 1", len(*calls))
	}
	if b, _ := os.ReadFile(path); string(b) != "NEW=1\n" {
		t.Errorf("file = %q, want the new contents", b)
	}
}

// If the file cannot be handed to admin the caller must hear about it - the
// portal would otherwise fail to read its own config with no explanation.
func TestInstallPortalEnvReportsOwnershipFailures(t *testing.T) {
	t.Run("admin account missing", func(t *testing.T) {
		stubOwnership(t)
		lookupPortalIDs = func() (int, int, error) { return 0, 0, errors.New("unknown user admin") }
		path := filepath.Join(t.TempDir(), ".env")
		err := installPortalEnv("billportal", path, "A=1\n")
		if err == nil {
			t.Fatal("want an error when admin cannot be looked up")
		}
	})
	t.Run("chown refused", func(t *testing.T) {
		stubOwnership(t)
		chownFile = func(string, int, int) error { return errors.New("operation not permitted") }
		path := filepath.Join(t.TempDir(), ".env")
		err := installPortalEnv("billportal", path, "A=1\n")
		if err == nil {
			t.Fatal("want an error when chown fails")
		}
	})
}

// The two public installers, end to end against a fake srvcman, must both go
// through the chown.
func TestPortalEnvCreatorsChownTheirEnv(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"conf":"ROUTER_ID=r1\n"}`))
	}))
	defer srv.Close()
	token := "t"

	oldCP, oldBP := captivePortalEnvPath, billPortalEnvPath
	t.Cleanup(func() { captivePortalEnvPath, billPortalEnvPath = oldCP, oldBP })
	dir := t.TempDir()
	captivePortalEnvPath = filepath.Join(dir, "captiveportal", ".env")
	billPortalEnvPath = filepath.Join(dir, "billportal", ".env")

	for _, tc := range []struct {
		name string
		run  func() error
		path string
	}{
		{"captiveportal", func() error { return CaptivePortalEnvCreate(srv.URL+"/", &token) }, captivePortalEnvPath},
		{"billportal", func() error { return BillPortalEnvCreate(srv.URL+"/", &token) }, billPortalEnvPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubOwnership(t)
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
			if len(*calls) != 1 || (*calls)[0].path != tc.path {
				t.Errorf("chown calls = %+v, want one for %s", *calls, tc.path)
			}
		})
	}
}
