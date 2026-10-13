package pfconfig

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// srvcman mounts the PPPoE module at /api/v1/pppoe. The fetch has to ask for
// exactly that path: with the plural it got a 404, never staged a config, and
// npppd was restarted with nothing to read.
func TestPppoeCreateFetchesTheMountedPathAndStagesTheConfig(t *testing.T) {
	const conf = "tunnel PPPOE0 protocol pppoe {\n\tlisten on interface em2\n}\n"
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path != "/pppoe/conf" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"conf":"tunnel PPPOE0 protocol pppoe {\n\tlisten on interface em2\n}\n"}`))
	}))
	defer srv.Close()

	old := npppdStagePath
	npppdStagePath = filepath.Join(t.TempDir(), "npppd.conf")
	defer func() { npppdStagePath = old }()
	token := "t"

	if err := PppoeCreate("", srv.URL+"/", &token); err != nil {
		t.Fatalf("PppoeCreate: %v (asked %v)", err, asked)
	}
	got, err := os.ReadFile(npppdStagePath)
	if err != nil {
		t.Fatalf("no config was staged: %v", err)
	}
	if string(got) != conf {
		t.Errorf("staged %q, want %q", got, conf)
	}
	if len(asked) != 1 || asked[0] != "/pppoe/conf" {
		t.Errorf("requested %v, want exactly /pppoe/conf", asked)
	}
}

// A failed fetch must leave nothing staged, so the install step cannot move a
// stale or empty file into /etc/npppd.
func TestPppoeCreateStagesNothingWhenTheFetchFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	old := npppdStagePath
	npppdStagePath = filepath.Join(t.TempDir(), "npppd.conf")
	defer func() { npppdStagePath = old }()
	token := "t"

	err := PppoeCreate("", srv.URL+"/", &token)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want the 404 reported", err)
	}
	if _, statErr := os.Stat(npppdStagePath); statErr == nil {
		t.Error("a config was staged although the fetch failed")
	}
}

// A file left over from an earlier run must not survive a failed fetch: the
// install step moves whatever is at that path into /etc/npppd.
func TestPppoeCreateRemovesAStaleStagedFile(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	old := npppdStagePath
	npppdStagePath = filepath.Join(t.TempDir(), "npppd.conf")
	defer func() { npppdStagePath = old }()
	if err := os.WriteFile(npppdStagePath, []byte("# yesterday's config\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	token := "t"
	if err := PppoeCreate("", srv.URL+"/", &token); err == nil {
		t.Fatal("expected the failed fetch to be reported")
	}
	if _, err := os.Stat(npppdStagePath); err == nil {
		t.Error("the stale staged config is still there to be installed")
	}
}
