package pfconfig

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestPfCreateExemptsVPNTrafficFromNoDF drives PfCreate for real against a
// fake srvcman (GetSubs is a plain HTTP GET, easy to stub) and inspects the
// exact scrub lines it generates - the closest verification available in
// this environment without a real OpenBSD box to run pfctl -nf against.
//
// This exists because getting this wrong is silent: a typo in the pf.conf
// text compiles and runs fine in Go, and only fails - or worse, doesn't fail
// but doesn't exempt anything - when pfctl actually parses the generated
// file on a real box.
func TestPfCreateExemptsVPNTrafficFromNoDF(t *testing.T) {
	minimalPfconfigJSON := `{
		"ifaces": [], "plans": [], "subs": [], "vouchers": [],
		"rules": [], "vlans": [], "pflows": [], "dhcps": [],
		"wifi_ip_list": "wifilist.txt",
		"subs_ip_list": "subslist.txt",
		"router": "testrouter"
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(minimalPfconfigJSON))
	}))
	defer srv.Close()

	// PfCreate writes to two hardcoded absolute paths regardless of the
	// rundir it's given - "/tmp/pf.conf" (see below) and
	// "/etc/npppd/npppd-users" - both pre-existing, unrelated to this
	// change. Real OpenBSD targets always have both directories; this
	// dev/test machine doesn't, so ensure they exist rather than let that
	// oddity fail a test that has nothing to do with it.
	for _, d := range []string{"tmp", "etc" + string(os.PathSeparator) + "npppd"} {
		if err := os.MkdirAll(string(os.PathSeparator)+d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir() + string(os.PathSeparator)
	tok := "tok"
	if err := PfCreate("testrouter", dir, srv.URL+"/", &tok); err != nil {
		t.Fatalf("PfCreate: %v", err)
	}

	// PfCreate currently writes the rendered pf.conf to a hardcoded
	// "/tmp/pf.conf" rather than rundir+"pf.conf" - a separate, pre-existing
	// oddity unrelated to this test (dir above is what PfCreate was given as
	// rundir, but this one write doesn't use it). Read from the literal path
	// PfCreate actually used, not from dir, so this test reflects PfCreate's
	// real current behavior rather than what it arguably should do.
	out, err := os.ReadFile("/tmp/pf.conf")
	if err != nil {
		t.Fatalf("reading generated pf.conf: %v", err)
	}
	t.Cleanup(func() { os.Remove("/tmp/pf.conf") })
	got := string(out)

	wantLines := []string{
		`match in proto { tcp, udp } scrub (no-df random-id max-mss 1440)`,
		`match in proto { esp, ah, gre } scrub (random-id)`,
		`match in proto udp to any port { 500, 4500, 1194, 51820 } scrub (random-id)`,
	}
	for _, want := range wantLines {
		if !strings.Contains(got, want) {
			t.Errorf("generated pf.conf missing exact line:\n  %s\ngot pf.conf:\n%s", want, got)
		}
	}

	// The general rule must precede the VPN-exception rules: pf's "sticky
	// until explicitly overridden" scrub semantics mean the LAST matching
	// rule for a given packet wins, so if the exception rules came first,
	// the general rule (which matches everything, including VPN traffic,
	// since it has no exclusion of its own - the exclusion only exists
	// because the *later* rules override it) would run last and silently
	// re-apply no-df/max-mss to VPN traffic, making this whole change a
	// no-op.
	generalIdx := strings.Index(got, wantLines[0])
	espIdx := strings.Index(got, wantLines[1])
	udpIdx := strings.Index(got, wantLines[2])
	if generalIdx < 0 || espIdx < 0 || udpIdx < 0 {
		t.Fatal("one or more scrub lines not found, cannot check ordering")
	}
	if !(generalIdx < espIdx && espIdx < udpIdx) {
		t.Errorf("scrub rules are in the wrong order (general=%d esp=%d udp=%d) - the general rule must come first or the exceptions get overridden right back", generalIdx, espIdx, udpIdx)
	}

	// The three protocols/ports that must NOT carry no-df or max-mss: esp,
	// ah, gre must never appear in the SAME line as "no-df", and the same
	// for the VPN UDP ports.
	for _, tc := range []struct{ proto, forbidden string }{
		{"esp, ah, gre", "no-df"},
		{"esp, ah, gre", "max-mss"},
		{"500, 4500, 1194, 51820", "no-df"},
		{"500, 4500, 1194, 51820", "max-mss"},
	} {
		for _, line := range strings.Split(got, "\n") {
			if strings.Contains(line, tc.proto) && strings.Contains(line, tc.forbidden) {
				t.Errorf("line for %q must not carry %q: %s", tc.proto, tc.forbidden, line)
			}
		}
	}
}
