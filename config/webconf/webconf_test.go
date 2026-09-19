package webconf

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validForm(overrides map[string]string) url.Values {
	v := url.Values{}
	d := Defaults()
	for _, f := range fields() {
		v.Set(f.Key, f.get(&d))
	}
	for k, o := range overrides {
		v.Set(k, o)
	}
	return v
}

// webPaths keeps a test's generated key pair inside its own temp dir instead
// of Defaults()' install-dir path.
func webPaths(dir string) map[string]string {
	return map[string]string{
		"webcert": filepath.Join(dir, "webconf.crt"),
		"webkey":  filepath.Join(dir, "webconf.key"),
	}
}

func formIn(dir string, overrides map[string]string) url.Values {
	m := webPaths(dir)
	for k, v := range overrides {
		m[k] = v
	}
	return validForm(m)
}

func post(t *testing.T, srv *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("adm", "sekrit")
	w := httptest.NewRecorder()
	srv.auth(srv.handleIndex)(w, r)
	return w
}

func newSrv(t *testing.T, path string) (*Store, *Server) {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	srv, err := NewServer(store, "adm", "sekrit")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return store, srv
}

func TestMissingFileStaysUnconfigured(t *testing.T) {
	store, _ := newSrv(t, filepath.Join(t.TempDir(), "settings.json"))
	if store.Configured() {
		t.Fatal("want unconfigured with no settings file")
	}
	select {
	case <-store.Ready():
		t.Fatal("Ready closed before any save")
	default:
	}
	if got := store.Get().MaxBuff; got != 1024 {
		t.Fatalf("want defaults pre-filled, got maxbuff %d", got)
	}
}

func TestEmptyPasswordRefused(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(store, "adm", ""); err == nil {
		t.Fatal("want error for empty password")
	}
	if _, err := NewServer(store, "  ", "pw"); err == nil {
		t.Fatal("want error for empty admin")
	}
}

func TestAuthRequired(t *testing.T) {
	_, srv := newSrv(t, filepath.Join(t.TempDir(), "settings.json"))

	for _, tc := range []struct{ name, user, pass string }{
		{"no creds", "", ""},
		{"wrong pass", "adm", "nope"},
		{"wrong user", "root", "sekrit"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.user != "" {
			r.SetBasicAuth(tc.user, tc.pass)
		}
		w := httptest.NewRecorder()
		srv.auth(srv.handleIndex)(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", tc.name, w.Code)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("adm", "sekrit")
	w := httptest.NewRecorder()
	srv.auth(srv.handleIndex)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated GET got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "arkgated configurator") {
		t.Error("form did not render")
	}
	if !strings.Contains(w.Body.String(), "Not configured yet") {
		t.Error("want the unconfigured banner")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("want Cache-Control: no-store")
	}
}

func TestSaveWritesSettingsAndUnblocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	store, srv := newSrv(t, path)

	w := post(t, srv, validForm(map[string]string{
		"srvcurl":     "https://srvcman.example/api/v1", // no trailing slash
		"rundir":      "/var/arkgate",                   // no trailing slash
		"apiuser":     "apiacct",
		"apipassword": "s3cret",
		"maxbuff":     "4096",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("save got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Saved.") {
		t.Fatalf("no save confirmation:\n%s", w.Body.String())
	}

	if !store.Configured() {
		t.Fatal("still unconfigured after a valid save")
	}
	select {
	case <-store.Ready():
	default:
		t.Fatal("Ready not closed after first save")
	}

	got := store.Get()
	if got.SrvcURL != "https://srvcman.example/api/v1/" {
		t.Errorf("srvcurl not normalized: %q", got.SrvcURL)
	}
	if got.RunDir != "/var/arkgate/" {
		t.Errorf("rundir not normalized: %q", got.RunDir)
	}
	if got.MaxBuff != 4096 {
		t.Errorf("maxbuff = %d", got.MaxBuff)
	}

	// Persisted, and re-openable as configured.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Settings
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("settings file is not valid JSON: %v", err)
	}
	if onDisk.APIUser != "apiacct" || onDisk.APIPassword != "s3cret" {
		t.Errorf("API credentials not persisted: %q / %q", onDisk.APIUser, onDisk.APIPassword)
	}
	// The pre-split base64 form must not be written back.
	if onDisk.Creds != "" {
		t.Errorf("legacy creds key should not be persisted, got %q", onDisk.Creds)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("settings file mode %04o, want 0600", perm)
		}
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Configured() {
		t.Fatal("reopened store should be configured")
	}
}

func TestInvalidSaveChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	store, srv := newSrv(t, path)

	// Seed a good config first.
	post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "good"}))
	before := store.Get()

	for _, tc := range []struct {
		name string
		form url.Values
		want string
	}{
		{"tiny maxbuff", validForm(map[string]string{"maxbuff": "8"}), "at least 64"},
		{"maxbuff not a number", validForm(map[string]string{"maxbuff": "lots"}), "whole number"},
		{"bad listenaddr", validForm(map[string]string{"listenaddr": "8443"}), "host:port"},
		{"empty client CA", validForm(map[string]string{"tlsclientca": ""}), "Client CA"},
		{"bad srvcurl scheme", validForm(map[string]string{"srvcurl": "ftp://x/"}), "http://"},
	} {
		w := post(t, srv, tc.form)
		body := w.Body.String()
		if !strings.Contains(body, "Nothing was saved") {
			t.Errorf("%s: expected rejection, got:\n%s", tc.name, body)
			continue
		}
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s: body missing %q", tc.name, tc.want)
		}
		if store.Get() != before {
			t.Errorf("%s: live settings changed despite rejection", tc.name)
		}
	}
}

func TestBlankSecretKeepsStoredCreds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	store, srv := newSrv(t, path)

	post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "original"}))

	// Blank password means "keep the stored one"; the username is an ordinary
	// text field and has to be resubmitted like any other.
	w := post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "", "maxbuff": "2048"}))
	if !strings.Contains(w.Body.String(), "Saved.") {
		t.Fatalf("blank secret should not fail validation:\n%s", w.Body.String())
	}
	if got := store.Get().APIPassword; got != "original" {
		t.Errorf("api password = %q, want the stored value kept", got)
	}
	if got := store.Get().APIUser; got != "u" {
		t.Errorf("api user = %q, want it unchanged", got)
	}
	if got := store.Get().MaxBuff; got != 2048 {
		t.Errorf("maxbuff = %d, want the other edit to land", got)
	}
	if strings.Contains(w.Body.String(), "original") {
		t.Error("the stored credential was echoed back into the page")
	}
}

func TestRestartWarningOnlyForStartupSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	_, srv := newSrv(t, path)

	// First save: nothing is bound yet, so nothing needs a restart.
	w := post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "p"}))
	if strings.Contains(w.Body.String(), "only take effect after a restart") {
		t.Error("first save should not ask for a restart")
	}

	// maxbuff is read per connection.
	w = post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "p", "maxbuff": "2048"}))
	if strings.Contains(w.Body.String(), "only take effect after a restart") {
		t.Error("maxbuff change should not need a restart")
	}

	// listenaddr is read once, when the socket is bound.
	w = post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "p", "maxbuff": "2048", "listenaddr": "10.0.0.1:9443"}))
	body := w.Body.String()
	if !strings.Contains(body, "only take effect after a restart") {
		t.Fatalf("listenaddr change should need a restart:\n%s", body)
	}
	if !strings.Contains(body, "mTLS listen address") {
		t.Error("restart list should name the changed setting")
	}
}

func TestCrossOriginSaveRejected(t *testing.T) {
	_, srv := newSrv(t, filepath.Join(t.TempDir(), "settings.json"))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(validForm(nil).Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://evil.example")
	r.SetBasicAuth("adm", "sekrit")
	w := httptest.NewRecorder()
	srv.auth(srv.handleIndex)(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST got %d, want 403", w.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(validForm(map[string]string{"apiuser": "u", "apipassword": "p"}).Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+r.Host)
	r.SetBasicAuth("adm", "sekrit")
	w = httptest.NewRecorder()
	srv.auth(srv.handleIndex)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("same-origin POST got %d", w.Code)
	}
}

func TestReloadRejectsBrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	store, srv := newSrv(t, path)
	post(t, srv, validForm(map[string]string{"apiuser": "u", "apipassword": "p"}))
	before := store.Get()

	if err := os.WriteFile(path, []byte(`{"maxbuff": 1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("want an error reloading unusable settings")
	}
	if store.Get() != before {
		t.Error("a failed reload must leave the live settings alone")
	}

	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("want an error reloading malformed JSON")
	}
}

// freePort grabs an ephemeral port and releases it, so ListenAndServe can be
// pointed at a known address (it reads WebAddr from the settings, and there
// is no way to ask it which port it landed on afterwards).
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestListenAndServeAndShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	store, srv := newSrv(t, path)

	dir := filepath.Dir(path)
	addr := freePort(t)
	post(t, srv, formIn(dir, map[string]string{"apiuser": "u", "apipassword": "p", "webaddr": addr}))
	if store.Get().WebAddr != addr {
		t.Fatalf("webaddr = %q, want %q", store.Get().WebAddr, addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	// The generated cert is self-signed by design, so the test client has to
	// skip verification - what it is checking is that TLS is served at all,
	// and separately (below) that the cert is the one on disk.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	base := "https://" + addr + "/"
	var res *http.Response
	var err error
	for i := 0; i < 100; i++ {
		res, err = client.Get(base)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("configurator never came up on %s: %v", addr, err)
	}

	// Plain HTTP must not reach the app: there is no plaintext listener to
	// fall back to, and an admin password must never cross one. Go's TLS
	// server answers a plaintext request with a 400 rather than dropping it,
	// so what matters is that it is neither the page (200) nor even the auth
	// challenge (401).
	if plain, perr := http.Get("http://" + addr + "/"); perr == nil {
		defer plain.Body.Close()
		if plain.StatusCode == http.StatusOK || plain.StatusCode == http.StatusUnauthorized {
			t.Errorf("configurator answered a plaintext request with %d", plain.StatusCode)
		}
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET got %d, want 401", res.StatusCode)
	}
	if !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("missing Basic challenge: %q", res.Header.Get("WWW-Authenticate"))
	}

	req, _ := http.NewRequest(http.MethodGet, base, nil)
	req.SetBasicAuth("adm", "sekrit")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authenticated GET got %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "Save settings") {
		t.Error("served page has no form")
	}

	// The page has to show the fingerprint of the cert it is actually served
	// with, or an admin has nothing to compare the browser warning against.
	onDisk, err := inspectCert(store.Get().WebCert)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), onDisk.Fingerprint) {
		t.Errorf("page does not show the served certificate's fingerprint %s", onDisk.Fingerprint)
	}
	if !strings.Contains(string(body), "Self-signed certificate") {
		t.Error("page should flag that the certificate is self-signed")
	}
	if len(res.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificates on the TLS connection")
	}
	sum := sha256.Sum256(res.TLS.PeerCertificates[0].Raw)
	if got := colonHex(sum[:]); got != onDisk.Fingerprint {
		t.Errorf("served cert %s does not match the one on disk %s", got, onDisk.Fingerprint)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ListenAndServe returned %v, want nil on shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return after ctx cancel")
	}
}

func TestEnsureWebCertGeneratesThenReuses(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "webconf.crt")
	key := filepath.Join(dir, "webconf.key")

	ci, err := ensureWebCert(crt, key, "0.0.0.0:1443")
	if err != nil {
		t.Fatalf("ensureWebCert: %v", err)
	}
	if !ci.Generated || !ci.SelfSigned {
		t.Errorf("want a generated self-signed cert, got %+v", ci)
	}
	if ci.Fingerprint == "" {
		t.Error("no fingerprint")
	}
	if ci.Expiring() {
		t.Errorf("a freshly generated cert should not be near expiry (%s)", ci.NotAfter)
	}

	// It must actually load as a TLS key pair - a cert that parses but does
	// not pair with its key would only fail later, at bind time.
	if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(key)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("key mode %04o, want 0600", perm)
		}
	}

	// A second call must reuse what is on disk, not mint a new key.
	again, err := ensureWebCert(crt, key, "0.0.0.0:1443")
	if err != nil {
		t.Fatal(err)
	}
	if again.Generated {
		t.Error("second call regenerated the cert")
	}
	if again.Fingerprint != ci.Fingerprint {
		t.Errorf("fingerprint changed on reuse: %s -> %s", ci.Fingerprint, again.Fingerprint)
	}
}

func TestGeneratedCertCoversLoopbackAndBindAddress(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "c.crt")
	key := filepath.Join(dir, "c.key")

	if _, err := ensureWebCert(crt, key, "10.9.8.7:8443"); err != nil {
		t.Fatal(err)
	}
	pemBytes, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Verifying against itself is the check that matters: it is what a
	// browser does once an admin imports this as a trust anchor.
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	for _, host := range []string{"127.0.0.1", "10.9.8.7", "localhost"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
			t.Errorf("cert not valid for %s: %v", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "10.0.0.1", Roots: pool}); err == nil {
		t.Error("cert should not be valid for an unrelated address")
	}
	if !leaf.IsCA {
		t.Error("want IsCA so the cert can be imported as a trust anchor")
	}
	if leaf.NotBefore.After(time.Now()) {
		t.Error("NotBefore should be backdated for clock skew")
	}
}

func TestInstalledCertIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "c.crt")
	key := filepath.Join(dir, "c.key")

	if _, err := ensureWebCert(crt, key, "127.0.0.1:1443"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := ensureWebCert(crt, key, "127.0.0.1:1443"); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("an existing certificate was overwritten")
	}
}

func TestWebCertIsIndependentOfMTLSPair(t *testing.T) {
	dir := t.TempDir()
	store, srv := newSrv(t, filepath.Join(dir, "settings.json"))

	// Settings must accept mTLS paths that do not exist and are unrelated to
	// the configurator's own pair - the two boundaries are separate, and the
	// configurator has to come up before any PKI material is provisioned.
	w := post(t, srv, formIn(dir, map[string]string{
		"apiuser":     "u",
		"apipassword": "p",
		"tlscert":     "/etc/ssl/ipc-only.crt",
		"tlskey":      "/etc/ssl/ipc-only.key",
		"tlsclientca": "/etc/ssl/srvcman-ca.crt",
	}))
	if !strings.Contains(w.Body.String(), "Saved.") {
		t.Fatalf("save rejected:\n%s", w.Body.String())
	}

	got := store.Get()
	if got.WebCert == got.TLSCert || got.WebKey == got.TLSKey {
		t.Error("configurator and mTLS pairs should not be the same files")
	}

	// Generating the configurator's pair must not touch the mTLS paths.
	if _, err := ensureWebCert(got.WebCert, got.WebKey, got.WebAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(got.TLSCert); !os.IsNotExist(err) {
		t.Errorf("ensureWebCert created or touched the mTLS cert path (%v)", err)
	}
}

func TestValidateRejectsSharedOrMissingWebPair(t *testing.T) {
	dir := t.TempDir()
	_, srv := newSrv(t, filepath.Join(dir, "settings.json"))

	for _, tc := range []struct {
		name string
		form url.Values
		want string
	}{
		{"no cert", formIn(dir, map[string]string{"apiuser": "u", "apipassword": "p", "webcert": ""}), "certificate path is required"},
		{"no key", formIn(dir, map[string]string{"apiuser": "u", "apipassword": "p", "webkey": ""}), "key path is required"},
		{"same file", formIn(dir, map[string]string{
			"apiuser":     "u",
			"apipassword": "p",
			"webcert":     filepath.Join(dir, "both.pem"),
			"webkey":      filepath.Join(dir, "both.pem"),
		}), "must be different files"},
	} {
		w := post(t, srv, tc.form)
		body := w.Body.String()
		if !strings.Contains(body, "Nothing was saved") || !strings.Contains(body, tc.want) {
			t.Errorf("%s: expected rejection mentioning %q, got:\n%s", tc.name, tc.want, body)
		}
	}
}

func TestDefaultWebAddrBindsAllAddresses(t *testing.T) {
	d := Defaults()
	if d.WebAddr != "0.0.0.0:1443" {
		t.Errorf("WebAddr default = %q, want 0.0.0.0:1443", d.WebAddr)
	}
	if d.LoopbackWeb() {
		t.Error("the default bind is not loopback-only")
	}
	// Still a valid setting, and still HTTPS-only with a mandatory password -
	// widening the bind must not have loosened anything else.
	d.APIUser, d.APIPassword = "u", "p"
	if errs := d.Validate(); len(errs) > 0 {
		t.Errorf("defaults should validate, got %v", errs)
	}
}

// With a wildcard bind - now the default - the certificate has to cover the
// address an admin actually types, which is the box's own LAN address rather
// than 127.0.0.1. certNames enumerates the host's unicast addresses for that.
func TestWildcardBindCertCoversLocalAddresses(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "c.crt")
	key := filepath.Join(dir, "c.key")

	if _, err := ensureWebCert(crt, key, "0.0.0.0:1443"); err != nil {
		t.Fatal(err)
	}
	pemBytes, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Find a real non-loopback address on this machine and require the cert
	// to cover it. Skip only if the machine genuinely has none.
	var want net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() && n.IP.To4() != nil {
			want = n.IP
			break
		}
	}
	if want == nil {
		t.Skip("no non-loopback IPv4 address on this host to check against")
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: want.String(), Roots: pool}); err != nil {
		t.Errorf("cert does not cover this host's own address %s: %v", want, err)
	}
	// Loopback must keep working too, for an ssh-tunnelled admin.
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: pool}); err != nil {
		t.Errorf("cert should still cover loopback: %v", err)
	}
}

func TestAPICredentialsAreSeparateFieldsNotBase64(t *testing.T) {
	// The whole point of the split: an operator types a username and a
	// password, never a base64 blob.
	keys := map[string]kind{}
	for _, f := range fields() {
		keys[f.Key] = f.Kind
	}
	if k, ok := keys["apiuser"]; !ok || k != kindText {
		t.Errorf("apiuser should be a plain text field, got %q ok=%v", k, ok)
	}
	if k, ok := keys["apipassword"]; !ok || k != kindSecret {
		t.Errorf("apipassword should be a secret field, got %q ok=%v", k, ok)
	}
	if _, ok := keys["creds"]; ok {
		t.Error("the pre-split creds field should no longer be offered in the form")
	}

	// Both halves are required, since srvcman's login is Basic auth.
	d := Defaults()
	errs := strings.Join(d.Validate(), "\n")
	if !strings.Contains(errs, "API username is required") {
		t.Errorf("missing username should be an error, got: %v", errs)
	}
	if !strings.Contains(errs, "API password is required") {
		t.Errorf("missing password should be an error, got: %v", errs)
	}
}

func TestLegacyBase64CredsMigrates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	// A settings.json from before the split: one base64 "user:password".
	old := Defaults()
	old.RunDir = dir + "/"
	old.WebCert = filepath.Join(dir, "w.crt")
	old.WebKey = filepath.Join(dir, "w.key")
	old.Creds = base64.StdEncoding.EncodeToString([]byte("apiacct:s3cret"))
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Get()
	if got.APIUser != "apiacct" || got.APIPassword != "s3cret" {
		t.Fatalf("migrated to %q / %q, want apiacct / s3cret", got.APIUser, got.APIPassword)
	}
	if got.Creds != "" {
		t.Errorf("legacy value should be cleared after migration, got %q", got.Creds)
	}
	// Migration alone must make the settings usable - no re-typing required.
	if !store.Configured() {
		t.Error("a migrated settings file should be configured")
	}

	// And it must not be written back in the old form.
	if _, _, err := store.Save(store.Get()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"creds"`) {
		t.Errorf("settings.json still carries a creds key:\n%s", raw)
	}
}

func TestLegacyCredsGarbageIsDroppedNotCarried(t *testing.T) {
	// The old -creds flag defaulted to "./rundir/", which is not valid base64
	// and was never a usable Basic value. It must surface as a missing
	// credential, not be forwarded to srvcman to fail as a 401.
	for _, bad := range []string{"./rundir/", "notbase64!!", base64.StdEncoding.EncodeToString([]byte("nocolon"))} {
		s := Defaults()
		s.Creds = bad
		migrated, garbage := s.migrateLegacyCreds()
		if migrated {
			t.Errorf("%q should not migrate", bad)
		}
		if !garbage {
			t.Errorf("%q should be reported as unusable", bad)
		}
		if s.APIUser != "" || s.APIPassword != "" {
			t.Errorf("%q left credentials %q/%q", bad, s.APIUser, s.APIPassword)
		}
		if s.Creds != "" {
			t.Errorf("%q should be cleared", bad)
		}
	}
}

func TestExplicitCredentialsBeatLegacyCreds(t *testing.T) {
	// A file carrying both must keep the new fields; the legacy value is only
	// a fallback for files that predate them.
	s := Defaults()
	s.APIUser, s.APIPassword = "newuser", "newpass"
	s.Creds = base64.StdEncoding.EncodeToString([]byte("olduser:oldpass"))
	if migrated, _ := s.migrateLegacyCreds(); migrated {
		t.Error("should not migrate over explicit credentials")
	}
	if s.APIUser != "newuser" || s.APIPassword != "newpass" {
		t.Errorf("explicit credentials were overwritten: %q / %q", s.APIUser, s.APIPassword)
	}
}
