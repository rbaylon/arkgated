// Package webconf owns every runtime setting arkgated used to take as a
// command-line flag, plus the web configurator that edits them (see
// server.go). Flags are gone: the only things still passed on the command
// line (or via ARKGATED_WEBADMIN/ARKGATED_WEBPASS, or a -config file) are
// the credentials for the configurator itself, because there is nowhere
// else to bootstrap them from.
//
// Everything else lives in a JSON file at Path. That path is a compile-time
// constant on purpose: -rundir is no longer a flag, so no setting can tell
// the daemon where its settings are without a chicken-and-egg problem. Path
// sits in the install dir the Makefile's distdir already uses.
package webconf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Path is where the settings JSON is read from and written to. See the
// package comment for why this is not itself configurable.
const Path = "/usr/local/arkgate/arkgated/settings.json"

// Settings is the whole of arkgated's runtime configuration - one field per
// flag main.go used to parse. JSON names match the old flag names, so a
// hand-written settings.json reads the way those flags did.
type Settings struct {
	SocketFile  string `json:"socketfile"`
	ArkGid      int    `json:"arkgid"`
	MaxBuff     int    `json:"maxbuff"`
	SrvcURL     string `json:"srvcurl"`
	ListenAddr  string `json:"listenaddr"`
	TLSCert     string `json:"tlscert"`
	TLSKey      string `json:"tlskey"`
	TLSClientCA string `json:"tlsclientca"`
	RunDir      string `json:"rundir"`
	APIUser     string `json:"apiuser"`
	APIPassword string `json:"apipassword"`
	WebAddr     string `json:"webaddr"`
	WebCert     string `json:"webcert"`
	WebKey      string `json:"webkey"`

	// Creds is the pre-split form of APIUser/APIPassword: one base64
	// "user:password" string, passed verbatim after "Basic ". It is only read,
	// never written - Open migrates it into the two fields above and clears it,
	// so an existing settings.json keeps working across the change. Once no
	// deployment has one of these left, this field can go.
	Creds string `json:"creds,omitempty"`
}

// migrateLegacyCreds moves a pre-split base64 "creds" value into APIUser and
// APIPassword, and reports whether it did. Anything that will not decode into
// "user:password" is dropped rather than carried forward: the old -creds flag
// defaulted to "./rundir/", which was never a valid Basic value, so a garbage
// value here is expected and should surface as "API username is required"
// rather than as a silent 401 from srvcman later.
func (s *Settings) migrateLegacyCreds() (migrated bool, hadGarbage bool) {
	legacy := s.Creds
	s.Creds = ""
	if legacy == "" || s.APIUser != "" || s.APIPassword != "" {
		return false, false
	}
	raw, err := base64.StdEncoding.DecodeString(legacy)
	if err != nil {
		return false, true
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false, true
	}
	s.APIUser, s.APIPassword = user, pass
	return true, false
}

// Defaults are the values the removed flags defaulted to, so an operator who
// saves the form untouched gets exactly the daemon that running ./arkgated
// with no arguments used to produce.
//
// The WebAddr/WebCert/WebKey group is new. The configurator binds all
// addresses, because on an arkgate box pf is the boundary that matters: the
// pf.conf this daemon generates is "block all" with explicit inbound passes
// (22, DNS, the portal ports, bootp) and none for this port, so the listener
// is not reachable from anywhere pf does not allow. It is always HTTPS and
// always password-protected regardless.
//
// The port is 1443 rather than anything in the 8080 range on purpose: the
// generated subscriber plan rules pass "to any port { 5060, 8080 }", and
// because that is "to any" it includes the router itself - so a configurator
// on 8080 would be reachable by any subscriber in a plan table, with pf
// passing it rather than blocking it. Nothing in the generated ruleset passes
// 1443, so it stays behind the default block. Check config/pf/pf.go before
// changing this default.
//
// Its key pair is deliberately its own, not the mTLS pair above: that one
// authenticates srvcman to this daemon, this one authenticates this daemon to
// an admin's browser. Different peers, different rotation schedules, different
// consequences if one leaks - see ensureWebCert, which generates a self-signed
// pair here on first start. Binding 0.0.0.0 is also why ensureWebCert
// enumerates this host's real addresses into the certificate's SANs: an admin
// browses to the box's LAN address, not to 127.0.0.1.
func Defaults() Settings {
	return Settings{
		SocketFile:  "/tmp/arkgated.sock",
		ArkGid:      1001,
		MaxBuff:     1024,
		SrvcURL:     "http://127.0.0.1/api/v1/",
		ListenAddr:  "0.0.0.0:8443",
		TLSCert:     "./rundir/arkgated.crt",
		TLSKey:      "./rundir/arkgated.key",
		TLSClientCA: "./rundir/ca.crt",
		RunDir:      "./rundir/",
		WebAddr:     "0.0.0.0:1443",
		WebCert:     filepath.Join(filepath.Dir(Path), "webconf.crt"),
		WebKey:      filepath.Join(filepath.Dir(Path), "webconf.key"),
	}
}

// Normalize fixes up the forms of a Settings that the rest of the daemon
// assumes rather than checks. RunDir and SrvcURL especially are used as bare
// string prefixes throughout config/pf and srvclient (rundir+"config.json",
// urlbase+"login"), so a missing trailing slash silently produces paths and
// URLs one level up - far easier to append it here than to audit every
// concatenation.
func (s *Settings) Normalize() {
	s.SocketFile = strings.TrimSpace(s.SocketFile)
	s.SrvcURL = strings.TrimSpace(s.SrvcURL)
	s.ListenAddr = strings.TrimSpace(s.ListenAddr)
	s.TLSCert = strings.TrimSpace(s.TLSCert)
	s.TLSKey = strings.TrimSpace(s.TLSKey)
	s.TLSClientCA = strings.TrimSpace(s.TLSClientCA)
	s.RunDir = strings.TrimSpace(s.RunDir)
	s.APIUser = strings.TrimSpace(s.APIUser)
	s.WebAddr = strings.TrimSpace(s.WebAddr)
	s.WebCert = strings.TrimSpace(s.WebCert)
	s.WebKey = strings.TrimSpace(s.WebKey)

	if s.RunDir != "" && !strings.HasSuffix(s.RunDir, "/") {
		s.RunDir += "/"
	}
	if s.SrvcURL != "" && !strings.HasSuffix(s.SrvcURL, "/") {
		s.SrvcURL += "/"
	}
}

// Validate reports every problem with s at once rather than the first, since
// it backs a web form that should show all the bad fields in one pass. Call
// Normalize first.
func (s *Settings) Validate() []string {
	var errs []string

	if s.SrvcURL == "" {
		errs = append(errs, "Service manager url is required")
	} else if u, err := url.Parse(s.SrvcURL); err != nil {
		errs = append(errs, "Service manager url is not a valid URL: "+err.Error())
	} else if u.Scheme != "http" && u.Scheme != "https" {
		errs = append(errs, "Service manager url must start with http:// or https://")
	} else if u.Host == "" {
		errs = append(errs, "Service manager url is missing a host")
	}

	// Both halves are needed: srvcman's login is HTTP Basic, and arkgated can
	// do nothing at all (no enroll, no GetSubs, no config generation) without a
	// token.
	if s.APIUser == "" {
		errs = append(errs, "API username is required - without it arkgated can never log in to srvcman")
	}
	if s.APIPassword == "" {
		errs = append(errs, "API password is required - without it arkgated can never log in to srvcman")
	}

	// The mTLS listener is not optional: main.go has always treated a
	// failure to build its tls.Config as fatal, so refuse settings that
	// could only ever produce that.
	if s.ListenAddr == "" {
		errs = append(errs, "IPC listen address is required")
	} else if _, _, err := net.SplitHostPort(s.ListenAddr); err != nil {
		errs = append(errs, "IPC listen address must be host:port: "+err.Error())
	}
	if s.TLSCert == "" {
		errs = append(errs, "TLS server certificate path is required")
	}
	if s.TLSKey == "" {
		errs = append(errs, "TLS server key path is required")
	}
	if s.TLSClientCA == "" {
		errs = append(errs, "Client CA certificate path is required - it is the only thing authenticating remote clients")
	}

	if s.RunDir == "" {
		errs = append(errs, "Rundir is required")
	}

	// maxbuff sizes the single read that has to swallow a whole Arkcmd JSON
	// payload; anything tiny silently truncates commands into unmarshal
	// errors instead of failing loudly here.
	if s.MaxBuff < 64 {
		errs = append(errs, "Max buffer size must be at least 64 bytes")
	}
	if s.ArkGid < 0 {
		errs = append(errs, "arkgate group id cannot be negative")
	}

	if s.WebAddr == "" {
		errs = append(errs, "Configurator listen address is required")
	} else if _, _, err := net.SplitHostPort(s.WebAddr); err != nil {
		errs = append(errs, "Configurator listen address must be host:port: "+err.Error())
	}
	// The configurator is always HTTPS, so it always needs somewhere to keep
	// a key pair - ensureWebCert generates one there if the files are
	// missing. Pointing these at the mTLS pair above would work, but don't:
	// that pair exists to authenticate srvcman to this daemon, and tying the
	// admin UI to it means an IPC cert rotation locks you out of the UI.
	if s.WebCert == "" {
		errs = append(errs, "Configurator certificate path is required")
	}
	if s.WebKey == "" {
		errs = append(errs, "Configurator key path is required")
	}
	if s.WebCert != "" && s.WebCert == s.WebKey {
		errs = append(errs, "Configurator certificate and key must be different files")
	}

	return errs
}

// LoopbackWeb reports whether WebAddr binds loopback only. Off-loopback -
// which is the default - the certificate is what an admin has to verify by
// hand, so this decides whether startup bothers pointing at the fingerprint.
func (s *Settings) LoopbackWeb() bool {
	host, _, err := net.SplitHostPort(s.WebAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// restartScoped lists the settings main.go reads exactly once, at startup -
// the listeners it opens and the rundir it loads config.json (and therefore
// pfcfg.Router) from. Editing these in the configurator writes them to disk
// but cannot move an already-bound socket, so the UI has to say so; SIGHUP
// re-reads the file but deliberately does not re-listen.
var restartScoped = map[string]bool{
	"socketfile":  true,
	"arkgid":      true,
	"listenaddr":  true,
	"tlscert":     true,
	"tlskey":      true,
	"tlsclientca": true,
	"rundir":      true,
	"webaddr":     true,
	"webcert":     true,
	"webkey":      true,
}

// Store holds the live Settings for the whole process. The configurator
// writes through it from its own goroutine while the accept loops and the
// token refresher read from it, so every read hands back a copy under the
// lock rather than a pointer into shared state.
type Store struct {
	mu         sync.RWMutex
	path       string
	cur        Settings
	configured bool

	readyOnce sync.Once
	ready     chan struct{}

	// changed is closed and replaced on every successful Save, as a
	// broadcast to anything waiting for the operator to correct a setting -
	// see Changed.
	changed chan struct{}
}

// Open returns a Store for the settings file at path. A missing file is not
// an error: the Store comes back unconfigured and pre-filled with Defaults,
// and the daemon is expected to wait on Ready while the operator fills in the
// web form.
func Open(path string) (*Store, error) {
	s := &Store{path: path, ready: make(chan struct{}), changed: make(chan struct{})}

	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		s.cur = Defaults()
		return s, nil
	}

	// Start from Defaults so a settings file written by an older build (or
	// trimmed by hand) picks up sensible values for absent keys instead of
	// Go zero values - a maxbuff of 0 would fail every read.
	cur := Defaults()
	if err := json.Unmarshal(b, &cur); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if migrated, garbage := cur.migrateLegacyCreds(); migrated {
		log.Printf("Migrated the legacy base64 %q setting into apiuser/apipassword; it will be written in the new form on the next save.", "creds")
	} else if garbage {
		log.Printf("Ignoring a legacy %q setting that is not base64 \"user:password\" - set the API username and password in the web configurator.", "creds")
	}
	cur.Normalize()
	if errs := cur.Validate(); len(errs) > 0 {
		// Keep the bad values so the form shows what needs fixing, but
		// stay unconfigured so the daemon waits rather than starting on
		// settings we already know cannot work.
		s.cur = cur
		return s, nil
	}
	s.cur = cur
	s.markConfigured()
	return s, nil
}

// Get returns a snapshot of the current settings.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Configured reports whether the settings on disk are present and valid -
// i.e. whether the daemon has anything to run with yet.
func (s *Store) Configured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configured
}

// Ready is closed as soon as the Store holds valid settings, whether they
// were already on disk at Open or arrived from the configurator's first
// save. main.go blocks on it before opening any listener.
func (s *Store) Ready() <-chan struct{} { return s.ready }

// Path is the settings file this Store reads and writes.
func (s *Store) Path() string { return s.path }

func (s *Store) markConfigured() {
	s.configured = true
	s.readyOnce.Do(func() { close(s.ready) })
}

// Save normalizes and validates n, writes it to disk, and makes it the live
// settings. Validation problems come back without disk or live state being
// touched, so a bad form submission changes nothing. changedRestart lists
// the restart-scoped settings that changed, for the UI to warn about.
func (s *Store) Save(n Settings) (errs []string, changedRestart []string, err error) {
	n.Normalize()
	if verrs := n.Validate(); len(verrs) > 0 {
		return verrs, nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.cur
	if err := writeSettings(s.path, n); err != nil {
		return nil, nil, err
	}

	if s.configured {
		// Only meaningful once there are live listeners to be stale
		// relative to; on the very first save nothing is bound yet.
		for _, f := range fields() {
			if restartScoped[f.Key] && f.get(&prev) != f.get(&n) {
				changedRestart = append(changedRestart, f.Label)
			}
		}
	}

	s.cur = n
	s.markConfigured()
	s.broadcast()
	return nil, changedRestart, nil
}

// Changed returns a channel closed the next time settings are saved. Callers
// capture it *before* testing whatever they are waiting on, so a save that
// lands in between is not missed:
//
//	for {
//		ch := store.Changed()
//		if err := attempt(store.Get()); err == nil {
//			break
//		}
//		<-ch
//	}
//
// This exists because the configurator is now the only way to fix a setting.
// Anything that fails on a bad value has to stay alive and retry rather than
// exit, or the operator is locked out of the one tool that could correct it.
func (s *Store) Changed() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.changed
}

// broadcast wakes everything waiting on Changed. Caller holds s.mu.
func (s *Store) broadcast() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// Reload re-reads the settings file, replacing the live settings. This is
// what SIGHUP does - the same job the old c.init(os.Args) flag re-parse did,
// and with the same limits: it changes what later reads see, it does not
// re-open listeners or rebuild the TLS config.
func (s *Store) Reload() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", s.path, err)
	}
	cur := Defaults()
	if err := json.Unmarshal(b, &cur); err != nil {
		return fmt.Errorf("parsing %s: %w", s.path, err)
	}
	cur.migrateLegacyCreds()
	cur.Normalize()
	if errs := cur.Validate(); len(errs) > 0 {
		return fmt.Errorf("%s is not usable: %s", s.path, strings.Join(errs, "; "))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = cur
	s.markConfigured()
	s.broadcast()
	return nil
}

// writeSettings persists n at path via a temp file and a rename, so a crash
// or a full disk mid-write leaves the previous settings intact instead of a
// truncated file the daemon would refuse to start from. Mode 0600, since
// Creds is an API credential.
func writeSettings(path string, n Settings) error {
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming %s to %s: %w", tmp, path, err)
	}
	return nil
}
