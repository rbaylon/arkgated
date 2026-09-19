package webconf

import (
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Server is the web configurator: the replacement for arkgated's command-line
// flags. It is deliberately the only writer of the settings file, and it is
// protected by HTTP Basic auth with the admin/password given on the command
// line (or in ARKGATED_WEBADMIN/ARKGATED_WEBPASS, or a -config file).
//
// Editing these settings is equivalent to root on this box - rundir and
// tlsclientca in particular decide what config gets generated and who is
// allowed to make the daemon shell out - so the password is mandatory, the
// listener defaults to loopback, and it is always HTTPS.
//
// Its TLS material is its own (WebCert/WebKey), never the mTLS pair the IPC
// listener uses. Those two serve unrelated purposes: the mTLS pair proves
// srvcman's identity to this daemon over a machine-to-machine link, this one
// proves this daemon's identity to a human's browser. Sharing them would mean
// an IPC certificate rotation silently breaks the admin UI, and that the
// blast radius of either key leaking covers both boundaries.
type Server struct {
	store *Store
	user  string
	pass  string

	// cert describes what ListenAndServe ended up serving, for the
	// fingerprint shown on the page - an admin verifying a self-signed cert
	// has nothing else to compare against.
	cert certInfo

	// routerSaved fires when the router config (rundir/config.json) is saved,
	// so main can stop waiting for a file that did not exist yet. Settings
	// have Store.Changed for the same job; the router config is not in the
	// Store because pfconfig.Init owns that file and reads it from disk.
	routerSaved *broadcaster
}

// NewServer returns a configurator for store. An empty password is refused
// rather than defaulted: an unauthenticated configurator is the same thing as
// an unauthenticated root shell, and silently picking a default password
// would be worse than failing to start.
func NewServer(store *Store, user, pass string) (*Server, error) {
	if strings.TrimSpace(user) == "" {
		return nil, errors.New("web configurator admin username is required (-webadmin or ARKGATED_WEBADMIN)")
	}
	if pass == "" {
		return nil, errors.New("web configurator admin password is required (-webpass or ARKGATED_WEBPASS)")
	}
	return &Server{store: store, user: user, pass: pass, routerSaved: newBroadcaster()}, nil
}

// ListenAndServe serves the configurator over HTTPS until ctx is cancelled.
// The address and key pair are read from the settings once, here - changing
// either in the form needs a restart, which is what the form says.
//
// On a fresh box WebCert/WebKey do not exist yet (nothing has been configured,
// so nothing has provisioned them), and there is no plaintext fallback to drop
// to, so a self-signed pair is generated first. The fingerprint is logged
// because that log line is on the console the operator is already looking at,
// and it is the only way to tell a real first visit from an interception.
func (srv *Server) ListenAndServe(ctx context.Context) error {
	cur := srv.store.Get()

	ci, err := ensureWebCert(cur.WebCert, cur.WebKey, cur.WebAddr)
	if err != nil {
		return err
	}
	srv.cert = ci

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.auth(srv.handleIndex))
	mux.HandleFunc("/router", srv.auth(srv.handleRouter))

	hs := &http.Server{
		Addr:              cur.WebAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutCtx)
	}()

	log.Printf("Web configurator on https://%s (settings: %s)", cur.WebAddr, srv.store.Path())
	if ci.Generated {
		log.Printf("Generated a self-signed certificate for the configurator at %s (key %s)", cur.WebCert, cur.WebKey)
	}
	log.Printf("Web configurator certificate: %s", ci.Summary())
	if ci.SelfSigned && !cur.LoopbackWeb() {
		log.Printf("The configurator is reachable off-box with a self-signed certificate - your browser will warn. Check the SHA-256 above matches before accepting it, or install your own certificate at %s.", cur.WebCert)
	}
	if ci.Expiring() {
		log.Printf("WARNING: the configurator certificate expires %s and nothing rotates it automatically - replace %s, or delete it to have a fresh self-signed pair generated on the next start.", ci.NotAfter.Format("2006-01-02"), cur.WebCert)
	}

	if err := hs.ListenAndServeTLS(cur.WebCert, cur.WebKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// auth wraps h in Basic auth. Both username and password are compared in
// constant time, and a wrong password is logged with the peer address - this
// endpoint is worth noticing brute force against.
func (srv *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Never let a browser or proxy keep a copy of a page containing
		// the daemon's configuration.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		user, pass, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(srv.user)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(srv.pass)) == 1
		if !ok || !userOK || !passOK {
			if ok {
				log.Printf("Web configurator: failed login from %s", r.RemoteAddr)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="arkgated configurator", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// sameOrigin guards the POST against a browser that still holds Basic auth
// credentials being made to submit this form by another site. Requests with
// no Origin/Referer at all (curl, a deployment script) are allowed through -
// those carry no ambient credentials to abuse.
func sameOrigin(r *http.Request) bool {
	check := func(raw string) (bool, bool) {
		if raw == "" {
			return false, false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false, true
		}
		return u.Host == r.Host, true
	}
	if ok, present := check(r.Header.Get("Origin")); present {
		return ok
	}
	if ok, present := check(r.Header.Get("Referer")); present {
		return ok
	}
	return true
}

func (srv *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		srv.render(w, srv.page(srv.store.Get(), nil))
	case http.MethodPost:
		srv.handleSave(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (srv *Server) handleSave(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		log.Printf("Web configurator: rejected cross-origin save from %s", r.RemoteAddr)
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Start from the live settings so a field the form did not submit keeps
	// its current value rather than being zeroed.
	next := srv.store.Get()
	fieldErrs := map[string]string{}

	for _, f := range fields() {
		switch f.Kind {
		case kindSecret:
			// The form never echoes the stored credential back to the
			// browser, so an empty submission means "leave it alone"
			// rather than "clear it".
			if v := r.PostForm.Get(f.Key); v != "" {
				if err := f.set(&next, v); err != nil {
					fieldErrs[f.Key] = err.Error()
				}
			}
		default:
			if !r.PostForm.Has(f.Key) {
				continue
			}
			if err := f.set(&next, r.PostForm.Get(f.Key)); err != nil {
				fieldErrs[f.Key] = err.Error()
			}
		}
	}

	if len(fieldErrs) > 0 {
		p := srv.page(next, fieldErrs)
		p.Errors = []string{"Some fields could not be read - nothing was saved."}
		srv.render(w, p)
		return
	}

	errs, changedRestart, err := srv.store.Save(next)
	if err != nil {
		p := srv.page(next, nil)
		p.Errors = []string{"Could not write " + srv.store.Path() + ": " + err.Error()}
		srv.render(w, p)
		return
	}
	if len(errs) > 0 {
		p := srv.page(next, nil)
		p.Errors = errs
		srv.render(w, p)
		return
	}

	log.Printf("Web configurator: settings saved by %s", r.RemoteAddr)
	if len(changedRestart) > 0 {
		log.Printf("Web configurator: restart needed to apply: %s", strings.Join(changedRestart, ", "))
	}

	p := srv.page(srv.store.Get(), nil)
	p.Saved = true
	p.RestartNeeded = changedRestart
	srv.render(w, p)
}

type pageField struct {
	Key     string
	Label   string
	Help    string
	Value   string
	Kind    string
	Restart bool
	Err     string
	IsSet   bool
}

type pageGroup struct {
	Name   string
	Fields []pageField
}

type page struct {
	SettingsPath  string
	Configured    bool
	Groups        []pageGroup
	Errors        []string
	Saved         bool
	RestartNeeded []string
	CertSummary   string
	CertSelfSign  bool
}

// page builds the view model for s. vals that failed to parse are reported
// per-field through fieldErrs.
func (srv *Server) page(s Settings, fieldErrs map[string]string) page {
	p := page{
		SettingsPath: srv.store.Path(),
		Configured:   srv.store.Configured(),
		CertSummary:  srv.cert.Summary(),
		CertSelfSign: srv.cert.SelfSigned,
	}

	byGroup := map[string][]pageField{}
	for _, f := range fields() {
		pf := pageField{
			Key:     f.Key,
			Label:   f.Label,
			Help:    f.Help,
			Kind:    string(f.Kind),
			Restart: f.Restart,
			Err:     fieldErrs[f.Key],
		}
		switch f.Kind {
		case kindSecret:
			// Value stays empty on purpose - see handleSave.
			pf.IsSet = f.get(&s) != ""
		default:
			pf.Value = f.get(&s)
		}
		byGroup[f.Group] = append(byGroup[f.Group], pf)
	}
	for _, g := range Groups {
		if fs := byGroup[g]; len(fs) > 0 {
			p.Groups = append(p.Groups, pageGroup{Name: g, Fields: fs})
		}
	}
	return p
}

func (srv *Server) render(w http.ResponseWriter, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTmpl.Execute(w, p); err != nil {
		log.Println("Web configurator: rendering page:", err)
	}
}

var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

// pageHTML is the whole configurator UI. It is inline and dependency-free on
// purpose: this page has to work on a freshly-installed gateway with no
// outbound network access, before any of the settings it edits exist.
const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>arkgated configurator</title>
<style>
:root {
  --bg: #f4f5f7; --panel: #ffffff; --ink: #1b1f24; --muted: #5b6470;
  --line: #d9dde3; --accent: #1f6feb; --warn-bg: #fff6e0; --warn-ink: #7a4b00;
  --err-bg: #fdecec; --err-ink: #8c1c1c; --ok-bg: #e7f6ec; --ok-ink: #14562c;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14171c; --panel: #1c2027; --ink: #e8ebef; --muted: #98a2b0;
    --line: #2c323b; --accent: #5b9bff; --warn-bg: #3a2d10; --warn-ink: #f0d18a;
    --err-bg: #3a1a1a; --err-ink: #f3b0b0; --ok-bg: #16301f; --ok-ink: #9adcb4;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 860px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
nav { margin: 0 0 24px; font-size: 14px; }
nav a { color: var(--accent); text-decoration: none; margin-right: 16px; }
nav a.here { color: var(--ink); font-weight: 600; }
.sub code { font-size: 12px; }
section {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 20px; margin-bottom: 16px;
}
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 16px; }
.f { margin-bottom: 18px; }
.f:last-child { margin-bottom: 0; }
label { display: block; font-weight: 600; margin-bottom: 4px; }
.help { color: var(--muted); font-size: 13px; margin: 4px 0 0; }
input[type=text], input[type=number], input[type=password] {
  width: 100%; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--bg); color: var(--ink); font: inherit; font-size: 14px;
}
input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
.fp {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; word-break: break-all; margin: 8px 0;
}
.tag {
  display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 6px;
  border-radius: 4px; background: var(--warn-bg); color: var(--warn-ink);
  margin-left: 6px; vertical-align: 1px; text-transform: none; letter-spacing: 0;
}
.fieldErr { color: var(--err-ink); font-size: 13px; margin: 4px 0 0; font-weight: 600; }
.note { border-radius: 8px; padding: 12px 14px; margin-bottom: 16px; font-size: 14px; }
.note ul { margin: 6px 0 0; padding-left: 20px; }
.note.err { background: var(--err-bg); color: var(--err-ink); }
.note.ok { background: var(--ok-bg); color: var(--ok-ink); }
.note.warn { background: var(--warn-bg); color: var(--warn-ink); }
button {
  background: var(--accent); color: #fff; border: 0; border-radius: 6px;
  padding: 10px 18px; font: inherit; font-weight: 600; cursor: pointer;
}
button:hover { filter: brightness(1.08); }
footer { color: var(--muted); font-size: 12px; margin-top: 24px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>arkgated configurator</h1>
  <p class="sub">Every setting below used to be a command-line flag. Saved to <code>{{.SettingsPath}}</code> (mode 0600).</p>
  <nav><a class="here" href="/">Daemon settings</a><a href="/router">Router config</a></nav>

  {{if not .Configured}}
  <div class="note warn"><strong>Not configured yet.</strong> arkgated is holding off on opening its IPC listeners until these settings are saved once.</div>
  {{end}}

  {{if .Saved}}
  <div class="note ok"><strong>Saved.</strong>
    {{if .RestartNeeded}}These only take effect after a restart (<code>rcctl restart arkgated</code>), because arkgated reads them once, when it binds its listeners:
      <ul>{{range .RestartNeeded}}<li>{{.}}</li>{{end}}</ul>
    {{else}}Applied to the running daemon.{{end}}
  </div>
  {{end}}

  {{if .Errors}}
  <div class="note err"><strong>Nothing was saved.</strong>
    <ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>
  </div>
  {{end}}

  {{if .CertSelfSign}}
  <div class="note warn"><strong>Self-signed certificate.</strong> Your browser warned you before showing this page, and that warning is only safe to accept if this matches what it showed you:
    <p class="fp">{{.CertSummary}}</p>
    The same line is in arkgated's startup log. Install your own certificate below to stop the warning for good.</div>
  {{else}}
  <div class="note ok">Served over HTTPS with an installed certificate: <span class="fp">{{.CertSummary}}</span></div>
  {{end}}

  <form method="post" action="/">
    {{range .Groups}}
    <section>
      <h2>{{.Name}}</h2>
      {{range .Fields}}
      <div class="f">
        <label for="{{.Key}}">{{.Label}}{{if .Restart}}<span class="tag">restart</span>{{end}}</label>
        {{if eq .Kind "number"}}
        <input type="number" id="{{.Key}}" name="{{.Key}}" value="{{.Value}}">
        {{else if eq .Kind "secret"}}
        <input type="password" id="{{.Key}}" name="{{.Key}}" value="" autocomplete="new-password"
               placeholder="{{if .IsSet}}unchanged - type to replace{{else}}not set{{end}}">
        {{else}}
        <input type="text" id="{{.Key}}" name="{{.Key}}" value="{{.Value}}">
        {{end}}
        <p class="help">{{.Help}}</p>
        {{if .Err}}<p class="fieldErr">{{.Err}}</p>{{end}}
      </div>
      {{end}}
    </section>
    {{end}}
    <button type="submit">Save settings</button>
  </form>

  <footer>Settings marked <span class="tag">restart</span> are read once at startup - saving them writes the file, but the running daemon keeps the listeners and rundir it started with. SIGHUP re-reads the file without re-opening listeners.</footer>
</div>
</body>
</html>
`
