package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/namsral/flag"
	Arkcommand "github.com/rbaylon/arkgated/arkcommand"
	pfconfig "github.com/rbaylon/arkgated/config/pf"
	"github.com/rbaylon/arkgated/config/webconf"
	"github.com/rbaylon/arkgated/srvclient"
	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
)

// webcreds is everything arkgated still takes on the command line. Every
// other setting moved into the web configurator (config/webconf), which
// persists them at webconf.Path - these two can't live there too, because
// they are what guards access to it.
type webcreds struct {
	admin string
	pass  string
}

type joborder struct {
	cmd  Arkcommand.Arkcmd
	conn net.Conn
}

// parseFlags reads the configurator credentials. Both are also settable as
// ARKGATED_WEBADMIN/ARKGATED_WEBPASS or in a -config file (namsral/flag), and
// one of those is the right way to supply the password in production - a
// -webpass on the command line is visible to every user via ps.
func parseFlags(args []string) (webcreds, error) {
	flags := flag.NewFlagSetWithEnvPrefix(args[0], "ARKGATED", flag.ExitOnError)
	flags.String(flag.DefaultConfigFlagname, "", "Path to a file holding webadmin/webpass (every other setting lives in the web configurator)")

	var (
		webadmin = flags.String("webadmin", "arkadmin", "Web configurator admin username")
		webpass  = flags.String("webpass", "", "Web configurator admin password - required; prefer ARKGATED_WEBPASS or a -config file over the command line, which ps exposes")
	)

	if err := flags.Parse(args[1:]); err != nil {
		return webcreds{}, err
	}
	return webcreds{admin: *webadmin, pass: *webpass}, nil
}

// serverTLSConfig builds the mutual-TLS config for the IPC listener:
// arkgated presents certfile/keyfile as its server identity, and only
// accepts client connections presenting a certificate signed by
// clientcafile - this is what lets srvcman authenticate to run privileged
// commands now that the listener is network-reachable instead of gated by
// Unix socket file permissions. Certs/keys are expected to come from the
// deployment's own PKI tooling; this daemon only ever reads them.
func serverTLSConfig(certfile, keyfile, clientcafile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS server cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(clientcafile)
	if err != nil {
		return nil, fmt.Errorf("reading client CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in client CA file %s", clientcafile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func refreshToken(store *webconf.Store) *string {
	// Read a fresh snapshot every tick rather than closing over one: the web
	// configurator can change creds/srvcurl underneath us, and picking the
	// new values up here is how a corrected credential starts working
	// without a restart.
	c := store.Get()

	// apitoken is nil whenever the last login attempt failed (e.g. srvcman
	// unreachable at startup, now a real possibility since it can run on a
	// separate host) - retry here on every tick instead of dereferencing a
	// nil token, so arkgated self-heals once srvcman comes back instead of
	// staying permanently stuck.
	if apitoken == nil {
		token, err := srvclient.GetToken(c.APIUser, c.APIPassword, c.SrvcURL+"login")
		if err != nil {
			log.Println("refreshToken:", err)
			return nil
		}
		log.Println("Token acquired")
		return token
	}
	expired, err := srvclient.CheckExpirationWithoutVerify(*apitoken)
	if err != nil {
		log.Println(err)
	}
	if expired {
		token, err := srvclient.GetToken(c.APIUser, c.APIPassword, c.SrvcURL+"login")
		if err != nil {
			return nil
		}
		log.Println("Token refreshed")
		return token
	}
	return nil
}

// outputResponse is what a WantOutput command gets back, in place of the
// plain "OK"/"NOK" every other command uses. The connection is closed
// right after this is written, so the client can just io.ReadAll(conn) and
// json.Unmarshal the result - no length prefix needed.
type outputResponse struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
	Error  string `json:"error"`
}

// runJob executes cmd and writes its result to conn before closing it - the
// single unit of work shared by worker() (for commands that must stay
// strictly ordered) and the connection handler's direct call for
// Arkcommand.IsConcurrent commands (which skip the shared queue entirely
// and just run here, in their own connection's goroutine).
func runJob(cmd Arkcommand.Arkcmd, conn net.Conn) {
	if cmd.WantOutput {
		code, out := cmd.RunWithOutput()
		resp := outputResponse{OK: code == 0, Output: string(out)}
		if code != 0 {
			resp.Error = fmt.Sprintf("%s exited %d", cmd.Cmd, code)
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			log.Println("marshaling output response:", err)
			conn.Write([]byte("NOK"))
		} else {
			conn.Write(respBytes)
		}
	} else {
		_, err := cmd.Run()
		if err != nil {
			log.Println(err)
			conn.Write([]byte("NOK"))
		} else {
			conn.Write([]byte("OK"))
		}
	}
	conn.Close()
}

func worker(job <-chan joborder, ctx context.Context) {
	log.Println("Executioner running")
	for {
		select {
		case jo := <-job:
			runJob(jo.cmd, jo.conn)
		case <-ctx.Done():
			return
		}
	}
}

// enrollOnce attempts enrollment unless it has already succeeded, and returns
// the new "enrolled" state. lastErr carries the previous failure so a srvcman
// that stays unreachable does not reprint the same line every tick; it is
// cleared on success.
//
// Enrollment is retried because it used to be attempted exactly once, at
// startup: a gateway that booted before srvcman was reachable logged
// "Enroll: no API token available" and then ran unenrolled until somebody
// restarted it, even though the token refresher acquired a token seconds
// later. Note this only registers the router with srvcman; the startup
// PfCreate that also failed is a staging step (it writes rundir/pf.conf, it
// does not load it into pf), and srvcman restages it on the next CheckPF.
func enrollOnce(store *webconf.Store, pfcfg *pfconfigmodel.Pfconfig, enrolled bool, lastErr *string) bool {
	if enrolled {
		return true
	}
	if err := srvclient.Enroll(store.Get().SrvcURL, apitoken, pfcfg); err != nil {
		// Deduplicated: the common failure here is "no API token available"
		// every 15s until srvcman answers, which is not worth a log line each
		// time. A *changed* error is worth seeing.
		if msg := err.Error(); msg != *lastErr {
			log.Println("Error enrolling router: ", err)
			*lastErr = msg
		}
		return false
	}
	*lastErr = ""
	return true
}

// refreshTokenLoop calls refreshToken on a fixed interval for as long as ctx
// is live, and retries enrollment on the same tick until it succeeds. This used to run inline, once per accepted connection, right
// before the single listener's blocking Accept() call - now that arkgated
// can listen on more than one socket at once (Unix + mTLS), there's no
// single Accept() to hang it off, so it's its own loop instead. Checks
// immediately on start (in case apitoken is already nil, e.g. the initial
// login at startup failed) rather than waiting out the first tick.
func refreshTokenLoop(store *webconf.Store, pfcfg *pfconfigmodel.Pfconfig, enrolled bool, lastEnrollErr string, ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	// enrolled/lastEnrollErr stay local to this goroutine, which is also the
	// only writer of apitoken - so retrying enrollment here adds no sharing
	// beyond what the token refresh already does. lastEnrollErr is handed in
	// from run()'s first attempt rather than starting empty, so a failure that
	// is still the same failure on the immediate first tick is not printed
	// twice at startup.
	for {
		if newtoken := refreshToken(store); newtoken != nil {
			apitoken = newtoken
		}
		// After the token, so the first retry can use a token that was not
		// available when run() made the initial attempt.
		enrolled = enrollOnce(store, pfcfg, enrolled, &lastEnrollErr)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func run(store *webconf.Store, out io.Writer, sockets []net.Listener, ctx context.Context) error {
	log.SetOutput(out)

	// rundir is read once, here: pfcfg (and so pfcfg.Router, used by every
	// CheckPF/ApplyIfaces below) comes out of rundir+config.json, so
	// re-pointing rundir from the configurator needs a restart - which is
	// what the configurator marks it as.
	rundir := store.Get().RunDir

	pfcfg, err := pfconfig.Init(rundir + "config.json")
	if err != nil {
		// pfcfg is nil here - every use below (and every CheckPF/ApplyIfaces
		// command for the rest of the process's life, via this same pfcfg
		// captured in the connection handler's closure) dereferences
		// pfcfg.Router, so there is no safe way to continue running with a
		// config we failed to load. Fail fast instead of limping along.
		return fmt.Errorf("reading json config: %w", err)
	}

	srvcurl := store.Get().SrvcURL
	// First attempt stays here, ahead of PfCreate: GetSubs has nothing to
	// return for a router srvcman does not know about yet. If it fails,
	// refreshTokenLoop keeps retrying - see enrollOnce.
	enrollErr := ""
	enrolled := enrollOnce(store, pfcfg, false, &enrollErr)

	if err := pfconfig.PfCreate(pfcfg.Router, rundir, srvcurl, apitoken); err != nil {
		log.Println("Error creating pf config file: ", err)
	}
	job := make(chan joborder, 10)
	go worker(job, ctx)
	go refreshTokenLoop(store, pfcfg, enrolled, enrollErr, ctx)

	// handleConn is shared by every listener's accept loop below - a
	// command means the same thing regardless of whether it arrived over
	// the local Unix socket or the remote mTLS listener.
	handleConn := func(conn net.Conn) {
		// Snapshot per connection rather than per process, so maxbuff and
		// srvcurl edits made in the web configurator take effect on the
		// next command instead of only after a restart.
		c := store.Get()

		buf := make([]byte, c.MaxBuff)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
		}
		msg := buf[:n]
		var cmd Arkcommand.Arkcmd
		if err := json.Unmarshal(msg, &cmd); err != nil {
			log.Println("Unmarshal error:", err)
			conn.Write([]byte("NOK"))
			conn.Close()
			return
		}
		if !Arkcommand.IsQuiet(cmd.Name) {
			log.Println("connection accepted")
			log.Printf("%v", cmd)
		}
		switch cmd.Name {
		case "CheckPF":
			// Refreshes pf.conf plus every hostname.<if>/mygate/
			// resolv.conf file in rundir from live data before the
			// queued job (pfctl -nf on the file just written) runs.
			if pferr := pfconfig.PfCreate(pfcfg.Router, rundir, c.SrvcURL, apitoken); pferr != nil {
				log.Println(pferr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(pferr)
				}
			}
		case "CheckConf_dhcpd":
			// Stages a fresh dhcpd.conf (fetched from srvcman) into
			// rundir before the queued job (dhcpd -nf on that file)
			// runs - see pfconfig.DhcpCreate.
			if dherr := pfconfig.DhcpCreate(rundir, c.SrvcURL, apitoken); dherr != nil {
				log.Println(dherr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(dherr)
				}
			}
		case "CheckConf_unbound":
			// Same as CheckConf_dhcpd, for unbound.conf.
			if dnerr := pfconfig.DnsCreate(rundir, c.SrvcURL, apitoken); dnerr != nil {
				log.Println(dnerr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(dnerr)
				}
			}
		case "BackupConf_npppd":
			// npppd has no config-validate mode, so srvcman's apply
			// flow has no "check" step to piggyback the regen
			// trigger on (unlike dhcpd/unbound) - this is the first
			// command in its sequence instead, still ahead of the
			// stage/restart steps that need the fresh file present.
			if pperr := pfconfig.PppoeCreate(rundir, c.SrvcURL, apitoken); pperr != nil {
				log.Println(pperr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(pperr)
				}
			}
		case "ApplyIfaces":
			// Fully self-contained: regenerates and applies
			// hostname.<if>/mygate itself, so there's no separate
			// job to queue afterward.
			if _, aerr := pfconfig.ApplyIfaces(pfcfg.Router, rundir, c.SrvcURL, apitoken); aerr != nil {
				log.Println(aerr)
				conn.Write([]byte("NOK"))
			} else {
				conn.Write([]byte("OK"))
			}
			conn.Close()
			return
		}
		if Arkcommand.IsConcurrent(cmd.Name) {
			// Read-only (ping/traceroute/netstat/ifconfig) - runs
			// right here, in this connection's own goroutine,
			// instead of behind the serialized worker queue. See
			// Arkcommand.concurrentCommands for why.
			runJob(cmd, conn)
			return
		}
		jo := joborder{cmd: cmd, conn: conn}
		job <- jo
	}

	// One accept loop per listener (Unix socket, mTLS TCP, or both), all
	// feeding the same handleConn. errs carries whichever listener fails
	// first (Accept only errors on real failure/shutdown, not per-command),
	// which is treated the same as a fatal error from the old single-socket
	// loop.
	errs := make(chan error, len(sockets))
	for _, sock := range sockets {
		go func(sock net.Listener) {
			for {
				conn, err := sock.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
					}
					errs <- err
					return
				}
				go handleConn(conn)
			}
		}(sock)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("Done running")
	case err := <-errs:
		return err
	}
}

// bindListeners opens the IPC transports for one settings snapshot. Anything
// it managed to open before failing is closed again, so a retry does not leak
// a half-bound socket or leave a stale Unix socket file behind.
func bindListeners(c webconf.Settings) ([]net.Listener, error) {
	var sockets []net.Listener
	fail := func(err error) ([]net.Listener, error) {
		for _, s := range sockets {
			s.Close()
		}
		if c.SocketFile != "" {
			os.Remove(c.SocketFile)
		}
		return nil, err
	}

	// Local Unix socket: same-host clients (srvcman/subsportal running on
	// this box) can use this instead of provisioning TLS certs at all - trust
	// here is filesystem permissions (gid arkgid, mode 0660), the same model
	// this daemon used before mTLS existed. Clear the socket path in the
	// configurator to disable it for a remote-only deployment.
	if c.SocketFile != "" {
		unixSock, err := net.Listen("unix", c.SocketFile)
		if err != nil {
			return fail(err)
		}
		sockets = append(sockets, unixSock)
		if err := os.Chown(c.SocketFile, os.Getuid(), c.ArkGid); err != nil {
			return fail(err)
		}
		if err := os.Chmod(c.SocketFile, 0660); err != nil {
			return fail(err)
		}
		log.Println("IPC running (unix) on " + c.SocketFile)
	}

	// Remote mTLS listener: for clients not on this host, where filesystem
	// permissions can't gate access - see serverTLSConfig. Its cert/key are
	// unrelated to the configurator's own pair; only srvcman authenticates
	// against these.
	tlsConfig, err := serverTLSConfig(c.TLSCert, c.TLSKey, c.TLSClientCA)
	if err != nil {
		return fail(err)
	}
	tlsSock, err := tls.Listen("tcp", c.ListenAddr, tlsConfig)
	if err != nil {
		return fail(err)
	}
	sockets = append(sockets, tlsSock)
	log.Println("IPC running (mTLS) on " + c.ListenAddr)

	return sockets, nil
}

// openListeners keeps trying bindListeners across settings changes, instead of
// exiting on the first failure.
//
// This matters because the configurator is now the only way to edit a setting.
// A wrong tlscert path, a port already in use or a bad arkgid used to be fixed
// by editing flags or app.config and restarting; now the fix lives in a web UI
// that a log.Fatal here would kill before it ever bound - locking the operator
// out of the one tool that could correct the value. So the daemon stays up,
// says what is wrong, and retries each time the settings are saved.
//
// It returns (nil, nil) if ctx is cancelled while waiting, and only ever
// returns an error for something no edit could fix.
func openListeners(store *webconf.Store, ctx context.Context) ([]net.Listener, error) {
	for {
		// Captured before the attempt, so a save that lands mid-attempt
		// still wakes the select below rather than being missed.
		changed := store.Changed()

		sockets, err := bindListeners(store.Get())
		if err == nil {
			return sockets, nil
		}

		log.Printf("Cannot open IPC listeners: %v", err)
		log.Printf("Fix the affected setting in the web configurator - retrying when it is saved.")

		select {
		case <-changed:
		case <-ctx.Done():
			return nil, nil
		}
	}
}

// awaitRouterConfig blocks until rundir/config.json exists and parses,
// retrying whenever the configurator saves it. It replaces the interactive
// stdin wizard that used to build this file (config/wizard): prompting on stdin
// was never reachable for an rc.d-started daemon, and there is a web form for
// it now.
//
// The gate is deliberately "loads", not "passes Validate". The form's
// validation is stricter than the old wizard's prompts, so a config.json an
// operator has been running for months could fail it (no interface marked
// default, a DHCP scope naming an interface that no longer exists). Refusing to
// start on that would be a regression, so those are logged as warnings and the
// daemon carries on - exactly the behaviour before this change, where run()
// only needed pfconfig.Init to succeed.
//
// Returns false only if ctx was cancelled while waiting.
func awaitRouterConfig(store *webconf.Store, websrv *webconf.Server, ctx context.Context) bool {
	warned := false
	for {
		// Captured before the attempt, so a save landing mid-check is not
		// missed - same discipline as Store.Changed.
		changed := websrv.RouterChanged()

		path := store.Get().RunDir + "config.json"
		cfg, found, err := webconf.LoadRouterConfig(path)
		switch {
		case err != nil:
			log.Printf("Router config at %s is unusable: %v", path, err)
		case !found:
			log.Printf("No router config at %s yet - fill it in at /router in the web configurator.", path)
		default:
			if problems := cfg.Validate(); len(problems) > 0 && !warned {
				log.Printf("Router config at %s loads but has %d problem(s); continuing anyway:", path, len(problems))
				for _, w := range problems {
					log.Printf("  - %s", w)
				}
				warned = true
			}
			return true
		}

		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

func waitForSignal(cancel context.CancelFunc, ctx context.Context, store *webconf.Store, sigchan chan os.Signal) {
	for {
		select {
		case s := <-sigchan:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Got SIGINT/SIGTERM, exiting.")
				if sf := store.Get().SocketFile; sf != "" {
					os.Remove(sf)
				}
				cancel()
			case syscall.SIGHUP:
				// Same job the old flag re-parse did, against the
				// settings file the configurator writes: it updates what
				// later reads see, it does not re-open listeners or
				// rebuild the TLS config.
				log.Println("SIGHUP received. Reloading config.")
				if err := store.Reload(); err != nil {
					log.Println("Reload failed, keeping current settings:", err)
				}
			}
		case <-ctx.Done():
			log.Printf("Context Done.")
			os.Exit(2)
		}
	}
}

var apitoken *string

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	creds, err := parseFlags(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	store, err := webconf.Open(webconf.Path)
	if err != nil {
		log.Fatal(err)
	}

	websrv, err := webconf.NewServer(store, creds.admin, creds.pass)
	if err != nil {
		log.Fatal(err)
	}

	go waitForSignal(cancel, ctx, store, signalChan)

	// The configurator comes up first and stays up: it is the only way to
	// set anything now that the flags are gone, so it has to be reachable
	// both before the daemon has usable settings and after, for edits.
	go func() {
		err := websrv.ListenAndServe(ctx)
		if err == nil {
			return
		}
		if !store.Configured() {
			// main is blocked on store.Ready() and the only thing that can
			// unblock it just died, so nothing will ever proceed. Exiting
			// beats hanging silently.
			log.Fatal("web configurator: ", err)
		}
		// Already configured, so the IPC transports are serving real work.
		// Losing the admin UI is bad but not worth taking a working router
		// daemon down for - complain and carry on.
		log.Printf("web configurator stopped: %v (settings can still be edited in %s and picked up with SIGHUP)", err, store.Path())
	}()

	if !store.Configured() {
		log.Printf("No usable settings in %s yet - open the web configurator and save them.", store.Path())
		select {
		case <-store.Ready():
			log.Println("Settings saved, continuing startup.")
		case <-ctx.Done():
			return
		}
	}

	if !awaitRouterConfig(store, websrv, ctx) {
		return // ctx cancelled while waiting
	}

	sockets, err := openListeners(store, ctx)
	if err != nil {
		log.Fatal(err)
	}
	if sockets == nil {
		return // ctx cancelled while waiting for usable settings
	}

	c := store.Get()

	//statCmd := Arkcommand.Arkcmd{Name: "systats", Cmd: c.RunDir + "scripts/getstats.pl", Opts: nil}

	//go srvclient.ExecScripts(&statCmd, "/tmp/mystats", 10)

	token, err := srvclient.GetToken(c.APIUser, c.APIPassword, c.SrvcURL+"login")
	apitoken = token
	if err != nil {
		log.Println(err)
	}

	if err := run(store, os.Stdout, sockets, ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
