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
	"github.com/rbaylon/arkgated/config/wizard"
	"github.com/rbaylon/arkgated/srvclient"
)

type config struct {
	sockfile    string
	arkgid      int
	maxbuff     int
	srvcurl     string
	listenaddr  string
	tlscert     string
	tlskey      string
	tlsclientca string
	rundir      string
	creds       string
}

type joborder struct {
	cmd  Arkcommand.Arkcmd
	conn net.Conn
}

func (c *config) init(args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	flags.String(flag.DefaultConfigFlagname, "", "Path to config file")

	var (
		sockfile    = flags.String("socketfile", "/tmp/arkgated.sock", "Path to the local Unix domain socket for same-host clients (srvcman/subsportal running on this box); empty disables it")
		arkgid      = flags.Int("arkgid", 1001, "arkgate group id - owns the Unix socket (mode 0660)")
		maxbuff     = flags.Int("maxbuff", 1024, "Max buffer size")
		srvcurl     = flags.String("srvcurl", "http://127.0.0.1/api/v1/", "Service manager url")
		listenaddr  = flags.String("listenaddr", "0.0.0.0:8443", "Network address to listen for IPC commands on")
		tlscert     = flags.String("tlscert", "./rundir/arkgated.crt", "Path to this daemon's TLS server certificate")
		tlskey      = flags.String("tlskey", "./rundir/arkgated.key", "Path to this daemon's TLS server private key")
		tlsclientca = flags.String("tlsclientca", "./rundir/ca.crt", "Path to the CA certificate used to verify client (srvcman) certificates")
		rundir      = flags.String("rundir", "./rundir/", "Path to rundir")
		creds       = flags.String("creds", "./rundir/", "Basic auth api creds")
	)

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	c.sockfile = *sockfile
	c.arkgid = *arkgid
	c.maxbuff = *maxbuff
	c.srvcurl = *srvcurl
	c.listenaddr = *listenaddr
	c.tlscert = *tlscert
	c.tlskey = *tlskey
	c.tlsclientca = *tlsclientca
	c.rundir = *rundir
	c.creds = *creds
	return nil
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

func refreshToken(c *config) *string {
	// apitoken is nil whenever the last login attempt failed (e.g. srvcman
	// unreachable at startup, now a real possibility since it can run on a
	// separate host) - retry here on every accept-loop tick instead of
	// dereferencing a nil token, so arkgated self-heals once srvcman comes
	// back instead of staying permanently stuck.
	if apitoken == nil {
		token, err := srvclient.GetToken(c.creds, c.srvcurl+"login")
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
		token, err := srvclient.GetToken(c.creds, c.srvcurl+"login")
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

// refreshTokenLoop calls refreshToken on a fixed interval for as long as ctx
// is live. This used to run inline, once per accepted connection, right
// before the single listener's blocking Accept() call - now that arkgated
// can listen on more than one socket at once (Unix + mTLS), there's no
// single Accept() to hang it off, so it's its own loop instead. Checks
// immediately on start (in case apitoken is already nil, e.g. the initial
// login at startup failed) rather than waiting out the first tick.
func refreshTokenLoop(c *config, ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if newtoken := refreshToken(c); newtoken != nil {
			apitoken = newtoken
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func run(c *config, out io.Writer, sockets []net.Listener, ctx context.Context) error {
	log.SetOutput(out)
	pfcfg, err := pfconfig.Init(c.rundir + "config.json")
	if err != nil {
		// pfcfg is nil here - every use below (and every CheckPF/ApplyIfaces
		// command for the rest of the process's life, via this same pfcfg
		// captured in the connection handler's closure) dereferences
		// pfcfg.Router, so there is no safe way to continue running with a
		// config we failed to load. Fail fast instead of limping along.
		return fmt.Errorf("reading json config: %w", err)
	}

	if err := srvclient.Enroll(c.srvcurl, apitoken, pfcfg); err != nil {
		log.Println("Error enrolling router: ", err)
	}

	if err := pfconfig.PfCreate(pfcfg.Router, c.rundir, c.srvcurl, apitoken); err != nil {
		log.Println("Error creating pf config file: ", err)
	}
	job := make(chan joborder, 10)
	go worker(job, ctx)
	go refreshTokenLoop(c, ctx)

	// handleConn is shared by every listener's accept loop below - a
	// command means the same thing regardless of whether it arrived over
	// the local Unix socket or the remote mTLS listener.
	handleConn := func(conn net.Conn) {
		buf := make([]byte, c.maxbuff)
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
			if pferr := pfconfig.PfCreate(pfcfg.Router, c.rundir, c.srvcurl, apitoken); pferr != nil {
				log.Println(pferr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(pferr)
				}
			}
		case "CheckConf_dhcpd":
			// Stages a fresh dhcpd.conf (fetched from srvcman) into
			// rundir before the queued job (dhcpd -nf on that file)
			// runs - see pfconfig.DhcpCreate.
			if dherr := pfconfig.DhcpCreate(c.rundir, c.srvcurl, apitoken); dherr != nil {
				log.Println(dherr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(dherr)
				}
			}
		case "CheckConf_unbound":
			// Same as CheckConf_dhcpd, for unbound.conf.
			if dnerr := pfconfig.DnsCreate(c.rundir, c.srvcurl, apitoken); dnerr != nil {
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
			if pperr := pfconfig.PppoeCreate(c.rundir, c.srvcurl, apitoken); pperr != nil {
				log.Println(pperr)
				if _, err := conn.Write([]byte("NOK")); err != nil {
					log.Println(pperr)
				}
			}
		case "ApplyIfaces":
			// Fully self-contained: regenerates and applies
			// hostname.<if>/mygate itself, so there's no separate
			// job to queue afterward.
			if _, aerr := pfconfig.ApplyIfaces(pfcfg.Router, c.rundir, c.srvcurl, apitoken); aerr != nil {
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

func waitForSignal(cancel context.CancelFunc, ctx context.Context, c *config, sigchan chan os.Signal) {
	for {
		select {
		case s := <-sigchan:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Got SIGINT/SIGTERM, exiting.")
				if c.sockfile != "" {
					os.Remove(c.sockfile)
				}
				cancel()
			case syscall.SIGHUP:
				log.Println("SIGHUP received. Relaoding config.")
				c.init(os.Args)
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

	c := &config{}

	go waitForSignal(cancel, ctx, c, signalChan)

	c.init(os.Args)

	configPath := c.rundir + "config.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := wizard.Run(configPath); err != nil {
			log.Fatal(err)
		}
	}

	var sockets []net.Listener

	// Local Unix socket: same-host clients (srvcman/subsportal running on
	// this box) can use this instead of provisioning TLS certs at all -
	// trust here is filesystem permissions (gid arkgid, mode 0660), the
	// same model this daemon used before mTLS existed. Set -socketfile ""
	// to disable it for a remote-only deployment.
	if c.sockfile != "" {
		unixSock, err := net.Listen("unix", c.sockfile)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.Chown(c.sockfile, os.Getuid(), c.arkgid); err != nil {
			log.Fatal(err)
		}
		if err := os.Chmod(c.sockfile, 0660); err != nil {
			log.Fatal(err)
		}
		sockets = append(sockets, unixSock)
		log.Println("IPC running (unix) on " + c.sockfile)
	}

	// Remote mTLS listener: for clients not on this host, where filesystem
	// permissions can't gate access - see serverTLSConfig.
	tlsConfig, err := serverTLSConfig(c.tlscert, c.tlskey, c.tlsclientca)
	if err != nil {
		log.Fatal(err)
	}
	tlsSock, err := tls.Listen("tcp", c.listenaddr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	sockets = append(sockets, tlsSock)
	log.Println("IPC running (mTLS) on " + c.listenaddr)

	//statCmd := Arkcommand.Arkcmd{Name: "systats", Cmd: c.rundir + "scripts/getstats.pl", Opts: nil}

	//go srvclient.ExecScripts(&statCmd, "/tmp/mystats", 10)

	token, err := srvclient.GetToken(c.creds, c.srvcurl+"login")
	apitoken = token
	if err != nil {
		log.Println(err)
	}

	if err := run(c, os.Stdout, sockets, ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
