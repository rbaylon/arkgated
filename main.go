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

	"github.com/namsral/flag"
	Arkcommand "github.com/rbaylon/arkgated/arkcommand"
	pfconfig "github.com/rbaylon/arkgated/config/pf"
	"github.com/rbaylon/arkgated/config/wizard"
	"github.com/rbaylon/arkgated/srvclient"
)

type config struct {
	maxbuff     int
	srvcurl     string
	listenaddr  string
	tlscert     string
	tlskey      string
	tlsclientca string
	cmdfile     string
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
		maxbuff     = flags.Int("maxbuff", 1024, "Max buffer size")
		srvcurl     = flags.String("srvcurl", "http://127.0.0.1/api/v1/", "Service manager url")
		listenaddr  = flags.String("listenaddr", "0.0.0.0:8443", "Network address to listen for IPC commands on")
		tlscert     = flags.String("tlscert", "./rundir/arkgated.crt", "Path to this daemon's TLS server certificate")
		tlskey      = flags.String("tlskey", "./rundir/arkgated.key", "Path to this daemon's TLS server private key")
		tlsclientca = flags.String("tlsclientca", "./rundir/ca.crt", "Path to the CA certificate used to verify client (srvcman) certificates")
		cmdfile     = flags.String("cmdfile", "./cmd.json", "Path to json command file")
		rundir      = flags.String("rundir", "./rundir/", "Path to rundir")
		creds       = flags.String("creds", "./rundir/", "Basic auth api creds")
	)

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	c.maxbuff = *maxbuff
	c.srvcurl = *srvcurl
	c.listenaddr = *listenaddr
	c.tlscert = *tlscert
	c.tlskey = *tlskey
	c.tlsclientca = *tlsclientca
	c.cmdfile = *cmdfile
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

func worker(job <-chan joborder, ctx context.Context) {
	log.Println("Executioner running")
	for {
		select {
		case jo := <-job:
			if jo.cmd.WantOutput {
				code, out := jo.cmd.RunWithOutput()
				resp := outputResponse{OK: code == 0, Output: string(out)}
				if code != 0 {
					resp.Error = fmt.Sprintf("%s exited %d", jo.cmd.Cmd, code)
				}
				respBytes, err := json.Marshal(resp)
				if err != nil {
					log.Println("marshaling output response:", err)
					jo.conn.Write([]byte("NOK"))
				} else {
					jo.conn.Write(respBytes)
				}
			} else {
				_, err := jo.cmd.Run()
				if err != nil {
					log.Println(err)
					jo.conn.Write([]byte("NOK"))
				} else {
					jo.conn.Write([]byte("OK"))
				}
			}
			jo.conn.Close()
		case <-ctx.Done():
			return
		}
	}
}

func run(c *config, out io.Writer, sock net.Listener, ctx context.Context) error {
	log.SetOutput(out)
	pfcfg, err := pfconfig.Init(c.rundir + "config.json")
	if err != nil {
		log.Println("Error reading json config: ", err)
	}

	srvclient.Enroll(c.srvcurl, apitoken, pfcfg)

	err = pfconfig.PfCreate(pfcfg.Router, c.rundir, c.srvcurl, apitoken)
	if err != nil {
		log.Println("Error creating pf config file: ", err)
	}
	job := make(chan joborder, 10)
	go worker(job, ctx)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Done running")
		default:
			newtoken := refreshToken(c)
			if newtoken != nil {
				apitoken = newtoken
			}
			conn, err := sock.Accept()
			if err != nil {
				return err
			}
			go func(conn net.Conn) {
				buf := make([]byte, c.maxbuff)
				n, err := conn.Read(buf)
				if err != nil {
					log.Println(err)
				}
				msg := buf[:n]
				var cmd Arkcommand.Arkcmd
				err = json.Unmarshal(msg, &cmd)
				if !Arkcommand.IsQuiet(cmd.Name) {
					log.Println("connection accepted")
					log.Printf("%v", cmd)
				}
				if err != nil {
					_, err = conn.Write([]byte("NOK"))
					if err != nil {
						log.Println("Reply error: ", err)
					}
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
				jo := joborder{cmd: cmd, conn: conn}
				job <- jo
			}(conn)
		}
	}
}

func waitForSignal(cancel context.CancelFunc, ctx context.Context, c *config, sigchan chan os.Signal) {
	for {
		select {
		case s := <-sigchan:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Got SIGINT/SIGTERM, exiting.")
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

	tlsConfig, err := serverTLSConfig(c.tlscert, c.tlskey, c.tlsclientca)
	if err != nil {
		log.Fatal(err)
	}
	socket, err := tls.Listen("tcp", c.listenaddr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	//statCmd := Arkcommand.Arkcmd{Name: "systats", Cmd: c.rundir + "scripts/getstats.pl", Opts: nil}

	//go srvclient.ExecScripts(&statCmd, "/tmp/mystats", 10)

	log.Println("IPC running (mTLS) on " + c.listenaddr)

	token, err := srvclient.GetToken(c.creds, c.srvcurl+"login")
	apitoken = token
	if err != nil {
		log.Println(err)
	}

	if err := run(c, os.Stdout, socket, ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
