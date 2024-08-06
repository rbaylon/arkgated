package main

import (
	"context"
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
	"github.com/rbaylon/arkgated/srvclient"
)

type config struct {
	maxbuff  int
	arkgid   int
	srvcurl  string
	sockfile string
	cmdfile  string
	rundir   string
	creds    string
}

func (c *config) init(args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	flags.String(flag.DefaultConfigFlagname, "", "Path to config file")

	var (
		maxbuff  = flags.Int("maxbuff", 1024, "Max buffer size")
		srvcurl  = flags.String("srvcurl", "http://127.0.0.1/api/v1/", "Service manager url")
		sockfile = flags.String("socketfile", "/tmp/arkgated.sock", "Path to create the socket file")
		arkgid   = flags.Int("arkgid", 1001, "arkgate group id")
		cmdfile  = flags.String("cmdfile", "./cmd.json", "Path to json command file")
		rundir   = flags.String("rundir", "./rundir/", "Path to rundir")
		creds    = flags.String("creds", "./rundir/", "Basic auth api creds")
	)

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	c.maxbuff = *maxbuff
	c.srvcurl = *srvcurl
	c.sockfile = *sockfile
	c.arkgid = *arkgid
	c.cmdfile = *cmdfile
	c.rundir = *rundir
	c.creds = *creds
	return nil
}

func run(c *config, out io.Writer, sock net.Listener) error {
	log.SetOutput(out)
	pfcfg, err := pfconfig.Init(c.rundir + "config.json")
	if err != nil {
		log.Println("Error reading json config: ", err)
	}

	srvclient.Enroll(c.srvcurl, apitoken, pfcfg)

	err = pfcfg.Create(c.rundir, c.srvcurl, apitoken)
	if err != nil {
		log.Println("Error creating pf config file: ", err)
	}

	for {
		log.Println("Blocking until we get connection")
		conn, err := sock.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			log.Println("connection accepted")
			defer conn.Close()
			buf := make([]byte, c.maxbuff)
			n, err := conn.Read(buf)
			if err != nil {
				log.Println(err)
			}
			msg := buf[:n]
			var cmd Arkcommand.Arkcmd
			err = json.Unmarshal(msg, &cmd)
			log.Printf("%v", cmd)
			if err != nil {
				_, err = conn.Write([]byte("NOK"))
				if err != nil {
					log.Println("Reply error: ", err)
				}
			}
			if cmd.Name == "CheckPF" {
				pfcfg.Create(c.rundir, c.srvcurl, apitoken)
			}
			_, err = cmd.Run()
			if err != nil {
				log.Println(err)
				_, err = conn.Write([]byte("NOK"))
				if err != nil {
					log.Println(err)
				}
			}
			conn.Write([]byte("OK"))
		}(conn)
	}
}

func waitForSignal(cancel context.CancelFunc, ctx context.Context, c *config, sigchan chan os.Signal) {
	for {
		select {
		case s := <-sigchan:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Got SIGINT/SIGTERM, exiting.")
				os.Remove(c.sockfile)
				os.Exit(2)
			case syscall.SIGHUP:
				log.Println("SIGHUP received. Relaoding config.")
				c.init(os.Args)
			}
		case <-ctx.Done():
			log.Printf("Context Done.")
		}
	}
}

var apitoken *string

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGKILL)

	c := &config{}

	go waitForSignal(cancel, ctx, c, signalChan)

	c.init(os.Args)
	socket, err := net.Listen("unix", c.sockfile)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Chown(c.sockfile, os.Getuid(), c.arkgid)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Chmod(c.sockfile, 0660)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("IPC running ")

	token, err := srvclient.GetToken(c.creds, c.srvcurl+"login")
	apitoken = token
	if err != nil {
		log.Println(err)
	}

	if err := run(c, os.Stdout, socket); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
