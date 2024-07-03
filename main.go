package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/namsral/flag"
	Arkcommand "github.com/rbaylon/arkgated/arkcommand"
)

type config struct {
	maxbuff  int
	arkgid   int
	commands []string
	sockfile string
	cmdfile  string
}

func (c *config) init(args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	flags.String(flag.DefaultConfigFlagname, "", "Path to config file")

	var (
		maxbuff  = flags.Int("maxbuff", 64, "Max buffer size")
		commands = flags.String("commands", "RELOADPF,TESTPF", "Comma separated commands")
		sockfile = flags.String("socketfile", "/tmp/arkgated.sock", "Path to create the socket file")
		arkgid   = flags.Int("arkgid", 1001, "arkgate group id")
		cmdfile  = flags.String("cmdfile", "./cmd.json", "Path to json command file")
	)

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	cmdlist := strings.Split(*commands, ",")

	c.maxbuff = *maxbuff
	c.commands = cmdlist
	c.sockfile = *sockfile
	c.arkgid = *arkgid
	c.cmdfile = *cmdfile
	log.Println("Using commands")
	for _, v := range c.commands {
		log.Println(v)
	}

	return nil
}

func run(c *config, out io.Writer, sock net.Listener) error {
	log.SetOutput(out)
	cmds := Arkcommand.Init(c.cmdfile)

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
			msg := strings.TrimSpace(string(buf[:n]))
			log.Println(msg)
			if slices.Contains(c.commands, msg) {
				acmd := cmds[msg]
				_, err := acmd.Run()
				if err != nil {
					log.Println("Run error: ", err)
				}
				_, err = conn.Write([]byte("OK"))
				if err != nil {
					log.Println("Reply error: ", err)
				}
			} else {
				_, err = conn.Write([]byte("NOK"))
				if err != nil {
					log.Println("Reply error: ", err)
				}
			}
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

	log.Println("IPC running")

	if err := run(c, os.Stdout, socket); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
