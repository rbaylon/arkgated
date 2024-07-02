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
)

type config struct {
	maxbuff  int
	commands []string
	sockfile string
}

func (c *config) init(args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	flags.String(flag.DefaultConfigFlagname, "", "Path to config file")

	var (
		maxbuff  = flags.Int("maxbuff", 64, "Max buffer size")
		commands = flags.String("commands", "STARTPF,STOPPF", "Comma separated commands")
		sockfile = flags.String("socketfile", "/tmp/arkgated.sock", "Path to create the socket file")
	)

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	cmdlist := strings.Split(*commands, ",")

	c.maxbuff = *maxbuff
	c.commands = cmdlist
	c.sockfile = *sockfile
	log.Println("Using commands")
	for _, v := range c.commands {
		log.Println(v)
	}

	return nil
}

func run(c *config, out io.Writer, sock net.Listener) error {
	log.SetOutput(out)

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
				log.Fatal(err)
			}
			msg := strings.TrimSpace(string(buf[:n]))
			log.Println(msg)
			if slices.Contains(c.commands, msg) {
				log.Println("OK")
			} else {
				log.Println("NOK")
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
	log.Println("IPC running")

	if err := run(c, os.Stdout, socket); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
