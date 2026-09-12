package Arkcommand

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
)

// WantOutput, when set by the client, tells the connection handler in
// main.go to run this command via RunWithOutput and reply with the
// captured output (JSON {ok,output,error}) instead of the plain "OK"/"NOK"
// used for every other command - see main.go's worker(). It's
// omitempty so existing callers that don't set it produce byte-identical
// JSON to before this field existed.
type Arkcmd struct {
	Name       string   `json:"name"`
	Cmd        string   `json:"cmd"`
	Opts       []string `json:"opts"`
	WantOutput bool     `json:"want_output,omitempty"`
}

type Arkcmds struct {
	Cmds []Arkcmd `json:"cmds"`
}

type Cmd interface {
	Run() (int, error)
	RunWithOutput() (int, []byte)
}

// quietCommands are periodic, high-frequency commands - gatewaymonitor's
// health-check ping (every pingInterval, per monitored gateway) and
// pfifaces' interface traffic-stats poll (netstat -ibn, hit by the UI
// dashboard on a short interval) - whose output isn't worth a log line on
// every single run; at that volume they drown out everything else in the
// log. Failures still surface through the caller's own handling
// (gatewaymonitor's success/failure history, the traffic-stats error
// response), just not as raw command output here.
var quietCommands = map[string]bool{
	"HealthPing": true,
	"Netstat":    true,
}

// IsQuiet reports whether name is a high-frequency command whose
// connection/output logging should be suppressed - see quietCommands.
func IsQuiet(name string) bool {
	return quietCommands[name]
}

// concurrentCommands are read-only, side-effect-free introspection commands
// (ping/traceroute/netstat/ifconfig) that main.go's connection handler runs
// immediately in their own connection's goroutine instead of handing off to
// the single serialized worker() queue. That queue exists to keep mutating
// commands (pf.conf/dhcpd.conf/unbound.conf/npppd.conf apply steps, route
// add/delete) strictly ordered - these commands touch no shared state, so
// running many of them at once is safe, and doing so matters in practice:
// gatewaymonitor fires one HealthPing per monitored gateway on every tick,
// all at once, and pfifaces polls Netstat/ListInterfaces on a short
// interval too. Funneling those through one serial worker alongside
// (potentially slow) mutating commands meant a burst of health checks - or
// even just one slow command in flight at the wrong moment - could blow
// past the caller's own timeout before ever being dequeued, producing
// falsely-"down" gateway statuses that reflected queueing delay, not
// reachability. Add a name here (and nowhere else) for any future
// read-only command that should get the same treatment; anything that
// writes a file, moves a file, or changes running state must NOT be added,
// since ordering among those is relied upon (e.g. pf.conf's
// check-then-backup-then-move-then-apply sequence).
var concurrentCommands = map[string]bool{
	"HealthPing":     true,
	"Ping":           true,
	"Traceroute":     true,
	"Netstat":        true,
	"ListInterfaces": true,
}

// IsConcurrent reports whether name is safe to run outside the serialized
// worker queue - see concurrentCommands.
func IsConcurrent(name string) bool {
	return concurrentCommands[name]
}

func (ac *Arkcmd) Run() (int, error) {
	cmd := exec.Command(ac.Cmd, ac.Opts...)
	out, err := cmd.Output()
	if !quietCommands[ac.Name] {
		log.Println(string(out))
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// RunWithOutput runs the command and always returns its captured output
// (stdout+stderr combined), even when it exits non-zero - callers like
// diagnostics (ping to an unreachable host, e.g.) need the output text
// precisely in that case, not just a bare failure code. Exit code is the
// process's real exit code when available, 1 otherwise (e.g. the binary
// itself couldn't be started).
func (ac *Arkcmd) RunWithOutput() (int, []byte) {
	quiet := quietCommands[ac.Name]
	if !quiet {
		log.Println("running:", ac.Cmd)
	}
	cmd := exec.Command(ac.Cmd, ac.Opts...)
	out, err := cmd.CombinedOutput()
	if !quiet {
		log.Println(string(out))
	}
	if err != nil {
		code := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
		return code, out
	}
	return 0, out
}

func Init(cmdfile string) map[string]Cmd {
	cmds := map[string]Cmd{}
	log.Println("Arkcmd file loaded: ", cmdfile)
	jsoncmdFile, err := os.Open(cmdfile)
	if err != nil {
		log.Println("Error during json open file: ", err)
	}
	defer jsoncmdFile.Close()
	byteValue, err := io.ReadAll(jsoncmdFile)
	if err != nil {
		log.Println("Error during reading json content: ", err)
	}
	var acmds Arkcmds
	err = json.Unmarshal(byteValue, &acmds)
	if err != nil {
		log.Println("Error during unmarshal: ", err)
	}
	for i := 0; i < len(acmds.Cmds); i++ {
		log.Println("json acmd:", acmds.Cmds[i].Name)
		cmds[acmds.Cmds[i].Name] = &acmds.Cmds[i]
	}
	return cmds
}
