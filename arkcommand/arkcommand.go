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

func (ac *Arkcmd) Run() (int, error) {
	cmd := exec.Command(ac.Cmd, ac.Opts...)
	out, err := cmd.Output()
	if err != nil {
		log.Println(string(out))
		return 1, err
	}
	log.Println(string(out))
	return 0, nil
}

// RunWithOutput runs the command and always returns its captured output
// (stdout+stderr combined), even when it exits non-zero - callers like
// diagnostics (ping to an unreachable host, e.g.) need the output text
// precisely in that case, not just a bare failure code. Exit code is the
// process's real exit code when available, 1 otherwise (e.g. the binary
// itself couldn't be started).
func (ac *Arkcmd) RunWithOutput() (int, []byte) {
	log.Println("running:", ac.Cmd)
	cmd := exec.Command(ac.Cmd, ac.Opts...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(out))
		code := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
		return code, out
	}
	log.Println(string(out))
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
