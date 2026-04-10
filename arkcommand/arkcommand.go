package Arkcommand

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
)

type Arkcmd struct {
	Name string   `json:"name"`
	Cmd  string   `json:"cmd"`
	Opts []string `json:"opts"`
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

func (ac *Arkcmd) RunWithOutput() (int, []byte) {
	log.Println("running:", ac.Cmd)
	cmd := exec.Command(ac.Cmd, ac.Opts...)
	out, err := cmd.Output()
	if err != nil {
		log.Println(string(out))
		return 1, nil
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
