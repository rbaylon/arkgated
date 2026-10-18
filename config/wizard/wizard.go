// Package wizard interactively builds the rundir config.json used to seed
// per-router static interface/DHCP config (see pfconfig.Init).
package wizard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type iface struct {
	Name         string `json:"name"`
	Device       string `json:"device"`
	Speed        string `json:"speed"`
	Default      bool   `json:"default"`
	Type         string `json:"type"`
	Gateway      string `json:"gateway"`
	Ip           string `json:"ip"`
	Netmask      string `json:"netmask"`
	LbPercentage int    `json:"lb_percentage"`
}

type dhcp struct {
	Subnet     string `json:"subnet"`
	Netmask    string `json:"netmask"`
	Routers    string `json:"routers"`
	Dnsservers string `json:"dnsservers"`
	Range      string `json:"range"`
	Type       string `json:"type"`
}

type pflow struct {
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Proto  int    `json:"proto"`
	Device string `json:"device"`
}

type config struct {
	Ifaces            []iface `json:"ifaces"`
	WifiIpList        string  `json:"wifi_ip_list"`
	SubsIpList        string  `json:"subs_ip_list"`
	SubsPortalPort    int     `json:"subs_portal_port"`
	CaptivePortalPort int     `json:"captive_portal_port"`
	Router            string  `json:"router"`
	LoadBalance       bool    `json:"load_balance"`
	Dhcps             []dhcp  `json:"dhcps"`
	Dns               string  `json:"dns"`
	Pflows            []pflow `json:"pflows"`
}

// Run interactively prompts on stdin/stdout and writes a config.json to path.
func Run(path string) error {
	in := bufio.NewReader(os.Stdin)

	fmt.Println("No config found at", path)
	fmt.Println("Let's create one now. Press enter to accept a default shown in [brackets].")

	cfg := config{}
	cfg.Router = promptRequired(in, "Router name")
	cfg.LoadBalance = promptBool(in, "Enable load balancing across external interfaces", false)
	cfg.SubsPortalPort = promptInt(in, "Subscriber portal port", 4000)
	cfg.CaptivePortalPort = promptInt(in, "Captive portal port", 3000)
	cfg.WifiIpList = prompt(in, "Wifi IP allowlist filename", "wifilist.txt")
	cfg.SubsIpList = prompt(in, "Subscriber IP list filename", "subslist.txt")
	cfg.Dns = prompt(in, "Upstream DNS servers (space separated)", "8.8.8.8 4.2.2.2")

	fmt.Println("\nNow let's configure network interfaces. At least one is required.")
	for i := 1; ; i++ {
		fmt.Printf("--- Interface %d ---\n", i)
		fc := iface{}
		fc.Name = promptRequired(in, "  Name (e.g. wan, lan)")
		fc.Device = promptRequired(in, "  Device (e.g. igc0)")
		fc.Type = promptChoice(in, "  Type", []string{"external", "internal"}, "external")
		fc.Speed = prompt(in, "  Speed (e.g. 900M)", "900M")
		fc.Ip = prompt(in, "  IP address", "")
		fc.Netmask = prompt(in, "  Netmask", "255.255.255.0")
		fc.Gateway = prompt(in, "  Gateway", "")
		fc.LbPercentage = promptInt(in, "  Load-balance weight/percentage", 0)
		fc.Default = promptBool(in, "  Is this the default route interface", false)
		cfg.Ifaces = append(cfg.Ifaces, fc)
		if !promptBool(in, "Add another interface", false) {
			break
		}
	}

	fmt.Println("\nNow let's configure DHCP scopes.")
	if promptBool(in, "Add a DHCP scope", len(cfg.Ifaces) > 0) {
		for i := 1; ; i++ {
			fmt.Printf("--- DHCP scope %d ---\n", i)
			dc := dhcp{}
			dc.Type = promptRequired(in, "  Applies to interface name")
			dc.Subnet = prompt(in, "  Subnet", "")
			dc.Netmask = prompt(in, "  Netmask", "255.255.0.0")
			dc.Routers = prompt(in, "  Router (gateway) IP", "")
			dc.Dnsservers = prompt(in, "  DNS server IP handed to clients", "")
			dc.Range = prompt(in, "  Address range (e.g. 172.16.1.1 172.16.9.255)", "")
			cfg.Dhcps = append(cfg.Dhcps, dc)
			if !promptBool(in, "Add another DHCP scope", false) {
				break
			}
		}
	}

	fmt.Println("\nNow let's configure NetFlow/pflow export.")
	if promptBool(in, "Add a pflow export", false) {
		for i := 1; ; i++ {
			fmt.Printf("--- pflow export %d ---\n", i)
			pc := pflow{}
			pc.Device = prompt(in, "  pflow device (e.g. pflow0)", "pflow0")
			pc.Src = prompt(in, "  Flow source address", "127.0.0.1")
			pc.Dst = prompt(in, "  Flow destination (host:port)", "")
			pc.Proto = promptInt(in, "  pflow protocol version", 10)
			cfg.Pflows = append(cfg.Pflows, pc)
			if !promptBool(in, "Add another pflow export", false) {
				break
			}
		}
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0640); err != nil {
		return err
	}
	fmt.Println("\nWrote", path)
	return nil
}

func readLine(in *bufio.Reader) string {
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

func prompt(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	v := readLine(in)
	if v == "" {
		return def
	}
	return v
}

func promptRequired(in *bufio.Reader, label string) string {
	for {
		v := prompt(in, label, "")
		if v != "" {
			return v
		}
		fmt.Println("  this field is required")
	}
}

func promptInt(in *bufio.Reader, label string, def int) int {
	for {
		s := prompt(in, label, strconv.Itoa(def))
		n, err := strconv.Atoi(s)
		if err != nil {
			fmt.Println("  please enter a whole number")
			continue
		}
		return n
	}
}

func promptBool(in *bufio.Reader, label string, def bool) bool {
	defStr := "y/N"
	if def {
		defStr = "Y/n"
	}
	fmt.Printf("%s [%s]: ", label, defStr)
	v := strings.ToLower(readLine(in))
	if v == "" {
		return def
	}
	return v == "y" || v == "yes"
}

func promptChoice(in *bufio.Reader, label string, choices []string, def string) string {
	for {
		v := prompt(in, fmt.Sprintf("%s (%s)", label, strings.Join(choices, "/")), def)
		for _, c := range choices {
			if v == c {
				return v
			}
		}
		fmt.Println("  please enter one of:", strings.Join(choices, ", "))
	}
}
