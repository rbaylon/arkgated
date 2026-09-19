package webconf

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// RouterConfig is the per-router static config that used to be built by the
// interactive stdin wizard (config/wizard, now removed) and lives at
// rundir/config.json. pfconfig.Init unmarshals this same file into
// pfconfigmodel.Pfconfig, and srvclient.Enroll POSTs it to srvcman to register
// the router.
//
// These structs mirror the srvcman model's JSON rather than embedding it: the
// real types carry gorm.Model, so marshaling them here would write ID,
// CreatedAt, UpdatedAt and DeletedAt noise into a hand-editable config file.
// The field names and tags must stay in step with pfifacemodel.Pfiface,
// dhcpmodel.Dhcp and pflowmodel.Pflow.
type RouterConfig struct {
	Ifaces            []RouterIface `json:"ifaces"`
	WifiIpList        string        `json:"wifi_ip_list"`
	SubsIpList        string        `json:"subs_ip_list"`
	SubsPortalPort    int           `json:"subs_portal_port"`
	CaptivePortalPort int           `json:"captive_portal_port"`
	Router            string        `json:"router"`
	LoadBalance       bool          `json:"load_balance"`
	Dhcps             []RouterDhcp  `json:"dhcps"`
	Dns               string        `json:"dns"`
	Pflows            []RouterPflow `json:"pflows"`
}

type RouterIface struct {
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

type RouterDhcp struct {
	Subnet     string `json:"subnet"`
	Netmask    string `json:"netmask"`
	Routers    string `json:"routers"`
	Dnsservers string `json:"dnsservers"`
	Range      string `json:"range"`
	Type       string `json:"type"`
}

type RouterPflow struct {
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Proto  int    `json:"proto"`
	Device string `json:"device"`
}

// autoconfIP is the literal Ip value meaning "let the interface configure
// itself" (dhclient/autoconf). pf.go's ConfigCreate special-cases it when
// deciding whether to write mygate/resolv.conf, so validation has to allow it
// through where a dotted quad would otherwise be required.
const autoconfIP = "autoconf"

// RouterDefaults are the wizard's old defaults, so an operator filling the
// form for the first time starts where the prompts used to.
func RouterDefaults() RouterConfig {
	return RouterConfig{
		WifiIpList:        "wifilist.txt",
		SubsIpList:        "subslist.txt",
		SubsPortalPort:    4000,
		CaptivePortalPort: 3000,
		Dns:               "8.8.8.8 4.2.2.2",
	}
}

// Normalize trims every field and drops rows the operator left entirely blank,
// which is how the form deletes a row and how its trailing empty rows are
// ignored.
func (c *RouterConfig) Normalize() {
	c.Router = strings.TrimSpace(c.Router)
	c.WifiIpList = strings.TrimSpace(c.WifiIpList)
	c.SubsIpList = strings.TrimSpace(c.SubsIpList)
	c.Dns = strings.Join(strings.Fields(c.Dns), " ")

	var ifs []RouterIface
	for _, i := range c.Ifaces {
		i.Name = strings.TrimSpace(i.Name)
		i.Device = strings.TrimSpace(i.Device)
		i.Speed = strings.TrimSpace(i.Speed)
		i.Type = strings.TrimSpace(i.Type)
		i.Gateway = strings.TrimSpace(i.Gateway)
		i.Ip = strings.TrimSpace(i.Ip)
		i.Netmask = strings.TrimSpace(i.Netmask)
		if i.Name == "" && i.Device == "" {
			continue
		}
		ifs = append(ifs, i)
	}
	c.Ifaces = ifs

	var dhcps []RouterDhcp
	for _, d := range c.Dhcps {
		d.Subnet = strings.TrimSpace(d.Subnet)
		d.Netmask = strings.TrimSpace(d.Netmask)
		d.Routers = strings.TrimSpace(d.Routers)
		d.Dnsservers = strings.TrimSpace(d.Dnsservers)
		d.Range = strings.Join(strings.Fields(d.Range), " ")
		d.Type = strings.TrimSpace(d.Type)
		if d.Subnet == "" && d.Type == "" && d.Range == "" {
			continue
		}
		dhcps = append(dhcps, d)
	}
	c.Dhcps = dhcps

	var pflows []RouterPflow
	for _, p := range c.Pflows {
		p.Src = strings.TrimSpace(p.Src)
		p.Dst = strings.TrimSpace(p.Dst)
		p.Device = strings.TrimSpace(p.Device)
		if p.Device == "" && p.Dst == "" {
			continue
		}
		pflows = append(pflows, p)
	}
	c.Pflows = pflows
}

// Validate reports every problem at once, for a form that should show them all.
//
// This is stricter than the old stdin wizard, deliberately. Several of these
// rules guard things that would otherwise take the daemon down or silently
// misconfigure the box:
//   - a netmask that is not a dotted quad reaches pf.MaskToCidr, which
//     log.Fatalf's on it, so a bad value here kills arkgated at the next
//     CheckPF;
//   - "default" drives whether mygate/resolv.conf get written at all, and
//     ConfigCreate just overwrites them per matching interface, so zero
//     defaults means no default route and several means last-one-wins;
//   - a DHCP scope's "type" is an interface *name* reference, which the wizard
//     accepted as free text and got wrong silently.
//
// Interfaces are the only required section. DHCP scopes and pflow exports are
// both optional, for different reasons - see the comments on each loop below.
func (c *RouterConfig) Validate() []string {
	var errs []string

	if c.Router == "" {
		errs = append(errs, "Router name is required - it is the key srvcman stores this router under")
	}
	if c.WifiIpList == "" {
		errs = append(errs, "Wifi IP allowlist filename is required")
	}
	if c.SubsIpList == "" {
		errs = append(errs, "Subscriber IP list filename is required")
	}
	if c.SubsPortalPort < 1 || c.SubsPortalPort > 65535 {
		errs = append(errs, "Subscriber portal port must be between 1 and 65535")
	}
	if c.CaptivePortalPort < 1 || c.CaptivePortalPort > 65535 {
		errs = append(errs, "Captive portal port must be between 1 and 65535")
	}
	if c.SubsPortalPort == c.CaptivePortalPort && c.SubsPortalPort != 0 {
		errs = append(errs, "Subscriber portal and captive portal cannot share a port")
	}
	for _, d := range strings.Fields(c.Dns) {
		if net.ParseIP(d) == nil {
			errs = append(errs, fmt.Sprintf("Upstream DNS %q is not an IP address", d))
		}
	}

	if len(c.Ifaces) == 0 {
		errs = append(errs, "At least one interface is required")
	}

	names := map[string]bool{}
	devices := map[string]bool{}
	defaults := 0
	for n, i := range c.Ifaces {
		label := i.Name
		if label == "" {
			label = fmt.Sprintf("interface %d", n+1)
		}
		if i.Name == "" {
			errs = append(errs, fmt.Sprintf("%s: name is required", label))
		} else if names[i.Name] {
			errs = append(errs, fmt.Sprintf("%s: duplicate interface name", label))
		}
		names[i.Name] = true

		if i.Device == "" {
			errs = append(errs, fmt.Sprintf("%s: device is required", label))
		} else if devices[i.Device] {
			errs = append(errs, fmt.Sprintf("%s: device %s is already used by another interface", label, i.Device))
		}
		devices[i.Device] = true

		if i.Type != "external" && i.Type != "internal" {
			errs = append(errs, fmt.Sprintf("%s: type must be external or internal", label))
		}

		if i.Ip == "" {
			errs = append(errs, fmt.Sprintf("%s: ip is required (or %q to configure it dynamically)", label, autoconfIP))
		} else if i.Ip != autoconfIP && net.ParseIP(i.Ip) == nil {
			errs = append(errs, fmt.Sprintf("%s: ip %q is not an IP address", label, i.Ip))
		}

		if i.Ip != autoconfIP {
			if i.Netmask == "" {
				errs = append(errs, fmt.Sprintf("%s: netmask is required", label))
			} else if !validDottedMask(i.Netmask) {
				errs = append(errs, fmt.Sprintf("%s: netmask %q is not a valid dotted netmask (e.g. 255.255.255.0)", label, i.Netmask))
			}
		}

		if i.Gateway != "" && net.ParseIP(i.Gateway) == nil {
			errs = append(errs, fmt.Sprintf("%s: gateway %q is not an IP address", label, i.Gateway))
		}

		if i.Default {
			defaults++
			if i.Ip != autoconfIP && i.Gateway == "" {
				errs = append(errs, fmt.Sprintf("%s: the default interface needs a gateway - it is what gets written to mygate", label))
			}
		}

		if i.LbPercentage < 0 || i.LbPercentage > 100 {
			errs = append(errs, fmt.Sprintf("%s: load-balance weight must be between 0 and 100", label))
		}
	}

	switch {
	case defaults == 0 && len(c.Ifaces) > 0:
		errs = append(errs, "Exactly one interface must be marked default - that is the one mygate and resolv.conf are written from")
	case defaults > 1:
		errs = append(errs, fmt.Sprintf("%d interfaces are marked default; only one can be", defaults))
	}

	// DHCP scopes are optional, and nothing inside a row is required either.
	// arkgated never reads Dhcps: it is purely part of the enrollment payload,
	// and srvcman's dhcp module owns dhcpd.conf from then on (arkgated fetches
	// the rendered text from /dhcpserver/conf - see pfconfig.DhcpCreate). So
	// these rules only catch typos in whatever the operator did fill in; they
	// do not insist on a complete scope, because srvcman is the thing that
	// decides what a complete scope is.
	for n, d := range c.Dhcps {
		label := d.Type
		if label == "" {
			label = fmt.Sprintf("DHCP scope %d", n+1)
		}
		if d.Type != "" && !names[d.Type] {
			errs = append(errs, fmt.Sprintf("%s: no interface is named %q", label, d.Type))
		}
		if d.Subnet != "" && net.ParseIP(d.Subnet) == nil {
			errs = append(errs, fmt.Sprintf("%s: subnet %q is not an IP address", label, d.Subnet))
		}
		if d.Netmask != "" && !validDottedMask(d.Netmask) {
			errs = append(errs, fmt.Sprintf("%s: netmask %q is not a valid dotted netmask", label, d.Netmask))
		}
		if d.Routers != "" && net.ParseIP(d.Routers) == nil {
			errs = append(errs, fmt.Sprintf("%s: router %q is not an IP address", label, d.Routers))
		}
		if d.Dnsservers != "" && net.ParseIP(d.Dnsservers) == nil {
			errs = append(errs, fmt.Sprintf("%s: DNS server %q is not an IP address", label, d.Dnsservers))
		}
		// dhcpd wants "range <low> <high>", so check the shape if one is given.
		if parts := strings.Fields(d.Range); len(parts) > 0 {
			if len(parts) != 2 {
				errs = append(errs, fmt.Sprintf("%s: range must be two addresses, low then high (e.g. 172.16.1.1 172.16.9.255)", label))
			}
			for _, p := range parts {
				if net.ParseIP(p) == nil {
					errs = append(errs, fmt.Sprintf("%s: range address %q is not an IP address", label, p))
				}
			}
		}
	}

	// pflow exports are optional, and nothing inside a row is required either -
	// same as DHCP. A row only reaches an actual hostname.if file if it is
	// complete; pf.ConfigCreate skips (and logs) any export missing a device,
	// source, destination or a valid version rather than writing a malformed
	// interface file. So these rules only catch typos in what was filled in.
	for n, p := range c.Pflows {
		label := p.Device
		if label == "" {
			label = fmt.Sprintf("pflow export %d", n+1)
		}
		if p.Src != "" && net.ParseIP(p.Src) == nil {
			errs = append(errs, fmt.Sprintf("%s: flow source %q is not an IP address", label, p.Src))
		}
		if p.Dst != "" {
			if _, _, err := net.SplitHostPort(p.Dst); err != nil {
				errs = append(errs, fmt.Sprintf("%s: flow destination must be host:port: %v", label, err))
			}
		}
		// pflow speaks version 5 or 10 only; 0 means "not set", which is fine
		// for a partial row and is what makes ConfigCreate skip it.
		if p.Proto != 0 && p.Proto != 5 && p.Proto != 10 {
			errs = append(errs, fmt.Sprintf("%s: pflow protocol version must be 5 or 10", label))
		}
	}

	return errs
}

// validDottedMask reports whether s is a dotted IPv4 netmask with contiguous
// leading ones (255.255.254.0 yes, 255.0.255.0 no). pf.MaskToCidr would accept
// the latter and silently produce a nonsense prefix length.
func validDottedMask(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	ones, bits := net.IPMask(v4).Size()
	// Size() returns 0,0 for a non-contiguous mask.
	return bits == 32 && (ones > 0 || s == "0.0.0.0")
}

// LoadRouterConfig reads the router config at path. A missing file comes back
// as RouterDefaults with found=false, so the form can offer a starting point
// without the caller having to distinguish "absent" from "empty".
func LoadRouterConfig(path string) (cfg RouterConfig, found bool, err error) {
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return RouterDefaults(), false, nil
		}
		return RouterDefaults(), false, fmt.Errorf("reading %s: %w", path, rerr)
	}
	// Start from defaults so a hand-trimmed file keeps sensible values for
	// keys it omits rather than picking up Go zero values.
	cfg = RouterDefaults()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return RouterDefaults(), true, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, true, nil
}

// SaveRouterConfig normalizes, validates and writes cfg to path. Validation
// problems come back without the file being touched. Mode 0640 and a
// temp-file + rename, matching how pf.go writes everything else in rundir -
// pfconfig.Init reads this at startup and a truncated file would stop the
// daemon.
func SaveRouterConfig(path string, cfg RouterConfig) ([]string, error) {
	cfg.Normalize()
	if errs := cfg.Validate(); len(errs) > 0 {
		return errs, nil
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return nil, fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("renaming %s to %s: %w", tmp, path, err)
	}
	return nil, nil
}

// broadcaster wakes waiters on an event, by closing a channel and replacing
// it. Same capture-then-test discipline as Store.Changed: take Wait() before
// checking the thing you are waiting on, or an event in between is missed.
type broadcaster struct {
	mu sync.Mutex
	ch chan struct{}
}

func newBroadcaster() *broadcaster {
	return &broadcaster{ch: make(chan struct{})}
}

func (b *broadcaster) Wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ch
}

func (b *broadcaster) Fire() {
	b.mu.Lock()
	defer b.mu.Unlock()
	close(b.ch)
	b.ch = make(chan struct{})
}

// atoiOr is the form parser's "missing or unparseable means keep the default"
// helper; per-field errors are reported separately by the caller.
func atoiOr(s string, def int) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def, false
	}
	return n, true
}
