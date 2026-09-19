package webconf

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// HostIface is one interface as OpenBSD reports it, so the router-config form
// can offer the devices that actually exist on this box instead of asking an
// operator to remember whether the NIC came up as em0 or igc0.
type HostIface struct {
	Device  string
	MAC     string
	Flags   []string
	Groups  []string
	Media   string   // the parenthetical, e.g. "1000baseT full-duplex"
	Status  string   // "active", "no carrier", ...
	Addrs   []string // IPv4 only, as "10.0.2.15/255.255.255.0"
	IP      string   // first IPv4, for pre-filling the form
	Netmask string   // its mask in dotted form, likewise
}

// Up reports whether the interface is administratively up.
func (h HostIface) Up() bool { return h.hasFlag("UP") }

// Egress reports membership of OpenBSD's egress group - the interface holding
// the default route. That is exactly the "default" flag the router config
// wants, so it seeds it.
func (h HostIface) Egress() bool {
	for _, g := range h.Groups {
		if g == "egress" {
			return true
		}
	}
	return false
}

func (h HostIface) hasFlag(f string) bool {
	for _, v := range h.Flags {
		if v == f {
			return true
		}
	}
	return false
}

// Assignable reports whether this is a real NIC an operator would put in the
// router config, as opposed to a pseudo-device.
//
// The test is driver-agnostic on purpose: OpenBSD has well over a hundred NIC
// drivers and any allowlist of names would silently hide someone's hardware.
// What every physical NIC has and no pseudo-device does is *both* an lladdr
// and a media line - lo0, enc0 and pflog0 have neither. The name check on top
// of that is only for the virtual devices arkgated creates itself from this
// very config, which must never be offered as a parent device.
func (h HostIface) Assignable() bool {
	if h.MAC == "" || h.Media == "" {
		return false
	}
	return !arkgatedManaged(h.Device)
}

// arkgatedManaged names the device classes this daemon creates or consumes
// itself - vlan/svlan from the Vlans config, pppac/pppx from npppd, pflow from
// the pflow export config, plus pf's own pseudo-interfaces.
var arkgatedManaged = func() func(string) bool {
	prefixes := []string{"vlan", "svlan", "pppac", "pppx", "pflow", "pflog", "enc", "lo", "carp", "bridge", "veb", "tpmr"}
	return func(dev string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(dev, p) {
				// Only when what follows is the unit number, so a real
				// driver that merely starts with those letters (say
				// "lo"-something, or "vlanX" as a driver name) is not
				// swallowed by accident.
				rest := strings.TrimPrefix(dev, p)
				if rest == "" {
					return true
				}
				if _, err := strconv.Atoi(rest); err == nil {
					return true
				}
			}
		}
		return false
	}
}()

// mediaRate pulls a link rate out of a media parenthetical, as a pf-style
// bandwidth string: "1000baseT full-duplex" -> "1000M", "10GbaseSR" -> "10G".
// Returns "" for autoselect/none/unknown shapes, in which case the form just
// has no suggestion to make.
var mediaRateRe = regexp.MustCompile(`^(\d+)(G?)base`)

func mediaRate(media string) string {
	m := mediaRateRe.FindStringSubmatch(strings.TrimSpace(media))
	if m == nil {
		return ""
	}
	if m[2] == "G" {
		return m[1] + "G"
	}
	return m[1] + "M"
}

// SpeedHint is the bandwidth to suggest for this interface's pf queues. It is
// the raw link rate; operators commonly set something a little under it to
// leave headroom (the sample config uses 600M/900M on gigabit links), which is
// why this is only ever a placeholder and never a forced value.
func (h HostIface) SpeedHint() string { return mediaRate(h.Media) }

// ifconfigLine matches the start of an interface block: name at column 0.
var ifconfigHeadRe = regexp.MustCompile(`^([a-z][a-z0-9]*):\s+flags=([0-9a-fA-F]+)<([^>]*)>`)

// hexMaskToDotted converts OpenBSD's "netmask 0xffffff00" to "255.255.255.0".
// ifconfig prints IPv4 masks in hex, and every consumer of this config (the
// hostname.if files, dhcpd.conf) wants dotted quads.
func hexMaskToDotted(hexMask string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(hexMask, "0x"), "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// parseIfconfig turns `ifconfig -a` output into HostIfaces. Split out from the
// exec so it can be tested against captured output from a real box.
func parseIfconfig(r io.Reader) []HostIface {
	var out []HostIface
	var cur *HostIface

	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if m := ifconfigHeadRe.FindStringSubmatch(line); m != nil {
			flush()
			cur = &HostIface{Device: m[1]}
			if m[3] != "" {
				cur.Flags = strings.Split(m[3], ",")
			}
			continue
		}
		if cur == nil {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "lladdr":
			if len(f) > 1 {
				cur.MAC = f[1]
			}
		case "groups:":
			cur.Groups = append(cur.Groups, f[1:]...)
		case "media:":
			// "media: Ethernet autoselect (1000baseT full-duplex)" - the
			// parenthetical is the negotiated rate, which is what we want;
			// without one there is no rate to report.
			if i := strings.Index(line, "("); i >= 0 {
				if j := strings.LastIndex(line, ")"); j > i {
					cur.Media = line[i+1 : j]
				}
			}
		case "status:":
			cur.Status = strings.Join(f[1:], " ")
		case "inet":
			// "inet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255"
			if len(f) < 2 {
				continue
			}
			ip, mask := f[1], ""
			for i := 2; i+1 < len(f); i++ {
				if f[i] == "netmask" {
					mask = hexMaskToDotted(f[i+1])
					break
				}
			}
			if cur.IP == "" {
				cur.IP, cur.Netmask = ip, mask
			}
			if mask != "" {
				cur.Addrs = append(cur.Addrs, ip+"/"+mask)
			} else {
				cur.Addrs = append(cur.Addrs, ip)
			}
		}
	}
	flush()
	return out
}

// ListHostIfaces runs ifconfig -a and parses it.
//
// This shells out rather than using net.Interfaces() because the two things
// that make the listing worth having - the egress group (which says which
// interface holds the default route, i.e. the config's "default" flag) and the
// negotiated media rate (which seeds the pf queue bandwidth) - are not exposed
// by Go's net package at all. ifconfig is the authoritative source on OpenBSD
// and gives all of it in one read.
//
// Callers must treat a failure as "no suggestions available", never as a
// reason to refuse configuration: this returns an error on any non-OpenBSD box
// (no ifconfig), and the form still has to let an operator type a device name.
func ListHostIfaces() ([]HostIface, error) {
	out, err := exec.Command("ifconfig", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("running ifconfig -a: %w", err)
	}
	return parseIfconfig(strings.NewReader(string(out))), nil
}

// AssignableHostIfaces is ListHostIfaces filtered to real NICs - what the form
// offers as device choices.
func AssignableHostIfaces() ([]HostIface, error) {
	all, err := ListHostIfaces()
	if err != nil {
		return nil, err
	}
	var out []HostIface
	for _, h := range all {
		if h.Assignable() {
			out = append(out, h)
		}
	}
	return out, nil
}

// defaultRouteRe matches the IPv4 default route in `route -n show -inet`:
//
//	default            10.0.2.2           UGS        5       20     -     8 em0
var defaultRouteRe = regexp.MustCompile(`^default\s+(\S+)\s`)

// DefaultGateway returns the IPv4 default gateway and the interface carrying
// it. The router config requires a gateway on whichever interface is marked
// default (it is what gets written to mygate), so pre-filling it from the live
// routing table is the difference between a form an operator can just save and
// one they have to go look this up for.
//
// An empty gateway is not an error: a box being configured for the first time
// may genuinely have no default route yet.
func DefaultGateway() (gw string, iface string) {
	out, err := exec.Command("route", "-n", "show", "-inet").Output()
	if err != nil {
		return "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		m := defaultRouteRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// The interface is the last field on the row.
		if f := strings.Fields(line); len(f) > 0 {
			iface = f[len(f)-1]
		}
		return m[1], iface
	}
	return "", ""
}
