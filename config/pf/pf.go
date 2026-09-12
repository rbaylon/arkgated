package pfconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc"
	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
	planmodel "github.com/rbaylon/srvcman/modules/plans/model"
	vlanmodel "github.com/rbaylon/srvcman/modules/vlans/model"
)

func MaskToCidr(maskString string) int {
	ip := net.ParseIP(maskString)
	if ip == nil {
		log.Fatalf("Invalid IP address: %s", maskString)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		log.Fatalf("IP address is not IPv4: %s", maskString)
	}
	mask := net.IPMask(ip4)
	prefixSize, _ := mask.Size()
	return prefixSize
}

func BroadcastAddr(n *net.IPNet) net.IP {
	ip := n.IP
	mask := n.Mask
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		// For IPv4, ^mask[i] does the bitwise NOT.
		// For IPv6, the calculation is more complex and usually not done this way.
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

func GetSubs(url string, token *string) (*pfconfigmodel.Pfconfig, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		res.Body.Close()
		return nil, err
	}
	defer res.Body.Close()
	responseData, ioerr := io.ReadAll(res.Body)
	if ioerr != nil {
		return nil, ioerr
	}
	var cfg pfconfigmodel.Pfconfig
	json.Unmarshal(responseData, &cfg)
	return &cfg, nil
}

type vlanmap struct {
	Vmap map[string]vlanmodel.Vlan
}

func getVlans(vlans []vlanmodel.Vlan) vlanmap {
	vm := vlanmap{}
	vm.Vmap = make(map[string]vlanmodel.Vlan)
	for _, v := range vlans {
		vm.Vmap[v.Name] = v
	}
	return vm
}
func ConfigCreate(c *pfconfigmodel.Pfconfig, rundir string) error {
	dnslist := ""
	vlans := getVlans(c.Vlans)
	for _, d := range c.Ifaces {
		vif := ""
		if strings.Contains(d.Device, "vlan") {
			cidr := MaskToCidr(d.Netmask)
			_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", d.Ip, cidr))
			if err != nil {
				fmt.Println("Error parsing CIDR:", err)
				return err
			}
			broadcast := BroadcastAddr(ipNet)
			vlan := vlans.Vmap[d.Device]
			vif = fmt.Sprintf(" %s parent %s rxprio %d txprio %d vnetid %d",
				broadcast, vlan.ParentDevice, vlan.RxPrio, vlan.TxPrio, vlan.VlanTag)
		}
		iface := fmt.Sprintf("inet %s %s%s\n", d.Ip, d.Netmask, vif)
		if d.Default {
			if d.Ip != "autoconf" {
				dnslist := fmt.Sprintf("%snameserver %s\n", dnslist, d.Gateway)
				err := os.WriteFile(rundir+"mygate", []byte(d.Gateway+"\n"), 0640)
				if err != nil {
					log.Println(err)
					return err
				}
				nservers := strings.Split(c.Dns, " ")
				for _, dns := range nservers {
					dnslist = fmt.Sprintf("%snameserver %s\n", dnslist, dns)
				}
				err = os.WriteFile(rundir+"resolv.conf", []byte(dnslist+"\n"), 0640)
				if err != nil {
					log.Println(err)
					return err
				}
			}
		}
		err := os.WriteFile(rundir+"hostname."+d.Device, []byte(iface+"\n"), 0640)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	for _, p := range c.Pflows {
		iface := fmt.Sprintf("flowsrc %s flowdst %s\npflowproto %d\n", p.Src, p.Dst, p.Proto)
		err := os.WriteFile(rundir+"hostname."+p.Device, []byte(iface+"\n"), 0640)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func PfCreate(router string, rundir string, urlbase string, t *string) error {
	newpfcfg, err := GetSubs(urlbase+"pfconfig/query/"+router, t)
	if err != nil {
		log.Println(err)
		return err
	}
	c := newpfcfg
	var macros string
	for _, v := range c.Ifaces {
		macros = fmt.Sprintf("%s%s = \"%s\"\n", macros, v.Name, v.Device)
	}
	tables := heredoc.Docf(`
table <allowed> persist file "%s"
table <subsexpr> persist file "%s"
table <fastdotcom> persist file "%s"
table <bad_hosts> persist
table <martians> { 0.0.0.0/8 169.254.0.0/16  \ 
       192.0.0.0/24 192.0.2.0/24 224.0.0.0/3 \
       198.18.0.0/15 198.51.100.0/24 \ 
       203.0.113.0/24 } 
set block-policy drop 
set loginterface egress 
set skip on lo0
set optimization normal
set limit states 2000000
set limit table-entries 400000
set limit anchors 10240
set limit src-nodes 2000000
`, rundir+c.WifiIpList, rundir+c.SubsIpList, rundir+"fast.com.blocks")
	var queues string
	var defiface string
	for _, v := range c.Ifaces {
		queues = fmt.Sprintf("%squeue %s on { $%s } bandwidth %s\nqueue %sdef parent %s bandwidth %s default\n",
			queues, v.Name, v.Name, v.Speed, v.Name, v.Name, v.Speed)
		queues = fmt.Sprintf("%squeue %slow parent %s bandwidth 20M qlimit 1024\n",
			queues, v.Name, v.Name)
		if v.Default {
			defiface = v.Name
		}
	}
	queues = queues + heredoc.Docf(` 
queue apps parent %s bandwidth 10M 
queue  ssh_interactive parent apps bandwidth 5M min 2M 
queue  ssh_bulk parent apps bandwidth 5M max 5M
# insert new queueus after this line 
`, defiface)
	matches := "match in all scrub (no-df random-id max-mss 1440)\n"
	var nats string
	for _, v := range c.Ifaces {
		if v.Type == "external" {
			nats = fmt.Sprintf("%smatch out on { $%s } inet from !($%s:network) to any nat-to ($%s:0)\n",
				nats, v.Name, v.Name, v.Name)
		} else {
			if v.Name != "management" {
				nats = fmt.Sprintf("%smatch in on { $%s } proto tcp from <subsexpr> to any port { 80, 443 } rdr-to 127.0.0.1 port %d\n",
					nats, v.Name, c.SubsPortalPort)
				nats = fmt.Sprintf("%smatch in on { $%s } proto tcp from !<allowed> to any port { 80, 443 } rdr-to 127.0.0.1 port %d\n",
					nats, v.Name, c.CaptivePortalPort)
			}
		}
		nats = fmt.Sprintf("%smatch out on { $%s } proto udp set prio 4\n",
			nats, v.Name)
	}
	matches = matches + nats
	defaultblock := heredoc.Doc(`
# default bock
block all
block in quick from <bad_hosts>
block in quick from <martians>
`)
	var defaultqrules string
	for _, v := range c.Ifaces {
		defaultqrules = fmt.Sprintf("%sblock return out on { $%s } inet all set queue %sdef\n",
			defaultqrules, v.Name, v.Name)
	}
	defaultqrules = fmt.Sprintf("%spass out from self\n", defaultqrules)
	var passrules string
	var gws []string
	//var extifs []string
	for _, v := range c.Ifaces {
		if v.Type == "external" {
			//extifs = append(extifs, v.Name)
			gws = append(gws, fmt.Sprintf("%s weight %d", v.Gateway, v.LbPercentage))
		}
	}
	var gateways string
	var lbrules string
	if c.LoadBalance {
		gateways = fmt.Sprintf("route-to { %s } round-robin sticky-address", strings.Join(gws, ", "))
	} else {
		gateways = ""
		lbrules = ""
	}

	for _, v := range c.Ifaces {
		if v.Type == "external" {
			passrules = fmt.Sprintf("%spass out quick on { $%s } proto {udp, tcp} to any port { 853, 53 }\n", passrules, v.Name)
			if v.Default {
				passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to $%s:0 port 22 keep state (max-src-conn-rate 10/10, overload <bad_hosts> flush global) set queue (ssh_interactive, ssh_bulk)\n",
					passrules, v.Name, v.Name)
			} else {
				passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to $%s:0 port 22 keep state (max-src-conn-rate 10/10, overload <bad_hosts> flush global) set queue (ssh_interactive, ssh_bulk) reply-to %s\n",
					passrules, v.Name, v.Name, v.Gateway)
			}
		} else {
			passrules = fmt.Sprintf("%spass in quick on { $%s } proto {udp, tcp} to any port 53 rdr-to $%s:0 port 53\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to { $%s:0, 127.0.0.1 } port { %d, %d, 22 }\n", passrules, v.Name, v.Name, c.CaptivePortalPort, c.SubsPortalPort)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto tcp from any to $%s:0 port = 22 keep state\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto udp from any port = bootpc to 255.255.255.255 port = bootps keep state\n", passrules, v.Name)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto udp from any port = bootpc to { $%s:0 } port = bootps keep state\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass out quick on { $%s } inet proto udp from { $%s:0 } port = bootps to any port = bootpc keep state\n", passrules, v.Name, v.Name)
		}
	}

	plans := make(map[string]string)
	planlist := make(map[string]planmodel.Plan)
	plantables := ""
	strules := ""
	planqueue := ""
	for _, v := range newpfcfg.Plans {
		plans[v.Plan] = ""
		planlist[v.Plan] = v
		plantables = fmt.Sprintf("%stable <%s> persist file \"%swifilist.txt%s\"\n", plantables, v.Plan, rundir, v.Plan)
		for _, i := range c.Ifaces {
			if i.Type == "external" {
				planqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n", planqueue, v.Plan, i.Name, i.Name, v.SpeedTestUp, v.SpeedTestUp)
				strules = fmt.Sprintf("%spass out quick on $%s set queue %s%s set prio 7 tagged \"%s\"\n", strules, i.Name, v.Plan, i.Name, v.Plan)
				strules = fmt.Sprintf("%spass out quick on $%s set queue %s%s set prio 7 tagged \"%sfast\"\n", strules, i.Name, v.Plan, i.Name, v.Plan)
			} else {
				planqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n", planqueue, v.Plan, i.Name, i.Name, v.SpeedTestDown, v.SpeedTestDown)
				strules = fmt.Sprintf("%spass in quick on $%s inet proto { tcp, udp } from <%s> to any port { 5060, 8080 } set queue %s%s set prio 7 tag \"%s\"\n", strules, i.Name, v.Plan, v.Plan, i.Name, v.Plan)
				strules = fmt.Sprintf("%spass in quick on $%s inet proto tcp from <%s> to <fastdotcom> port 443 set queue %s%s set prio 7 tag \"%sfast\"\n", strules, i.Name, v.Plan, v.Plan, i.Name, v.Plan)
			}
		}
	}
	var subqueue string
	var subpass string
	var gateway string
	var pppcreds string
	for _, i := range newpfcfg.Ifaces {
		for _, voucher := range newpfcfg.Vouchers {
			if voucher.Status == "active" {
				if i.Type == "external" {
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n",
						subqueue, voucher.Value, i.Name, i.Name, voucher.Upspeed, voucher.Upspeed)
					subpass = fmt.Sprintf("%spass out quick on $%s set queue %s%s tagged \"%s\"\n",
						subpass, i.Name, voucher.Value, i.Name, voucher.Value)
				} else {
					if voucher.Gateway != "" {
						gateway = fmt.Sprintf("route-to %s", voucher.Gateway)
					} else {
						gateway = gateways
					}
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms\n",
						subqueue, voucher.Value, i.Name, i.Name, voucher.Downspeed, voucher.Downspeed, voucher.Burstspeed, voucher.Duration)
					subpass = fmt.Sprintf("%spass in quick on $%s from %s %s set queue %s%s tag \"%s\"\n",
						subpass, i.Name, voucher.Ip, gateway, voucher.Value, i.Name, voucher.Value)
				}
			}
		}
		for _, sub := range newpfcfg.Subs {
			if sub.Status == "active" {
				ident := strings.Replace(sub.Mac, ":", "", -1)
				priority := ""
				if sub.Priority > 0 {
					priority = fmt.Sprintf("set prio %d", sub.Priority)
				}
				if i.Type == "external" {
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM qlimit 1024\n",
						subqueue, ident, i.Name, i.Name, planlist[sub.Plan].Upspeed, planlist[sub.Plan].Upspeed)

					//subqueue = fmt.Sprintf("%squeue %s%stest parent %s bandwidth %dM min 5M max %dM qlimit 1024\n",
					//subqueue, ident, i.Name, i.Name, planlist[sub.Plan].SpeedTestUp, planlist[sub.Plan].SpeedTestUp)

					//subpass = fmt.Sprintf("%spass out quick on $%s set queue (%s%stest, %slow) set prio 7 tagged \"%stest\"\n",
					//subpass, i.Name, ident, i.Name, i.Name, ident)

					subpass = fmt.Sprintf("%spass out quick on $%s set queue (%s%s, %slow) %s tagged \"%s\"\n",
						subpass, i.Name, ident, i.Name, i.Name, priority, ident)
				} else {
					if i.Name == sub.Type {
						if sub.Pppusername != "" && sub.Ppppassword != "" {
							pppcreds = fmt.Sprintf("%s%s:\\\n\t:password=%s:\\\n\t:framed-ip-address=%s:\n\n",
								pppcreds, sub.Pppusername, sub.Ppppassword, sub.FramedIp)
						}

						if sub.Gateway != "" {
							gateway = fmt.Sprintf("route-to %s", sub.Gateway)
						} else {
							gateway = gateways
						}
						subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms qlimit 1024\n",
							subqueue, ident, i.Name, i.Name, planlist[sub.Plan].Downspeed, planlist[sub.Plan].Downspeed, planlist[sub.Plan].Downspeed*2, 3000)

						//subqueue = fmt.Sprintf("%squeue %s%stest parent %s bandwidth %dM min 5M max %dM qlimit 1024\n", subqueue, ident, i.Name, i.Name, planlist[sub.Plan].SpeedTestDown, planlist[sub.Plan].SpeedTestDown)

						//subpass = fmt.Sprintf("%spass in quick on $%s inet proto { tcp, udp } from %s to any port { 5060, 8080 } %s set queue (%s%stest, %slow) set prio 7 tag \"%stest\"\n",
						//subpass, i.Name, sub.FramedIp, gateway, ident, i.Name, i.Name, ident)

						subpass = fmt.Sprintf("%spass in quick on $%s from %s %s set queue (%s%s, %slow) %s label \"%s\" tag \"%s\"\n",
							subpass, i.Name, sub.FramedIp, gateway, ident, i.Name, i.Name, priority, sub.FramedIp, ident)
					}
				}
			}
		}
	}
	fwrules := ""
	for _, rule := range newpfcfg.Rules {
		subqueue = subqueue + rule.QRule
		fwrules = fwrules + rule.OutRule
		fwrules = fwrules + rule.Rule
	}
	var wifilist string
	var subslist string
	for _, voucher := range newpfcfg.Vouchers {
		if voucher.Status == "active" {
			wifilist = fmt.Sprintf("%s%s\n", wifilist, voucher.Ip)
		}
	}
	for _, sub := range newpfcfg.Subs {
		if sub.Status == "active" {
			wifilist = fmt.Sprintf("%s%s\n", wifilist, sub.FramedIp)
			plans[sub.Plan] = fmt.Sprintf("%s%s\n", plans[sub.Plan], sub.FramedIp)
		} else {
			subslist = fmt.Sprintf("%s%s\n", subslist, sub.FramedIp)
		}
	}
	os.Rename(rundir+c.WifiIpList, rundir+c.WifiIpList+".old")
	err = os.WriteFile(rundir+c.WifiIpList, []byte(wifilist), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	for k, v := range plans {
		os.Rename(rundir+c.WifiIpList+k, rundir+c.WifiIpList+k+".old")
		err = os.WriteFile(rundir+c.WifiIpList+k, []byte(v), 0600)
		if err != nil {
			log.Println(err)
			return err
		}
	}
	os.Rename(rundir+c.SubsIpList, rundir+c.SubsIpList+".old")
	err = os.WriteFile(rundir+c.SubsIpList, []byte(subslist), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	configstring := macros + plantables + tables + queues + planqueue + subqueue + matches + defaultblock + defaultqrules + passrules + strules + fwrules + subpass + lbrules
	err = os.WriteFile("/tmp/pf.conf", []byte(configstring), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	err = os.WriteFile("/etc/npppd/npppd-users", []byte(pppcreds), 0600)
	if err != nil {
		log.Println(err)
		return err
	}

	err = ConfigCreate(c, rundir)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

// fetchConfText GETs a {"conf": "..."} response from urlbase (e.g. srvcman's
// /api/v1/dhcpserver/conf or /api/v1/unbounddns/conf) and returns the conf
// text. DhcpCreate/DnsCreate use this to pull config text rendered
// server-side by srvcman, which owns the underlying DhcpServer/UnboundDns
// records, rather than duplicating that rendering logic here.
func fetchConfText(url string, token *string) (string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	var resp struct {
		Conf string `json:"conf"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	return resp.Conf, nil
}

// DhcpCreate fetches the freshly rendered dhcpd.conf text from srvcman
// (which owns the DhcpServer records) and stages it at rundir+"dhcpd.conf" -
// the same path modules/changes' apply flow on srvcman then backs up/stages
// into /etc/dhcpd.conf and restarts dhcpd from, via ordinary Arkcmd mv/rcctl
// commands. srvcman no longer writes this file itself: since srvcman and
// arkgated may run on separate hosts, a file srvcman wrote to its own disk
// was never visible to arkgated's mv of that same path - fetching the
// content here means the file being backed up/staged always exists on the
// host doing the backing up.
func DhcpCreate(rundir, urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"dhcpserver/conf", token)
	if err != nil {
		return err
	}
	return os.WriteFile("/tmp/dhcpd.conf", []byte(conf), 0640)
}

// DnsCreate is DhcpCreate's unbound.conf equivalent, fetching from srvcman's
// /unbounddns/conf and staging at rundir+"unbound.conf".
func DnsCreate(rundir, urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"unbounddns/conf", token)
	if err != nil {
		return err
	}
	return os.WriteFile("/tmp/unbound.conf", []byte(conf), 0640)
}

// PppoeCreate is DhcpCreate's npppd.conf equivalent, fetching from srvcman's
// /pppoes/conf and staging at rundir+"npppd.conf".
func PppoeCreate(rundir, urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"pppoes/conf", token)
	if err != nil {
		return err
	}
	return os.WriteFile("/tmp/npppd.conf", []byte(conf), 0640)
}

// promoteIfDifferent replaces dst with src's content, but only if they
// differ (or dst doesn't exist yet) - reports whether it did anything. dst
// is backed up to a timestamped copy first. src not existing is not an
// error (e.g. no default gateway configured for this router yet); it just
// means there's nothing to promote.
func promoteIfDifferent(src, dst string) (bool, error) {
	newdata, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if olddata, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(olddata, newdata) {
			return false, nil
		}
		if err := os.Rename(dst, fmt.Sprintf("%s.%d", dst, time.Now().Unix())); err != nil {
			log.Println("promoteIfDifferent: backup of", dst, "failed:", err)
		}
	}
	if err := os.WriteFile(dst, newdata, 0640); err != nil {
		return false, err
	}
	return true, nil
}

// ApplyIfaces regenerates every configured interface's hostname.<if> file
// (plus mygate/resolv.conf for the default interface) from live Pfconfig
// data, then promotes each into /etc and restarts networking for it - but
// only for files whose freshly rendered content actually differs from
// what's currently installed, so pinging one gateway's config doesn't
// disrupt an unrelated interface's active connections with an unneeded
// netstart. This replaces srvcman's former approach of writing hostname.<if>
// files to its own /tmp and asking arkgated to mv them: that broke once
// srvcman and arkgated could run on separate hosts, since the file srvcman
// wrote was never visible on arkgated's filesystem. Now arkgated both
// generates and applies these files itself.
func ApplyIfaces(router, rundir, urlbase string, token *string) ([]string, error) {
	c, err := GetSubs(urlbase+"pfconfig/query/"+router, token)
	if err != nil {
		return nil, err
	}
	if err := ConfigCreate(c, "/tmp/"); err != nil {
		return nil, err
	}
	var applied []string
	for _, d := range c.Ifaces {
		changed, err := promoteIfDifferent("/tmp/hostname."+d.Device, "/etc/hostname."+d.Device)
		if err != nil {
			return applied, err
		}
		if !changed {
			continue
		}
		if out, err := exec.Command("sh", "/etc/netstart", d.Device).CombinedOutput(); err != nil {
			log.Println(string(out))
			return applied, fmt.Errorf("netstart %s: %w", d.Device, err)
		}
		applied = append(applied, d.Device)
	}
	gwChanged, err := promoteIfDifferent("/tmp/mygate", "/etc/mygate")
	if err != nil {
		return applied, err
	}
	if gwChanged {
		if out, err := exec.Command("sh", "/etc/netstart").CombinedOutput(); err != nil {
			log.Println(string(out))
			return applied, fmt.Errorf("netstart: %w", err)
		}
		applied = append(applied, "mygate")
	}
	return applied, nil
}

func Init(config string) (*pfconfigmodel.Pfconfig, error) {
	jsoncmdFile, err := os.Open(config)
	if err != nil {
		log.Println("Error during json open file: ", err)
		return nil, err
	}
	defer jsoncmdFile.Close()
	byteValue, err := io.ReadAll(jsoncmdFile)
	if err != nil {
		log.Println("Error during reading json content: ", err)
		return nil, err
	}
	var cfg pfconfigmodel.Pfconfig
	err = json.Unmarshal(byteValue, &cfg)
	if err != nil {
		log.Println("Error during unmarshal: ", err)
		return nil, err
	}
	return &cfg, nil
}
