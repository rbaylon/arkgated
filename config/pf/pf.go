package pfconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/MakeNowJust/heredoc"
	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
	planmodel "github.com/rbaylon/srvcman/modules/plans/model"
	pppoemodel "github.com/rbaylon/srvcman/modules/pppoes/model"
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

func GetPpp(token *string, urlbase string, pfconfigid uint) ([]pppoemodel.Pppoe, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", urlbase+"pppoe/pfconfig/"+strconv.Itoa(int(pfconfigid)), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		res.Body.Close()
		return nil, err
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("npppd record not found for pfconfig id: %d", pfconfigid)
	}
	defer res.Body.Close()
	responseData, ioerr := io.ReadAll(res.Body)
	if ioerr != nil {
		return nil, ioerr
	}
	ppp := []pppoemodel.Pppoe{}
	json.Unmarshal(responseData, &ppp)
	return ppp, nil
}

func DhcpCreate(c *pfconfigmodel.Pfconfig, rundir string) error {
	dhcp := ""
	for _, d := range c.Dhcps {
		net_block := heredoc.Docf(`
subnet %s netmask %s {
  option routers %s;
  option domain-name-servers %s, 1.1.1.1, 1.0.0.1;
  range %s;
}
`, d.Subnet, d.Netmask, d.Routers, d.Dnsservers, d.Range)
		dhcp = fmt.Sprintf("%s%s", dhcp, net_block)
	}
	err := os.WriteFile(rundir+"dhcpd.conf", []byte(dhcp), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func DnsCreate(c *pfconfigmodel.Pfconfig, rundir string) error {
	dnsblock := heredoc.Docf(`
server:
    interface: 0.0.0.0
    #outgoing-interface: 192.168.254.254
    # Use system CA bundle for TLS verification
    tls-cert-bundle: "/etc/ssl/cert.pem"
    access-control: 172.16.0.0/12 allow
    do-not-query-localhost: no
    hide-identity: yes
    hide-version: yes
    prefetch: yes

forward-zone:
    name: "."
    forward-tls-upstream: yes

    # Primary upstreams (DNS over TLS)
    forward-addr: 1.1.1.1@853
    forward-addr: 1.0.0.1@853
    forward-addr: 9.9.9.9@853
    forward-addr: 149.112.112.112@853

    # Fallback upstreams (plain DNS, port 53)
    forward-addr: 8.8.8.8
    forward-addr: 8.8.4.4
	`)
	err := os.WriteFile(rundir+"unbound.conf", []byte(dnsblock), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
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

func NppdCreate(token *string, urlbase string, rundir string, pfconfigid uint) error {
	nppd, err := GetPpp(token, urlbase, pfconfigid)
	if err != nil {
		return err
	}
	npppdauth := heredoc.Docf(`
authentication LOCAL type local {
        users-file "/etc/npppd/npppd-users"
        user-max-session 1
}

		`)

	cfg := fmt.Sprintf("%s\n", npppdauth)
	for _, d := range nppd {
		npppd := heredoc.Docf(`
tunnel PPPOE%d protocol pppoe {
		listen on interface %s
}

ipcp IPCP%d {
		pool-address %s
		dns-servers %s
}

interface pppac%d address %s ipcp IPCP%d
bind tunnel from PPPOE%d authenticated by LOCAL to pppac%d

`,
			d.DevIndex, d.Device, d.DevIndex, d.PoolAddress, d.DnsAddress, d.DevIndex, d.Ip,
			d.DevIndex, d.DevIndex, d.DevIndex)
		cfg = fmt.Sprintf("%s%s\n", cfg, npppd)
	}
	err = os.WriteFile("/etc/npppd/npppd.conf.tmp", []byte(cfg+"\n"), 0644)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func PfCreate(router string, rundir string, urlbase string, t *string) error {
	newpfcfg, err := GetSubs(urlbase+"pfconfig/query/"+router, t)
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
queue selfq parent %s bandwidth 10M min 5M max 10M burst 15M for 100ms 
queue apps parent %s bandwidth 10M 
queue  ssh_interactive parent apps bandwidth 5M min 2M 
queue  ssh_bulk parent apps bandwidth 5M max 5M
# insert new queueus after this line 
`, defiface, defiface)
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
	if err != nil {
		log.Println(err)
		return err
	}
	if c.LoadBalance {
		gateways = fmt.Sprintf("route-to { %s } round-robin sticky-address", strings.Join(gws, ", "))
	} else {
		gateways = ""
		lbrules = ""
	}

	for _, v := range c.Ifaces {
		if v.Type == "external" {
			passrules = fmt.Sprintf("%spass out quick on { $%s } proto {udp, tcp} to any port { 853, 53 }\n", passrules, v.Name)
			passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to $%s:0 port 22 keep state (max-src-conn-rate 10/10, overload <bad_hosts> flush global) set queue (ssh_interactive, ssh_bulk)\n",
				passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 } to any set queue selfq\n", passrules, v.Name, v.Name)

			passrules = fmt.Sprintf("%spass out on { $%s } inet proto icmp from { $%s:0 } to any\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 } to any\n", passrules, v.Name, v.Name)
		} else {
			passrules = fmt.Sprintf("%spass in quick on { $%s } proto {udp, tcp} to any port 53 rdr-to $%s:0 port 53\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 }\n", passrules, v.Name, v.Name)
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
					subpass = fmt.Sprintf("%spass out on $%s set queue %s%s tagged \"%s\"\n",
						subpass, i.Name, voucher.Value, i.Name, voucher.Value)
				} else {
					if voucher.Gateway != "" {
						gateway = fmt.Sprintf("route-to %s", voucher.Gateway)
					} else {
						gateway = gateways
					}
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms\n",
						subqueue, voucher.Value, i.Name, i.Name, voucher.Downspeed, voucher.Downspeed, voucher.Burstspeed, voucher.Duration)
					subpass = fmt.Sprintf("%spass in on $%s from %s %s set queue %s%s tag \"%s\"\n",
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

					subpass = fmt.Sprintf("%spass out on $%s set queue (%s%s, %slow) %s tagged \"%s\"\n",
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

						subpass = fmt.Sprintf("%spass in on $%s from %s %s set queue (%s%s, %slow) %s tag \"%s\"\n",
							subpass, i.Name, sub.FramedIp, gateway, ident, i.Name, i.Name, priority, ident)
					}
				}
			}
		}
	}
	for _, rule := range newpfcfg.Rules {
		subqueue = subqueue + rule.QRule
		subpass = subpass + rule.OutRule
		subpass = subpass + rule.Rule
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
	configstring := macros + plantables + tables + queues + planqueue + subqueue + matches + defaultblock + defaultqrules + passrules + strules + subpass + lbrules
	err = os.WriteFile(rundir+"pf.conf", []byte(configstring), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	err = os.WriteFile("/etc/npppd/npppd-users-tmp", []byte(pppcreds), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	err = DhcpCreate(c, rundir)
	if err != nil {
		log.Println(err)
		return err
	}

	err = DnsCreate(c, rundir)
	if err != nil {
		log.Println(err)
		return err
	}

	err = ConfigCreate(c, rundir)
	if err != nil {
		log.Println(err)
		return err
	}
	err = NppdCreate(t, urlbase, rundir, newpfcfg.ID)
	if err != nil {
		log.Println(err)
	}
	return nil
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
