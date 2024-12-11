package pfconfig

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/MakeNowJust/heredoc"
	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
)

func GetSubs(url string, token *string) (*pfconfigmodel.Pfconfig, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer res.Body.Close()
	responseData, ioerr := ioutil.ReadAll(res.Body)
	if ioerr != nil {
		return nil, ioerr
	}
	var cfg pfconfigmodel.Pfconfig
	json.Unmarshal(responseData, &cfg)
	return &cfg, nil
}

func DhcpCreate(c *pfconfigmodel.Pfconfig, rundir string) error {
	dhcp := ""
	for _, d := range c.Dhcps {
		net_block := heredoc.Docf(`
subnet %s netmask %s {
  option routers %s;
  option domain-name-servers %s, 8.8.8.8, 4.2.2.2;
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

func ConfigCreate(c *pfconfigmodel.Pfconfig) error {
	dnslist := ""
	for _, d := range c.Ifaces {
		iface := fmt.Sprintf("inet %s %s\n", d.Ip, d.Netmask)
		if d.Default {
			if d.Ip != "autoconf" {
				dnslist := fmt.Sprintf("%snameserver %s\n", dnslist, d.Gateway)
				err := os.WriteFile("/etc/mygate", []byte(d.Gateway), 0640)
				if err != nil {
					log.Println(err)
					return err
				}
				nservers := strings.Split(c.Dns, " ")
				for _, dns := range nservers {
					dnslist := fmt.Sprintf("%snameserver %s\n", dnslist, dns)
				}
				err := os.WriteFile("/etc/resolv.conf", []byte(dnslist), 0640)
				if err != nil {
					log.Println(err)
					return err
				}
			}
		}
		err := os.WriteFile("/etc/hostname."+d.Device, []byte(iface), 0640)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	for _, p := range c.Pflows {
		iface := fmt.Sprintf("flowsrc %s flowdst %s\npflowproto %d\n", p.Src, p.Dst, p.Proto)
		err := os.WriteFile("/etc/hostname."+p.Device, []byte(iface), 0640)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func PfCreate(c *pfconfigmodel.Pfconfig, rundir string, urlbase string, t *string) error {
	var macros string
	for _, v := range c.Ifaces {
		macros = fmt.Sprintf("%s%s = \"%s\"\n", macros, v.Name, v.Device)
	}
	tables := heredoc.Docf(`
table <allowed> persist file "%s"
table <subsexpr> persist file "%s"
table <bad_hosts> persist
table <martians> { 0.0.0.0/8 169.254.0.0/16  \ 
       192.0.0.0/24 192.0.2.0/24 224.0.0.0/3 \
       198.18.0.0/15 198.51.100.0/24 \ 
       203.0.113.0/24 } 
set block-policy drop 
set loginterface egress 
set skip on lo0 
`, rundir+c.WifiIpList, rundir+c.SubsIpList)
	var queues string
	var defiface string
	for _, v := range c.Ifaces {
		queues = fmt.Sprintf("%squeue %s on { $%s } bandwidth %s\nqueue %sdef parent %s bandwidth 2M default\n",
			queues, v.Name, v.Name, v.Speed, v.Name, v.Name)
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
	var extifs []string
	for _, v := range c.Ifaces {
		if v.Type == "external" {
			extifs = append(extifs, v.Name)
			gws = append(gws, v.Gateway)
		}
	}
	var gateways string
	var lbrules string
	if c.LoadBalance {
		gateways = fmt.Sprintf("route-to { %s } round-robin sticky-address", strings.Join(gws, " "))
		for _, g := range extifs {
			for _, v := range c.Ifaces {
				if v.Type == "external" {
					if v.Name != g {
						lbrules = fmt.Sprintf("%spass out on $%s from $%s route-to %s\n", lbrules, g, v.Name, v.Gateway)
					}
				}
			}
		}
	} else {
		gateways = ""
		lbrules = ""
	}

	for _, v := range c.Ifaces {
		if v.Type == "external" {
			passrules = fmt.Sprintf("%spass out quick on { $%s } proto {udp, tcp} to any port 53\n", passrules, v.Name)
			if v.Default {
				passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to $%s:0 port 22 keep state (max-src-conn-rate 10/10, overload <bad_hosts> flush global) set queue (ssh_interactive, ssh_bulk)\n",
					passrules, v.Name, v.Name)
				passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 } to any set queue selfq\n", passrules, v.Name, v.Name)
			}
			passrules = fmt.Sprintf("%spass out on { $%s } inet proto icmp from { $%s:0 } to any\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 } to any\n", passrules, v.Name, v.Name)
		} else {
			passrules = fmt.Sprintf("%spass in quick on { $%s } proto {udp, tcp} to any port 53\n", passrules, v.Name)
			passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 }\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to { $%s:0, 127.0.0.1 } port { %d, %d, 22, 667 }\n", passrules, v.Name, v.Name, c.CaptivePortalPort, c.SubsPortalPort)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto tcp from any to $%s:0 port = 22 keep state\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto tcp from any to $%s:0 port = 9100 keep state\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto udp from any port = bootpc to 255.255.255.255 port = bootps keep state\n", passrules, v.Name)
			passrules = fmt.Sprintf("%spass in quick on { $%s } inet proto udp from any port = bootpc to { $%s:0 } port = bootps keep state\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass out quick on { $%s } inet proto udp from { $%s:0 } port = bootps to any port = bootpc keep state\n", passrules, v.Name, v.Name)
		}
	}

	newpfcfg, err := GetSubs(urlbase+"pfconfig/query/"+c.Router, t)
	if err != nil {
		log.Println(err)
		return err
	}
	var subqueue string
	var subpass string
	for _, i := range c.Ifaces {
		for _, voucher := range newpfcfg.Vouchers {
			if i.Type == "external" {
				subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n",
					subqueue, voucher.Value, i.Name, i.Name, voucher.Upspeed, voucher.Upspeed)
				subpass = fmt.Sprintf("%spass out on $%s set queue %s%s tagged \"%s\"\n",
					subpass, i.Name, voucher.Value, i.Name, voucher.Value)
			} else {
				if i.Name == voucher.Type {
					gateways = ""
					if voucher.Gateway != "" {
						gateways = fmt.Sprintf("route-to %s", voucher.Gateway)
					}
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms\n",
						subqueue, voucher.Value, i.Name, i.Name, voucher.Downspeed, voucher.Downspeed, voucher.Burstspeed, voucher.Duration)
					subpass = fmt.Sprintf("%spass in on $%s from %s %s set queue %s%s tag \"%s\"\n",
						subpass, i.Name, voucher.Ip, gateways, voucher.Value, i.Name, voucher.Value)
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
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n", subqueue, ident, i.Name, i.Name, sub.Upspeed, sub.Upspeed)
					subpass = fmt.Sprintf("%spass out on $%s set queue %s%s %s tagged \"%s\"\n",
						subpass, i.Name, ident, i.Name, priority, ident)
					/*ulbw := sub.Upspeed - 1
					subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n",
						subqueue, ident, i.Name, i.Name, sub.Upspeed, sub.Upspeed)
					subqueue = fmt.Sprintf("%squeue %s%sack parent %s%s bandwidth 5M min 1M\n", subqueue, ident, i.Name, ident, i.Name)
					subqueue = fmt.Sprintf("%squeue %s%sdata parent %s%s bandwidth %dM min 5M max %dM\n", subqueue, ident, i.Name, ident, i.Name, ulbw, sub.Upspeed)
					subpass = fmt.Sprintf("%spass out on $%s set queue ( %s%sdata, %s%sack ) %s tagged \"%s\"\n",
						subpass, i.Name, ident, i.Name, ident, i.Name, priority, ident)
					*/
				} else {
					if i.Name == sub.Type {
						//dlbw := sub.Downspeed - 1
						gateways = ""
						if sub.Gateway != "" {
							gateways = fmt.Sprintf("route-to %s", sub.Gateway)
						}
						subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms\n",
							subqueue, ident, i.Name, i.Name, sub.Downspeed, sub.Downspeed, sub.Burstspeed, sub.Duration)
						subpass = fmt.Sprintf("%spass in on $%s from %s %s set queue %s%s %s tag \"%s\"\n",
							subpass, i.Name, sub.FramedIp, gateways, ident, i.Name, priority, ident)
						/*
							subqueue = fmt.Sprintf("%squeue %s%s parent %s bandwidth %dM min 5M max %dM\n",
								subqueue, ident, i.Name, i.Name, sub.Downspeed, sub.Downspeed)
							subqueue = fmt.Sprintf("%squeue %s%sack parent %s%s bandwidth 5M min 1M\n", subqueue, ident, i.Name, ident, i.Name)
							subqueue = fmt.Sprintf("%squeue %s%sdata parent %s%s bandwidth %dM min 5M max %dM burst %dM for %dms\n", subqueue, ident, i.Name, ident, i.Name, dlbw, sub.Downspeed, sub.Burstspeed, sub.Duration)
							subpass = fmt.Sprintf("%spass in on $%s from %s %s set queue ( %s%sdata, %s%sack ) %s tag \"%s\"\n",
								subpass, i.Name, sub.FramedIp, gateways, ident, i.Name, ident, i.Name, priority, ident)
						*/
					}
				}
			}
		}
	}
	var wifilist string
	var subslist string
	for _, voucher := range newpfcfg.Vouchers {
		wifilist = fmt.Sprintf("%s%s\n", wifilist, voucher.Ip)
	}
	for _, sub := range newpfcfg.Subs {
		if sub.Status == "active" {
			wifilist = fmt.Sprintf("%s%s\n", wifilist, sub.FramedIp)
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
	os.Rename(rundir+c.SubsIpList, rundir+c.SubsIpList+".old")
	err = os.WriteFile(rundir+c.SubsIpList, []byte(subslist), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	configstring := macros + tables + queues + subqueue + matches + defaultblock + defaultqrules + passrules + subpass + lbrules
	err = os.WriteFile(rundir+"pf.conf", []byte(configstring), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	err = DhcpCreate(c, rundir)
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

func Init(config string) (*pfconfigmodel.Pfconfig, error) {
	jsoncmdFile, err := os.Open(config)
	if err != nil {
		log.Println("Error during json open file: ", err)
		return nil, err
	}
	defer jsoncmdFile.Close()
	byteValue, err := ioutil.ReadAll(jsoncmdFile)
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
