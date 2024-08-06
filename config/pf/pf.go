package pfconfig

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MakeNowJust/heredoc"
)

type Voucher struct {
	Value         string    `json:"value"`
	Type          string    `json:"type"`
	Hours         int       `json:"hours"`
	Status        string    `json:"status"`
	Downspeed     int       `json:"downspeed"`
	Upspeed       int       `json:"upspeed"`
	Burstspeed    int       `json:"burstspeed"`
	Duration      int       `json:"duration"`
	Ip            string    `json:"ip"`
	DateStarted   time.Time `json:"date_started"`
	DateEnd       time.Time `json:"date_end"`
	DateExpires   time.Time `json:"date_expires"`
	HoursConsumed float64   `json:"hours_consumed"`
	PfConfigID    uint      `json:"pfconfig_id"`
}

type Iface struct {
	Name       string `json:"name"`
	Speed      string `json:"speed"`
	Device     string `json:"device"`
	Default    bool   `json:"default"`
	Type       string `json:"type"`
	PfConfigID uint   `json:"pfconfig_id"`
}

type PfConfig struct {
	Ifaces            []Iface   `json:"ifaces"`
	WifiIpList        string    `json:"wifi_ip_list"`
	SubsIpList        string    `json:"subs_ip_list"`
	SubsPortalPort    int       `json:"subs_portal_port"`
	CaptivePortalPort int       `json:"captive_portal_port"`
	Router            string    `json:"router"`
	Vouchers          []Voucher `json:"vouchers"`
}

func GetSubs(url string, token *string) (*PfConfig, error) {
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
	var cfg PfConfig
	json.Unmarshal(responseData, &cfg)
	return &cfg, nil
}

func (c *PfConfig) Create(rundir string, urlbase string, t *string) error {
	var macros string
	for _, v := range c.Ifaces {
		macros = fmt.Sprintf("%s%s = \"%s\"\n", macros, v.Name, v.Device)
	}
	tables := heredoc.Docf(`
table <wifi> persist file "%s"
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
			if v.Name == "lan" {
				nats = fmt.Sprintf("%smatch in on { $%s } proto tcp from !<wifi> to any port { 80, 443 } rdr-to 127.0.0.1 port %d\n",
					nats, v.Name, c.CaptivePortalPort)
			} else {
				nats = fmt.Sprintf("%smatch in on { $%s } proto tcp from <subsexpr> to any port { 80, 443 } rdr-to 127.0.0.1 port %d\n",
					nats, v.Name, c.SubsPortalPort)
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
	for _, v := range c.Ifaces {
		if v.Type == "external" {
			passrules = fmt.Sprintf("%spass out on { $%s } proto {udp, tcp} to any port 53\n", passrules, v.Name)
			if v.Default {
				passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to $%s:0 port 22 keep state (max-src-conn-rate 10/10, overload <bad_hosts> flush global) set queue (ssh_interactive, ssh_bulk)\n",
					passrules, v.Name, v.Name)
				passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0, 127.0.0.1 } to any set queue selfq\n", passrules, v.Name, v.Name)
			}
			passrules = fmt.Sprintf("%spass out on { $%s } inet proto icmp from { $%s:0, 127.0.0.1 } to any\n", passrules, v.Name, v.Name)
		} else {
			passrules = fmt.Sprintf("%spass in on { $%s } proto {udp, tcp} to any port 53\n", passrules, v.Name)
			passrules = fmt.Sprintf("%spass out on { $%s } from { $%s:0 }\n", passrules, v.Name, v.Name)
			passrules = fmt.Sprintf("%spass in on { $%s } inet proto tcp from any to { $%s:0, 127.0.0.1 } port { %d, %d }\n", passrules, v.Name, v.Name, c.CaptivePortalPort, c.SubsPortalPort)
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
				subqueue = fmt.Sprintf("%squeue %s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms\n",
					subqueue, voucher.Value, i.Name, voucher.Upspeed, voucher.Upspeed, voucher.Burstspeed, voucher.Duration)
				subpass = fmt.Sprintf("%spass out on $%s set queue %s tagged %s\n",
					subpass, i.Name, voucher.Value, voucher.Value)
			} else {
				if voucher.Type == i.Name {
					subqueue = fmt.Sprintf("%squeue %s parent %s bandwidth %dM min 5M max %dM burst %dM for %dms\n",
						subqueue, voucher.Value, i.Name, voucher.Downspeed, voucher.Downspeed, voucher.Burstspeed, voucher.Duration)
					subpass = fmt.Sprintf("%spass in on $%s from %s set queue %s tag %s\n",
						subpass, i.Name, voucher.Ip, voucher.Value, voucher.Value)
				}
			}
		}
	}
	var wifilist string
	var subslist string
	for _, voucher := range newpfcfg.Vouchers {
		if voucher.Type == "lan" {
			wifilist = fmt.Sprintf("%s%s\n", wifilist, voucher.Ip)
		} else {
			subslist = fmt.Sprintf("%s%s\n", subslist, voucher.Ip)
		}
	}
	err = os.WriteFile(rundir+c.WifiIpList, []byte(wifilist), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	err = os.WriteFile(rundir+c.SubsIpList, []byte(subslist), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	configstring := macros + tables + queues + subqueue + matches + defaultblock + defaultqrules + passrules + subpass
	err = os.WriteFile(rundir+"pf.conf", []byte(configstring), 0600)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func Init(config string) (*PfConfig, error) {
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
	var cfg PfConfig
	err = json.Unmarshal(byteValue, &cfg)
	if err != nil {
		log.Println("Error during unmarshal: ", err)
		return nil, err
	}
	return &cfg, nil
}
