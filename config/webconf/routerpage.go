package webconf

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// blankRows is how many empty rows the DHCP and pflow sections render beyond
// what is already configured, since neither is derived from hardware and they
// would otherwise have nowhere to be added. One is enough: the form has no
// required client-side scripting, so filling that row and saving adds the
// entry and a fresh blank row comes back for the next one. Clearing a row's key
// fields deletes it (see RouterConfig.Normalize).
//
// Interfaces deliberately get none - see seedRowsFrom.
const blankRows = 1

// routerConfigPath is where the router config lives, derived from the settings'
// rundir. It is not a setting of its own: pfconfig.Init reads exactly
// rundir+"config.json" and nothing else.
func (srv *Server) routerConfigPath() string {
	return srv.store.Get().RunDir + "config.json"
}

// RouterChanged fires on every successful router-config save, so main can stop
// waiting for a config.json that did not exist or would not load.
func (srv *Server) RouterChanged() <-chan struct{} { return srv.routerSaved.Wait() }

func (srv *Server) handleRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		path := srv.routerConfigPath()
		cfg, found, err := LoadRouterConfig(path)
		p := srv.routerPage(cfg, found)
		if err != nil {
			// A file that exists but will not parse: show the error and the
			// defaults, so the operator can rewrite it through the form
			// rather than having to hand-edit broken JSON over ssh.
			p.Errors = []string{err.Error()}
		}
		srv.renderRouter(w, p)
	case http.MethodPost:
		srv.handleRouterSave(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (srv *Server) handleRouterSave(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		log.Printf("Web configurator: rejected cross-origin router save from %s", r.RemoteAddr)
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg, fieldErrs := parseRouterForm(r)

	if len(fieldErrs) > 0 {
		p := srv.routerPage(cfg, true)
		p.Errors = append([]string{"Nothing was saved."}, fieldErrs...)
		srv.renderRouter(w, p)
		return
	}

	path := srv.routerConfigPath()
	errs, err := SaveRouterConfig(path, cfg)
	if err != nil {
		p := srv.routerPage(cfg, true)
		p.Errors = []string{"Could not write " + path + ": " + err.Error()}
		srv.renderRouter(w, p)
		return
	}
	if len(errs) > 0 {
		p := srv.routerPage(cfg, true)
		p.Errors = append([]string{"Nothing was saved."}, errs...)
		srv.renderRouter(w, p)
		return
	}

	log.Printf("Web configurator: router config saved by %s to %s", r.RemoteAddr, path)
	srv.routerSaved.Fire()

	saved, found, _ := LoadRouterConfig(path)
	p := srv.routerPage(saved, found)
	p.Saved = true
	srv.renderRouter(w, p)
}

// parseRouterForm rebuilds a RouterConfig from indexed form fields
// ("iface.0.name", "dhcp.1.subnet", ...). Rows are read until an index has no
// keys at all, so the number of rows is driven by what the form posted rather
// than by anything the server has to remember between requests.
func parseRouterForm(r *http.Request) (RouterConfig, []string) {
	var errs []string
	cfg := RouterDefaults()

	cfg.Router = r.PostForm.Get("router")
	cfg.WifiIpList = r.PostForm.Get("wifi_ip_list")
	cfg.SubsIpList = r.PostForm.Get("subs_ip_list")
	cfg.Dns = r.PostForm.Get("dns")
	cfg.LoadBalance = r.PostForm.Get("load_balance") != ""

	num := func(key string, def int) int {
		n, ok := atoiOr(r.PostForm.Get(key), def)
		if !ok {
			errs = append(errs, fmt.Sprintf("%s must be a whole number", key))
		}
		return n
	}
	cfg.SubsPortalPort = num("subs_portal_port", cfg.SubsPortalPort)
	cfg.CaptivePortalPort = num("captive_portal_port", cfg.CaptivePortalPort)

	// hasRow keeps trailing blank rows from ending the scan early when the
	// operator fills, say, row 3 but not row 2.
	hasRow := func(prefix string, i int, fields ...string) bool {
		for _, f := range fields {
			if r.PostForm.Has(fmt.Sprintf("%s.%d.%s", prefix, i, f)) {
				return true
			}
		}
		return false
	}
	get := func(prefix string, i int, f string) string {
		return r.PostForm.Get(fmt.Sprintf("%s.%d.%s", prefix, i, f))
	}

	ifaceFields := []string{"name", "device", "speed", "type", "gateway", "ip", "netmask", "lb_percentage", "default"}
	for i := 0; hasRow("iface", i, ifaceFields...); i++ {
		in := RouterIface{
			Name:    get("iface", i, "name"),
			Device:  get("iface", i, "device"),
			Speed:   get("iface", i, "speed"),
			Type:    get("iface", i, "type"),
			Gateway: get("iface", i, "gateway"),
			Ip:      get("iface", i, "ip"),
			Netmask: get("iface", i, "netmask"),
		}
		// One radio named "default" across all rows carries the row index, so
		// exactly one interface can be the default by construction.
		in.Default = r.PostForm.Get("default_iface") == strconv.Itoa(i)
		lb, ok := atoiOr(get("iface", i, "lb_percentage"), 0)
		if !ok {
			errs = append(errs, fmt.Sprintf("interface %d: load-balance weight must be a whole number", i+1))
		}
		in.LbPercentage = lb
		cfg.Ifaces = append(cfg.Ifaces, in)
	}

	dhcpFields := []string{"type", "subnet", "netmask", "routers", "dnsservers", "range"}
	for i := 0; hasRow("dhcp", i, dhcpFields...); i++ {
		cfg.Dhcps = append(cfg.Dhcps, RouterDhcp{
			Type:       get("dhcp", i, "type"),
			Subnet:     get("dhcp", i, "subnet"),
			Netmask:    get("dhcp", i, "netmask"),
			Routers:    get("dhcp", i, "routers"),
			Dnsservers: get("dhcp", i, "dnsservers"),
			Range:      get("dhcp", i, "range"),
		})
	}

	pflowFields := []string{"device", "src", "dst", "proto"}
	for i := 0; hasRow("pflow", i, pflowFields...); i++ {
		proto, ok := atoiOr(get("pflow", i, "proto"), 10)
		if !ok {
			errs = append(errs, fmt.Sprintf("pflow export %d: protocol version must be a whole number", i+1))
		}
		cfg.Pflows = append(cfg.Pflows, RouterPflow{
			Device: get("pflow", i, "device"),
			Src:    get("pflow", i, "src"),
			Dst:    get("pflow", i, "dst"),
			Proto:  proto,
		})
	}

	return cfg, errs
}

// --- view model ---

type routerIfaceRow struct {
	Idx int
	RouterIface
	SpeedHint string // from the host's media rate, when the device is known

	// Detected facts about this row's device, shown inline on the row. These
	// used to be a separate read-only table above the form, which meant every
	// interface appeared twice on the page.
	Known  bool
	Up     bool
	Status string
	Media  string
	Addrs  string
	Egress bool
}

type routerPage struct {
	Path   string
	Found  bool
	Errors []string
	Saved  bool
	Ifaces []routerIfaceRow
	Dhcps  []struct {
		Idx int
		RouterDhcp
	}
	Pflows []struct {
		Idx int
		RouterPflow
	}
	Router            string
	WifiIpList        string
	SubsIpList        string
	SubsPortalPort    int
	CaptivePortalPort int
	LoadBalance       bool
	Dns               string

	// DetectErr is set when the host's interfaces could not be read at all;
	// PseudoNames are the devices that exist but cannot be assigned (loopback,
	// pf, arkgated-managed), listed as a one-line note instead of table rows.
	DetectErr   string
	DeviceNames []string
	PseudoNames []string
}

// routerPage builds the view model, and is where the host's own interface list
// gets attached. A failure to enumerate is reported on the page but never
// blocks the form: on a box where ifconfig is missing or unreadable an operator
// must still be able to type device names in by hand.
func (srv *Server) routerPage(cfg RouterConfig, found bool) routerPage {
	p := routerPage{
		Path:              srv.routerConfigPath(),
		Found:             found,
		Router:            cfg.Router,
		WifiIpList:        cfg.WifiIpList,
		SubsIpList:        cfg.SubsIpList,
		SubsPortalPort:    cfg.SubsPortalPort,
		CaptivePortalPort: cfg.CaptivePortalPort,
		LoadBalance:       cfg.LoadBalance,
		Dns:               cfg.Dns,
	}

	hostIfs, err := listHostIfaces()
	if err != nil {
		p.DetectErr = err.Error()
	}
	for _, h := range hostIfs {
		if h.Assignable() {
			p.DeviceNames = append(p.DeviceNames, h.Device)
		} else {
			p.PseudoNames = append(p.PseudoNames, h.Device)
		}
	}

	p.Ifaces = seedRowsFrom(hostIfs, cfg)

	for i, d := range cfg.Dhcps {
		p.Dhcps = append(p.Dhcps, struct {
			Idx int
			RouterDhcp
		}{i, d})
	}
	for n := 0; n < blankRows; n++ {
		p.Dhcps = append(p.Dhcps, struct {
			Idx int
			RouterDhcp
		}{len(cfg.Dhcps) + n, RouterDhcp{Netmask: "255.255.255.0"}})
	}

	for i, f := range cfg.Pflows {
		p.Pflows = append(p.Pflows, struct {
			Idx int
			RouterPflow
		}{i, f})
	}
	for n := 0; n < blankRows; n++ {
		p.Pflows = append(p.Pflows, struct {
			Idx int
			RouterPflow
		}{len(cfg.Pflows) + n, RouterPflow{Proto: 10, Src: "127.0.0.1"}})
	}

	return p
}

// seedRowsFrom lays out the interface rows: everything already configured,
// then one pre-filled row per detected NIC that is not configured yet, then
// blank rows to grow into.
//
// Split out of routerPage so it can be tested against captured ifconfig output
// without an HTTP server - the pre-fill rules are the fiddly part, and one of
// them (marking the egress row Default) was wrong in a way only a real box
// revealed.
func seedRowsFrom(hostIfs []HostIface, cfg RouterConfig) []routerIfaceRow {
	speed := map[string]string{}
	byDev := map[string]HostIface{}
	var assignable []string
	for _, h := range hostIfs {
		byDev[h.Device] = h
		if h.Assignable() {
			assignable = append(assignable, h.Device)
			speed[h.Device] = h.SpeedHint()
		}
	}

	var rows []routerIfaceRow
	haveDefault := false
	used := map[string]bool{}
	for i, in := range cfg.Ifaces {
		if in.Default {
			haveDefault = true
		}
		used[in.Device] = true
		row := routerIfaceRow{Idx: i, RouterIface: in, SpeedHint: speed[in.Device]}
		attachDetected(&row, byDev)
		rows = append(rows, row)
	}

	next := len(cfg.Ifaces)
	for _, dev := range assignable {
		if used[dev] {
			continue
		}
		row := routerIfaceRow{Idx: next, SpeedHint: speed[dev]}
		row.Device = dev
		row.Speed = speed[dev]

		h := byDev[dev]
		row.Ip, row.Netmask = h.IP, h.Netmask
		// An egress-group NIC is the box's current default route, so it is the
		// best guess for the config's default interface - and its live gateway
		// is what mygate would need. Setting Default on the *row* is what makes
		// the radio render checked; an index on the page struct does not,
		// because the template reads each row.
		if h.Egress() {
			row.Type = "external"
			if gw, gwif := DefaultGateway(); gwif == dev {
				row.Gateway = gw
			}
			if !haveDefault {
				row.Default = true
				haveDefault = true
			}
		}
		attachDetected(&row, byDev)
		rows = append(rows, row)
		next++
	}

	// No spare interface rows: the list is exactly this box's physical NICs
	// (plus anything already configured on a device that is no longer present,
	// so it can still be seen and removed). Two NICs means two rows. Adding an
	// interface that no NIC corresponds to is not a thing you can do here -
	// vlan and pppac interfaces come from srvcman, not from this file.
	//
	// The one exception keeps the form usable: if there is nothing to show at
	// all - no config yet and ifconfig unreadable - render a single empty row
	// so a device name can still be typed in.
	if len(rows) == 0 {
		rows = append(rows, routerIfaceRow{Idx: 0})
	}
	return rows
}

// attachDetected copies what ifconfig said about this row's device onto the
// row, so the live state is shown next to the field it describes instead of in
// a second table that listed every interface all over again.
func attachDetected(row *routerIfaceRow, byDev map[string]HostIface) {
	h, ok := byDev[row.Device]
	if !ok || row.Device == "" {
		return
	}
	row.Known = true
	row.Up = h.Up()
	row.Status = h.Status
	row.Media = h.Media
	row.Addrs = strings.Join(h.Addrs, ", ")
	row.Egress = h.Egress()
	if row.SpeedHint == "" {
		row.SpeedHint = h.SpeedHint()
	}
}

func (srv *Server) renderRouter(w http.ResponseWriter, p routerPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := routerTmpl.Execute(w, p); err != nil {
		log.Println("Web configurator: rendering router page:", err)
	}
}
