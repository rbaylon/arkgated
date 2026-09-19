package webconf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goodRouter is the shape the old stdin wizard produced, as a baseline the
// tests mutate one field at a time.
func goodRouter() RouterConfig {
	c := RouterDefaults()
	c.Router = "devopenbsd"
	c.Ifaces = []RouterIface{
		{Name: "wan", Device: "em0", Speed: "900M", Default: true, Type: "external",
			Gateway: "10.0.2.2", Ip: "10.0.2.15", Netmask: "255.255.255.0"},
		{Name: "lan", Device: "em1", Speed: "900M", Type: "internal",
			Ip: "172.16.0.1", Netmask: "255.255.0.0"},
	}
	c.Dhcps = []RouterDhcp{
		{Type: "lan", Subnet: "172.16.0.0", Netmask: "255.255.0.0",
			Routers: "172.16.0.1", Dnsservers: "172.16.0.1", Range: "172.16.1.1 172.16.9.255"},
	}
	c.Pflows = []RouterPflow{{Device: "pflow0", Src: "127.0.0.1", Dst: "127.0.0.1:9995", Proto: 10}}
	return c
}

func TestGoodRouterConfigValidates(t *testing.T) {
	c := goodRouter()
	c.Normalize()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("baseline config should be valid, got: %v", errs)
	}
}

func TestRouterValidationCatchesDaemonKillers(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*RouterConfig)
		want string
	}{
		// pf.MaskToCidr log.Fatalf's on a mask it cannot parse, so this rule is
		// the difference between a form error and a dead daemon.
		{"unparseable netmask", func(c *RouterConfig) { c.Ifaces[0].Netmask = "255.255.255" }, "not a valid dotted netmask"},
		{"non-contiguous netmask", func(c *RouterConfig) { c.Ifaces[0].Netmask = "255.0.255.0" }, "not a valid dotted netmask"},
		{"missing netmask", func(c *RouterConfig) { c.Ifaces[0].Netmask = "" }, "netmask is required"},
		// ConfigCreate writes mygate/resolv.conf only for the default iface.
		{"no default iface", func(c *RouterConfig) { c.Ifaces[0].Default = false }, "Exactly one interface must be marked default"},
		{"two default ifaces", func(c *RouterConfig) { c.Ifaces[1].Default = true }, "are marked default"},
		{"default without gateway", func(c *RouterConfig) { c.Ifaces[0].Gateway = "" }, "needs a gateway"},
		// Type gates most of the pf.conf generation.
		{"bad type", func(c *RouterConfig) { c.Ifaces[0].Type = "wan" }, "type must be external or internal"},
		// A DHCP scope's type is an interface name reference.
		{"dhcp names unknown iface", func(c *RouterConfig) { c.Dhcps[0].Type = "nope" }, "no interface is named"},
		{"dhcp bad range", func(c *RouterConfig) { c.Dhcps[0].Range = "172.16.1.1" }, "range must be two addresses"},
		{"dhcp range not an ip", func(c *RouterConfig) { c.Dhcps[0].Range = "172.16.1.1 nope" }, "is not an IP address"},
		// Duplicates silently clobber generated hostname.if files.
		{"duplicate device", func(c *RouterConfig) { c.Ifaces[1].Device = "em0" }, "already used by another interface"},
		{"duplicate name", func(c *RouterConfig) { c.Ifaces[1].Name = "wan" }, "duplicate interface name"},
		{"no ifaces", func(c *RouterConfig) { c.Ifaces = nil }, "At least one interface is required"},
		{"no router name", func(c *RouterConfig) { c.Router = "" }, "Router name is required"},
		{"bad ip", func(c *RouterConfig) { c.Ifaces[1].Ip = "172.16.0.999" }, "is not an IP address"},
		{"portal port clash", func(c *RouterConfig) { c.CaptivePortalPort = c.SubsPortalPort }, "cannot share a port"},
		{"bad dns", func(c *RouterConfig) { c.Dns = "8.8.8.8 notanip" }, "is not an IP address"},
		{"pflow bad version", func(c *RouterConfig) { c.Pflows[0].Proto = 9 }, "must be 5 or 10"},
		{"pflow bad dst", func(c *RouterConfig) { c.Pflows[0].Dst = "10.0.0.5" }, "must be host:port"},
		{"lb weight out of range", func(c *RouterConfig) { c.Ifaces[0].LbPercentage = 140 }, "between 0 and 100"},
	} {
		c := goodRouter()
		tc.mut(&c)
		c.Normalize()
		errs := c.Validate()
		if !strings.Contains(strings.Join(errs, "\n"), tc.want) {
			t.Errorf("%s: want an error containing %q, got: %v", tc.name, tc.want, errs)
		}
	}
}

func TestAutoconfInterfaceNeedsNoMaskOrGateway(t *testing.T) {
	// pf.go's ConfigCreate skips mygate/resolv.conf for an "autoconf" address,
	// so requiring a mask or gateway there would reject a valid config.
	c := goodRouter()
	c.Ifaces[0].Ip = autoconfIP
	c.Ifaces[0].Netmask = ""
	c.Ifaces[0].Gateway = ""
	c.Normalize()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("autoconf interface should be valid, got: %v", errs)
	}
}

func TestNormalizeDropsBlankRows(t *testing.T) {
	c := goodRouter()
	c.Ifaces = append(c.Ifaces, RouterIface{}, RouterIface{Name: "  ", Device: " "})
	c.Dhcps = append(c.Dhcps, RouterDhcp{})
	c.Pflows = append(c.Pflows, RouterPflow{Proto: 10})
	c.Normalize()
	if len(c.Ifaces) != 2 {
		t.Errorf("ifaces = %d, want 2 (blank rows dropped)", len(c.Ifaces))
	}
	if len(c.Dhcps) != 1 {
		t.Errorf("dhcps = %d, want 1", len(c.Dhcps))
	}
	if len(c.Pflows) != 1 {
		t.Errorf("pflows = %d, want 1", len(c.Pflows))
	}
}

func TestSaveRouterConfigRoundTripsWizardShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	errs, err := SaveRouterConfig(path, goodRouter())
	if err != nil || len(errs) > 0 {
		t.Fatalf("save failed: %v / %v", err, errs)
	}

	// The on-disk JSON must use exactly the keys pfconfig.Init and srvcman's
	// model expect - this file is read back locally and POSTed on enroll.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	for _, k := range []string{"ifaces", "wifi_ip_list", "subs_ip_list", "subs_portal_port",
		"captive_portal_port", "router", "load_balance", "dhcps", "dns", "pflows"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	ifs := raw["ifaces"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "device", "speed", "default", "type", "gateway", "ip", "netmask", "lb_percentage"} {
		if _, ok := ifs[k]; !ok {
			t.Errorf("interface missing key %q", k)
		}
	}
	// No gorm.Model noise leaking into a hand-editable file.
	for _, k := range []string{"ID", "CreatedAt", "UpdatedAt", "DeletedAt", "pfconfig_id"} {
		if _, ok := ifs[k]; ok {
			t.Errorf("interface should not carry %q", k)
		}
	}

	back, found, err := LoadRouterConfig(path)
	if err != nil || !found {
		t.Fatalf("reload failed: %v / found=%v", err, found)
	}
	if back.Router != "devopenbsd" || len(back.Ifaces) != 2 || !back.Ifaces[0].Default {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestSaveRouterConfigRejectsWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	bad := goodRouter()
	bad.Ifaces[0].Netmask = "255.255.255"

	errs, err := SaveRouterConfig(path, bad)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Error("a rejected save must not create the file")
	}
}

func TestLoadRouterConfigMissingAndBroken(t *testing.T) {
	dir := t.TempDir()

	cfg, found, err := LoadRouterConfig(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("a missing file is not an error: %v", err)
	}
	if found {
		t.Error("found should be false")
	}
	if cfg.SubsPortalPort != 4000 || cfg.WifiIpList != "wifilist.txt" {
		t.Errorf("missing file should yield wizard defaults, got %+v", cfg)
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{not json"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, found, err := LoadRouterConfig(broken); err == nil || !found {
		t.Errorf("broken file should report an error and found=true (got err=%v found=%v)", err, found)
	}

	// A file that omits keys keeps the defaults for them rather than zeroing.
	partial := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(partial, []byte(`{"router":"r1"}`), 0640); err != nil {
		t.Fatal(err)
	}
	got, _, err := LoadRouterConfig(partial)
	if err != nil {
		t.Fatal(err)
	}
	if got.Router != "r1" || got.SubsPortalPort != 4000 {
		t.Errorf("partial file should keep defaults, got %+v", got)
	}
}

// --- the form ---

func routerForm(dev0, dev1 string) url.Values {
	v := url.Values{}
	v.Set("router", "devopenbsd")
	v.Set("wifi_ip_list", "wifilist.txt")
	v.Set("subs_ip_list", "subslist.txt")
	v.Set("subs_portal_port", "4000")
	v.Set("captive_portal_port", "3000")
	v.Set("dns", "8.8.8.8 4.2.2.2")

	v.Set("iface.0.name", "wan")
	v.Set("iface.0.device", dev0)
	v.Set("iface.0.type", "external")
	v.Set("iface.0.speed", "900M")
	v.Set("iface.0.ip", "10.0.2.15")
	v.Set("iface.0.netmask", "255.255.255.0")
	v.Set("iface.0.gateway", "10.0.2.2")
	v.Set("iface.0.lb_percentage", "0")

	v.Set("iface.1.name", "lan")
	v.Set("iface.1.device", dev1)
	v.Set("iface.1.type", "internal")
	v.Set("iface.1.speed", "900M")
	v.Set("iface.1.ip", "172.16.0.1")
	v.Set("iface.1.netmask", "255.255.0.0")
	v.Set("iface.1.gateway", "")
	v.Set("iface.1.lb_percentage", "0")

	v.Set("default_iface", "0")

	// A trailing blank row, as the form always renders.
	for _, f := range []string{"name", "device", "type", "ip", "netmask", "gateway", "speed"} {
		v.Set("iface.2."+f, "")
	}
	v.Set("iface.2.lb_percentage", "0")
	return v
}

func postRouter(t *testing.T, srv *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/router", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("adm", "sekrit")
	w := httptest.NewRecorder()
	srv.auth(srv.handleRouter)(w, r)
	return w
}

// routerSrv wires a Server whose rundir points at a temp dir, so the router
// page reads and writes config.json there.
func routerSrv(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, srv := newSrv(t, filepath.Join(dir, "settings.json"))
	post(t, srv, formIn(dir, map[string]string{"creds": "c", "rundir": dir}))
	if got := store.Get().RunDir; got != dir+"/" {
		t.Fatalf("rundir = %q, want %q", got, dir+"/")
	}
	return srv, dir + "/config.json"
}

func TestRouterPageSavesFromForm(t *testing.T) {
	srv, path := routerSrv(t)

	w := postRouter(t, srv, routerForm("em0", "em1"))
	if w.Code != http.StatusOK {
		t.Fatalf("save got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Saved.") {
		t.Fatalf("no save confirmation:\n%s", w.Body.String())
	}

	cfg, found, err := LoadRouterConfig(path)
	if err != nil || !found {
		t.Fatalf("config.json not written: %v found=%v", err, found)
	}
	if len(cfg.Ifaces) != 2 {
		t.Fatalf("ifaces = %d, want 2 (the blank third row must be dropped)", len(cfg.Ifaces))
	}
	if !cfg.Ifaces[0].Default || cfg.Ifaces[1].Default {
		t.Error("the default radio should mark exactly interface 0")
	}
	if cfg.Ifaces[1].Name != "lan" || cfg.Ifaces[1].Device != "em1" {
		t.Errorf("second interface = %+v", cfg.Ifaces[1])
	}
	if cfg.LoadBalance {
		t.Error("load_balance was not submitted and should be false")
	}
}

func TestRouterFormRejectionDoesNotWrite(t *testing.T) {
	srv, path := routerSrv(t)

	form := routerForm("em0", "em1")
	form.Set("iface.0.netmask", "255.255.255") // reaches MaskToCidr otherwise
	w := postRouter(t, srv, form)
	body := w.Body.String()
	if !strings.Contains(body, "Nothing was saved") {
		t.Fatalf("expected rejection:\n%s", body)
	}
	if !strings.Contains(body, "not a valid dotted netmask") {
		t.Error("rejection should name the bad netmask")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("rejected save must not create config.json")
	}

	// The operator's input must come back in the form, not be discarded.
	if !strings.Contains(body, `value="255.255.255"`) {
		t.Error("submitted value should be re-rendered for correction")
	}
}

func TestRouterFormDefaultRadioIsExclusive(t *testing.T) {
	srv, path := routerSrv(t)

	form := routerForm("em0", "em1")
	form.Set("default_iface", "1")
	// The default interface is what mygate is written from, so moving the
	// default also means giving that row a gateway.
	form.Set("iface.1.gateway", "172.16.0.254")
	if w := postRouter(t, srv, form); !strings.Contains(w.Body.String(), "Saved.") {
		t.Fatalf("save failed:\n%s", w.Body.String())
	}
	cfg, _, err := LoadRouterConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ifaces[0].Default {
		t.Error("interface 0 should not be default")
	}
	if !cfg.Ifaces[1].Default {
		t.Error("interface 1 should be default")
	}
}

func TestRouterPageShowsUnconfiguredBannerAndNav(t *testing.T) {
	srv, _ := routerSrv(t)

	r := httptest.NewRequest(http.MethodGet, "/router", nil)
	r.SetBasicAuth("adm", "sekrit")
	w := httptest.NewRecorder()
	srv.auth(srv.handleRouter)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /router got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Not created yet", "Router config", "Interfaces on this box",
		`href="/"`, `name="iface.0.device"`, "Save router config"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestRouterPageRequiresAuth(t *testing.T) {
	srv, _ := routerSrv(t)
	r := httptest.NewRequest(http.MethodGet, "/router", nil)
	w := httptest.NewRecorder()
	srv.auth(srv.handleRouter)(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /router got %d, want 401", w.Code)
	}
}

func TestRouterSaveIsCrossOriginProtected(t *testing.T) {
	srv, _ := routerSrv(t)
	r := httptest.NewRequest(http.MethodPost, "/router", strings.NewReader(routerForm("em0", "em1").Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://evil.example")
	r.SetBasicAuth("adm", "sekrit")
	w := httptest.NewRecorder()
	srv.auth(srv.handleRouter)(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin router POST got %d, want 403", w.Code)
	}
}

func TestRouterSaveFiresChangedBroadcast(t *testing.T) {
	srv, _ := routerSrv(t)

	// Captured before the save, the way main's gate loop does it.
	changed := srv.RouterChanged()
	select {
	case <-changed:
		t.Fatal("broadcast fired before any save")
	default:
	}

	postRouter(t, srv, routerForm("em0", "em1"))

	select {
	case <-changed:
	default:
		t.Fatal("a successful save must wake main's router-config gate")
	}
}

func TestRouterSaveRejectionDoesNotFireBroadcast(t *testing.T) {
	srv, _ := routerSrv(t)
	changed := srv.RouterChanged()

	form := routerForm("em0", "em1")
	form.Set("iface.0.netmask", "nonsense")
	postRouter(t, srv, form)

	select {
	case <-changed:
		t.Error("a rejected save must not wake the gate")
	default:
	}
}

func TestDefaultRouteRegexMatchesOpenBSDRouteOutput(t *testing.T) {
	// Verbatim from `route -n show -inet` on OpenBSD 7.9.
	const out = `Routing tables

Internet:
Destination        Gateway            Flags   Refs      Use   Mtu  Prio Iface
default            10.0.2.2           UGS        5       20     -     8 em0  
224/4              127.0.0.1          URS        0        0 32768     8 lo0  
10.0.2/24          10.0.2.15          UCn        1        0     -     4 em0  
`
	var gw, iface string
	for _, line := range strings.Split(out, "\n") {
		if m := defaultRouteRe.FindStringSubmatch(line); m != nil {
			gw = m[1]
			f := strings.Fields(line)
			iface = f[len(f)-1]
			break
		}
	}
	if gw != "10.0.2.2" || iface != "em0" {
		t.Errorf("parsed gateway %q on %q, want 10.0.2.2 on em0", gw, iface)
	}
	// "default" must anchor at the start so a destination merely containing it
	// is not mistaken for the default route.
	if defaultRouteRe.MatchString("10.0.2/24          10.0.2.15          UCn") {
		t.Error("a non-default route matched")
	}
}

// Regression: the egress interface's row must come back with Default set, since
// that is what checks the radio. Setting an index on the page struct instead
// left every radio unchecked on a real box.
func TestDetectedEgressRowIsMarkedDefault(t *testing.T) {
	rows := seedRowsFrom(loadFixture(t), RouterConfig{})

	var em0 *routerIfaceRow
	for i := range rows {
		if rows[i].Device == "em0" {
			em0 = &rows[i]
		}
	}
	if em0 == nil {
		t.Fatal("em0 was not seeded as a row")
	}
	if !em0.Default {
		t.Error("the egress interface's row must be marked default so its radio renders checked")
	}
	if em0.Type != "external" {
		t.Errorf("egress row type = %q, want external", em0.Type)
	}
	if em0.Ip != "10.0.2.15" || em0.Netmask != "255.255.255.0" {
		t.Errorf("egress row address = %q/%q, want the live one", em0.Ip, em0.Netmask)
	}

	// Only one row may be default.
	n := 0
	for _, r := range rows {
		if r.Default {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d rows marked default, want exactly 1", n)
	}
}

// An already-configured default must win over the detected egress guess.
func TestConfiguredDefaultBeatsDetectedEgress(t *testing.T) {
	cfg := RouterConfig{Ifaces: []RouterIface{
		{Name: "lan", Device: "em1", Type: "internal", Default: true, Ip: "172.16.0.1", Netmask: "255.255.0.0", Gateway: "172.16.0.254"},
	}}
	rows := seedRowsFrom(loadFixture(t), cfg)

	n := 0
	for _, r := range rows {
		if r.Default {
			n++
			if r.Device != "em1" {
				t.Errorf("default row is %q, want the configured em1", r.Device)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d rows marked default, want exactly 1", n)
	}
}
