package pfconfig

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// harness replaces the three outside calls: the API lists, route(8) and sh.
type harness struct {
	t         *testing.T
	statics   []staticRouteRec
	monitors  []gatewayMonitorRec
	failList  map[string]bool // "staticroutes"/"gatewaymonitor" -> fetch fails
	addFails  map[string]bool // dest -> "route add" fails (already there)
	chgFails  map[string]bool // dest -> "route change" fails too
	calls     []string        // everything that ran, in order
	netstartE error
}

func (h *harness) install() func() {
	oldF, oldR, oldN := fetchList, runRoute, runNetstart
	fetchList = func(url string, token *string, out any) error {
		var name string
		var data any
		switch {
		case strings.HasSuffix(url, "staticroutes"):
			name, data = "staticroutes", h.statics
		case strings.HasSuffix(url, "gatewaymonitor"):
			name, data = "gatewaymonitor", h.monitors
		default:
			h.t.Fatalf("unexpected url %s", url)
		}
		if h.failList[name] {
			return errors.New("api down")
		}
		b, _ := json.Marshal(data)
		return json.Unmarshal(b, out)
	}
	runRoute = func(args ...string) ([]byte, error) {
		h.calls = append(h.calls, "route "+strings.Join(args, " "))
		// args: -q <add|change> <flag> <dest> <gw> -label <name>
		verb, dest := args[1], args[3]
		if verb == "add" && h.addFails[dest] {
			return []byte("File exists"), errors.New("exit 1")
		}
		if verb == "change" && h.chgFails[dest] {
			return []byte("not in table"), errors.New("exit 1")
		}
		return nil, nil
	}
	runNetstart = func(args ...string) ([]byte, error) {
		h.calls = append(h.calls, "sh "+strings.Join(args, " "))
		return []byte("netstart output"), h.netstartE
	}
	return func() { fetchList, runRoute, runNetstart = oldF, oldR, oldN }
}

func newHarness(t *testing.T) *harness {
	return &harness{t: t, failList: map[string]bool{}, addFails: map[string]bool{}, chgFails: map[string]bool{}}
}

var tok = "t"

func TestRestoreInstallsStaticRoutesAndMonitorRoutes(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{
		{Name: "toOffice", Type: "net", Destination: "10.20.0.0/16", Gateway: "192.168.1.254"},
		{Name: "toHost", Type: "host", Destination: "203.0.113.9", Gateway: "192.168.1.253"},
	}
	h.monitors = []gatewayMonitorRec{{Name: "wan1mon", Ip: "192.168.208.2", MonitorIp: "1.1.1.1"}}
	defer h.install()()
	installed, failed := RestoreRoutes("http://x/api/v1/", &tok)
	if installed != 3 || failed != 0 {
		t.Fatalf("installed=%d failed=%d calls=%v", installed, failed, h.calls)
	}
	want := []string{
		"route -q add -net 10.20.0.0/16 192.168.1.254 -label toOffice",
		"route -q add -host 203.0.113.9 192.168.1.253 -label toHost",
		"route -q add -host 1.1.1.1 192.168.208.2 -label wan1mon",
	}
	for i, w := range want {
		if h.calls[i] != w {
			t.Errorf("call %d = %q, want %q", i, h.calls[i], w)
		}
	}
}

func TestARouteThatIsAlreadyThereIsChangedNotLost(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{{Name: "r", Type: "host", Destination: "203.0.113.9", Gateway: "192.168.1.1"}}
	h.addFails["203.0.113.9"] = true
	defer h.install()()
	installed, failed := RestoreRoutes("http://x/", &tok)
	if installed != 1 || failed != 0 {
		t.Fatalf("installed=%d failed=%d", installed, failed)
	}
	if len(h.calls) != 2 || !strings.Contains(h.calls[1], "-q change -host 203.0.113.9 192.168.1.1") {
		t.Errorf("calls = %v", h.calls)
	}
}

func TestAFailingRouteDoesNotStopTheOthers(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{
		{Name: "bad", Type: "host", Destination: "203.0.113.9", Gateway: "10.9.9.9"},
		{Name: "good", Type: "host", Destination: "203.0.113.10", Gateway: "10.9.9.9"},
	}
	h.addFails["203.0.113.9"], h.chgFails["203.0.113.9"] = true, true
	defer h.install()()
	installed, failed := RestoreRoutes("http://x/", &tok)
	if installed != 1 || failed != 1 {
		t.Fatalf("installed=%d failed=%d", installed, failed)
	}
}

func TestValuesThatAreNotPlainAddressesNeverReachRoute(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{
		{Name: "-flushall", Type: "host", Destination: "203.0.113.9", Gateway: "10.0.0.1"},
		{Name: "a;b", Type: "host", Destination: "203.0.113.9", Gateway: "10.0.0.1"},
		{Name: "ok1", Type: "host", Destination: "x y", Gateway: "10.0.0.1"},
		{Name: "ok2", Type: "host", Destination: "203.0.113.9", Gateway: "-inet"},
		{Name: "ok3", Type: "net", Destination: "10.0.0.0/99", Gateway: "10.0.0.1"},
		{Name: "blank", Type: "host", Destination: "", Gateway: ""},
	}
	defer h.install()()
	installed, failed := RestoreRoutes("http://x/", &tok)
	if installed != 0 || failed != 5 || len(h.calls) != 0 {
		t.Fatalf("installed=%d failed=%d calls=%v", installed, failed, h.calls)
	}
}

func TestOneListBeingUnavailableStillRestoresTheOther(t *testing.T) {
	h := newHarness(t)
	h.monitors = []gatewayMonitorRec{{Name: "m", Ip: "192.168.208.2", MonitorIp: "1.1.1.1"}}
	h.failList["staticroutes"] = true
	defer h.install()()
	installed, failed := RestoreRoutes("http://x/", &tok)
	if installed != 1 || failed != 1 {
		t.Fatalf("installed=%d failed=%d", installed, failed)
	}
}

func TestRoutesAreRestoredAfterEveryNetstart(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{{Name: "r", Type: "net", Destination: "10.20.0.0/16", Gateway: "192.168.1.254"}}
	defer h.install()()
	for _, device := range []string{"em2", ""} {
		h.calls = nil
		if err := netstart(device, "http://x/", &tok); err != nil {
			t.Fatalf("netstart(%q): %v", device, err)
		}
		want := "sh /etc/netstart"
		if device != "" {
			want += " " + device
		}
		if len(h.calls) != 2 || h.calls[0] != want || !strings.HasPrefix(h.calls[1], "route -q add -net 10.20.0.0/16") {
			t.Errorf("netstart(%q): calls = %v", device, h.calls)
		}
	}
}

func TestAFailedNetstartIsAnErrorAndRestoresNothing(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{{Name: "r", Type: "net", Destination: "10.20.0.0/16", Gateway: "192.168.1.254"}}
	h.netstartE = errors.New("exit 1")
	defer h.install()()
	if err := netstart("em2", "http://x/", &tok); err == nil {
		t.Fatal("a failed netstart was not reported")
	}
	if len(h.calls) != 1 {
		t.Errorf("routes were touched after a failed netstart: %v", h.calls)
	}
}

func TestRoutesAreRestoredAtStartOnceSrvcmanAnswers(t *testing.T) {
	h := newHarness(t)
	h.statics = []staticRouteRec{{Name: "r", Type: "net", Destination: "10.20.0.0/16", Gateway: "192.168.1.254"}}
	h.monitors = []gatewayMonitorRec{{Name: "m", Ip: "192.168.208.2", MonitorIp: "1.1.1.1"}}
	h.failList["staticroutes"] = true // srvcman is still starting
	defer h.install()()
	oldRetry := retryEvery
	retryEvery = time.Millisecond
	defer func() { retryEvery = oldRetry }()
	tries := 0
	token := func() *string {
		tries++
		if tries == 3 {
			h.failList["staticroutes"] = false // it is up now
		}
		if tries == 1 {
			return nil // not logged in yet
		}
		return &tok
	}
	RestoreRoutesWhenReady(context.Background(), "http://x/", token)
	// The monitor route may be installed on the early, partial attempt as well
	// (a repeat is harmless); the static route needs the list, so exactly once.
	var statics, monitors int
	for _, c := range h.calls {
		switch {
		case strings.HasPrefix(c, "route -q add -net 10.20.0.0/16"):
			statics++
		case strings.HasPrefix(c, "route -q add -host 1.1.1.1"):
			monitors++
		}
	}
	if statics != 1 || monitors < 1 {
		t.Fatalf("static installed %d times, monitor %d times, calls = %v", statics, monitors, h.calls)
	}
}

func TestStartRestoreGivesUpWhenSrvcmanNeverAnswers(t *testing.T) {
	h := newHarness(t)
	h.failList["staticroutes"] = true
	defer h.install()()
	oldRetry, oldGive := retryEvery, giveUpAfter
	retryEvery, giveUpAfter = time.Millisecond, 20*time.Millisecond
	defer func() { retryEvery, giveUpAfter = oldRetry, oldGive }()
	RestoreRoutesWhenReady(context.Background(), "http://x/", func() *string { return &tok })
	if len(h.calls) != 0 {
		t.Errorf("routes touched without a list: %v", h.calls)
	}
}
