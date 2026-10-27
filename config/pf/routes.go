package pfconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

// /etc/netstart rebuilds the network configuration and can flush the routes it
// does not know about. The routes srvcman manages - the static routes and the
// host routes the gateway monitors ping through - live only in the kernel's
// routing table, not in any file netstart reads, so they are installed again
// after every netstart.

// staticRouteRec and gatewayMonitorRec are the fields arkgated needs from
// srvcman's /staticroutes and /gatewaymonitor lists.
type staticRouteRec struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
}

type gatewayMonitorRec struct {
	Name      string `json:"name"`
	Ip        string `json:"ip"`
	MonitorIp string `json:"monitor_ip"`
}

// routeSpec is one route to install: route add <flag> <dest> <gw> -label <name>.
type routeSpec struct {
	flag, dest, gw, label string
}

// runRoute runs route(8); tests replace it.
var runRoute = func(args ...string) ([]byte, error) {
	return exec.Command("/sbin/route", args...).CombinedOutput()
}

// fetchList is how the lists are fetched; tests replace it.
var fetchList = func(url string, token *string, out any) error {
	if token == nil {
		return fmt.Errorf("no API token available")
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d: %s", url, res.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

var routeLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// specFor turns a static route record into a route to install, or says why it
// cannot be (the values come from the API; nothing that is not a plain address
// or label ever reaches route(8)).
func specFor(r staticRouteRec) (routeSpec, error) {
	if !routeLabel.MatchString(r.Name) {
		return routeSpec{}, fmt.Errorf("unusable route name %q", r.Name)
	}
	gw := net.ParseIP(r.Gateway)
	if gw == nil {
		return routeSpec{}, fmt.Errorf("route %s: bad gateway %q", r.Name, r.Gateway)
	}
	if r.Type == "net" {
		if _, _, err := net.ParseCIDR(r.Destination); err != nil {
			return routeSpec{}, fmt.Errorf("route %s: bad network %q", r.Name, r.Destination)
		}
		return routeSpec{"-net", r.Destination, r.Gateway, r.Name}, nil
	}
	if net.ParseIP(r.Destination) == nil {
		return routeSpec{}, fmt.Errorf("route %s: bad host %q", r.Name, r.Destination)
	}
	return routeSpec{"-host", r.Destination, r.Gateway, r.Name}, nil
}

func monitorSpec(g gatewayMonitorRec) (routeSpec, error) {
	return specFor(staticRouteRec{Name: g.Name, Type: "host", Destination: g.MonitorIp, Gateway: g.Ip})
}

// install adds the route, or changes it when it is already there (a netstart
// that did not flush it), so the result is the same either way.
func install(s routeSpec) error {
	add := []string{"-q", "add", s.flag, s.dest, s.gw, "-label", s.label}
	if out, err := runRoute(add...); err != nil {
		chg := []string{"-q", "change", s.flag, s.dest, s.gw, "-label", s.label}
		if out2, err2 := runRoute(chg...); err2 != nil {
			return fmt.Errorf("route add/change %s %s via %s: %v: %s / %s", s.flag, s.dest, s.gw, err2, out, out2)
		}
	}
	return nil
}

// RestoreRoutes installs every static route and every gateway monitor's host
// route again and returns how many it installed and how many failed. A failure
// is logged and does not stop the others. urlbase is srvcman's API base
// ("http://host:port/api/v1/").
func RestoreRoutes(urlbase string, token *string) (installed, failed int) {
	installed, failed, _ = restore(urlbase, token)
	return installed, failed
}

// restore is RestoreRoutes, and also reports whether both lists could be read
// (false when srvcman could not be reached, so nothing is known yet).
func restore(urlbase string, token *string) (installed, failed int, listed bool) {
	listed = true
	var specs []routeSpec
	var statics []staticRouteRec
	if err := fetchList(urlbase+"staticroutes", token, &statics); err != nil {
		log.Println("routes: could not read the static routes:", err)
		failed++
		listed = false
	}
	for _, r := range statics {
		if r.Destination == "" || r.Gateway == "" {
			continue
		}
		s, err := specFor(r)
		if err != nil {
			log.Println("routes:", err)
			failed++
			continue
		}
		specs = append(specs, s)
	}
	var monitors []gatewayMonitorRec
	if err := fetchList(urlbase+"gatewaymonitor", token, &monitors); err != nil {
		log.Println("routes: could not read the gateway monitors:", err)
		failed++
		listed = false
	}
	for _, g := range monitors {
		if g.MonitorIp == "" || g.Ip == "" {
			continue
		}
		s, err := monitorSpec(g)
		if err != nil {
			log.Println("routes:", err)
			failed++
			continue
		}
		specs = append(specs, s)
	}
	for _, s := range specs {
		if err := install(s); err != nil {
			log.Println("routes:", err)
			failed++
			continue
		}
		installed++
	}
	return installed, failed, listed
}

// retryEvery and giveUpAfter pace RestoreRoutesWhenReady; tests shorten them.
var (
	retryEvery  = 5 * time.Second
	giveUpAfter = 5 * time.Minute
)

// RestoreRoutesWhenReady installs the managed routes again after a boot or an
// arkgated restart. The kernel keeps none of them across a reboot, and arkgated
// starts alongside srvcman, so the lists are retried until srvcman answers (or
// giveUpAfter has passed). token returns the current API token, nil until the
// first login has worked.
func RestoreRoutesWhenReady(ctx context.Context, urlbase string, token func() *string) {
	deadline := time.Now().Add(giveUpAfter)
	for {
		if t := token(); t != nil {
			if installed, failed, listed := restore(urlbase, t); listed {
				log.Printf("routes: restored %d at start (%d failed)", installed, failed)
				return
			}
		}
		if time.Now().After(deadline) {
			log.Println("routes: gave up restoring routes at start; srvcman did not answer")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryEvery):
		}
	}
}

// netstart runs /etc/netstart (for one device, or for everything when device is
// empty) and then puts the managed routes back. A netstart that fails is an
// error; routes that cannot be restored are only logged, because the network
// itself did come up.
func netstart(device, urlbase string, token *string) error {
	args := []string{"/etc/netstart"}
	if device != "" {
		args = append(args, device)
	}
	if out, err := runNetstart(args...); err != nil {
		log.Println(string(out))
		return err
	}
	installed, failed := RestoreRoutes(urlbase, token)
	log.Printf("routes: restored %d after netstart %s (%d failed)", installed, device, failed)
	return nil
}

// runNetstart runs sh with the arguments; tests replace it.
var runNetstart = func(args ...string) ([]byte, error) {
	return exec.Command("sh", args...).CombinedOutput()
}
