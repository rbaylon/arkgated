package webconf

import "html/template"

var routerTmpl = template.Must(template.New("router").Parse(routerHTML))

// routerHTML is the router-config page: what the stdin wizard used to ask,
// plus the host's real interface list so devices are picked rather than
// remembered. Inline and script-free on purpose - the repeating sections work
// by posting indexed field names and re-rendering, so nothing here depends on
// JavaScript being available on whatever the operator browses from.
const routerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>arkgated router config</title>
<style>
:root {
  --bg: #f4f5f7; --panel: #ffffff; --ink: #1b1f24; --muted: #5b6470;
  --line: #d9dde3; --accent: #1f6feb; --warn-bg: #fff6e0; --warn-ink: #7a4b00;
  --err-bg: #fdecec; --err-ink: #8c1c1c; --ok-bg: #e7f6ec; --ok-ink: #14562c;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14171c; --panel: #1c2027; --ink: #e8ebef; --muted: #98a2b0;
    --line: #2c323b; --accent: #5b9bff; --warn-bg: #3a2d10; --warn-ink: #f0d18a;
    --err-bg: #3a1a1a; --err-ink: #f3b0b0; --ok-bg: #16301f; --ok-ink: #9adcb4;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1100px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
nav { margin: 0 0 24px; font-size: 14px; }
nav a { color: var(--accent); text-decoration: none; margin-right: 16px; }
nav a.here { color: var(--ink); font-weight: 600; text-decoration: none; }
section {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 20px; margin-bottom: 16px;
}
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 4px; }
.hint { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; }
label { display: block; font-weight: 600; margin-bottom: 4px; font-size: 13px; }
input[type=text], input[type=number] {
  width: 100%; padding: 7px 9px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--bg); color: var(--ink); font: inherit; font-size: 14px;
}
input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
.help { color: var(--muted); font-size: 12px; margin: 4px 0 0; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .05em; }
td.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.row {
  border: 1px solid var(--line); border-radius: 8px; padding: 14px;
  margin-bottom: 12px; background: var(--bg);
}
.row h3 { margin: 0 0 12px; font-size: 13px; color: var(--muted); font-weight: 600; }
.pill {
  display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 7px;
  border-radius: 999px; background: var(--ok-bg); color: var(--ok-ink); margin-left: 6px;
}
.pill.off { background: var(--warn-bg); color: var(--warn-ink); }
.pill.pseudo { background: var(--line); color: var(--muted); }
.opt {
  font-size: 11px; font-weight: 600; text-transform: none; letter-spacing: 0;
  padding: 1px 7px; border-radius: 999px; background: var(--line); color: var(--muted);
  margin-left: 6px; vertical-align: 1px;
}
.note { border-radius: 8px; padding: 12px 14px; margin-bottom: 16px; font-size: 14px; }
.note ul { margin: 6px 0 0; padding-left: 20px; }
.note.err { background: var(--err-bg); color: var(--err-ink); }
.note.ok { background: var(--ok-bg); color: var(--ok-ink); }
.note.warn { background: var(--warn-bg); color: var(--warn-ink); }
.inline { display: flex; align-items: center; gap: 8px; }
.inline label { margin: 0; font-weight: 400; }
button {
  background: var(--accent); color: #fff; border: 0; border-radius: 6px;
  padding: 10px 18px; font: inherit; font-weight: 600; cursor: pointer;
}
button:hover { filter: brightness(1.08); }
footer { color: var(--muted); font-size: 12px; margin-top: 24px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Router config</h1>
  <p class="sub">The per-router interface, DHCP and flow-export config. Saved to <code class="mono">{{.Path}}</code>.</p>
  <nav><a href="/">Daemon settings</a><a class="here" href="/router">Router config</a></nav>

  {{if not .Found}}
  <div class="note warn"><strong>Not created yet.</strong> arkgated needs this file before it can generate pf.conf or enroll with srvcman. The interfaces detected on this box are pre-filled below — check them and save.</div>
  {{end}}

  {{if .Saved}}
  <div class="note ok"><strong>Saved.</strong> arkgated reads this file at startup, so restart it (<code class="mono">rcctl restart arkgated</code>) to pick the change up. Interface files are re-rendered from it on the next pf apply, and applied by <code class="mono">ApplyIfaces</code>.</div>
  {{end}}

  {{if .Errors}}
  <div class="note err"><strong>{{index .Errors 0}}</strong>
    {{if gt (len .Errors) 1}}<ul>{{range $i, $e := .Errors}}{{if $i}}<li>{{$e}}</li>{{end}}{{end}}</ul>{{end}}
  </div>
  {{end}}

  <form method="post" action="/router">
    <datalist id="devices">{{range .DeviceNames}}<option value="{{.}}">{{end}}</datalist>

    <section>
      <h2>Router</h2>
      <div class="grid">
        <div>
          <label for="router">Router name</label>
          <input type="text" id="router" name="router" value="{{.Router}}">
          <p class="help">The key srvcman stores this router under.</p>
        </div>
        <div>
          <label for="dns">Upstream DNS</label>
          <input type="text" id="dns" name="dns" value="{{.Dns}}">
          <p class="help">Space separated, written to resolv.conf.</p>
        </div>
        <div>
          <label for="subs_portal_port">Subscriber portal port</label>
          <input type="number" id="subs_portal_port" name="subs_portal_port" value="{{.SubsPortalPort}}">
        </div>
        <div>
          <label for="captive_portal_port">Captive portal port</label>
          <input type="number" id="captive_portal_port" name="captive_portal_port" value="{{.CaptivePortalPort}}">
        </div>
        <div>
          <label for="wifi_ip_list">Wifi IP allowlist file</label>
          <input type="text" id="wifi_ip_list" name="wifi_ip_list" value="{{.WifiIpList}}">
        </div>
        <div>
          <label for="subs_ip_list">Subscriber IP list file</label>
          <input type="text" id="subs_ip_list" name="subs_ip_list" value="{{.SubsIpList}}">
        </div>
      </div>
      <div class="inline" style="margin-top:14px">
        <input type="checkbox" id="load_balance" name="load_balance" value="true"{{if .LoadBalance}} checked{{end}}>
        <label for="load_balance">Load balance across external interfaces (uses each one's weight below)</label>
      </div>
    </section>

    <section>
      <h2>Interfaces</h2>
      <p class="hint">Devices found on this box by <code class="mono">ifconfig -a</code> are pre-filled below, with their live state shown on each row. Clear a row's name and device to delete it. Exactly one interface is the default route — that is the one <code class="mono">mygate</code> and <code class="mono">resolv.conf</code> are written from.</p>
      {{if .DetectErr}}<div class="note warn">Could not read the interface list: <span class="mono">{{.DetectErr}}</span><br>Type device names in by hand.</div>{{end}}
      {{range .Ifaces}}
      <div class="row">
        <h3>Interface {{.Idx}}{{if .Known}} — <span class="mono">{{.Device}}</span>
          {{if .Up}}<span class="pill">up</span>{{else}}<span class="pill off">down</span>{{end}}
          {{if .Egress}}<span class="pill">egress</span>{{end}}{{end}}</h3>
        {{if .Known}}<p class="help mono">{{with .Status}}{{.}}{{end}}{{with .Media}} &middot; {{.}}{{end}}{{with .Addrs}} &middot; {{.}}{{end}}</p>{{end}}
        <div class="grid">
          <div>
            <label for="iface.{{.Idx}}.name">Name</label>
            <input type="text" id="iface.{{.Idx}}.name" name="iface.{{.Idx}}.name" value="{{.Name}}" placeholder="wan, lan">
          </div>
          <div>
            <label for="iface.{{.Idx}}.device">Device</label>
            <input type="text" id="iface.{{.Idx}}.device" name="iface.{{.Idx}}.device" value="{{.Device}}" list="devices" placeholder="em0">
          </div>
          <div>
            <label for="iface.{{.Idx}}.type">Type</label>
            <input type="text" id="iface.{{.Idx}}.type" name="iface.{{.Idx}}.type" value="{{.Type}}" list="iftypes" placeholder="external / internal">
          </div>
          <div>
            <label for="iface.{{.Idx}}.speed">Speed</label>
            <input type="text" id="iface.{{.Idx}}.speed" name="iface.{{.Idx}}.speed" value="{{.Speed}}" placeholder="{{if .SpeedHint}}{{.SpeedHint}}{{else}}900M{{end}}">
            <p class="help">{{if .SpeedHint}}Link negotiates {{.SpeedHint}}; leave headroom.{{else}}pf queue bandwidth.{{end}}</p>
          </div>
          <div>
            <label for="iface.{{.Idx}}.ip">IP</label>
            <input type="text" id="iface.{{.Idx}}.ip" name="iface.{{.Idx}}.ip" value="{{.Ip}}" placeholder="10.0.0.1 or autoconf">
          </div>
          <div>
            <label for="iface.{{.Idx}}.netmask">Netmask</label>
            <input type="text" id="iface.{{.Idx}}.netmask" name="iface.{{.Idx}}.netmask" value="{{.Netmask}}" placeholder="255.255.255.0">
          </div>
          <div>
            <label for="iface.{{.Idx}}.gateway">Gateway</label>
            <input type="text" id="iface.{{.Idx}}.gateway" name="iface.{{.Idx}}.gateway" value="{{.Gateway}}">
          </div>
          <div>
            <label for="iface.{{.Idx}}.lb_percentage">LB weight</label>
            <input type="number" id="iface.{{.Idx}}.lb_percentage" name="iface.{{.Idx}}.lb_percentage" value="{{.LbPercentage}}">
          </div>
        </div>
        <div class="inline" style="margin-top:12px">
          <input type="radio" id="default.{{.Idx}}" name="default_iface" value="{{.Idx}}"{{if .Default}} checked{{end}}>
          <label for="default.{{.Idx}}">Default route interface</label>
        </div>
      </div>
      {{end}}
      <datalist id="iftypes"><option value="external"><option value="internal"></datalist>
      {{if .PseudoNames}}
      <p class="hint" style="margin:0">Not assignable here (loopback, pf, or created by arkgated itself):
        {{range $i, $d := .PseudoNames}}{{if $i}}, {{end}}<span class="mono">{{$d}}</span>{{end}}</p>
      {{end}}
    </section>

    <section>
      <h2>DHCP scopes <span class="opt">optional</span></h2>
      <p class="hint">Only used to seed srvcman when this router first enrolls &mdash; srvcman's dhcp module owns <code class="mono">dhcpd.conf</code> after that, and arkgated just fetches the rendered text from it. Leave this empty and manage scopes in srvcman. Nothing here is required; whatever you do fill in is only checked for typos. Clear a row's interface, subnet and range to delete it.</p>
      {{range .Dhcps}}
      <div class="row">
        <h3>Scope {{.Idx}}</h3>
        <div class="grid">
          <div>
            <label for="dhcp.{{.Idx}}.type">Interface</label>
            <input type="text" id="dhcp.{{.Idx}}.type" name="dhcp.{{.Idx}}.type" value="{{.Type}}" placeholder="lan">
          </div>
          <div>
            <label for="dhcp.{{.Idx}}.subnet">Subnet</label>
            <input type="text" id="dhcp.{{.Idx}}.subnet" name="dhcp.{{.Idx}}.subnet" value="{{.Subnet}}" placeholder="172.16.0.0">
          </div>
          <div>
            <label for="dhcp.{{.Idx}}.netmask">Netmask</label>
            <input type="text" id="dhcp.{{.Idx}}.netmask" name="dhcp.{{.Idx}}.netmask" value="{{.Netmask}}">
          </div>
          <div>
            <label for="dhcp.{{.Idx}}.routers">Router handed to clients</label>
            <input type="text" id="dhcp.{{.Idx}}.routers" name="dhcp.{{.Idx}}.routers" value="{{.Routers}}">
          </div>
          <div>
            <label for="dhcp.{{.Idx}}.dnsservers">DNS handed to clients</label>
            <input type="text" id="dhcp.{{.Idx}}.dnsservers" name="dhcp.{{.Idx}}.dnsservers" value="{{.Dnsservers}}">
          </div>
          <div>
            <label for="dhcp.{{.Idx}}.range">Range</label>
            <input type="text" id="dhcp.{{.Idx}}.range" name="dhcp.{{.Idx}}.range" value="{{.Range}}" placeholder="172.16.1.1 172.16.9.255">
          </div>
        </div>
      </div>
      {{end}}
    </section>

    <section>
      <h2>pflow exports <span class="opt">optional</span></h2>
      <p class="hint">NetFlow/pflow export. Entirely optional — leave it empty and nothing is generated. A complete row is written to <code class="mono">hostname.&lt;device&gt;</code> as <code class="mono">flowsrc</code>/<code class="mono">flowdst</code>/<code class="mono">pflowproto</code>; a row missing any of those is saved but skipped when the interface files are rendered (arkgated logs which one), because a partial export would produce a file that breaks <code class="mono">netstart</code>. Clear a row's device and destination to delete it.</p>
      {{range .Pflows}}
      <div class="row">
        <h3>Export {{.Idx}}</h3>
        <div class="grid">
          <div>
            <label for="pflow.{{.Idx}}.device">Device</label>
            <input type="text" id="pflow.{{.Idx}}.device" name="pflow.{{.Idx}}.device" value="{{.Device}}" placeholder="pflow0">
          </div>
          <div>
            <label for="pflow.{{.Idx}}.src">Flow source</label>
            <input type="text" id="pflow.{{.Idx}}.src" name="pflow.{{.Idx}}.src" value="{{.Src}}">
          </div>
          <div>
            <label for="pflow.{{.Idx}}.dst">Flow destination</label>
            <input type="text" id="pflow.{{.Idx}}.dst" name="pflow.{{.Idx}}.dst" value="{{.Dst}}" placeholder="10.0.0.5:9995">
          </div>
          <div>
            <label for="pflow.{{.Idx}}.proto">Version</label>
            <input type="number" id="pflow.{{.Idx}}.proto" name="pflow.{{.Idx}}.proto" value="{{.Proto}}">
            <p class="help">5 or 10.</p>
          </div>
        </div>
      </div>
      {{end}}
    </section>

    <button type="submit">Save router config</button>
  </form>

  <footer>Two blank rows are offered in each section; save and they reappear, so there is no need to add rows before filling them. Every value here is read by arkgated at startup and sent to srvcman on enrollment.</footer>
</div>
</body>
</html>
`
