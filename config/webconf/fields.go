package webconf

import (
	"fmt"
	"strconv"
)

// kind tells the template which input to render and the form parser how to
// read the value back.
type kind string

const (
	kindText   kind = "text"
	kindNumber kind = "number"
	kindSecret kind = "secret"
)

// field describes one setting: how to label it in the configurator, and how
// to read it out of and back into a Settings. It is the single source of
// truth shared by the form and the restart-required diff, so adding a setting
// means adding exactly one entry here (plus the struct field and, if it is
// read only at startup, a restartScoped entry).
type field struct {
	Key     string
	Label   string
	Help    string
	Group   string
	Kind    kind
	Restart bool

	get func(*Settings) string
	set func(*Settings, string) error
}

// Groups are rendered as sections, in this order.
const (
	groupIPC  = "IPC transports"
	groupAPI  = "Service manager (srvcman) API"
	groupPath = "Paths"
	groupWeb  = "This configurator"
)

// Groups is the section order the form renders in.
var Groups = []string{groupIPC, groupAPI, groupPath, groupWeb}

// fields returns the field table. The get/set closures capture the *Settings
// passed at call time rather than a fixed one, so the table is built fresh
// per call - cheap, and it keeps the closures from aliasing one Settings.
func fields() []field {
	return []field{
		{
			Key:     "socketfile",
			Label:   "Unix socket path",
			Help:    "Local Unix domain socket for same-host clients (srvcman/subsportal on this box). Leave empty to disable it for a remote-only deployment.",
			Group:   groupIPC,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.SocketFile },
			set:     func(s *Settings, v string) error { s.SocketFile = v; return nil },
		},
		{
			Key:     "arkgid",
			Label:   "arkgate group id",
			Help:    "Group that owns the Unix socket (mode 0660). Filesystem permissions are the only thing gating the local transport, so this group is effectively root on this box.",
			Group:   groupIPC,
			Kind:    kindNumber,
			Restart: true,
			get:     func(s *Settings) string { return strconv.Itoa(s.ArkGid) },
			set:     setInt(func(s *Settings) *int { return &s.ArkGid }),
		},
		{
			Key:     "listenaddr",
			Label:   "mTLS listen address",
			Help:    "host:port for the mutual-TLS listener used by clients that are not on this host.",
			Group:   groupIPC,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.ListenAddr },
			set:     func(s *Settings, v string) error { s.ListenAddr = v; return nil },
		},
		{
			Key:   "maxbuff",
			Label: "Max buffer size",
			Help:  "Bytes read per connection. Must be large enough to hold a whole command payload, or commands are truncated into unmarshal errors.",
			Group: groupIPC,
			Kind:  kindNumber,
			get:   func(s *Settings) string { return strconv.Itoa(s.MaxBuff) },
			set:   setInt(func(s *Settings) *int { return &s.MaxBuff }),
		},

		{
			Key:   "srvcurl",
			Label: "Service manager url",
			Help:  "Base URL of srvcman's API, trailing slash included (one is added if you omit it).",
			Group: groupAPI,
			Kind:  kindText,
			get:   func(s *Settings) string { return s.SrvcURL },
			set:   func(s *Settings, v string) error { s.SrvcURL = v; return nil },
		},
		{
			Key:   "creds",
			Label: "Basic auth api creds",
			Help:  "Credential arkgated logs in to srvcman with. Stored in the settings file (mode 0600); leave the field blank to keep the saved value.",
			Group: groupAPI,
			Kind:  kindSecret,
			get:   func(s *Settings) string { return s.Creds },
			set:   func(s *Settings, v string) error { s.Creds = v; return nil },
		},

		{
			Key:     "rundir",
			Label:   "Rundir",
			Help:    "Working directory for generated config (pf.conf, dhcpd.conf, hostname.*, config.json). Trailing slash is added if you omit it.",
			Group:   groupPath,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.RunDir },
			set:     func(s *Settings, v string) error { s.RunDir = v; return nil },
		},
		{
			Key:     "tlscert",
			Label:   "TLS server certificate",
			Help:    "This daemon's server certificate, presented on the mTLS listener.",
			Group:   groupPath,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.TLSCert },
			set:     func(s *Settings, v string) error { s.TLSCert = v; return nil },
		},
		{
			Key:     "tlskey",
			Label:   "TLS server key",
			Help:    "Private key for the certificate above.",
			Group:   groupPath,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.TLSKey },
			set:     func(s *Settings, v string) error { s.TLSKey = v; return nil },
		},
		{
			Key:     "tlsclientca",
			Label:   "Client CA certificate",
			Help:    "CA that client certificates must be signed by. This is the only thing standing between reachable-over-the-network and root running an arbitrary binary, so treat changes here as changes to the whole trust boundary.",
			Group:   groupPath,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.TLSClientCA },
			set:     func(s *Settings, v string) error { s.TLSClientCA = v; return nil },
		},

		{
			Key:     "webaddr",
			Label:   "Configurator listen address",
			Help:    "host:port this page is served on. Defaults to loopback only - reach it over an ssh tunnel rather than widening it.",
			Group:   groupWeb,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.WebAddr },
			set:     func(s *Settings, v string) error { s.WebAddr = v; return nil },
		},
		{
			Key:     "webcert",
			Label:   "Configurator certificate",
			Help:    "This page is always served over HTTPS. A self-signed certificate is generated here on first start if the file is missing; point this at your own certificate instead to stop the browser warning. Keep it separate from the mTLS pair above - that one authenticates srvcman to this daemon, this one authenticates this daemon to your browser.",
			Group:   groupWeb,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.WebCert },
			set:     func(s *Settings, v string) error { s.WebCert = v; return nil },
		},
		{
			Key:     "webkey",
			Label:   "Configurator key",
			Help:    "Private key for the certificate above, written mode 0600 when generated. An existing pair is never overwritten, including after it expires.",
			Group:   groupWeb,
			Kind:    kindText,
			Restart: true,
			get:     func(s *Settings) string { return s.WebKey },
			set:     func(s *Settings, v string) error { s.WebKey = v; return nil },
		},
	}
}

// setInt builds a set func for an int field, reporting a form-friendly error
// rather than strconv's wording.
func setInt(ptr func(*Settings) *int) func(*Settings, string) error {
	return func(s *Settings, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("must be a whole number")
		}
		*ptr(s) = n
		return nil
	}
}
