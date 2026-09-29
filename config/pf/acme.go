package pfconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	acmeClientBin = "/usr/sbin/acme-client"
	rcctlBin      = "/usr/sbin/rcctl"
	acmeConfPath  = "/etc/acme-client.conf"
	acmeStagePath = "/tmp/acme-client.conf"
	nginxConfPath = "/etc/nginx/nginx.conf"
)

// fqdnRegex mirrors srvcman's validate.FQDN. The name arrives over the
// API rather than off the wire, but it still ends up in a command argument
// and two file paths, so it is re-checked here: arkgated runs as root and
// this is the last point before exec.
var fqdnRegex = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// nginxCertRegex and nginxKeyRegex match the certificate paths in
// nginx.conf that this module owns: either the shipped self-signed pair
// under /usr/local/arkgate/ssl, or a pair this module wrote on a previous
// run. Matching the previously-written form too is what makes changing the
// FQDN work - a plain literal search for the self-signed paths finds
// nothing on the second run, and nginx would silently keep serving the old
// certificate.
var (
	nginxCertRegex = regexp.MustCompile(`/usr/local/arkgate/ssl/cert\.pem|/etc/ssl/[A-Za-z0-9.-]+\.fullchain\.pem`)
	nginxKeyRegex  = regexp.MustCompile(`/usr/local/arkgate/ssl/private/key\.pem|/etc/ssl/private/[A-Za-z0-9.-]+\.key`)
)

// acmeCmdTimeout bounds acme-client itself. Issuance involves an ACME
// challenge round trip to Let's Encrypt, so it is slower than anything
// else this daemon runs, but it must still not hang forever.
const acmeCmdTimeout = 100 * time.Second

// fetchActiveFqdn asks srvcman which name certificates are currently
// managed for. An empty result means certificate management is switched
// off, which is a no-op rather than an error.
func fetchActiveFqdn(urlbase string, token *string) (string, error) {
	if token == nil {
		return "", fmt.Errorf("fetchActiveFqdn: no API token available")
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", urlbase+"acme/active", nil)
	if err != nil {
		return "", err
	}
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
		Fqdn string `json:"fqdn"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	return resp.Fqdn, nil
}

// backupFile copies path to a timestamped sibling before it is modified,
// preserving its mode. A missing original is not an error - there is
// simply nothing to keep.
func backupFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	mode := os.FileMode(0640)
	if info, serr := os.Stat(path); serr == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(fmt.Sprintf("%s.%d", path, time.Now().Unix()), data, mode)
}

// runBounded runs one command under acmeCmdTimeout and returns its
// combined output.
func runBounded(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
		return string(out), err
	case <-time.After(acmeCmdTimeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
		return string(out), fmt.Errorf("%s timed out after %s", name, acmeCmdTimeout)
	}
}

// installAcmeConf stages srvcman's rendered acme-client.conf, has
// acme-client itself check the syntax, and only then installs it over
// /etc/acme-client.conf (keeping a timestamped backup).
//
// The check is `acme-client -n -f <staged> <fqdn>`: -n parses and exits 0
// for a good file, or prints "<file>:<line>: syntax error" and exits 1 for
// a bad one. Checking the staged copy first is what keeps a malformed
// config from replacing a working /etc/acme-client.conf - the same
// order dhcpd/unbound/snmpd get from their -nf check. Note -n validates
// syntax only; it exits 0 even when the handle has no domain block, so it
// is not a check that the requested name is actually configured.
func installAcmeConf(fqdn, conf string) error {
	if err := os.WriteFile(acmeStagePath, []byte(conf), 0644); err != nil {
		return fmt.Errorf("staging %s: %w", acmeStagePath, err)
	}
	if out, err := runBounded(acmeClientBin, "-n", "-f", acmeStagePath, fqdn); err != nil {
		return fmt.Errorf("%s is invalid, leaving %s alone: %s", acmeStagePath, acmeConfPath, strings.TrimSpace(out))
	}
	if err := backupFile(acmeConfPath); err != nil {
		return fmt.Errorf("backing up %s: %w", acmeConfPath, err)
	}
	if err := os.WriteFile(acmeConfPath, []byte(conf), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", acmeConfPath, err)
	}
	return nil
}

// rewriteNginxPaths swaps the certificate and key paths this module owns
// for fqdn's. Kept separate from the file handling so the substitution
// itself - the part that has to cope with both a fresh self-signed config
// and one this module already rewrote - can be exercised directly.
func rewriteNginxPaths(content, fqdn string) string {
	out := nginxCertRegex.ReplaceAllString(content, fmt.Sprintf("/etc/ssl/%s.fullchain.pem", fqdn))
	return nginxKeyRegex.ReplaceAllString(out, fmt.Sprintf("/etc/ssl/private/%s.key", fqdn))
}

// pointNginxAt rewrites nginx.conf's certificate and key paths to fqdn's,
// after backing the file up. It reports whether anything changed.
func pointNginxAt(fqdn string) (bool, error) {
	data, err := os.ReadFile(nginxConfPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", nginxConfPath, err)
	}
	updated := rewriteNginxPaths(string(data), fqdn)
	if updated == string(data) {
		return false, nil
	}
	if err := backupFile(nginxConfPath); err != nil {
		return false, fmt.Errorf("backing up %s: %w", nginxConfPath, err)
	}
	mode := os.FileMode(0644)
	if info, serr := os.Stat(nginxConfPath); serr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(nginxConfPath, []byte(updated), mode); err != nil {
		return false, fmt.Errorf("writing %s: %w", nginxConfPath, err)
	}
	return true, nil
}

// ApplyAcme issues (or renews) the gateway's Let's Encrypt certificate and
// points nginx at it, as one operation:
//
//  1. install /etc/acme-client.conf from srvcman's rendered copy, after
//     acme-client -n accepts it
//  2. acme-client -v <fqdn>
//  3. back up nginx.conf and rewrite its cert/key paths
//  4. rcctl restart nginx
//
// It is a no-op when no record is enabled. Step 2 is the one that can
// legitimately fail on a correct config - acme-client has to answer a
// challenge for <fqdn>, which needs a public A record pointing at this box
// - so its output is returned verbatim for the caller to surface rather
// than collapsed into a generic error.
//
// nginx is restarted whenever acme-client succeeded, not only when the
// paths changed: on a renewal the paths are already right and the point of
// the restart is to make nginx pick up the new certificate file.
//
// Trouble in steps 3-4 is reported in the returned text but does not fail
// the call, because by then the certificate has already been issued.
// Returning an error there invites a retry, and retrying issuance is not
// free: Let's Encrypt rate-limits duplicate certificates (5 per week per
// name), so a box with nginx missing or misconfigured would burn that
// allowance re-requesting a certificate it already holds.
func ApplyAcme(urlbase string, token *string) (string, error) {
	fqdn, err := fetchActiveFqdn(urlbase, token)
	if err != nil {
		return "", err
	}
	if fqdn == "" {
		return "certificate management is disabled, nothing to do", nil
	}
	if !fqdnRegex.MatchString(fqdn) {
		return "", fmt.Errorf("refusing to act on invalid fqdn %q", fqdn)
	}

	conf, err := fetchConfText(urlbase+"acme/conf", token)
	if err != nil {
		return "", err
	}
	if err := installAcmeConf(fqdn, conf); err != nil {
		return "", err
	}

	var report strings.Builder
	fmt.Fprintf(&report, "installed %s\n", acmeConfPath)
	out, err := runBounded(acmeClientBin, "-v", fqdn)
	report.WriteString(out)
	if err != nil {
		log.Println("acme: acme-client failed:", err, out)
		return report.String(), fmt.Errorf("acme-client -v %s: %w", fqdn, err)
	}

	// From here on the certificate exists, so problems are reported rather
	// than returned as errors - see the note above about rate limits.
	if _, serr := os.Stat(nginxConfPath); serr != nil {
		fmt.Fprintf(&report, "\ncertificate issued, but %s was not found - nginx was left untouched and not restarted.\n", nginxConfPath)
		fmt.Fprintf(&report, "Point your web server at %s and %s by hand.\n",
			fmt.Sprintf("/etc/ssl/%s.fullchain.pem", fqdn), fmt.Sprintf("/etc/ssl/private/%s.key", fqdn))
		return report.String(), nil
	}

	changed, err := pointNginxAt(fqdn)
	if err != nil {
		log.Println("acme:", err)
		fmt.Fprintf(&report, "\ncertificate issued, but updating %s failed: %v\n", nginxConfPath, err)
		return report.String(), nil
	}
	if changed {
		fmt.Fprintf(&report, "\n%s updated to use %s\n", nginxConfPath, fqdn)
	} else {
		fmt.Fprintf(&report, "\n%s already points at %s\n", nginxConfPath, fqdn)
	}

	if out, err := runBounded(rcctlBin, "restart", "nginx"); err != nil {
		log.Println("acme: nginx restart failed:", err, out)
		fmt.Fprintf(&report, "certificate issued, but restarting nginx failed: %s\n", strings.TrimSpace(out))
		return report.String(), nil
	}
	report.WriteString("nginx restarted\n")
	return report.String(), nil
}
