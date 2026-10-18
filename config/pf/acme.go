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
	acmeClientBin  = "/usr/sbin/acme-client"
	relaydBin      = "/usr/sbin/relayd"
	rcctlBin       = "/usr/sbin/rcctl"
	acmeConfPath   = "/etc/acme-client.conf"
	acmeStagePath  = "/tmp/acme-client.conf"
	relaydConfPath = "/etc/relayd.conf"
)

// fqdnRegex mirrors srvcman's validate.FQDN. The name arrives over the
// API rather than off the wire, but it still ends up in a command argument
// and two file paths, so it is re-checked here: arkgated runs as root and
// this is the last point before exec.
var fqdnRegex = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// relaydKeypairRegex matches a "tls keypair <name>" directive, quoted or
// not. relayd's keypair directive takes no paths - it derives them as
// /etc/ssl/<name>.crt and /etc/ssl/private/<name>.key - so setting the
// name to the FQDN is the whole job, and matching whatever name is there
// (rather than the literal "arkgate.local") is what makes both a re-run
// and an FQDN change work.
//
// It deliberately does not match a line with a trailing comment; leaving
// such a line alone is better than reformatting it.
var relaydKeypairRegex = regexp.MustCompile(`^(\s*tls\s+keypair\s+)"?[^"\s]+"?\s*$`)

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

// rewriteRelaydKeypair points every "tls keypair" directive at fqdn.
// Kept separate from the file handling so the substitution itself - the
// part that has to cope with the shipped name, a re-run, and an FQDN
// change - can be exercised directly.
//
// Comment lines are skipped rather than matched. relayd.conf's own
// commentary includes the phrases "tls keypair name" and "tls keypair
// NAME cert ... key ...", and rewriting those would mangle the
// documentation that explains why this directive works the way it does.
func rewriteRelaydKeypair(content, fqdn string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		if m := relaydKeypairRegex.FindStringSubmatch(line); m != nil {
			lines[i] = fmt.Sprintf("%s%q", m[1], fqdn)
		}
	}
	return strings.Join(lines, "\n")
}

// pointRelaydAt sets relayd.conf's keypair name to fqdn, after backing the
// file up, and only keeps the change if relayd itself accepts the result.
// It reports whether anything changed.
//
// The verification step is not optional here: relayd -n loads the keypair
// as part of checking the config, so it fails outright when
// /etc/ssl/<fqdn>.crt isn't there yet - and relayd is what serves this
// management UI, so restarting it with a config it cannot load would take
// the UI down with it. On rejection the previous config is put straight
// back and the restart is skipped.
func pointRelaydAt(fqdn string) (bool, error) {
	data, err := os.ReadFile(relaydConfPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", relaydConfPath, err)
	}
	updated := rewriteRelaydKeypair(string(data), fqdn)
	if updated == string(data) {
		return false, nil
	}
	if err := backupFile(relaydConfPath); err != nil {
		return false, fmt.Errorf("backing up %s: %w", relaydConfPath, err)
	}
	mode := os.FileMode(0644)
	if info, serr := os.Stat(relaydConfPath); serr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(relaydConfPath, []byte(updated), mode); err != nil {
		return false, fmt.Errorf("writing %s: %w", relaydConfPath, err)
	}
	if out, cerr := runBounded(relaydBin, "-n", "-f", relaydConfPath); cerr != nil {
		if rerr := os.WriteFile(relaydConfPath, data, mode); rerr != nil {
			return false, fmt.Errorf("relayd rejected the updated %s (%s) and restoring it failed: %v",
				relaydConfPath, strings.TrimSpace(out), rerr)
		}
		return false, fmt.Errorf("relayd rejected the updated %s, previous config restored: %s",
			relaydConfPath, strings.TrimSpace(out))
	}
	return true, nil
}

// ApplyAcme issues (or renews) the gateway's Let's Encrypt certificate and
// points relayd at it, as one operation:
//
//  1. install /etc/acme-client.conf from srvcman's rendered copy, after
//     acme-client -n accepts it
//  2. acme-client -v <fqdn>
//  3. back up relayd.conf, set its keypair name to <fqdn>, and keep the
//     change only if relayd -n accepts it
//  4. rcctl restart relayd
//
// The order matters and cannot be rearranged: relayd -n loads the keypair
// while checking the config, so step 3 can only succeed after step 2 has
// written /etc/ssl/<fqdn>.crt and /etc/ssl/private/<fqdn>.key.
//
// It is a no-op when no record is enabled. Step 2 is the one that can
// legitimately fail on a correct config - acme-client has to answer a
// challenge for <fqdn>, which needs a public A record pointing at this box
// - so its output is returned verbatim for the caller to surface rather
// than collapsed into a generic error.
//
// relayd is restarted whenever acme-client succeeded, not only when the
// keypair name changed: on a renewal the name is already right and the
// point of the restart is to make relayd pick up the new certificate.
//
// Trouble in steps 3-4 is reported in the returned text but does not fail
// the call, because by then the certificate has already been issued.
// Returning an error there invites a retry, and retrying issuance is not
// free: Let's Encrypt rate-limits duplicate certificates (5 per week per
// name), so a box with relayd missing or misconfigured would burn that
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
	if _, serr := os.Stat(relaydConfPath); serr != nil {
		fmt.Fprintf(&report, "\ncertificate issued, but %s was not found - relayd was left untouched and not restarted.\n", relaydConfPath)
		fmt.Fprintf(&report, "Point your TLS front end at /etc/ssl/%s.crt and /etc/ssl/private/%s.key by hand.\n", fqdn, fqdn)
		return report.String(), nil
	}

	changed, err := pointRelaydAt(fqdn)
	if err != nil {
		log.Println("acme:", err)
		fmt.Fprintf(&report, "\ncertificate issued, but %v\n", err)
		fmt.Fprintf(&report, "relayd was not restarted, so the running service is untouched.\n")
		return report.String(), nil
	}
	if changed {
		fmt.Fprintf(&report, "\n%s keypair set to %s\n", relaydConfPath, fqdn)
	} else {
		fmt.Fprintf(&report, "\n%s keypair already set to %s\n", relaydConfPath, fqdn)
	}

	if out, err := runBounded(rcctlBin, "restart", "relayd"); err != nil {
		log.Println("acme: relayd restart failed:", err, out)
		fmt.Fprintf(&report, "certificate issued, but restarting relayd failed: %s\n", strings.TrimSpace(out))
		return report.String(), nil
	}
	report.WriteString("relayd restarted\n")
	return report.String(), nil
}
