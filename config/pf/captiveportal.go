package pfconfig

import (
	"fmt"
	"os"
	"path/filepath"
)

// captivePortalEnvPath is where the captive-portal app reads its
// configuration from. It must match srvcman's captiveportalmodel.EnvPath.
const captivePortalEnvPath = "/usr/local/arkgate/captiveportal/.env"

// CaptivePortalEnvCreate fetches the captive-portal app's rendered .env
// from srvcman and installs it.
//
// Unlike the other *Create functions this writes straight to the app's
// directory rather than staging under /tmp: the file is the app's own
// config, not something the changes apply flow later backs up and moves
// into /etc, so there is no staging step to fit into.
//
// It is written 0600, and that is not incidental - the file carries
// API_AUTH, a base64 "user:password" for a live srvcman account. 0640
// (what the other generated configs use) would expose the credential to
// every member of the file's group. The parent directory is created if the
// app has not been installed yet, so an admin can configure the portal
// before deploying it.
func CaptivePortalEnvCreate(urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"captiveportal/conf", token)
	if err != nil {
		return err
	}
	if conf == "" {
		return fmt.Errorf("captiveportal: srvcman returned an empty .env, refusing to overwrite %s", captivePortalEnvPath)
	}
	if err := os.MkdirAll(filepath.Dir(captivePortalEnvPath), 0755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(captivePortalEnvPath), err)
	}
	if err := os.WriteFile(captivePortalEnvPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", captivePortalEnvPath, err)
	}
	return nil
}
