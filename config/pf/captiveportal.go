package pfconfig

import (
	"fmt"
)

// captivePortalEnvPath is where the captive-portal app reads its
// configuration from. It must match srvcman's captiveportalmodel.EnvPath.
// A var only so tests can point it at a temp dir.
var captivePortalEnvPath = "/usr/local/arkgate/captiveportal/.env"

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
// every member of the file's group. The file is then chowned to admin, the
// account the portal runs as (see installPortalEnv). The parent directory is
// created if the app has not been installed yet, so an admin can configure
// the portal before deploying it.
func CaptivePortalEnvCreate(urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"captiveportal/conf", token)
	if err != nil {
		return err
	}
	if conf == "" {
		return fmt.Errorf("captiveportal: srvcman returned an empty .env, refusing to overwrite %s", captivePortalEnvPath)
	}
	return installPortalEnv("captiveportal", captivePortalEnvPath, conf)
}
