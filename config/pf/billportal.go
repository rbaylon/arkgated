package pfconfig

import (
	"fmt"
)

// billPortalEnvPath is where the bill-portal app reads its configuration
// from. It must match srvcman's billportalmodel.EnvPath.
// A var only so tests can point it at a temp dir.
var billPortalEnvPath = "/usr/local/arkgate/billportal/.env"

// BillPortalEnvCreate fetches the bill-portal app's rendered .env from
// srvcman and installs it.
//
// Same shape as CaptivePortalEnvCreate, including the 0600 mode and the
// chown to admin: the file carries API_AUTH, a base64 "user:password" for a
// live srvcman account.
func BillPortalEnvCreate(urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"billportal/conf", token)
	if err != nil {
		return err
	}
	if conf == "" {
		return fmt.Errorf("billportal: srvcman returned an empty .env, refusing to overwrite %s", billPortalEnvPath)
	}
	return installPortalEnv("billportal", billPortalEnvPath, conf)
}
