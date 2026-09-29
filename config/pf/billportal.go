package pfconfig

import (
	"fmt"
	"os"
	"path/filepath"
)

// billPortalEnvPath is where the bill-portal app reads its configuration
// from. It must match srvcman's billportalmodel.EnvPath.
const billPortalEnvPath = "/usr/local/arkgate/billportal/.env"

// BillPortalEnvCreate fetches the bill-portal app's rendered .env from
// srvcman and installs it.
//
// Same shape as CaptivePortalEnvCreate, including the 0600 mode: the file
// carries API_AUTH, a base64 "user:password" for a live srvcman account.
func BillPortalEnvCreate(urlbase string, token *string) error {
	conf, err := fetchConfText(urlbase+"billportal/conf", token)
	if err != nil {
		return err
	}
	if conf == "" {
		return fmt.Errorf("billportal: srvcman returned an empty .env, refusing to overwrite %s", billPortalEnvPath)
	}
	if err := os.MkdirAll(filepath.Dir(billPortalEnvPath), 0755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(billPortalEnvPath), err)
	}
	if err := os.WriteFile(billPortalEnvPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", billPortalEnvPath, err)
	}
	return nil
}
