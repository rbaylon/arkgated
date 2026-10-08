package pfconfig

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// portalUser is the account the captive-portal and bill-portal services run
// as (their rc.d scripts set daemon_user="admin"). Their .env has to be
// owned by it: arkgated runs as root, so a file it writes is root's, and the
// 0600 mode that protects the credential inside would then lock the service
// out of its own configuration.
const portalUser = "admin"

// lookupPortalIDs resolves portalUser's uid and gid. A var so tests can
// stand in for the system's user database.
var lookupPortalIDs = func() (uid, gid int, err error) {
	u, err := user.Lookup(portalUser)
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup(portalUser)
	if err != nil {
		return 0, 0, err
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, err
	}
	if gid, err = strconv.Atoi(g.Gid); err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// chownFile is os.Chown; a var so tests can observe it.
var chownFile = os.Chown

// installPortalEnv writes conf to path as a portal's .env and hands the file
// to the portal's user (chown admin:admin <path>).
//
// The file is written 0600 first and chowned afterwards, so it is never
// readable by anyone else at any point. Writing is done on every call, but
// ownership is set on every call too - an existing file keeps whatever owner
// it had, so without this a .env created earlier by root would stay root's.
// If the chown fails the new contents are already in place; the error says
// so rather than pretending nothing happened.
func installPortalEnv(name, path, conf string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	uid, gid, err := lookupPortalIDs()
	if err != nil {
		return fmt.Errorf("%s: %s was written but not given to %s: %w", name, path, portalUser, err)
	}
	if err := chownFile(path, uid, gid); err != nil {
		return fmt.Errorf("%s: %s was written but not given to %s: %w", name, path, portalUser, err)
	}
	return nil
}
