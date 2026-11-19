//go:build unix

package panelboot

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

func secureData(dir string) error {
	if dir == "" || dir == "." || dir == "/" {
		return nil
	}
	_ = os.Chmod(dir, 0o700) // #nosec G302 -- directory must be executable for owner
	_ = os.Chmod(filepath.Join(dir, "vpshub.db"), 0o600)
	if os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup("vpshub")
	if err != nil {
		return nil
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil
	}
	return filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}
