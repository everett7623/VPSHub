//go:build !unix

package panelboot

import (
	"os"
	"path/filepath"
)

func secureData(dir string) error {
	if dir == "" || dir == "." || dir == "/" {
		return nil
	}
	_ = os.Chmod(dir, 0o700) // #nosec G302 -- directory must be executable for owner
	_ = os.Chmod(filepath.Join(dir, "vpshub.db"), 0o600)
	return nil
}
