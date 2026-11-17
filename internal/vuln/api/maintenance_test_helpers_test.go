package api

import (
	"os"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
)

func osStat(path string) (os.FileInfo, error) { return os.Stat(path) }

func intelOpen(path string) (*intel.Store, error) {
	st, err := intel.OpenStore(path)
	if err != nil {
		return nil, err
	}
	st.Close()
	return st, nil
}
