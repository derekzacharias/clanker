package api

import (
	"net/http"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/auth"
)

// requiredPermission maps a request onto the role level it needs.
//
// One table instead of a check in every handler: a new route inherits the right level by
// being a read or a write, and the exceptions (accounts, configuration, maintenance) are
// listed here where they can be reviewed together. The default for an unrecognised
// mutation is PermWrite — failing closed on reads would make new endpoints unusable, while
// failing open on writes would be a hole.
func requiredPermission(r *http.Request) auth.Permission {
	path := r.URL.Path
	method := r.Method
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return auth.PermRead
	}
	switch {
	case strings.HasPrefix(path, "/api/users"), strings.HasPrefix(path, "/api/access"):
		return auth.PermAdmin
	case path == "/api/settings" || strings.HasPrefix(path, "/api/integrations/"):
		return auth.PermAdmin
	case strings.HasPrefix(path, "/api/maintenance/"):
		return auth.PermAdmin
	case strings.HasPrefix(path, "/api/intel/sync"):
		// Starting or cancelling intelligence synchronization changes the
		// assessment substrate; read-only users see the status only.
		return auth.PermAdmin
	case path == "/api/agents/enroll-token" || strings.HasPrefix(path, "/api/agents/enroll-token/"):
		// Minting an enrollment token creates a credential for a new machine.
		return auth.PermAdmin
	}
	return auth.PermWrite
}
