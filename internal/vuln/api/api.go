// Package api exposes Clanker Guard's assessment data over HTTP for the web UI.
//
// The API is a thin, read-mostly projection of data the scanner already
// produced: reports in the local SQLite store, feed freshness, and scan jobs.
// It never re-implements correlation or risk scoring — those stay in
// internal/vuln/assess so the UI and the CLI can never disagree.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/auth"
	"github.com/bgdnvk/clanker/internal/vuln/fleet"
	"github.com/bgdnvk/clanker/internal/vuln/improve"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// Options configures the HTTP server.
type Options struct {
	// CachePath is the SQLite intelligence/history database.
	CachePath string
	// WebDir is the built frontend directory (empty disables static serving).
	WebDir string
	// ToolVersion is reported by /api/meta and shown in the UI footer.
	ToolVersion string
	// Token, when set, is required on every /api request (X-Guard-Token).
	Token string
	// AuthPath is the credential file for password sign-in. An empty path
	// disables password auth entirely (token-only or unauthenticated).
	AuthPath string
	// Auth overrides AuthPath (tests). When nil, AuthPath is loaded.
	Auth *auth.Store
	// SessionTTL is how long a sign-in lasts. Defaults to auth.DefaultSessionTTL.
	SessionTTL time.Duration
	// TrustedProxies lists the addresses of reverse proxies (IPs or CIDRs) whose
	// X-Forwarded-For header is trusted. Empty means "no proxy": the header is
	// ignored and rate limits key on the real peer address.
	TrustedProxies []string
	// ReleaseBase is the published artifact base URL. When empty the UI is told
	// that no artifacts are published yet instead of being shown fake commands.
	ReleaseBase string
	// Logger receives request and job logs.
	Logger *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
	// RunScan overrides the assessment runner (tests). Defaults to scan.Run.
	RunScan func(ctx context.Context, opts scan.Options) (scan.Result, error)
}

// Server owns the store, the job manager and the HTTP mux.
type Server struct {
	opts    Options
	store   *intel.Store
	improve *improve.Engine
	jobs    *jobManager
	mux     *http.ServeMux
	log     *slog.Logger
	started time.Time
	auth    *auth.Store
	logins  *loginLimiter
	fleet   *fleet.Store
	// enrollLimiter throttles enrollment-token guessing per source address.
	enrollLimiter *loginLimiter
	// presence tracks agents holding an open claim request (reachability).
	presence *presence
	// trustedProxies are the peers whose X-Forwarded-For header is believed.
	trustedProxies []*net.IPNet
}

// New opens the store and returns a ready server.
func New(opts Options) (*Server, error) {
	if opts.CachePath == "" {
		opts.CachePath = scan.DefaultCachePath()
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.RunScan == nil {
		opts.RunScan = scan.Run
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = auth.DefaultSessionTTL
	}
	trustedProxies, err := parseTrustedProxies(opts.TrustedProxies)
	if err != nil {
		return nil, err
	}
	// A missing credential file is the normal token-only/loopback case, not an
	// error: password sign-in is simply switched off.
	if opts.Auth == nil && opts.AuthPath != "" {
		st, err := auth.Load(opts.AuthPath)
		switch {
		case errors.Is(err, auth.ErrNotConfigured):
		case err != nil:
			return nil, fmt.Errorf("load password credentials: %w", err)
		default:
			opts.Auth = st
		}
	}
	store, err := intel.OpenStore(opts.CachePath)
	if err != nil {
		return nil, fmt.Errorf("open cache: %w", err)
	}
	improveEngine, err := improve.New(store)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("initialise improvement engine: %w", err)
	}
	s := &Server{
		opts:           opts,
		store:          store,
		improve:        improveEngine,
		jobs:           newJobManager(),
		mux:            http.NewServeMux(),
		log:            opts.Logger,
		started:        opts.Now(),
		auth:           opts.Auth,
		logins:         newLoginLimiter(loginMaxFailures, loginLimitWindow),
		enrollLimiter:  newLoginLimiter(agentEnrollFailures, loginLimitWindow),
		presence:       newPresence(),
		trustedProxies: trustedProxies,
	}
	// The fleet registry lives in the same SQLite file as scan history, so an
	// ingested report and the endpoint that sent it commit against one writer.
	fleetStore, err := fleet.New(store.DB())
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("initialise fleet registry: %w", err)
	}
	s.fleet = fleetStore
	if s.auth != nil {
		if mode, insecure := s.auth.InsecurePerms(); insecure {
			s.log.Warn("credential file is readable by other accounts; run: chmod 600",
				"path", s.auth.Path(), "mode", mode.String())
		}
	}
	s.routes()
	return s, nil
}

// Close releases resources held by the server.
func (s *Server) Close() error { return s.store.Close() }

// Handler returns the fully wired HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.middleware(s.mux)
}

// Listen starts the server on addr. A non-loopback listener requires a token so
// that scan-triggering endpoints are never exposed unauthenticated.
func (s *Server) Listen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		if !s.authRequired() {
			return fmt.Errorf("refusing to listen on %s without authentication: set CLANKER_GUARD_TOKEN or create a password with `clanker vuln auth set-password`", addr)
		}
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.log.Info("clanker guard api listening", "addr", addr, "web_dir", s.opts.WebDir)
	return srv.ListenAndServe()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/auth/session", s.handleAuthSession)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("GET /api/meta", s.handleMeta)

	s.mux.HandleFunc("GET /api/overview", s.handleOverview)
	s.mux.HandleFunc("GET /api/assets", s.handleAssets)
	s.mux.HandleFunc("GET /api/assets/{host}", s.handleAssetDetail)
	s.mux.HandleFunc("GET /api/vulnerabilities", s.handleVulnerabilities)
	s.mux.HandleFunc("GET /api/vulnerabilities/{id}", s.handleVulnerabilityDetail)

	s.mux.HandleFunc("GET /api/scans", s.handleScans)
	s.mux.HandleFunc("POST /api/scans", s.handleStartScan)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleScanDetail)
	s.mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancelScan)

	s.mux.HandleFunc("GET /api/reports", s.handleReports)
	s.mux.HandleFunc("GET /api/reports/{id}", s.handleReport)
	s.mux.HandleFunc("GET /api/reports/{id}/export", s.handleReportExport)
	s.mux.HandleFunc("GET /api/software/export", s.handleSoftwareExport)

	s.mux.HandleFunc("GET /api/feeds", s.handleFeeds)
	s.mux.HandleFunc("POST /api/feeds/update", s.handleFeedUpdate)

	// Endpoint fleet: agents authenticate with their own bearer token (checked in
	// the handler), the operator manages them through the dashboard session.
	s.mux.HandleFunc("POST /api/agents/enroll", s.handleAgentEnroll)
	s.mux.HandleFunc("POST /api/agents/checkin", s.handleAgentCheckin)
	s.mux.HandleFunc("POST /api/agents/report", s.handleAgentReport)
	s.mux.HandleFunc("GET /api/agents", s.handleAgents)
	s.mux.HandleFunc("POST /api/agents/{id}/revoke", s.handleAgentRevoke)
	s.mux.HandleFunc("POST /api/agents/{id}/scan", s.handleAgentQueueScan)
	s.mux.HandleFunc("POST /api/agents/{id}/scan/cancel", s.handleAgentCancelScan)
	s.mux.HandleFunc("POST /api/agents/tasks/claim", s.handleAgentClaimTask)
	s.mux.HandleFunc("POST /api/agents/tasks/complete", s.handleAgentCompleteTask)
	s.mux.HandleFunc("GET /api/agents/{id}/events", s.handleAgentEvents)
	s.mux.HandleFunc("POST /api/agents/enroll-token", s.handleEnrollTokenRotate)
	// Kept as an alias so existing tooling keeps working; both mint a new token.
	s.mux.HandleFunc("POST /api/agents/enroll-token/rotate", s.handleEnrollTokenRotate)
	s.mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	s.mux.HandleFunc("PUT /api/settings", s.handlePutSettings)
	s.mux.HandleFunc("POST /api/ask", s.handleAsk)

	// Continuous improvement: analyst feedback, proposals, quality metrics.
	s.mux.HandleFunc("POST /api/vulnerabilities/{id}/feedback", s.handleFindingFeedback)
	s.mux.HandleFunc("GET /api/vulnerabilities/{id}/history", s.handleFindingHistory)
	s.mux.HandleFunc("DELETE /api/vulnerabilities/{id}/feedback", s.handleDeleteFeedback)
	s.mux.HandleFunc("GET /api/improvements", s.handleImprovements)
	s.mux.HandleFunc("GET /api/improvements/{id}", s.handleImprovement)
	s.mux.HandleFunc("POST /api/improvements/{id}/transition", s.handleImprovementTransition)
	s.mux.HandleFunc("POST /api/improvements/{id}/evaluate", s.handleImprovementEvaluate)
	s.mux.HandleFunc("GET /api/quality", s.handleQuality)
	s.mux.HandleFunc("GET /api/feedback/export", s.handleFeedbackExport)

	// Static SPA (built frontend). Missing build renders a helpful page.
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")

		// Liveness and the sign-in endpoints are unauthenticated on purpose: the
		// login page has to reach them before a session exists. None of them
		// exposes assessment data.
		needsAuth := strings.HasPrefix(r.URL.Path, "/api/") && !publicAPIPaths[r.URL.Path]
		if needsAuth && s.authRequired() {
			method, _ := s.authenticate(r)
			switch {
			case method == authNone:
				s.log.Warn("unauthenticated api request", "method", r.Method, "path", r.URL.Path, "remote", s.clientIP(r))
				writeError(w, http.StatusUnauthorized, "unauthorized", "sign in or send a valid X-Guard-Token")
				return
			case method == authViaCookie && !cookieMutationAllowed(r):
				s.log.Warn("cross-site state change refused", "method", r.Method, "path", r.URL.Path, "origin", r.Header.Get("Origin"))
				writeError(w, http.StatusForbidden, "cross_site_request", "state-changing requests must come from the dashboard itself")
				return
			}
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic serving request", "path", r.URL.Path, "panic", p)
				writeError(rec, http.StatusInternalServerError, "internal_error", "unexpected server error")
			}
			s.log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(rec, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ---------------------------------------------------------------- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: msg, Code: code})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"uptime":  s.opts.Now().Sub(s.started).String(),
		"version": s.opts.ToolVersion,
	})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	// Capabilities are advertised honestly so the UI can disable what this build
	// does not implement instead of pretending it works.
	writeJSON(w, http.StatusOK, map[string]any{
		"tool":    "clanker-guard",
		"version": s.opts.ToolVersion,
		"cache":   s.opts.CachePath,
		"web_dir": s.opts.WebDir,
		"capabilities": map[string]bool{
			"local_scan":   true,
			"network_scan": true,
			"sbom_scan":    true,
			"llm":          false,
			"agent_push":   true,
		},
		"release": map[string]any{
			"published": s.opts.ReleaseBase != "",
			"base_url":  s.opts.ReleaseBase,
		},
	})
}

// serveStatic serves the built SPA with a history-API fallback.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.opts.WebDir == "" {
		s.renderBuildHint(w)
		return
	}
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if clean == "." || clean == "" {
		clean = "index.html"
	}
	// Prevent path traversal: only serve inside WebDir.
	full := filepath.Join(s.opts.WebDir, clean)
	if !strings.HasPrefix(full, filepath.Clean(s.opts.WebDir)+string(os.PathSeparator)) && full != filepath.Join(s.opts.WebDir, "index.html") {
		http.NotFound(w, r)
		return
	}
	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		// Hashed assets are immutable; the shell must be revalidated so a rebuilt
		// interface is picked up without a hard refresh.
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeFile(w, r, full)
		return
	}
	index := filepath.Join(s.opts.WebDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		s.renderBuildHint(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, index)
}

func (s *Server) renderBuildHint(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Clanker Guard API</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:4rem auto;padding:0 1.5rem;color:#1f2933;line-height:1.6}
code{background:#f4f6f8;padding:.15rem .35rem;border-radius:4px}pre{background:#0f172a;color:#e2e8f0;padding:1rem;border-radius:8px;overflow:auto}</style>
</head><body>
<h1>Clanker Guard API is running</h1>
<p>The web interface has not been built yet. Build it once:</p>
<pre>cd web
npm install
npm run build</pre>
<p>Then restart with <code>clanker vuln serve --web-dir web/dist</code>.</p>
<p>API: <code>GET /api/overview</code> · <code>GET /api/vulnerabilities</code> · <code>POST /api/scans</code></p>
</body></html>`)
}
