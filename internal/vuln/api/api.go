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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	jobs    *jobManager
	mux     *http.ServeMux
	log     *slog.Logger
	started time.Time
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
	store, err := intel.OpenStore(opts.CachePath)
	if err != nil {
		return nil, fmt.Errorf("open cache: %w", err)
	}
	s := &Server{
		opts:    opts,
		store:   store,
		jobs:    newJobManager(),
		mux:     http.NewServeMux(),
		log:     opts.Logger,
		started: opts.Now(),
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
		if s.opts.Token == "" {
			return fmt.Errorf("refusing to listen on %s without authentication: set CLANKER_GUARD_TOKEN (the UI sends it as X-Guard-Token)", addr)
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

	s.mux.HandleFunc("GET /api/feeds", s.handleFeeds)
	s.mux.HandleFunc("POST /api/feeds/update", s.handleFeedUpdate)
	s.mux.HandleFunc("GET /api/agents", s.handleAgents)
	s.mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	s.mux.HandleFunc("PUT /api/settings", s.handlePutSettings)
	s.mux.HandleFunc("POST /api/ask", s.handleAsk)

	// Static SPA (built frontend). Missing build renders a helpful page.
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")

		if strings.HasPrefix(r.URL.Path, "/api/") && s.opts.Token != "" {
			if r.Header.Get("X-Guard-Token") != s.opts.Token {
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid X-Guard-Token")
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
			"network_scan": false,
			"sbom_scan":    false,
			"llm":          false,
			"agent_push":   false,
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
		http.ServeFile(w, r, full)
		return
	}
	index := filepath.Join(s.opts.WebDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		s.renderBuildHint(w)
		return
	}
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
