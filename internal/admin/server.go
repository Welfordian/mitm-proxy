package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mitm-proxy/internal/admin/auth"
	"mitm-proxy/internal/admin/ui"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/copilot"
	"mitm-proxy/internal/deployments"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/policy"
	"mitm-proxy/internal/store"
	"mitm-proxy/internal/threats"
)

type Options struct {
	Addr          string
	Token         string
	ReadToken     string
	UIEnabled     bool
	Store         *store.Store
	Config        func() *cfgpkg.Config
	ConfigPath    string
	ProxyVersion  string
	ProxyStarted  time.Time
	GeneratedAuth bool
	ThreatScanner *threats.Manager
	CopilotClient copilot.Client
	EventBus      *events.Bus
	SaveConfig    func(context.Context, *cfgpkg.Config) error
	ReloadConfig  func(context.Context) error
	Restart       func(context.Context) error
	RotateCA      func(context.Context) error
	ImportCA      func(context.Context, string, string) error
	PublishEvent  func(events.Event)
}

type Server struct {
	options Options
	server  *http.Server
}

const (
	repeaterBodyLimit    = 65536
	repeaterTimeoutMS    = 30000
	repeaterMinTimeoutMS = 1000
	repeaterMaxTimeoutMS = 120000
)

type repeaterCaseInput struct {
	SourceFlowID string              `json:"source_flow_id"`
	Name         string              `json:"name"`
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	TimeoutMS    int                 `json:"timeout_ms"`
	ScopeID      string              `json:"scope_id"`
}

func New(options Options) *Server {
	mux := http.NewServeMux()
	s := &Server{options: options}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/health", s.handleHealth)
	apiMux.HandleFunc("/api/version", s.handleVersion)
	apiMux.HandleFunc("/api/audit", s.handleAudit)
	apiMux.HandleFunc("/api/traffic", s.handleTraffic)
	apiMux.HandleFunc("/api/traffic/export", s.handleTrafficExport)
	apiMux.HandleFunc("/api/traffic/", s.handleTrafficDetail)
	apiMux.HandleFunc("/api/traffic/stream", s.handleTrafficStream)
	apiMux.HandleFunc("/api/repeater/cases", s.handleRepeaterCases)
	apiMux.HandleFunc("/api/repeater/cases/", s.handleRepeaterCaseDetail)
	apiMux.HandleFunc("/api/ai/traffic/", s.handleAITraffic)
	apiMux.HandleFunc("/api/ai/repeater/cases/", s.handleAIRepeater)
	apiMux.HandleFunc("/api/ai/notes", s.handleAINotes)
	apiMux.HandleFunc("/api/ai/notes/", s.handleAINoteDetail)
	apiMux.HandleFunc("/api/scopes", s.handleScopes)
	apiMux.HandleFunc("/api/scopes/", s.handleScopeDetail)
	apiMux.HandleFunc("/metrics", s.handleMetrics)
	apiMux.HandleFunc("/api/certificates/ca", s.handleCACertificate)
	apiMux.HandleFunc("/api/certificates/ca/download", s.handleCACertificateDownload)
	apiMux.HandleFunc("/api/certificates/ca/rotate", s.handleCARotate)
	apiMux.HandleFunc("/api/certificates/ca/import", s.handleCAImport)
	apiMux.HandleFunc("/api/certificates/leaf", s.handleLeafCertificates)
	apiMux.HandleFunc("/api/deployments", s.handleDeployments)
	apiMux.HandleFunc("/api/deployments/current", s.handleCurrentDeployment)
	apiMux.HandleFunc("/api/deployments/current/reload", s.handleDeploymentReload)
	apiMux.HandleFunc("/api/deployments/current/restart", s.handleDeploymentRestart)
	apiMux.HandleFunc("/api/logs", s.handleLogs)
	apiMux.HandleFunc("/api/blocks/test", s.handleBlockTest)
	apiMux.HandleFunc("/api/blocks/ports", s.handleBlockedPorts)
	apiMux.HandleFunc("/api/blocks/ports/", s.handleBlockedPortDetail)
	apiMux.HandleFunc("/api/blocks/domains", s.handleBlockedDomains)
	apiMux.HandleFunc("/api/blocks/domains/", s.handleBlockedDomainDetail)
	apiMux.HandleFunc("/api/blocks/ips", s.handleBlockedIPs)
	apiMux.HandleFunc("/api/blocks/ips/", s.handleBlockedIPDetail)
	apiMux.HandleFunc("/api/cache/resource", s.handleCacheResource)
	apiMux.HandleFunc("/api/cache", s.handleCache)
	apiMux.HandleFunc("/api/cache/purge", s.handleCachePurge)
	apiMux.HandleFunc("/api/settings/danger", s.handleSettingsDanger)
	apiMux.HandleFunc("/api/settings", s.handleSettings)
	apiMux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	apiMux.HandleFunc("/api/admin/users/", s.handleAdminUserDetail)
	apiMux.HandleFunc("/api/threats/events", s.handleThreatEvents)
	apiMux.HandleFunc("/api/threats/events/", s.handleThreatEventDetail)
	apiMux.HandleFunc("/api/threats/config", s.handleThreatConfig)
	apiMux.HandleFunc("/api/threats/test", s.handleThreatTest)
	apiMux.HandleFunc("/api/threats/stream", s.handleThreatStream)
	apiMux.HandleFunc("/api/threats/rules", s.handleThreatRules)
	apiMux.HandleFunc("/api/threats/quarantine", s.handleThreatQuarantine)
	apiMux.HandleFunc("/api/threats/cache/invalidate", s.handleThreatCacheInvalidate)

	protected := auth.Middleware{Token: options.Token, ReadToken: options.ReadToken}.Wrap(apiMux)
	mux.Handle("/api/", protected)
	mux.Handle("/metrics", protected)

	if options.UIEnabled {
		dist, err := fs.Sub(ui.Dist, "dist")
		if err != nil {
			log.Printf("admin UI unavailable: %v", err)
		} else {
			fileServer := http.StripPrefix("/admin/", http.FileServer(http.FS(dist)))
			mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
				assetPath := strings.TrimPrefix(r.URL.Path, "/admin/")
				if assetPath == "" || !strings.Contains(filepath.Base(assetPath), ".") {
					r.URL.Path = "/admin/"
				}
				fileServer.ServeHTTP(w, r)
			})
			mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
				target := "/admin/"
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusFound)
			})
		}
	}

	s.server = &http.Server{
		Addr:              options.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

func (s *Server) ListenAndServe() error {
	if s.options.Store != nil {
		_ = s.options.Store.AddAudit(context.Background(), "system", "admin.start", map[string]any{
			"addr": s.options.Addr,
			"ui":   s.options.UIEnabled,
		}, "")
	}
	s.startEventRecorder()
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) startEventRecorder() {
	if s.options.Store == nil || s.options.EventBus == nil {
		return
	}
	ch := s.options.EventBus.Subscribe("*")
	go func() {
		for event := range ch {
			if err := s.options.Store.RecordEvent(context.Background(), event); err != nil {
				log.Printf("admin store event record error: %v", err)
			}
		}
	}()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
		"admin": map[string]any{
			"addr":           s.options.Addr,
			"ui_enabled":     s.options.UIEnabled,
			"token_required": s.options.Token != "",
		},
		"proxy": map[string]any{
			"listen_addr":    cfg.ListenAddr,
			"mitm_enabled":   cfg.EnableMITM,
			"config_path":    s.options.ConfigPath,
			"cache_enabled":  cfg.Cache.Enabled,
			"excluded_count": len(cfg.ExcludedDomains),
		},
		"uptime_seconds": int64(time.Since(s.options.ProxyStarted).Seconds()),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.options.ProxyVersion,
		"started": s.options.ProxyStarted.UTC(),
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		writeJSON(w, http.StatusOK, []store.AuditEntry{})
		return
	}

	entries, err := s.options.Store.ListAudit(r.Context(), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		if s.options.Store == nil {
			s.handleNotImplemented(w, r)
			return
		}
		if err := s.options.Store.ClearTraffic(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "traffic.clear", nil)
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
		return
	}
	if s.options.Store != nil {
		scopeID, includeOutOfScope := scopeFilter(r)
		limit, offset := paginationParams(r, 200)
		flows, err := s.options.Store.ListTrafficScopedPage(r.Context(), limit, offset, scopeID, includeOutOfScope, r.URL.Query().Get("q"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, flows)
		return
	}
	if s.options.EventBus == nil {
		writeJSON(w, http.StatusOK, []events.Event{})
		return
	}
	writeJSON(w, http.StatusOK, s.options.EventBus.Recent("*", 200))
}

func scopeFilter(r *http.Request) (string, bool) {
	include := strings.EqualFold(r.URL.Query().Get("include_out_of_scope"), "true")
	return strings.TrimSpace(r.URL.Query().Get("scope_id")), include
}

func paginationParams(r *http.Request, defaultLimit int) (int, int) {
	limit := defaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			offset = parsed
		}
	}
	return limit, offset
}

func (s *Server) handleScopes(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		scopes, err := s.options.Store.ListResearchScopes(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, scopes)
	case http.MethodPost:
		var scope store.ResearchScope
		if err := json.NewDecoder(r.Body).Decode(&scope); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(scope.Name) == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		created, err := s.options.Store.CreateResearchScope(r.Context(), scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "scope.create", map[string]any{"id": created.ID, "name": created.Name})
		writeJSON(w, http.StatusCreated, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScopeDetail(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/scopes/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope not found"})
		return
	}
	id := parts[0]
	if len(parts) > 1 {
		s.handleScopeAssignment(w, r, id, parts[1:])
		return
	}
	switch r.Method {
	case http.MethodGet:
		scope, ok, err := s.options.Store.GetResearchScope(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope not found"})
			return
		}
		writeJSON(w, http.StatusOK, scope)
	case http.MethodPut:
		var scope store.ResearchScope
		if err := json.NewDecoder(r.Body).Decode(&scope); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		scope.ID = id
		if strings.TrimSpace(scope.Name) == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		updated, err := s.options.Store.UpdateResearchScope(r.Context(), scope)
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope not found"})
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "scope.update", map[string]any{"id": id})
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := s.options.Store.DeleteResearchScope(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "scope.delete", map[string]any{"id": id})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScopeAssignment(w http.ResponseWriter, r *http.Request, scopeID string, parts []string) {
	if r.Method != http.MethodPost || len(parts) != 3 || parts[0] != "assign" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown scope action"})
		return
	}
	if _, ok, err := s.options.Store.GetResearchScope(r.Context(), scopeID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope not found"})
		return
	}
	targetID := strings.TrimSpace(parts[2])
	switch parts[1] {
	case "traffic":
		if err := s.options.Store.AssignTrafficScope(r.Context(), targetID, scopeID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "repeater":
		if err := s.options.Store.AssignRepeaterScope(r.Context(), targetID, scopeID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown scope assignment target"})
		return
	}
	s.audit(r, "scope.assign", map[string]any{"scope_id": scopeID, "target": parts[1], "target_id": targetID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (s *Server) handleTrafficDetail(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/export") {
		s.handleTrafficDetailExport(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/replay") {
		s.handleTrafficReplay(w, r)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/traffic/"), "/")
	if s.options.Store != nil {
		flow, ok, err := s.options.Store.GetTrafficDetail(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ok {
			writeJSON(w, http.StatusOK, flow)
			return
		}
	}
	if s.options.EventBus != nil {
		if event, ok := s.options.EventBus.Get(id); ok {
			writeJSON(w, http.StatusOK, event)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "traffic flow not found"})
}

func (s *Server) handleTrafficDetailExport(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "traffic flow not found"})
		return
	}
	id := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/traffic/"), "/export"), "/")
	flow, ok, err := s.options.Store.GetTrafficDetail(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "traffic flow not found"})
		return
	}
	if r.URL.Query().Get("format") == "har" {
		writeDownloadJSON(w, http.StatusOK, "traffic-"+safeFilenamePart(id)+".har", trafficDetailHAR(flow))
		return
	}
	writeDownloadJSON(w, http.StatusOK, "traffic-"+safeFilenamePart(id)+".json", flow)
}

func (s *Server) handleTrafficReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}

	path := strings.TrimSuffix(r.URL.Path, "/replay")
	id := strings.Trim(strings.TrimPrefix(path, "/api/traffic/"), "/")
	flow, ok, err := s.options.Store.GetTrafficDetail(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "traffic flow not found"})
		return
	}
	if flow.Method == "" || strings.EqualFold(flow.Method, http.MethodConnect) || strings.TrimSpace(flow.URL) == "" {
		http.Error(w, "traffic flow cannot be replayed", http.StatusBadRequest)
		return
	}

	c, err := repeaterCaseFromTraffic(flow)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	run := sendRepeaterCase(r.Context(), c)
	if run.Error != "" {
		http.Error(w, run.Error, http.StatusBadGateway)
		return
	}
	s.audit(r, "traffic.replay", map[string]any{"id": id, "status": run.Status})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             run.Status,
		"headers":            run.ResponseHeaders,
		"body":               strings.TrimSpace(run.ResponseBody),
		"truncated_at_bytes": repeaterBodyLimit,
	})
}

func (s *Server) handleRepeaterCases(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		scopeID, includeOutOfScope := scopeFilter(r)
		cases, err := s.options.Store.ListRepeaterCasesScoped(r.Context(), 200, scopeID, includeOutOfScope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, cases)
	case http.MethodPost:
		var input repeaterCaseInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		c, err := s.repeaterCaseFromInput(r.Context(), input, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		created, err := s.options.Store.CreateRepeaterCase(r.Context(), c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "repeater.case.create", map[string]any{"id": created.ID, "source_flow_id": created.SourceFlowID})
		writeJSON(w, http.StatusCreated, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRepeaterCaseDetail(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/repeater/cases/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "repeater case not found"})
		return
	}
	id := parts[0]
	if len(parts) > 1 {
		if parts[1] == "send" {
			s.handleRepeaterSend(w, r, id)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown repeater action"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		c, ok, err := s.options.Store.GetRepeaterCase(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "repeater case not found"})
			return
		}
		runs, err := s.options.Store.ListRepeaterRuns(r.Context(), id, 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, store.RepeaterCaseDetail{Case: c, Runs: runs})
	case http.MethodPut:
		var input repeaterCaseInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		c, err := s.repeaterCaseFromInput(r.Context(), input, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		updated, err := s.options.Store.UpdateRepeaterCase(r.Context(), c)
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "repeater case not found"})
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "repeater.case.update", map[string]any{"id": id})
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := s.options.Store.DeleteRepeaterCase(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "repeater.case.delete", map[string]any{"id": id})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, ok, err := s.options.Store.GetRepeaterCase(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "repeater case not found"})
		return
	}
	if err := validateRepeaterCase(c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	run := sendRepeaterCase(r.Context(), c)
	stored, err := s.options.Store.AddRepeaterRun(r.Context(), run)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "repeater.case.send", map[string]any{"id": id, "run_id": stored.ID, "status": stored.Status, "error": stored.Error})
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) handleAITraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/ai/traffic/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "traffic flow not found"})
		return
	}
	id, action := parts[0], parts[1]
	flow, ok, err := s.options.Store.GetTrafficDetail(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "traffic flow not found"})
		return
	}
	var kind string
	switch action {
	case "explain":
		kind = copilot.KindExplanation
	case "suggest-tests":
		kind = copilot.KindTestSuggestions
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown ai action"})
		return
	}
	context := s.trafficAIContext(flow)
	note, err := s.generateAINote(r.Context(), kind, "traffic", flow.ID, flow.ScopeID, context)
	if err != nil {
		http.Error(w, err.Error(), statusForAIError(err))
		return
	}
	s.audit(r, "ai."+kind, map[string]any{"target_type": "traffic", "target_id": flow.ID, "note_id": note.ID})
	writeJSON(w, http.StatusOK, note)
}

func (s *Server) handleAIRepeater(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/ai/repeater/cases/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "repeater case not found"})
		return
	}
	id, action := parts[0], parts[1]
	c, ok, err := s.options.Store.GetRepeaterCase(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "repeater case not found"})
		return
	}
	runs, err := s.options.Store.ListRepeaterRuns(r.Context(), id, 2)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var kind string
	var context any
	switch action {
	case "suggest-tests":
		kind = copilot.KindTestSuggestions
		context = s.repeaterAIContext(c)
	case "compare-runs":
		if len(runs) < 2 {
			http.Error(w, "at least two repeater runs are required", http.StatusBadRequest)
			return
		}
		kind = copilot.KindRunComparison
		context = s.repeaterRunComparisonContext(c, runs[0], runs[1])
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown ai action"})
		return
	}
	note, err := s.generateAINote(r.Context(), kind, "repeater_case", c.ID, c.ScopeID, context)
	if err != nil {
		http.Error(w, err.Error(), statusForAIError(err))
		return
	}
	s.audit(r, "ai."+kind, map[string]any{"target_type": "repeater_case", "target_id": c.ID, "note_id": note.ID})
	writeJSON(w, http.StatusOK, note)
}

func (s *Server) handleAINotes(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, _ := paginationParams(r, 100)
		notes, err := s.options.Store.ListAINotes(r.Context(), store.AINoteFilter{
			TargetType: r.URL.Query().Get("target_type"),
			TargetID:   r.URL.Query().Get("target_id"),
			ScopeID:    r.URL.Query().Get("scope_id"),
			Limit:      limit,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, notes)
	case http.MethodPost:
		var note store.AINote
		if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(note.TargetType) == "" || strings.TrimSpace(note.TargetID) == "" {
			http.Error(w, "target_type and target_id are required", http.StatusBadRequest)
			return
		}
		created, err := s.options.Store.CreateAINote(r.Context(), note)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "ai.note.create", map[string]any{"id": created.ID, "target_type": created.TargetType, "target_id": created.TargetID})
		writeJSON(w, http.StatusCreated, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAINoteDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/ai/notes/"), "/")
	if id == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "ai note not found"})
		return
	}
	if err := s.options.Store.DeleteAINote(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "ai.note.delete", map[string]any{"id": id})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) generateAINote(ctx context.Context, kind, targetType, targetID, scopeID string, evidence any) (store.AINote, error) {
	if kind == copilot.KindTestSuggestions && strings.TrimSpace(scopeID) == "" {
		content := json.RawMessage(`{"summary":"This item is out of scope. Passive review only.","safe_manual_tests":[],"parameters_to_review":[],"headers_to_review":[],"scope_warning":"Out-of-scope traffic can be explained, but active testing suggestions are intentionally withheld."}`)
		return s.options.Store.CreateAINote(ctx, store.AINote{
			Kind:       kind,
			TargetType: targetType,
			TargetID:   targetID,
			ScopeID:    scopeID,
			Title:      "AI test suggestions",
			Summary:    "This item is out of scope. Passive review only.",
			Content:    content,
		})
	}
	cfg := s.options.Config().AICopilot
	if !cfg.Enabled {
		return store.AINote{}, fmt.Errorf("AI copilot is disabled; enable ai_copilot.enabled in Settings or config.json and reload the running proxy")
	}
	client := s.options.CopilotClient
	if client == nil {
		client = copilot.NewOpenAIClient()
	}
	result, err := client.Generate(ctx, cfg, kind, evidence)
	if err != nil {
		return store.AINote{}, err
	}
	return s.options.Store.CreateAINote(ctx, store.AINote{
		Kind:       kind,
		TargetType: targetType,
		TargetID:   targetID,
		ScopeID:    scopeID,
		Model:      result.Model,
		PromptHash: result.PromptHash,
		Title:      result.Title,
		Summary:    result.Summary,
		Content:    result.Content,
	})
}

func statusForAIError(err error) int {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timed out") {
		return http.StatusGatewayTimeout
	}
	if strings.Contains(msg, "disabled") || strings.Contains(msg, "api key") || strings.Contains(msg, "unsupported") {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

func (s *Server) trafficAIContext(flow store.TrafficDetail) map[string]any {
	cfg := s.options.Config().AICopilot
	requestHeaders, responseHeaders := splitTrafficHeaders(flow.Headers)
	query := map[string][]string{}
	for k, vals := range flow.QueryParams {
		query[k] = redactedStringValues(vals, cfg.RedactBeforeAI)
	}
	cookieNames := []string{}
	for name := range flow.Cookies {
		cookieNames = append(cookieNames, name)
	}
	return map[string]any{
		"out_of_scope": !isConcreteScopeID(flow.ScopeID),
		"scope_id":     flow.ScopeID,
		"request": map[string]any{
			"id":                  flow.ID,
			"method":              flow.Method,
			"url":                 redactedString(flow.URL, cfg.RedactBeforeAI),
			"host":                flow.Host,
			"protocol":            flow.Protocol,
			"remote_ip":           flow.RemoteIP,
			"query_params":        query,
			"cookie_names":        cookieNames,
			"headers":             redactedHeaders(requestHeaders, cfg.RedactBeforeAI),
			"body_sample":         cappedBodySample(flow.RequestBody, cfg.MaxBodyBytes, cfg.RedactBeforeAI),
			"body_sample_present": flow.RequestBody != "",
		},
		"response": map[string]any{
			"status":              flow.Status,
			"mime_type":           flow.MIMEType,
			"duration_ms":         flow.DurationMS,
			"bytes":               flow.Bytes,
			"cache_hit":           flow.CacheHit,
			"blocked":             flow.Blocked,
			"rule_id":             flow.RuleID,
			"headers":             redactedHeaders(responseHeaders, cfg.RedactBeforeAI),
			"body_sample":         cappedBodySample(flow.ResponseBody, cfg.MaxBodyBytes, cfg.RedactBeforeAI),
			"body_sample_present": flow.ResponseBody != "",
		},
	}
}

func (s *Server) repeaterAIContext(c store.RepeaterCase) map[string]any {
	cfg := s.options.Config().AICopilot
	return map[string]any{
		"out_of_scope": !isConcreteScopeID(c.ScopeID),
		"scope_id":     c.ScopeID,
		"case": map[string]any{
			"id":                  c.ID,
			"name":                c.Name,
			"source_flow_id":      c.SourceFlowID,
			"method":              c.Method,
			"url":                 redactedString(c.URL, cfg.RedactBeforeAI),
			"timeout_ms":          c.TimeoutMS,
			"headers":             redactedHeaders(http.Header(c.Headers), cfg.RedactBeforeAI),
			"body_sample":         cappedBodySample(c.Body, cfg.MaxBodyBytes, cfg.RedactBeforeAI),
			"body_sample_present": c.Body != "",
		},
	}
}

func (s *Server) repeaterRunComparisonContext(c store.RepeaterCase, current, previous store.RepeaterRun) map[string]any {
	cfg := s.options.Config().AICopilot
	return map[string]any{
		"out_of_scope": !isConcreteScopeID(c.ScopeID),
		"scope_id":     c.ScopeID,
		"case": map[string]any{
			"id":             c.ID,
			"name":           c.Name,
			"source_flow_id": c.SourceFlowID,
			"method":         c.Method,
			"url":            redactedString(c.URL, cfg.RedactBeforeAI),
		},
		"current_run":  repeaterRunAIContext(current, cfg),
		"previous_run": repeaterRunAIContext(previous, cfg),
	}
}

func repeaterRunAIContext(run store.RepeaterRun, cfg cfgpkg.AICopilotConfig) map[string]any {
	return map[string]any{
		"id":                  run.ID,
		"created_at":          run.CreatedAt,
		"status":              run.Status,
		"duration_ms":         run.DurationMS,
		"bytes":               run.Bytes,
		"error":               run.Error,
		"headers":             redactedHeaders(http.Header(run.ResponseHeaders), cfg.RedactBeforeAI),
		"body_length":         len(run.ResponseBody),
		"body_sample":         cappedBodySample(run.ResponseBody, cfg.MaxBodyBytes, cfg.RedactBeforeAI),
		"body_sample_present": run.ResponseBody != "",
	}
}

func splitTrafficHeaders(records []store.HeaderRecord) (http.Header, http.Header) {
	requestHeaders := http.Header{}
	responseHeaders := http.Header{}
	for _, record := range records {
		if record.Direction == "response" {
			responseHeaders.Add(record.Name, record.Value)
			continue
		}
		requestHeaders.Add(record.Name, record.Value)
	}
	return requestHeaders, responseHeaders
}

func redactedHeaders(headers http.Header, enabled bool) http.Header {
	if !enabled {
		out := http.Header{}
		for key, values := range headers {
			out[key] = append([]string(nil), values...)
		}
		return out
	}
	return threats.RedactHeaders(headers)
}

func cappedBodySample(body string, limit int64, redact bool) string {
	if limit <= 0 {
		limit = 32768
	}
	data := []byte(body)
	if int64(len(data)) > limit {
		data = data[:limit]
	}
	if redact {
		data = threats.RedactBody(data)
	}
	return string(data)
}

func redactedString(value string, redact bool) string {
	if !redact {
		return value
	}
	return string(threats.RedactBody([]byte(value)))
}

func redactedStringValues(values []string, redact bool) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, redactedString(value, redact))
	}
	return out
}

func isConcreteScopeID(scopeID string) bool {
	return strings.TrimSpace(scopeID) != "" && strings.TrimSpace(scopeID) != "__out_of_scope__"
}

func (s *Server) repeaterCaseFromInput(ctx context.Context, input repeaterCaseInput, id string) (store.RepeaterCase, error) {
	var c store.RepeaterCase
	if id != "" {
		existing, ok, err := s.options.Store.GetRepeaterCase(ctx, id)
		if err != nil {
			return store.RepeaterCase{}, err
		}
		if !ok {
			return store.RepeaterCase{}, fmt.Errorf("repeater case not found")
		}
		c = existing
	} else if strings.TrimSpace(input.SourceFlowID) != "" {
		flow, ok, err := s.options.Store.GetTrafficDetail(ctx, strings.TrimSpace(input.SourceFlowID))
		if err != nil {
			return store.RepeaterCase{}, err
		}
		if !ok {
			return store.RepeaterCase{}, fmt.Errorf("source traffic flow not found")
		}
		cloned, err := repeaterCaseFromTraffic(flow)
		if err != nil {
			return store.RepeaterCase{}, err
		}
		c = cloned
	} else {
		c = store.RepeaterCase{
			Headers:   map[string][]string{},
			TimeoutMS: repeaterTimeoutMS,
		}
	}

	if input.SourceFlowID != "" && c.SourceFlowID == "" {
		c.SourceFlowID = strings.TrimSpace(input.SourceFlowID)
	}
	if input.Name != "" || id != "" {
		c.Name = strings.TrimSpace(input.Name)
	}
	if input.Method != "" || id != "" {
		c.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	}
	if input.URL != "" || id != "" {
		c.URL = strings.TrimSpace(input.URL)
	}
	if input.Headers != nil {
		c.Headers = input.Headers
	}
	if input.Body != "" || id != "" || c.SourceFlowID == "" {
		c.Body = input.Body
	}
	if input.TimeoutMS != 0 {
		c.TimeoutMS = input.TimeoutMS
	}
	if input.ScopeID != "" {
		c.ScopeID = strings.TrimSpace(input.ScopeID)
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = repeaterTimeoutMS
	}
	if c.Name == "" {
		c.Name = defaultRepeaterName(c.Method, c.URL)
	}
	if c.Headers == nil {
		c.Headers = map[string][]string{}
	}
	if err := validateRepeaterCase(c); err != nil {
		return store.RepeaterCase{}, err
	}
	return c, nil
}

func repeaterCaseFromTraffic(flow store.TrafficDetail) (store.RepeaterCase, error) {
	c := store.RepeaterCase{
		SourceFlowID: flow.ID,
		Name:         defaultRepeaterName(flow.Method, flow.URL),
		Method:       strings.ToUpper(strings.TrimSpace(flow.Method)),
		URL:          strings.TrimSpace(flow.URL),
		Headers:      map[string][]string{},
		Body:         flow.RequestBody,
		TimeoutMS:    repeaterTimeoutMS,
		ScopeID:      flow.ScopeID,
	}
	for _, header := range flow.Headers {
		if header.Direction != "request" || skipReplayHeader(header.Name) {
			continue
		}
		c.Headers[header.Name] = append(c.Headers[header.Name], header.Value)
	}
	if err := validateRepeaterCase(c); err != nil {
		return store.RepeaterCase{}, err
	}
	return c, nil
}

func validateRepeaterCase(c store.RepeaterCase) error {
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if method == "" {
		return fmt.Errorf("method is required")
	}
	if method == http.MethodConnect {
		return fmt.Errorf("CONNECT cannot be sent from the repeater")
	}
	parsed, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("valid absolute URL is required")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	if c.TimeoutMS < repeaterMinTimeoutMS || c.TimeoutMS > repeaterMaxTimeoutMS {
		return fmt.Errorf("timeout_ms must be between %d and %d", repeaterMinTimeoutMS, repeaterMaxTimeoutMS)
	}
	return nil
}

func sendRepeaterCase(ctx context.Context, c store.RepeaterCase) store.RepeaterRun {
	run := store.RepeaterRun{
		CaseID:          c.ID,
		CreatedAt:       time.Now().UTC(),
		ResponseHeaders: map[string][]string{},
	}
	start := time.Now()
	req, err := buildRepeaterRequest(ctx, c)
	if err != nil {
		run.Error = err.Error()
		return run
	}
	client := &http.Client{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond}
	resp, err := client.Do(req)
	run.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		run.Error = err.Error()
		return run
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, repeaterBodyLimit+1))
	if err != nil {
		run.Error = err.Error()
		return run
	}
	if len(body) > repeaterBodyLimit {
		body = body[:repeaterBodyLimit]
	}
	run.Status = resp.StatusCode
	run.Bytes = int64(len(body))
	run.ResponseHeaders = map[string][]string(resp.Header.Clone())
	run.ResponseBody = string(body)
	return run
}

func buildRepeaterRequest(ctx context.Context, c store.RepeaterCase) (*http.Request, error) {
	if err := validateRepeaterCase(c); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(strings.TrimSpace(c.Method)), strings.TrimSpace(c.URL), strings.NewReader(c.Body))
	if err != nil {
		return nil, err
	}
	for name, values := range c.Headers {
		if skipReplayHeader(name) {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	return req, nil
}

func skipReplayHeader(name string) bool {
	if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") {
		return true
	}
	for _, header := range hopByHopReplayHeaders {
		if strings.EqualFold(name, header) {
			return true
		}
	}
	return false
}

var hopByHopReplayHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func defaultRepeaterName(method, rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.Host != "" {
		return strings.TrimSpace(strings.ToUpper(method) + " " + parsed.Host + parsed.EscapedPath())
	}
	if strings.TrimSpace(method) == "" && strings.TrimSpace(rawURL) == "" {
		return "Untitled repeater case"
	}
	return strings.TrimSpace(strings.ToUpper(method) + " " + rawURL)
}

func (s *Server) handleTrafficExport(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		writeJSON(w, http.StatusOK, []store.TrafficFlow{})
		return
	}
	flows, err := s.options.Store.ListTraffic(r.Context(), 1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("format") == "har" {
		s.audit(r, "traffic.export", map[string]any{"format": "har", "count": len(flows)})
		writeDownloadJSON(w, http.StatusOK, "traffic.har", trafficHAR(flows))
		return
	}

	s.audit(r, "traffic.export", map[string]any{"format": "json", "count": len(flows)})
	writeDownloadJSON(w, http.StatusOK, "traffic.json", flows)
}

func (s *Server) handleTrafficStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	if s.options.EventBus == nil {
		<-r.Context().Done()
		return
	}

	ch := s.options.EventBus.Subscribe("*")
	for {
		select {
		case event := <-ch:
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Topic, data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP mitm_proxy_uptime_seconds Seconds since proxy startup.\n")
	fmt.Fprintf(w, "# TYPE mitm_proxy_uptime_seconds gauge\n")
	fmt.Fprintf(w, "mitm_proxy_uptime_seconds %d\n", int64(time.Since(s.options.ProxyStarted).Seconds()))
	fmt.Fprintf(w, "# HELP mitm_proxy_admin_enabled Admin server enabled flag.\n")
	fmt.Fprintf(w, "# TYPE mitm_proxy_admin_enabled gauge\n")
	fmt.Fprintf(w, "mitm_proxy_admin_enabled 1\n")
	fmt.Fprintf(w, "# HELP mitm_proxy_mitm_enabled MITM enabled flag.\n")
	fmt.Fprintf(w, "# TYPE mitm_proxy_mitm_enabled gauge\n")
	if cfg.EnableMITM {
		fmt.Fprintf(w, "mitm_proxy_mitm_enabled 1\n")
	} else {
		fmt.Fprintf(w, "mitm_proxy_mitm_enabled 0\n")
	}
	if s.options.ThreatScanner != nil {
		metrics := s.options.ThreatScanner.Metrics()
		fmt.Fprintf(w, "# HELP mitm_proxy_threats_blocked_total Blocked threat count.\n")
		fmt.Fprintf(w, "# TYPE mitm_proxy_threats_blocked_total counter\n")
		fmt.Fprintf(w, "mitm_proxy_threats_blocked_total %d\n", metrics.BlockedThreats)
		fmt.Fprintf(w, "# HELP mitm_proxy_threats_ai_calls_total AI classifier calls.\n")
		fmt.Fprintf(w, "# TYPE mitm_proxy_threats_ai_calls_total counter\n")
		fmt.Fprintf(w, "mitm_proxy_threats_ai_calls_total %d\n", metrics.AICalls)
	}
	if s.options.Store != nil {
		stats, err := s.options.Store.TrafficStats(r.Context())
		if err == nil {
			fmt.Fprintf(w, "# HELP mitm_proxy_traffic_flows_total Captured traffic flow count.\n")
			fmt.Fprintf(w, "# TYPE mitm_proxy_traffic_flows_total counter\n")
			fmt.Fprintf(w, "mitm_proxy_traffic_flows_total %d\n", stats.Total)
			fmt.Fprintf(w, "# HELP mitm_proxy_traffic_blocked_total Blocked traffic flow count.\n")
			fmt.Fprintf(w, "# TYPE mitm_proxy_traffic_blocked_total counter\n")
			fmt.Fprintf(w, "mitm_proxy_traffic_blocked_total %d\n", stats.Blocked)
			fmt.Fprintf(w, "# HELP mitm_proxy_cache_hits_total Cached traffic hit count.\n")
			fmt.Fprintf(w, "# TYPE mitm_proxy_cache_hits_total counter\n")
			fmt.Fprintf(w, "mitm_proxy_cache_hits_total %d\n", stats.CacheHit)
		}
	}
}

func (s *Server) handleCACertificate(w http.ResponseWriter, r *http.Request) {
	cert, path, err := s.loadCACert()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	fingerprint := sha256.Sum256(cert.Raw)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"fingerprint": strings.ToUpper(hex.EncodeToString(fingerprint[:])),
		"created_at":  cert.NotBefore,
		"expires_at":  cert.NotAfter,
		"path":        path,
	})
}

func (s *Server) handleCACertificateDownload(w http.ResponseWriter, r *http.Request) {
	_, path, err := s.loadCACert()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca-cert.pem"`)
	http.ServeFile(w, r, path)
}

func (s *Server) handleCARotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.RotateCA == nil {
		s.handleNotImplemented(w, r)
		return
	}
	if err := s.options.RotateCA(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "certificates.ca.rotate", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated"})
}

func (s *Server) handleCAImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.ImportCA == nil {
		s.handleNotImplemented(w, r)
		return
	}

	var input struct {
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(input.CertPath) == "" || strings.TrimSpace(input.KeyPath) == "" {
		http.Error(w, "cert_path and key_path are required", http.StatusBadRequest)
		return
	}
	if err := s.options.ImportCA(r.Context(), input.CertPath, input.KeyPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "certificates.ca.import", map[string]any{"cert_path": input.CertPath})
	writeJSON(w, http.StatusOK, map[string]string{"status": "imported"})
}

func (s *Server) handleLeafCertificates(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "total": 0, "has_more": false})
		return
	}
	limit, offset := paginationParams(r, 10)
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	page, err := s.options.Store.ListCertificatesPage(r.Context(), limit, offset, query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":    page.Items,
		"total":    page.Total,
		"has_more": page.HasMore,
		"limit":    limit,
		"offset":   offset,
		"q":        query,
	})
}

func (s *Server) handleDeployments(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"current":  s.currentDeployment(),
		"profiles": deployments.DefaultProfiles(),
	})
}

func (s *Server) handleCurrentDeployment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.currentDeployment())
}

func (s *Server) handleDeploymentReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.ReloadConfig == nil {
		s.handleNotImplemented(w, r)
		return
	}
	if err := s.options.ReloadConfig(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "deployment.reload", map[string]any{"config_path": s.options.ConfigPath})
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (s *Server) handleDeploymentRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Restart == nil {
		s.handleNotImplemented(w, r)
		return
	}
	if err := s.options.Restart(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "deployment.restart", map[string]any{"config_path": s.options.ConfigPath})
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "restarting"})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	paths := []string{cfg.ThreatScanner.DebugLogPath}
	lines := []string{}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		read, err := tailFile(path, 200)
		if err == nil {
			lines = append(lines, read...)
		}
	}
	writeJSON(w, http.StatusOK, lines)
}

func (s *Server) handleBlockedPorts(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, cfg.BlockedPorts)
	case http.MethodPost:
		var input struct {
			Port int `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Port <= 0 || input.Port > 65535 {
			http.Error(w, "invalid port", http.StatusBadRequest)
			return
		}
		for _, port := range cfg.BlockedPorts {
			if port == input.Port {
				writeJSON(w, http.StatusOK, cfg.BlockedPorts)
				return
			}
		}
		cfg.BlockedPorts = append(cfg.BlockedPorts, input.Port)
		s.audit(r, "blocks.ports.add", map[string]any{"port": input.Port})
		writeJSON(w, http.StatusCreated, cfg.BlockedPorts)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlockedPortDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	portText := strings.TrimPrefix(r.URL.Path, "/api/blocks/ports/")
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	cfg := s.options.Config()
	cfg.BlockedPorts = removeInt(cfg.BlockedPorts, port)
	s.audit(r, "blocks.ports.delete", map[string]any{"port": port})
	writeJSON(w, http.StatusOK, cfg.BlockedPorts)
}

func (s *Server) handleBlockedDomains(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, cfg.BlockedDomains)
	case http.MethodPost:
		var input struct {
			Pattern string `json:"pattern"`
			Domain  string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		pattern := strings.TrimSpace(input.Pattern)
		if pattern == "" {
			pattern = strings.TrimSpace(input.Domain)
		}
		if pattern == "" {
			http.Error(w, "missing domain pattern", http.StatusBadRequest)
			return
		}
		cfg.BlockedDomains = appendUniqueString(cfg.BlockedDomains, pattern)
		s.audit(r, "blocks.domains.add", map[string]any{"pattern": pattern})
		writeJSON(w, http.StatusCreated, cfg.BlockedDomains)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlockedDomainDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pattern := strings.TrimPrefix(r.URL.Path, "/api/blocks/domains/")
	cfg := s.options.Config()
	cfg.BlockedDomains = removeString(cfg.BlockedDomains, pattern)
	s.audit(r, "blocks.domains.delete", map[string]any{"pattern": pattern})
	writeJSON(w, http.StatusOK, cfg.BlockedDomains)
}

func (s *Server) handleBlockedIPs(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, cfg.BlockedIPs)
	case http.MethodPost:
		var input struct {
			Pattern string `json:"pattern"`
			IP      string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		pattern := strings.TrimSpace(input.Pattern)
		if pattern == "" {
			pattern = strings.TrimSpace(input.IP)
		}
		if net.ParseIP(pattern) == nil {
			if _, _, err := net.ParseCIDR(pattern); err != nil {
				http.Error(w, "invalid IP or CIDR", http.StatusBadRequest)
				return
			}
		}
		cfg.BlockedIPs = appendUniqueString(cfg.BlockedIPs, pattern)
		s.audit(r, "blocks.ips.add", map[string]any{"pattern": pattern})
		writeJSON(w, http.StatusCreated, cfg.BlockedIPs)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlockedIPDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pattern := strings.TrimPrefix(r.URL.Path, "/api/blocks/ips/")
	cfg := s.options.Config()
	cfg.BlockedIPs = removeString(cfg.BlockedIPs, pattern)
	s.audit(r, "blocks.ips.delete", map[string]any{"pattern": pattern})
	writeJSON(w, http.StatusOK, cfg.BlockedIPs)
}

func (s *Server) handleBlockTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	cfg := s.options.Config()
	engine := policy.New(cfg.BlockedPorts, cfg.BlockedDomains, cfg.BlockedIPs)
	decisions := []policy.BlockDecision{
		engine.CheckPort(input.Port),
		engine.CheckDomain(input.Host),
	}
	if parsedIP := net.ParseIP(input.IP); parsedIP != nil {
		decisions = append(decisions, engine.CheckIP(parsedIP))
	}

	for _, decision := range decisions {
		if decision.Blocked {
			writeJSON(w, http.StatusOK, decision)
			return
		}
	}

	writeJSON(w, http.StatusOK, policy.BlockDecision{})
}

func (s *Server) handleCache(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	limit, offset := paginationParams(r, 10)
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	size, count := cacheStats(cfg.Cache.Directory)
	page := cacheEntries(cfg.Cache.Directory, limit, offset, query)
	var items any = page.Items
	itemsTotal := page.Total
	hasMore := page.HasMore
	if s.options.Store != nil {
		if storeSize, storeCount, err := s.options.Store.CacheStats(r.Context()); err == nil {
			size = storeSize
			count = storeCount
		}
		if storePage, err := s.options.Store.ListCacheEntries(r.Context(), limit, offset, query); err == nil {
			items = storePage.Items
			itemsTotal = storePage.Total
			hasMore = storePage.HasMore
		}
	}
	location := cfg.Cache.Directory
	if s.options.Store != nil {
		location = cfg.AdminStore
	}
	payload := map[string]any{
		"enabled":     cfg.Cache.Enabled,
		"directory":   location,
		"ttl":         cfg.Cache.TTL,
		"size":        size,
		"entries":     count,
		"items":       items,
		"items_total": itemsTotal,
		"has_more":    hasMore,
		"limit":       limit,
		"offset":      offset,
		"q":           query,
	}
	if s.options.Store != nil {
		if stats, err := s.options.Store.TrafficStats(r.Context()); err == nil {
			payload["hits"] = stats.CacheHit
			payload["misses"] = stats.Total - stats.CacheHit
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleCacheResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if !isCacheKey(key) {
		http.Error(w, "invalid cache key", http.StatusBadRequest)
		return
	}

	if s.options.Store != nil {
		entry, err := s.options.Store.LoadCacheEntry(r.Context(), key)
		if err != nil {
			http.Error(w, "cached resource not found", http.StatusNotFound)
			return
		}
		writeCachedResource(w, entry.URL, entry.Status, entry.Headers, entry.Body)
		return
	}

	cfg := s.options.Config()
	cached, err := cachedResponseByKey(cfg.Cache.Directory, key)
	if err != nil {
		http.Error(w, "cached resource not found", http.StatusNotFound)
		return
	}
	writeCachedResource(w, cached.URL, cached.Status, cached.Header, cached.Body)
}

func writeCachedResource(w http.ResponseWriter, rawURL string, status int, headers http.Header, body []byte) {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}

	w.Header().Set("Content-Type", contentType)
	copyCachedResourceHeader(w.Header(), headers, "Content-Encoding")
	copyCachedResourceHeader(w.Header(), headers, "Content-Language")
	copyCachedResourceHeader(w.Header(), headers, "Content-Location")
	copyCachedResourceHeader(w.Header(), headers, "ETag")
	copyCachedResourceHeader(w.Header(), headers, "Last-Modified")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if rawURL != "" {
		w.Header().Set("X-Original-URL", rawURL)
	}

	if status < 100 || status > 599 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func copyCachedResourceHeader(dst, src http.Header, name string) {
	for _, value := range src.Values(name) {
		dst.Add(name, value)
	}
}

func (s *Server) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		Domain string `json:"domain"`
	}
	_ = json.NewDecoder(r.Body).Decode(&input)

	cfg := s.options.Config()
	var removed int
	var err error
	if s.options.Store != nil {
		removed, err = s.options.Store.PurgeCache(r.Context(), input.Domain)
	} else {
		removed, err = purgeCache(cfg.Cache.Directory, input.Domain)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "cache.purge", map[string]any{"domain": input.Domain, "removed": removed})
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.options.Config()
	if r.Method == http.MethodPut {
		var input struct {
			EnableMITM      *bool    `json:"enable_mitm"`
			ExcludedDomains []string `json:"excluded_domains"`
			VerboseLogging  *bool    `json:"verbose_logging"`
			LogRequests     *bool    `json:"log_requests"`
			MinTLSVersion   string   `json:"min_tls_version"`
			IdleTimeout     *int     `json:"idle_timeout_seconds"`
			TrafficCapture  *struct {
				StoreBodies  *bool  `json:"store_bodies"`
				MaxBodyBytes *int64 `json:"max_body_bytes"`
				RedactBodies *bool  `json:"redact_bodies"`
			} `json:"traffic_capture"`
			AICopilot *struct {
				Enabled         *bool  `json:"enabled"`
				Provider        string `json:"provider"`
				Model           string `json:"model"`
				TimeoutMS       *int   `json:"timeout_ms"`
				MaxBodyBytes    *int64 `json:"max_body_bytes"`
				RedactBeforeAI  *bool  `json:"redact_before_ai"`
				OpenAIAPIKeyEnv string `json:"openai_api_key_env"`
			} `json:"ai_copilot"`
			Cache *struct {
				Enabled           *bool    `json:"enabled"`
				Directory         string   `json:"directory"`
				IncludeDomains    []string `json:"include_domains"`
				ExcludeDomains    []string `json:"exclude_domains"`
				IncludeExtensions []string `json:"include_extensions"`
				ExcludeExtensions []string `json:"exclude_extensions"`
				TTL               *int     `json:"ttl"`
			} `json:"cache"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if input.EnableMITM != nil {
			cfg.EnableMITM = *input.EnableMITM
		}
		if input.ExcludedDomains != nil {
			cfg.ExcludedDomains = input.ExcludedDomains
		}
		if input.VerboseLogging != nil {
			cfg.VerboseLogging = *input.VerboseLogging
		}
		if input.LogRequests != nil {
			cfg.LogRequests = *input.LogRequests
		}
		if input.MinTLSVersion != "" {
			cfg.MinTLSVersion = input.MinTLSVersion
		}
		if input.IdleTimeout != nil {
			cfg.IdleConnTimeout = *input.IdleTimeout
		}
		if input.TrafficCapture != nil {
			if input.TrafficCapture.StoreBodies != nil {
				cfg.TrafficCapture.StoreBodies = *input.TrafficCapture.StoreBodies
			}
			if input.TrafficCapture.MaxBodyBytes != nil {
				cfg.TrafficCapture.MaxBodyBytes = *input.TrafficCapture.MaxBodyBytes
			}
			if input.TrafficCapture.RedactBodies != nil {
				cfg.TrafficCapture.RedactBodies = *input.TrafficCapture.RedactBodies
			}
		}
		if input.AICopilot != nil {
			if input.AICopilot.Enabled != nil {
				cfg.AICopilot.Enabled = *input.AICopilot.Enabled
			}
			if input.AICopilot.Provider != "" {
				cfg.AICopilot.Provider = input.AICopilot.Provider
			}
			if input.AICopilot.Model != "" {
				cfg.AICopilot.Model = input.AICopilot.Model
			}
			if input.AICopilot.TimeoutMS != nil {
				cfg.AICopilot.TimeoutMS = *input.AICopilot.TimeoutMS
			}
			if input.AICopilot.MaxBodyBytes != nil {
				cfg.AICopilot.MaxBodyBytes = *input.AICopilot.MaxBodyBytes
			}
			if input.AICopilot.RedactBeforeAI != nil {
				cfg.AICopilot.RedactBeforeAI = *input.AICopilot.RedactBeforeAI
			}
			if input.AICopilot.OpenAIAPIKeyEnv != "" {
				cfg.AICopilot.OpenAIAPIKeyEnv = input.AICopilot.OpenAIAPIKeyEnv
			}
		}
		if input.Cache != nil {
			if input.Cache.Enabled != nil {
				cfg.Cache.Enabled = *input.Cache.Enabled
			}
			if input.Cache.Directory != "" {
				cfg.Cache.Directory = input.Cache.Directory
			}
			if input.Cache.IncludeDomains != nil {
				cfg.Cache.IncludeDomains = input.Cache.IncludeDomains
			}
			if input.Cache.ExcludeDomains != nil {
				cfg.Cache.ExcludeDomains = input.Cache.ExcludeDomains
			}
			if input.Cache.IncludeExtensions != nil {
				cfg.Cache.IncludeExtensions = input.Cache.IncludeExtensions
			}
			if input.Cache.ExcludeExtensions != nil {
				cfg.Cache.ExcludeExtensions = input.Cache.ExcludeExtensions
			}
			if input.Cache.TTL != nil {
				cfg.Cache.TTL = *input.Cache.TTL
			}
		}
		if s.options.Store != nil {
			_ = s.options.Store.SetSetting(r.Context(), "runtime_config", safeSettings(cfg))
		}
		if s.options.SaveConfig != nil {
			if err := s.options.SaveConfig(r.Context(), cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.audit(r, "settings.persist", map[string]any{"config_path": s.options.ConfigPath})
		}
		if s.options.PublishEvent != nil {
			s.options.PublishEvent(events.Event{
				Topic: events.TopicConfigUpdated,
				Time:  time.Now().UTC(),
				Payload: map[string]any{
					"source": "admin.settings",
				},
			})
		}
		s.audit(r, "settings.update", safeSettings(cfg))
		writeJSON(w, http.StatusOK, safeSettings(cfg))
		return
	}

	writeJSON(w, http.StatusOK, safeSettings(cfg))
}

func (s *Server) handleSettingsDanger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	var input struct {
		Action  string `json:"action"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !input.Confirm {
		http.Error(w, "confirmation is required", http.StatusBadRequest)
		return
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	switch action {
	case "all":
		if err := s.options.Store.PurgeResearchData(r.Context(), true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "settings.danger.purge_all", nil)
		writeJSON(w, http.StatusOK, map[string]string{"status": "purged", "action": action})
	case "except_cache":
		if err := s.options.Store.PurgeResearchData(r.Context(), false); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "settings.danger.purge_except_cache", nil)
		writeJSON(w, http.StatusOK, map[string]string{"status": "purged", "action": action})
	case "cache":
		removed, err := s.options.Store.PurgeCache(r.Context(), "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "settings.danger.purge_cache", map[string]any{"removed": removed})
		writeJSON(w, http.StatusOK, map[string]any{"status": "purged", "action": action, "removed": removed})
	default:
		http.Error(w, "unknown dangerous action", http.StatusBadRequest)
	}
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if s.options.Store == nil {
		writeJSON(w, http.StatusOK, []store.AdminUser{})
		return
	}

	switch r.Method {
	case http.MethodGet:
		users, err := s.options.Store.ListAdminUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, users)
	case http.MethodPost:
		var input struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(input.Name)
		role := strings.ToLower(strings.TrimSpace(input.Role))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if role == "" {
			role = "read"
		}
		if role != "admin" && role != "read" {
			http.Error(w, "role must be admin or read", http.StatusBadRequest)
			return
		}
		user, err := s.options.Store.AddAdminUser(r.Context(), name, role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(r, "admin.users.add", map[string]any{"id": user.ID, "name": user.Name, "role": user.Role})
		writeJSON(w, http.StatusCreated, user)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.Store == nil {
		s.handleNotImplemented(w, r)
		return
	}
	idText := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/users/"), "/")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	if err := s.options.Store.DeleteAdminUser(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "admin.users.delete", map[string]any{"id": id})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func safeSettings(cfg *cfgpkg.Config) map[string]any {
	return map[string]any{
		"listen_addr":          cfg.ListenAddr,
		"enable_mitm":          cfg.EnableMITM,
		"excluded_domains":     cfg.ExcludedDomains,
		"verbose_logging":      cfg.VerboseLogging,
		"log_requests":         cfg.LogRequests,
		"min_tls_version":      cfg.MinTLSVersion,
		"idle_timeout_seconds": cfg.IdleConnTimeout,
		"cache":                cfg.Cache,
		"traffic_capture":      cfg.TrafficCapture,
		"ai_copilot":           cfg.AICopilot,
	}
}

func (s *Server) handleThreatEvents(w http.ResponseWriter, r *http.Request) {
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusOK, map[string]any{"metrics": threats.Metrics{}, "events": []threats.Event{}})
		return
	}
	eventsOut := s.scopedThreatEvents(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"metrics": s.options.ThreatScanner.Metrics(),
		"events":  eventsOut,
	})
}

type scopedThreatEvent struct {
	threats.Event
	ScopeID string `json:"scope_id,omitempty"`
}

func (s *Server) scopedThreatEvents(r *http.Request) []scopedThreatEvent {
	eventsIn := s.options.ThreatScanner.ListEvents(100)
	out := make([]scopedThreatEvent, 0, len(eventsIn))
	scopeID, includeOutOfScope := scopeFilter(r)
	for _, event := range eventsIn {
		eventScopeID := ""
		if s.options.Store != nil {
			eventScopeID, _ = s.options.Store.MatchResearchScope(r.Context(), event.Method, event.URL, event.Host)
		}
		if scopeID == "__out_of_scope__" {
			if eventScopeID != "" {
				continue
			}
		} else if scopeID != "" {
			if includeOutOfScope {
				if eventScopeID != "" && eventScopeID != scopeID {
					continue
				}
			} else if eventScopeID != scopeID {
				continue
			}
		}
		out = append(out, scopedThreatEvent{Event: event, ScopeID: eventScopeID})
	}
	return out
}

func (s *Server) handleThreatEventDetail(w http.ResponseWriter, r *http.Request) {
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "threat scanner unavailable"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/threats/events/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "threat event not found"})
		return
	}

	id := parts[0]
	if len(parts) > 1 && r.Method == http.MethodPost {
		action := parts[1]
		switch action {
		case "allow", "block", "quarantine", "false-positive":
			overrideAction := action
			if action == "false-positive" {
				overrideAction = "allow"
			}
			event, ok := s.options.ThreatScanner.OverrideEvent(id, overrideAction)
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "threat event not found"})
				return
			}
			if s.options.Store != nil {
				_ = s.options.Store.AddAudit(r.Context(), "admin", "threat.override", map[string]any{
					"id":     id,
					"action": action,
				}, r.RemoteAddr)
			}
			writeJSON(w, http.StatusOK, event)
			return
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown threat action"})
			return
		}
	}

	event, ok := s.options.ThreatScanner.GetEvent(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "threat event not found"})
		return
	}
	writeJSON(w, http.StatusOK, event)
}

func (s *Server) handleThreatConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		s.handleNotImplemented(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.options.Config().ThreatScanner)
}

func (s *Server) handleThreatTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "threat scanner unavailable"})
		return
	}
	var input struct {
		Target      threats.ScanTarget  `json:"target"`
		Method      string              `json:"method"`
		URL         string              `json:"url"`
		Host        string              `json:"host"`
		StatusCode  int                 `json:"status_code"`
		Headers     map[string][]string `json:"headers"`
		ContentType string              `json:"content_type"`
		Body        string              `json:"body"`
		RemoteIP    string              `json:"remote_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	scanInput := threats.ScanInput{
		Target:      input.Target,
		Method:      input.Method,
		URL:         input.URL,
		Host:        input.Host,
		StatusCode:  input.StatusCode,
		Headers:     input.Headers,
		ContentType: input.ContentType,
		BodySample:  []byte(input.Body),
		BodyHash:    threats.BodyHash([]byte(input.Body)),
		RemoteIP:    input.RemoteIP,
	}
	verdict, err := s.options.ThreatScanner.Test(r.Context(), scanInput)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"verdict": verdict, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verdict": verdict})
}

func (s *Server) handleThreatStream(w http.ResponseWriter, r *http.Request) {
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "threat scanner unavailable"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := s.options.ThreatScanner.Subscribe()
	fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	for {
		select {
		case event := <-ch:
			fmt.Fprintf(w, "event: threat\ndata: %s\n\n", threats.EventJSON(event))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleThreatRules(w http.ResponseWriter, r *http.Request) {
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusOK, []threats.RuleDefinition{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"catalog": s.options.ThreatScanner.RuleCatalog(),
		"top":     s.options.ThreatScanner.Metrics().TopRules,
	})
}

func (s *Server) handleThreatQuarantine(w http.ResponseWriter, r *http.Request) {
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusOK, []threats.QuarantineMetadata{})
		return
	}
	writeJSON(w, http.StatusOK, s.options.ThreatScanner.QuarantineItems())
}

func (s *Server) handleThreatCacheInvalidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.options.ThreatScanner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "threat scanner unavailable"})
		return
	}
	s.options.ThreatScanner.InvalidateCache()
	if s.options.Store != nil {
		_ = s.options.Store.AddAudit(r.Context(), "admin", "threat.cache.invalidate", nil, r.RemoteAddr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "invalidated"})
}

func (s *Server) handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

func (s *Server) currentDeployment() map[string]any {
	cfg := s.options.Config()
	return map[string]any{
		"name":         "local",
		"kind":         "local",
		"status":       "running",
		"started_at":   s.options.ProxyStarted,
		"config_path":  s.options.ConfigPath,
		"listen_addr":  cfg.ListenAddr,
		"mitm_enabled": cfg.EnableMITM,
		"profiles":     deployments.DefaultProfiles(),
	}
}

func (s *Server) loadCACert() (*x509.Certificate, string, error) {
	cfg := s.options.Config()
	path := cfg.CACertPath
	if path == "" {
		path = cfg.CACertOutputPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read CA certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse CA certificate: %w", err)
	}
	return cert, path, nil
}

func (s *Server) audit(r *http.Request, action string, details any) {
	if s.options.Store == nil {
		return
	}
	_ = s.options.Store.AddAudit(r.Context(), "admin", action, details, r.RemoteAddr)
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func removeString(values []string, value string) []string {
	out := values[:0]
	for _, existing := range values {
		if existing != value {
			out = append(out, existing)
		}
	}
	return out
}

func removeInt(values []int, value int) []int {
	out := values[:0]
	for _, existing := range values {
		if existing != value {
			out = append(out, existing)
		}
	}
	return out
}

func cacheStats(dir string) (int64, int) {
	var size int64
	var entries int
	if strings.TrimSpace(dir) == "" {
		return 0, 0
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		size += info.Size()
		entries++
		return nil
	})
	return size, entries
}

type cacheEntriesPage struct {
	Items   []map[string]any
	Total   int
	HasMore bool
}

func cacheEntries(dir string, limit, offset int, query string) cacheEntriesPage {
	if strings.TrimSpace(dir) == "" || limit <= 0 {
		return cacheEntriesPage{Items: []map[string]any{}}
	}
	items := []map[string]any{}
	total := 0
	needle := strings.ToLower(strings.TrimSpace(query))
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var cached struct {
			URL       string `json:"url"`
			Status    int    `json:"status"`
			Body      []byte `json:"body"`
			StoredAt  int64  `json:"stored_at_unix"`
			ExpiresAt int64  `json:"expires_at_unix"`
		}
		if err := json.Unmarshal(data, &cached); err != nil {
			return nil
		}
		if cached.ExpiresAt > 0 && time.Now().Unix() > cached.ExpiresAt {
			_ = os.Remove(path)
			return nil
		}
		if cached.Status == http.StatusNotModified && len(cached.Body) == 0 {
			_ = os.Remove(path)
			return nil
		}
		info, _ := d.Info()
		key := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if needle != "" && !cacheEntryMatches(needle, key, cached.URL, cached.Status, cached.ExpiresAt, info) {
			return nil
		}
		total++
		if total <= offset {
			return nil
		}
		if len(items) >= limit {
			return nil
		}
		item := map[string]any{
			"path":       path,
			"key":        key,
			"view_url":   "/api/cache/resource?key=" + url.QueryEscape(key),
			"url":        cached.URL,
			"status":     cached.Status,
			"stored_at":  time.Unix(cached.StoredAt, 0).UTC(),
			"expires_at": time.Unix(cached.ExpiresAt, 0).UTC(),
		}
		if info != nil {
			item["size"] = info.Size()
		}
		items = append(items, item)
		return nil
	})
	return cacheEntriesPage{
		Items:   items,
		Total:   total,
		HasMore: offset+len(items) < total,
	}
}

func cacheEntryMatches(needle, key, rawURL string, status int, expiresAt int64, info fs.FileInfo) bool {
	haystacks := []string{
		strings.ToLower(key),
		strings.ToLower(rawURL),
		strconv.Itoa(status),
		time.Unix(expiresAt, 0).UTC().Format(time.RFC3339),
	}
	if info != nil {
		haystacks = append(haystacks, strconv.FormatInt(info.Size(), 10))
	}
	for _, value := range haystacks {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

type cachedResponse struct {
	URL       string      `json:"url"`
	Status    int         `json:"status"`
	Header    http.Header `json:"header"`
	Body      []byte      `json:"body"`
	ExpiresAt int64       `json:"expires_at_unix"`
}

func cachedResponseByKey(dir, key string) (*cachedResponse, error) {
	if strings.TrimSpace(dir) == "" || !isCacheKey(key) {
		return nil, os.ErrNotExist
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	var found *cachedResponse
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != nil || filepath.Ext(path) != ".json" {
			return nil
		}
		if !strings.EqualFold(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), key) {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return nil
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		var cached cachedResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			return err
		}
		if cached.ExpiresAt > 0 && time.Now().Unix() > cached.ExpiresAt {
			_ = os.Remove(abs)
			return os.ErrNotExist
		}
		if cached.Status == http.StatusNotModified && len(cached.Body) == 0 {
			_ = os.Remove(abs)
			return os.ErrNotExist
		}
		found = &cached
		return fs.SkipAll
	})
	if err != nil && err != fs.SkipAll {
		return nil, err
	}
	if found == nil {
		return nil, os.ErrNotExist
	}
	return found, nil
}

func isCacheKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, ch := range key {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func purgeCache(dir, domain string) (int, error) {
	if strings.TrimSpace(dir) == "" {
		return 0, nil
	}

	target := dir
	if strings.TrimSpace(domain) != "" {
		target = filepath.Join(dir, domain)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return 0, fmt.Errorf("resolve cache directory: %w", err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return 0, fmt.Errorf("resolve purge target: %w", err)
	}
	if absTarget != absDir && !strings.HasPrefix(absTarget, absDir+string(os.PathSeparator)) {
		return 0, fmt.Errorf("refusing to purge outside cache directory")
	}

	removed := 0
	err = filepath.WalkDir(absTarget, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return removeErr
		}
		removed++
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return removed, err
}

func tailFile(path string, limit int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, nil
}

func trafficHAR(flows []store.TrafficFlow) map[string]any {
	entries := make([]map[string]any, 0, len(flows))
	for _, flow := range flows {
		entries = append(entries, trafficHAREntry(flow))
	}
	return trafficHARLog(entries)
}

func trafficDetailHAR(flow store.TrafficDetail) map[string]any {
	entry := trafficHAREntry(flow.TrafficFlow)
	request := entry["request"].(map[string]any)
	response := entry["response"].(map[string]any)
	request["headers"] = harHeaders(flow.Headers, "request")
	request["queryString"] = harNameValues(flow.QueryParams)
	request["cookies"] = harCookies(flow.Cookies)
	if flow.RequestBody != "" {
		request["postData"] = map[string]any{
			"mimeType": "",
			"text":     flow.RequestBody,
		}
		request["bodySize"] = len(flow.RequestBody)
	}
	response["headers"] = harHeaders(flow.Headers, "response")
	if flow.ResponseBody != "" {
		response["content"] = map[string]any{
			"size":     len(flow.ResponseBody),
			"mimeType": flow.MIMEType,
			"text":     flow.ResponseBody,
		}
		response["bodySize"] = len(flow.ResponseBody)
	}
	return trafficHARLog([]map[string]any{entry})
}

func trafficHAREntry(flow store.TrafficFlow) map[string]any {
	started := flow.CreatedAt.Format(time.RFC3339Nano)
	return map[string]any{
		"startedDateTime": started,
		"time":            flow.DurationMS,
		"request": map[string]any{
			"method":      flow.Method,
			"url":         flow.URL,
			"httpVersion": flow.Protocol,
			"headers":     []any{},
			"queryString": []any{},
			"cookies":     []any{},
			"headersSize": -1,
			"bodySize":    -1,
		},
		"response": map[string]any{
			"status":      flow.Status,
			"statusText":  http.StatusText(flow.Status),
			"httpVersion": flow.Protocol,
			"headers":     []any{},
			"cookies":     []any{},
			"content": map[string]any{
				"size":     flow.Bytes,
				"mimeType": flow.MIMEType,
			},
			"redirectURL":  "",
			"headersSize":  -1,
			"bodySize":     flow.Bytes,
			"_cacheHit":    flow.CacheHit,
			"_blocked":     flow.Blocked,
			"_blockRuleID": flow.RuleID,
		},
		"cache": map[string]any{},
		"timings": map[string]any{
			"send":    0,
			"wait":    flow.DurationMS,
			"receive": 0,
		},
	}
}

func trafficHARLog(entries []map[string]any) map[string]any {
	return map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"creator": map[string]string{
				"name":    "mitm-proxy",
				"version": "dev",
			},
			"entries": entries,
		},
	}
}

func harHeaders(headers []store.HeaderRecord, direction string) []map[string]string {
	out := []map[string]string{}
	for _, header := range headers {
		if header.Direction != direction {
			continue
		}
		out = append(out, map[string]string{"name": header.Name, "value": header.Value})
	}
	return out
}

func harNameValues(values map[string][]string) []map[string]string {
	out := []map[string]string{}
	for name, vals := range values {
		for _, value := range vals {
			out = append(out, map[string]string{"name": name, "value": value})
		}
	}
	return out
}

func harCookies(values map[string]string) []map[string]string {
	out := []map[string]string{}
	for name, value := range values {
		out = append(out, map[string]string{"name": name, "value": value})
	}
	return out
}

func GenerateToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func IsLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "::1" || host == "localhost" || host == ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeDownloadJSON(w http.ResponseWriter, status int, filename string, value any) {
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeFilenamePart(filename)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, status, value)
}

func safeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "download"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "download"
	}
	if len(out) > 120 {
		return out[:120]
	}
	return out
}
