package webui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/identity"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/pairing"
	"github.com/rdpanywhere/rdpanywhere/internal/presence"
	"github.com/rdpanywhere/rdpanywhere/internal/rdpcheck"
	"github.com/rdpanywhere/rdpanywhere/internal/tunnel"
)

//go:embed static/*
var staticFiles embed.FS

var webLog = logger.For(logger.CompWebUI)

type Server struct {
	cfg      *config.Config
	node     *node.Node
	pairing  *pairing.Manager
	presence *presence.Manager
	tunnel   *tunnel.Manager
	identity *identity.Identity
	mux      *http.ServeMux

	// sessionToken is the long-lived credential stored in the HttpOnly cookie.
	// It never appears in a URL — not in command lines, not in browser history.
	sessionToken string

	// launchTokens are single-use tokens embedded in URLs handed to openBrowser.
	// Each BaseURL() call mints a fresh one; it is burned on first redemption.
	// Even if another process reads the command-line argument, the token is
	// already dead by the time the browser has loaded the page.
	launchMu     sync.Mutex
	launchTokens map[string]struct{}

	applyNetworkConfig   func(context.Context) error
	ensureNetworkBackend func(context.Context, string) error
	networkStatus        func() map[string]any

	connectMu      sync.Mutex
	activeConnects map[string]*connectAttempt
	connectStatus  map[string]connectStatus
	activeSessions map[string]*connectSession
}

const (
	connectOperationTimeout = 75 * time.Second
	connectStaleAfter       = 90 * time.Second
)

type connectStatus struct {
	Key       string    `json:"key"`
	Stage     string    `json:"stage"`
	Message   string    `json:"message"`
	Protocol  string    `json:"protocol,omitempty"`
	Peer      string    `json:"peer,omitempty"`
	LocalAddr string    `json:"local_addr,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Done      bool      `json:"done"`
	Active    bool      `json:"active"`
}

type connectAttempt struct {
	StartedAt time.Time
	Cancel    context.CancelFunc
}

type connectSession struct {
	Key       string
	Peer      string
	Protocol  string
	LocalAddr string
	StartedAt time.Time
	Proxy     *tunnel.LocalProxy
}

func New(
	cfg *config.Config,
	n *node.Node,
	p *pairing.Manager,
	pres *presence.Manager,
	t *tunnel.Manager,
	id *identity.Identity,
) *Server {
	var sessionBytes [16]byte
	rand.Read(sessionBytes[:])
	s := &Server{
		cfg: cfg, node: n, pairing: p, presence: pres, tunnel: t, identity: id,
		sessionToken:   hex.EncodeToString(sessionBytes[:]),
		launchTokens:   make(map[string]struct{}),
		activeConnects: make(map[string]*connectAttempt),
		connectStatus:  make(map[string]connectStatus),
		activeSessions: make(map[string]*connectSession),
	}
	s.mux = http.NewServeMux()
	s.routes()
	return s
}

func (s *Server) SetApplyNetworkConfig(fn func(context.Context) error) {
	s.applyNetworkConfig = fn
}

func (s *Server) SetEnsureNetworkBackend(fn func(context.Context, string) error) {
	s.ensureNetworkBackend = fn
}

func (s *Server) SetNetworkStatusProvider(fn func() map[string]any) {
	s.networkStatus = fn
}

// BaseURL mints a fresh single-use launch token and returns the authenticated
// dashboard URL. The token is burned on first redemption, so even if another
// process reads the browser command-line argument it cannot be replayed.
func (s *Server) BaseURL() string {
	var b [16]byte
	rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	s.launchMu.Lock()
	s.launchTokens[tok] = struct{}{}
	s.launchMu.Unlock()
	return "http://127.0.0.1:18080/?token=" + tok
}

// serveHTTP is the top-level handler. All requests require either the
// long-lived session cookie or a valid (unburned) single-use launch token.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !allowDashboardSource(r) {
		webLog.Warn("dashboard request rejected by source process check",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// Long-lived session cookie → pass through.
	if c, err := r.Cookie("DeskAccess_session"); err == nil && c.Value == s.sessionToken {
		s.mux.ServeHTTP(w, r)
		return
	}
	// Single-use launch token in URL → burn it, set session cookie, redirect.
	if tok := r.URL.Query().Get("token"); tok != "" {
		s.launchMu.Lock()
		_, valid := s.launchTokens[tok]
		delete(s.launchTokens, tok) // burn regardless — no replays
		s.launchMu.Unlock()

		if valid {
			http.SetCookie(w, &http.Cookie{
				Name:     "DeskAccess_session",
				Value:    s.sessionToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			u := *r.URL
			q := u.Query()
			q.Del("token")
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		webLog.Info("api request rejected by web session",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"has_cookie", hasCookie(r, "DeskAccess_session"),
			"has_token", r.URL.Query().Get("token") != "",
		)
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}

func (s *Server) Start(ctx context.Context) {
	srv := &http.Server{
		Addr:    "127.0.0.1:18080",
		Handler: http.HandlerFunc(s.serveHTTP),
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	fmt.Println("Web UI:", s.BaseURL())
	srv.ListenAndServe()
}

func (s *Server) routes() {
	// Serve static UI files
	staticFS, _ := fs.Sub(staticFiles, "static")
	s.mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// API
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/remotes", s.handleRemotes)
	s.mux.HandleFunc("/api/url/onetime", s.handleURLOneTime)
	s.mux.HandleFunc("/api/url/pairing", s.handleURLPairing)
	s.mux.HandleFunc("/api/invites", s.handleInvites)             // GET list
	s.mux.HandleFunc("/api/invites/revoke", s.handleRevoke)       // DELETE ?id=
	s.mux.HandleFunc("/api/invites/rename", s.handleRenameInvite) // PATCH {id,label}
	s.mux.HandleFunc("/api/connect", s.handleConnect)
	s.mux.HandleFunc("/api/connect/cancel", s.handleCancelConnect)
	s.mux.HandleFunc("/api/disconnect", s.handleDisconnect)
	s.mux.HandleFunc("/api/launch", s.handleLaunch)
	s.mux.HandleFunc("/api/connect/status", s.handleConnectStatus)
	s.mux.HandleFunc("/api/remotes/add", s.handleAddRemote)
	s.mux.HandleFunc("/api/remotes/rename", s.handleRenameRemote)
	s.mux.HandleFunc("/api/remotes/delete", s.handleDeleteRemote)
	s.mux.HandleFunc("/api/allowed", s.handleAllowed)
	s.mux.HandleFunc("/api/allowed/rename", s.handleRenameAllowed)
	s.mux.HandleFunc("/api/allowed/delete", s.handleDeleteAllowed)
	s.mux.HandleFunc("/api/label", s.handleLabel)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/logs", s.handleLogs)
	s.mux.HandleFunc("/api/client-log", s.handleClientLog)
	s.mux.HandleFunc("/api/scan", s.handleScan)
	s.mux.HandleFunc("/api/config", s.handleConfig) // GET + PATCH relay/dht config
}

// GET /api/config  — app protocol + discovery configuration
// PATCH /api/config body supports app, relay, dht, and bittorrent_dht sections.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.cfg.NormalizeNetworkBackend()
		respond(w, map[string]any{
			"share_backend": s.cfg.ActiveNetworkBackend(),
			"app": map[string]any{
				"protocol":    protocolOrDefault(s.cfg.RDP.Protocol),
				"target_port": targetPortOrDefault(s.cfg.RDP.TargetAddr, s.cfg.RDP.Protocol),
			},
			"relay": map[string]any{
				"mode":    s.cfg.Relay.Mode,
				"servers": s.cfg.Relay.Servers,
			},
			"dht": map[string]any{
				"mode":      s.cfg.DHT.Mode,
				"bootstrap": s.cfg.DHT.Bootstrap,
			},
			"bittorrent_dht": map[string]any{
				"mode":                  s.cfg.BTDHT.Mode,
				"bootstrap":             s.cfg.BTDHT.Bootstrap,
				"publish_interval_secs": s.cfg.BTDHT.PublishIntervalSecs,
			},
			"iroh": map[string]any{
				"mode":    s.cfg.Iroh.Mode,
				"servers": s.cfg.Iroh.Servers,
			},
		})

	case http.MethodPatch:
		oldBackend := s.cfg.ActiveNetworkBackend()
		oldRelayMode := s.cfg.Relay.Mode
		oldRelayServers := strings.Join(s.cfg.Relay.Servers, "\n")
		oldDHTMode := s.cfg.DHT.Mode
		oldDHTBootstrap := strings.Join(s.cfg.DHT.Bootstrap, "\n")
		oldBTDHTMode := s.cfg.BTDHT.Mode
		oldBTDHTBootstrap := strings.Join(s.cfg.BTDHT.Bootstrap, "\n")
		oldBTDHTInterval := s.cfg.BTDHT.PublishIntervalSecs
		oldIrohMode := s.cfg.Iroh.Mode
		oldIrohServers := strings.Join(s.cfg.Iroh.Servers, "\n")

		var req struct {
			ShareBackend string `json:"share_backend"`
			App          *struct {
				Protocol   string `json:"protocol"`
				TargetPort int    `json:"target_port"`
			} `json:"app"`
			Relay *struct {
				Mode    string   `json:"mode"`
				Servers []string `json:"servers"`
			} `json:"relay"`
			DHT *struct {
				Mode      string   `json:"mode"`
				Bootstrap []string `json:"bootstrap"`
			} `json:"dht"`
			BTDHT *struct {
				Mode                string   `json:"mode"`
				Bootstrap           []string `json:"bootstrap"`
				PublishIntervalSecs int      `json:"publish_interval_secs"`
			} `json:"bittorrent_dht"`
			Iroh *struct {
				Mode    string   `json:"mode"`
				Servers []string `json:"servers"`
			} `json:"iroh"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.ShareBackend != "" {
			switch req.ShareBackend {
			case "iroh", "bittorrent_dht", "libp2p_relay", "libp2p_dht":
				s.cfg.Network.ShareBackend = req.ShareBackend
			default:
				http.Error(w, "invalid share_backend", http.StatusBadRequest)
				return
			}
		}
		if req.App != nil {
			proto := protocolOrDefault(req.App.Protocol)
			port := req.App.TargetPort
			if port <= 0 {
				port = rdpcheck.ParseProtocol(proto).DefaultPort()
			}
			s.cfg.RDP.Protocol = proto
			s.cfg.RDP.TargetAddr = fmt.Sprintf("127.0.0.1:%d", port)
		}
		if req.Relay != nil {
			s.cfg.Relay.Mode = normalizeNetworkMode(req.Relay.Mode)
			if req.Relay.Servers != nil {
				s.cfg.Relay.Servers = req.Relay.Servers
			}
		}
		if req.DHT != nil {
			s.cfg.DHT.Mode = normalizeNetworkMode(req.DHT.Mode)
			if req.DHT.Bootstrap != nil {
				s.cfg.DHT.Bootstrap = req.DHT.Bootstrap
			}
		}
		if req.BTDHT != nil {
			s.cfg.BTDHT.Mode = normalizeNetworkMode(req.BTDHT.Mode)
			if req.BTDHT.Bootstrap != nil {
				s.cfg.BTDHT.Bootstrap = req.BTDHT.Bootstrap
			}
			if req.BTDHT.PublishIntervalSecs > 0 {
				s.cfg.BTDHT.PublishIntervalSecs = req.BTDHT.PublishIntervalSecs
			}
		}
		if req.Iroh != nil {
			s.cfg.Iroh.Mode = normalizeNetworkMode(req.Iroh.Mode)
			if req.Iroh.Servers != nil {
				s.cfg.Iroh.Servers = req.Iroh.Servers
			}
		}
		if err := s.cfg.Save(); err != nil {
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		networkChanged := oldBackend != s.cfg.ActiveNetworkBackend() ||
			oldRelayMode != s.cfg.Relay.Mode ||
			oldRelayServers != strings.Join(s.cfg.Relay.Servers, "\n") ||
			oldDHTMode != s.cfg.DHT.Mode ||
			oldDHTBootstrap != strings.Join(s.cfg.DHT.Bootstrap, "\n") ||
			oldBTDHTMode != s.cfg.BTDHT.Mode ||
			oldBTDHTBootstrap != strings.Join(s.cfg.BTDHT.Bootstrap, "\n") ||
			oldBTDHTInterval != s.cfg.BTDHT.PublishIntervalSecs ||
			oldIrohMode != s.cfg.Iroh.Mode ||
			oldIrohServers != strings.Join(s.cfg.Iroh.Servers, "\n")
		if networkChanged && s.applyNetworkConfig != nil {
			applyCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			defer cancel()
			if err := s.applyNetworkConfig(applyCtx); err != nil {
				http.Error(w, "saved but apply failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		deletedPairingLinks := 0
		if oldBackend != s.cfg.ActiveNetworkBackend() && s.pairing != nil {
			deletedPairingLinks = s.pairing.DeletePendingPairingInvitesExceptBackend(s.cfg.ActiveNetworkBackend())
			webLog.Info("stale pairing invites deleted after backend change",
				"old_backend", oldBackend,
				"share_backend", s.cfg.ActiveNetworkBackend(),
				"deleted", deletedPairingLinks)
		}
		respond(w, map[string]any{"status": "saved", "applied": networkChanged, "deleted_pairing_links": deletedPairingLinks})

	default:
		http.Error(w, "GET or PATCH required", http.StatusMethodNotAllowed)
	}
}

func normalizeNetworkMode(mode string) string {
	switch mode {
	case "custom", "mixed":
		return "custom"
	case "disabled":
		return "disabled"
	default:
		return "public"
	}
}

// GET /api/logs?lines=200 — recent JSON log lines for diagnostics.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	lines := 200
	if raw := r.URL.Query().Get("lines"); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &lines); err != nil || lines <= 0 {
			lines = 200
		}
	}
	if lines > 1000 {
		lines = 1000
	}
	out, err := logger.Tail(lines)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	respond(w, map[string]any{
		"log_file": logger.CurrentLogFile(),
		"lines":    out,
	})
}

func (s *Server) handleClientLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Level   string         `json:"level"`
		Message string         `json:"message"`
		Context map[string]any `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		webLog.Info("browser log rejected", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		msg = "browser event"
	}
	args := []any{"remote_addr", r.RemoteAddr}
	for key, value := range req.Context {
		if key == "" {
			continue
		}
		args = append(args, key, value)
	}
	switch strings.ToLower(strings.TrimSpace(req.Level)) {
	case "warn", "warning":
		webLog.Warn(msg, args...)
	case "error":
		webLog.Error(msg, args...)
	default:
		webLog.Info(msg, args...)
	}
	respond(w, map[string]string{"status": "ok"})
}

func protocolOrDefault(proto string) string {
	p := rdpcheck.ParseProtocol(proto)
	if p == "" {
		return "rdp"
	}
	return string(p)
}

func targetPortOrDefault(targetAddr, proto string) int {
	def := rdpcheck.ParseProtocol(proto).DefaultPort()
	if idx := strings.LastIndex(targetAddr, ":"); idx >= 0 && idx+1 < len(targetAddr) {
		var port int
		if _, err := fmt.Sscanf(targetAddr[idx+1:], "%d", &port); err == nil && port > 0 {
			return port
		}
	}
	return def
}

// GET /api/status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	backend := "software"
	tpmBackend := false
	machineID := s.node.NodeID()
	machineIDSource := "peer_id"
	if s.identity != nil {
		backend = string(s.identity.Backend)
		tpmBackend = s.identity.Backend == identity.BackendTPM
		if s.identity.Attestation != nil {
			if thumb := s.identity.Attestation.AttestationKeyThumbprint(); thumb != "" {
				machineID = thumb
				machineIDSource = "tpm_attestation_key"
			}
		}
	}
	resp := map[string]any{
		"node_id":                  s.node.NodeID(),
		"machine_id":               machineID,
		"machine_id_source":        machineIDSource,
		"label":                    s.cfg.Node.Label,
		"identity_backend":         backend,
		"identity_hardware_backed": tpmBackend,
		"tpm_backend":              tpmBackend,
		"tpm_vendor":               "",
		"log_file":                 logger.CurrentLogFile(),
		"share_backend":            s.cfg.ActiveNetworkBackend(),
	}
	if s.networkStatus != nil {
		resp["network_status"] = s.networkStatus()
	}
	if s.identity != nil && s.identity.Attestation != nil {
		resp["tpm_vendor"] = s.identity.Attestation.Manufacturer
	}
	respond(w, resp)
}

// GET /api/remotes — list paired remotes. Online only means an active tunnel is open.
func (s *Server) handleRemotes(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var statuses []any
	presenceByID := make(map[string]presence.Status)
	if s.presence != nil {
		for _, st := range s.presence.All() {
			presenceByID[st.NodeID] = st
		}
	}
	for _, remote := range s.cfg.Remotes {
		st, ok := presenceByID[remote.NodeID]
		if !ok {
			st = presence.Status{
				NodeID: remote.NodeID,
				Label:  remote.Label,
			}
		}
		session, connected := s.connectedSession("peer:" + remote.NodeID)
		localAddr := ""
		connectedProtocol := ""
		connType := node.ConnUnknown
		if session != nil {
			localAddr = session.LocalAddr
			connectedProtocol = session.Protocol
			if s.node != nil {
				connType = s.node.ConnTypeFor(st.NodeID)
			}
		}
		connectKey := "peer:" + remote.NodeID
		connecting, connectStage, connectMessage := s.connectingState(connectKey)
		statuses = append(statuses, map[string]any{
			"node_id":              st.NodeID,
			"label":                st.Label,
			"online":               connected,
			"last_seen":            st.LastSeen,
			"conn_type":            connType, // "direct" | "relayed" | "unknown"
			"discovery_source":     "",
			"discovery_error":      "",
			"discovery_checked_at": time.Time{},
			"connected":            connected,
			"local_addr":           localAddr,
			"connected_protocol":   connectedProtocol,
			"connecting":           connecting,
			"connect_stage":        connectStage,
			"connect_message":      connectMessage,
		})
	}
	connectedCount := 0
	for _, status := range statuses {
		if st, ok := status.(map[string]any); ok {
			if connected, _ := st["connected"].(bool); connected {
				connectedCount++
			}
		}
	}
	webLog.Info("paired remotes returned",
		"method", r.Method,
		"remotes", len(statuses),
		"connected", connectedCount,
		"duration", time.Since(started).String(),
	)
	respond(w, statuses)
}

// POST /api/url/onetime
func (s *Server) handleURLOneTime(w http.ResponseWriter, r *http.Request) {
	s.handleGenerateURL(w, r, "onetime")
}

// POST /api/url/pairing
func (s *Server) handleURLPairing(w http.ResponseWriter, r *http.Request) {
	s.handleGenerateURL(w, r, "pairing")
}

func (s *Server) handleGenerateURL(w http.ResponseWriter, r *http.Request, mode string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DurationMins int    `json:"duration_mins"`
		Label        string `json:"label"`
		Protocol     string `json:"protocol"` // "rdp" | "ssh" | "vnc" | "custom"
		Port         int    `json:"port"`     // 0 = use protocol default
	}
	req.Protocol = "rdp"
	json.NewDecoder(r.Body).Decode(&req)
	if mode == "onetime" {
		req.DurationMins = 60
	} else {
		req.DurationMins = 0
	}

	// Resolve target port: explicit override → protocol default
	targetPort := req.Port
	if targetPort == 0 {
		targetPort = rdpcheck.ParseProtocol(req.Protocol).DefaultPort()
	}

	ttl := time.Duration(req.DurationMins) * time.Minute
	if req.DurationMins == 0 {
		ttl = 0
	}

	rawURL, view, err := s.pairing.GenerateURL(mode, ttl, strings.TrimSpace(req.Label), req.Protocol, targetPort)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"url":        rawURL,
		"expires_at": view.ExpiresAt,
		"invite":     view,
	})
}

// GET /api/invites — list all invites (pending, used, revoked, expired)
func (s *Server) handleInvites(w http.ResponseWriter, r *http.Request) {
	respond(w, s.pairing.ListInvites())
}

// DELETE /api/invites/revoke?id=<inviteID>
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE required", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if err := s.pairing.RevokeInvite(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	respond(w, map[string]string{"status": "deleted"})
}

// PATCH /api/invites/rename  body: { id, label }
func (s *Server) handleRenameInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "PATCH required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id and label required", http.StatusBadRequest)
		return
	}
	if err := s.pairing.RenameInvite(req.ID, strings.TrimSpace(req.Label)); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}

// POST /api/connect — client connects to a remote via URL or nodeID
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		URL    string `json:"url"`     // deskaccess:// invite link
		NodeID string `json:"node_id"` // paired remote (no code needed)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	connectKey := connectRequestKey(req.NodeID, req.URL)
	if connectKey == "" {
		http.Error(w, "url or node_id required", http.StatusBadRequest)
		return
	}
	if session, ok := s.connectedSession(connectKey); ok {
		webLog.Info("connect returned existing active session",
			"connect_key", connectKey,
			"peer", shortID(session.Peer),
			"local_addr", session.LocalAddr)
		respond(w, map[string]any{
			"local_addr": session.LocalAddr,
			"launched":   false,
			"client":     "",
			"protocol":   session.Protocol,
			"active":     true,
		})
		return
	}
	if !s.beginConnect(connectKey) {
		st, age := s.activeConnectStatus(connectKey)
		webLog.Info("connect rejected because already in progress",
			"connect_key", connectKey,
			"remote_addr", r.RemoteAddr,
			"stage", st.Stage,
			"message", st.Message,
			"age", age.String())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		respond(w, map[string]any{
			"error":   "connection already in progress",
			"stage":   st.Stage,
			"message": st.Message,
			"age":     age.String(),
			"status":  st,
		})
		return
	}
	connectCtx, connectCancel := context.WithTimeout(r.Context(), connectOperationTimeout)
	s.setConnectCancel(connectKey, connectCancel)
	defer connectCancel()
	connectStarted := time.Now()
	s.setConnectStatus(connectKey, "starting", "Starting connection", "", "", "", nil, false)
	webLog.Info("connect started", "connect_key", connectKey, "remote_addr", r.RemoteAddr)
	defer func() {
		s.endConnect(connectKey)
		webLog.Info("connect finished", "connect_key", connectKey, "duration", time.Since(connectStarted).String())
	}()

	var localAddr string
	var proxy *tunnel.LocalProxy
	var connErr error
	proto := s.cfg.RDP.Protocol
	if proto == "" {
		proto = "rdp"
	}

	switch {
	case req.URL != "":
		s.setConnectStatus(connectKey, "discovery", "Reading invite and discovering host", "", "", "", nil, false)
		inviteBackend := pairing.InviteNetworkBackend(req.URL)
		if inviteBackend != "" && s.ensureNetworkBackend != nil {
			s.setConnectStatus(connectKey, "backend", "Starting "+inviteBackend+" backend", "", "", "", nil, false)
			if err := s.ensureNetworkBackend(connectCtx, inviteBackend); err != nil {
				webLog.Warn("connect backend ensure failed", "connect_key", connectKey, "backend", inviteBackend, "err", err)
				if connectCtx.Err() != nil {
					s.setConnectStatus(connectKey, "canceled", "Connection canceled", "", "", "", nil, true)
					http.Error(w, "connection canceled", http.StatusRequestTimeout)
					return
				}
				s.setConnectStatus(connectKey, "failed", "Backend startup failed", "", "", "", err, true)
				http.Error(w, "backend startup failed: "+err.Error(), http.StatusBadGateway)
				return
			}
		}
		result, err := s.pairing.ConnectByURL(connectCtx, req.URL)
		if err != nil {
			if fallbackPeer := s.pairingFallbackPeer(req.URL, err); fallbackPeer != "" {
				webLog.Info("invite connect failed with used pairing link, falling back to paired reauth",
					"connect_key", connectKey,
					"peer", shortID(fallbackPeer),
					"backend", inviteBackend,
					"err", err)
				s.setConnectStatus(connectKey, "reauth", "Link already used, using saved paired access", "", fallbackPeer, "", nil, false)
				result, err = s.pairing.ReauthPairedWithBackend(connectCtx, fallbackPeer, inviteBackend)
			}
		}
		if err != nil {
			webLog.Warn("connect pairing failed", "connect_key", connectKey, "err", err)
			if connectCtx.Err() != nil {
				s.setConnectStatus(connectKey, "canceled", "Connection canceled", "", "", "", nil, true)
				http.Error(w, "connection canceled", http.StatusRequestTimeout)
				return
			}
			msg := inviteConnectErrorMessage(err)
			s.setConnectStatus(connectKey, "failed", "Invite authentication failed", "", "", "", errors.New(msg), true)
			http.Error(w, msg, http.StatusBadGateway)
			return
		}
		s.setConnectStatus(connectKey, "authenticated", "Invite authenticated", result.Protocol, result.PeerID, "", nil, false)
		s.setConnectStatus(connectKey, "tunnel", tunnelStatusMessage(result), result.Protocol, result.PeerID, "", nil, false)
		if result.BitTorrentQUICEndpoint != "" {
			proxy, connErr = s.tunnel.ConnectBitTorrentQUICSession(
				connectCtx, result.PeerID, result.BitTorrentQUICEndpoint, result.SessionToken,
				result.TargetPort)
		} else if result.IrohTicket != "" {
			proxy, connErr = s.tunnel.ConnectIrohSession(
				connectCtx, result.PeerID, result.IrohTicket, result.SessionToken,
				result.TargetPort)
		} else {
			proxy, connErr = s.tunnel.ConnectSession(
				connectCtx, result.PeerID, result.RelayAddrs, result.SessionToken,
				result.TargetPort)
		}
		if connErr == nil {
			localAddr = proxy.Addr
			proto = result.Protocol
			s.registerConnectSession(connectKey, result.PeerID, proto, proxy)
		}

	case req.NodeID != "":
		pairedBackend := s.pairing.RemoteBackend(req.NodeID)
		if pairedBackend == "" {
			err := fmt.Errorf("paired machine is missing invite backend; remove and pair it again")
			s.setConnectStatus(connectKey, "failed", "Pairing data is incomplete", "", req.NodeID, "", err, true)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if pairedBackend != "" && s.ensureNetworkBackend != nil {
			s.setConnectStatus(connectKey, "backend", "Starting "+pairedBackend+" backend", "", req.NodeID, "", nil, false)
			if err := s.ensureNetworkBackend(connectCtx, pairedBackend); err != nil {
				webLog.Warn("connect backend ensure failed", "connect_key", connectKey, "backend", pairedBackend, "peer", shortID(req.NodeID), "err", err)
				if connectCtx.Err() != nil {
					s.setConnectStatus(connectKey, "canceled", "Connection canceled", "", req.NodeID, "", nil, true)
					http.Error(w, "connection canceled", http.StatusRequestTimeout)
					return
				}
				s.setConnectStatus(connectKey, "failed", "Backend startup failed", "", req.NodeID, "", err, true)
				http.Error(w, "backend startup failed: "+err.Error(), http.StatusBadGateway)
				return
			}
		}
		s.setConnectStatus(connectKey, "reauth", "Authenticating paired host", "", req.NodeID, "", nil, false)
		result, err := s.pairing.ReauthPairedWithBackend(connectCtx, req.NodeID, pairedBackend)
		if err != nil {
			webLog.Warn("connect reauth failed", "connect_key", connectKey, "peer", shortID(req.NodeID), "err", err)
			if connectCtx.Err() != nil {
				s.setConnectStatus(connectKey, "canceled", "Connection canceled", "", req.NodeID, "", nil, true)
				http.Error(w, "connection canceled", http.StatusRequestTimeout)
				return
			}
			s.setConnectStatus(connectKey, "failed", "Paired host authentication failed", "", req.NodeID, "", err, true)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		s.setConnectStatus(connectKey, "authenticated", "Paired host authenticated", result.Protocol, result.PeerID, "", nil, false)
		s.setConnectStatus(connectKey, "tunnel", tunnelStatusMessage(result), result.Protocol, result.PeerID, "", nil, false)
		if result.BitTorrentQUICEndpoint != "" {
			proxy, connErr = s.tunnel.ConnectBitTorrentQUICSession(
				connectCtx, result.PeerID, result.BitTorrentQUICEndpoint, result.SessionToken,
				result.TargetPort)
		} else if result.IrohTicket != "" {
			proxy, connErr = s.tunnel.ConnectIrohSession(
				connectCtx, result.PeerID, result.IrohTicket, result.SessionToken,
				result.TargetPort)
		} else {
			proxy, connErr = s.tunnel.ConnectSession(
				connectCtx, result.PeerID, result.RelayAddrs, result.SessionToken,
				result.TargetPort)
		}
		if connErr == nil && result.Protocol != "" {
			localAddr = proxy.Addr
			proto = result.Protocol
			s.registerConnectSession(connectKey, result.PeerID, proto, proxy)
		}

	default:
		http.Error(w, "url or node_id required", http.StatusBadRequest)
		return
	}

	if connErr != nil {
		webLog.Warn("connect tunnel failed", "connect_key", connectKey, "err", connErr)
		if connectCtx.Err() != nil {
			s.setConnectStatus(connectKey, "canceled", "Connection canceled", proto, "", "", nil, true)
			http.Error(w, "connection canceled", http.StatusRequestTimeout)
			return
		}
		s.setConnectStatus(connectKey, "failed", "Tunnel setup failed", proto, "", "", connErr, true)
		http.Error(w, "connection failed: "+connErr.Error(), http.StatusBadGateway)
		return
	}

	s.setConnectStatus(connectKey, "ready", "Local tunnel ready", proto, "", localAddr, nil, true)
	respond(w, map[string]any{
		"local_addr":      localAddr,
		"launched":        false,
		"client":          "",
		"protocol":        proto,
		"error":           "",
		"active":          true,
		"launch_from_ui":  true,
		"manual_fallback": true,
	})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		key = connectRequestKey(req.NodeID, "")
	}
	if key == "" {
		http.Error(w, "node_id or key required", http.StatusBadRequest)
		return
	}
	session, ok := s.disconnectSession(key)
	if !ok {
		webLog.Info("disconnect requested for inactive session", "connect_key", key, "remote_addr", r.RemoteAddr)
		respond(w, map[string]any{"status": "not_connected", "key": key, "active": false})
		return
	}
	webLog.Info("connect session disconnected",
		"connect_key", key,
		"peer", shortID(session.Peer),
		"local_addr", session.LocalAddr,
		"remote_addr", r.RemoteAddr)
	respond(w, map[string]any{
		"status":     "disconnected",
		"key":        key,
		"peer":       session.Peer,
		"local_addr": session.LocalAddr,
		"active":     false,
	})
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		key = connectRequestKey(req.NodeID, "")
	}
	if key == "" {
		http.Error(w, "node_id or key required", http.StatusBadRequest)
		return
	}
	session, ok := s.connectedSession(key)
	if !ok || session == nil || session.LocalAddr == "" {
		http.Error(w, "tunnel is not connected", http.StatusConflict)
		return
	}
	proto := session.Protocol
	if proto == "" {
		proto = s.cfg.RDP.Protocol
	}
	if proto == "" {
		proto = "rdp"
	}
	webLog.Info("launch requested for active tunnel",
		"connect_key", key,
		"peer", shortID(session.Peer),
		"protocol", proto,
		"local_addr", session.LocalAddr,
		"remote_addr", r.RemoteAddr)
	s.setConnectStatus(key, "ready", "Tunnel ready at "+session.LocalAddr, proto, session.Peer, session.LocalAddr, nil, true)
	respond(w, map[string]any{
		"local_addr":      session.LocalAddr,
		"launched":        false,
		"client":          "",
		"protocol":        proto,
		"error":           "",
		"active":          true,
		"launch_from_ui":  true,
		"manual_fallback": true,
	})
}

func (s *Server) handleCancelConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		key = connectRequestKey(req.NodeID, "")
	}
	if key == "" {
		http.Error(w, "node_id or key required", http.StatusBadRequest)
		return
	}
	canceled := s.cancelConnect(key)
	if !canceled {
		respond(w, map[string]any{"status": "not_connecting", "key": key})
		return
	}
	webLog.Info("connect canceled by user", "connect_key", key, "remote_addr", r.RemoteAddr)
	respond(w, map[string]any{"status": "canceling", "key": key})
}

func tunnelStatusMessage(result *pairing.ConnectResult) string {
	switch {
	case result == nil:
		return "Opening tunnel"
	case result.BitTorrentQUICEndpoint != "":
		return "Opening BitTorrent DHT tunnel"
	case result.IrohTicket != "":
		return "Opening iroh tunnel"
	default:
		return "Opening libp2p tunnel"
	}
}

func inviteConnectErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "link already used"):
		return "This invite link was already used by another machine. Ask the host to generate a new invite."
	case strings.Contains(lower, "invalid link"), strings.Contains(lower, "invalid invite proof"):
		return "This invite link is invalid. Ask the host to generate a new invite."
	case strings.Contains(lower, "link has expired"):
		return "This invite link has expired. Ask the host to generate a new invite."
	case strings.Contains(lower, "link has been revoked"):
		return "This invite link was revoked. Ask the host to generate a new invite."
	default:
		return msg
	}
}

func (s *Server) registerConnectSession(key, peer, proto string, proxy *tunnel.LocalProxy) {
	if proxy == nil {
		return
	}
	now := time.Now()
	session := &connectSession{
		Key:       key,
		Peer:      peer,
		Protocol:  proto,
		LocalAddr: proxy.Addr,
		StartedAt: now,
		Proxy:     proxy,
	}
	s.connectMu.Lock()
	old := s.activeSessions[key]
	s.activeSessions[key] = session
	st := s.connectStatus[key]
	st.Key = key
	st.Peer = peer
	st.Protocol = proto
	st.LocalAddr = proxy.Addr
	st.Active = true
	st.UpdatedAt = now
	s.connectStatus[key] = st
	s.connectMu.Unlock()
	if old != nil && old.Proxy != nil {
		old.Proxy.Close()
	}
	webLog.Info("connect session registered",
		"connect_key", key,
		"peer", shortID(peer),
		"protocol", proto,
		"local_addr", proxy.Addr)
}

func (s *Server) connectedSession(key string) (*connectSession, bool) {
	s.connectMu.Lock()
	defer s.connectMu.Unlock()
	session, ok := s.activeSessions[key]
	return session, ok && session != nil
}

func (s *Server) disconnectSession(key string) (*connectSession, bool) {
	s.connectMu.Lock()
	session, ok := s.activeSessions[key]
	if ok {
		delete(s.activeSessions, key)
	}
	st := s.connectStatus[key]
	if st.Key == "" {
		st.Key = key
	}
	if session != nil {
		st.Peer = session.Peer
		st.Protocol = session.Protocol
		st.LocalAddr = session.LocalAddr
	}
	st.Stage = "disconnected"
	st.Message = "Disconnected"
	st.Error = ""
	st.Active = false
	st.Done = true
	st.UpdatedAt = time.Now()
	s.connectStatus[key] = st
	s.connectMu.Unlock()

	if session != nil && session.Proxy != nil {
		session.Proxy.Close()
	}
	return session, ok
}

func connectRequestKey(nodeID, rawURL string) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID != "" {
		return "peer:" + nodeID
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if peerID := pairing.InvitePeerID(rawURL); peerID != "" {
		return "peer:" + peerID
	}
	return "url:" + shortID(rawURL)
}

func (s *Server) pairingFallbackPeer(rawURL string, err error) string {
	if err == nil || !strings.Contains(err.Error(), "link already used") {
		return ""
	}
	peerID := pairing.InvitePeerID(rawURL)
	if peerID == "" {
		return ""
	}
	for _, remote := range s.cfg.Remotes {
		if remote.NodeID == peerID {
			return peerID
		}
	}
	return ""
}

func (s *Server) beginConnect(key string) bool {
	s.connectMu.Lock()
	defer s.connectMu.Unlock()
	now := time.Now()
	if attempt, ok := s.activeConnects[key]; ok {
		if now.Sub(attempt.StartedAt) > connectStaleAfter {
			webLog.Warn("stale connect lock cleared",
				"connect_key", key,
				"age", now.Sub(attempt.StartedAt).String(),
			)
			if attempt.Cancel != nil {
				attempt.Cancel()
			}
			delete(s.activeConnects, key)
			st := s.connectStatus[key]
			if !st.Done {
				st.Key = key
				st.Stage = "failed"
				st.Message = "Previous connection attempt timed out"
				st.Error = "connect attempt exceeded " + connectStaleAfter.String()
				st.UpdatedAt = now
				st.Done = true
				s.connectStatus[key] = st
			}
		} else {
			return false
		}
	}
	if _, ok := s.activeConnects[key]; ok {
		return false
	}
	s.activeConnects[key] = &connectAttempt{StartedAt: now}
	return true
}

func (s *Server) setConnectCancel(key string, cancel context.CancelFunc) {
	s.connectMu.Lock()
	if attempt := s.activeConnects[key]; attempt != nil {
		attempt.Cancel = cancel
	}
	s.connectMu.Unlock()
}

func (s *Server) endConnect(key string) {
	s.connectMu.Lock()
	delete(s.activeConnects, key)
	s.connectMu.Unlock()
}

func (s *Server) cancelConnect(key string) bool {
	s.connectMu.Lock()
	attempt := s.activeConnects[key]
	if attempt == nil {
		s.connectMu.Unlock()
		return false
	}
	cancel := attempt.Cancel
	st := s.connectStatus[key]
	if st.Key == "" {
		st.Key = key
	}
	st.Stage = "canceling"
	st.Message = "Canceling connection"
	st.Error = ""
	st.Done = false
	st.UpdatedAt = time.Now()
	s.connectStatus[key] = st
	s.connectMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

func (s *Server) connectingState(key string) (bool, string, string) {
	s.connectMu.Lock()
	defer s.connectMu.Unlock()
	if s.activeConnects[key] == nil {
		return false, "", ""
	}
	st := s.connectStatus[key]
	return true, st.Stage, st.Message
}

func (s *Server) activeConnectStatus(key string) (connectStatus, time.Duration) {
	s.connectMu.Lock()
	defer s.connectMu.Unlock()
	now := time.Now()
	st := s.connectStatus[key]
	age := time.Duration(0)
	if attempt, ok := s.activeConnects[key]; ok && attempt != nil {
		age = now.Sub(attempt.StartedAt)
	}
	if st.Key == "" {
		st.Key = key
	}
	return st, age
}

func (s *Server) setConnectStatus(key, stage, message, proto, peer, localAddr string, err error, done bool) {
	now := time.Now()
	s.connectMu.Lock()
	st := s.connectStatus[key]
	if st.StartedAt.IsZero() {
		st.StartedAt = now
	}
	st.Key = key
	st.Stage = stage
	st.Message = message
	if proto != "" {
		st.Protocol = proto
	}
	if peer != "" {
		st.Peer = peer
	}
	if localAddr != "" {
		st.LocalAddr = localAddr
	}
	st.Error = ""
	if err != nil {
		st.Error = err.Error()
	}
	st.UpdatedAt = now
	st.Done = done
	s.connectStatus[key] = st
	s.connectMu.Unlock()
	webLog.Info("connect status updated",
		"connect_key", key,
		"stage", stage,
		"message", message,
		"protocol", proto,
		"local_addr", localAddr,
		"done", done,
		"err", st.Error,
	)
}

func (s *Server) handleConnectStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		key = connectRequestKey(r.URL.Query().Get("node_id"), r.URL.Query().Get("url"))
	}
	if key == "" {
		http.Error(w, "key, node_id, or url required", http.StatusBadRequest)
		return
	}
	s.connectMu.Lock()
	st, ok := s.connectStatus[key]
	s.connectMu.Unlock()
	if !ok {
		respond(w, connectStatus{
			Key:       key,
			Stage:     "idle",
			Message:   "Idle",
			UpdatedAt: time.Now(),
			Done:      true,
		})
		return
	}
	respond(w, st)
}

func shortID(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:12]
}

// POST /api/remotes/add — add a paired remote to the list
func (s *Server) handleAddRemote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req config.RemoteConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.cfg.AddRemote(req)
	if err := s.cfg.Save(); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "added"})
}

// DELETE /api/remotes/delete
func (s *Server) handleDeleteRemote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE required", http.StatusMethodNotAllowed)
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	newRemotes := s.cfg.Remotes[:0]
	for _, rem := range s.cfg.Remotes {
		if rem.NodeID != nodeID {
			newRemotes = append(newRemotes, rem)
		}
	}
	s.cfg.Remotes = newRemotes
	s.cfg.Save()
	respond(w, map[string]string{"status": "removed"})
}

// PATCH /api/remotes/rename  body: { node_id, label }
func (s *Server) handleRenameRemote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "PATCH required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Label  string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" || req.Label == "" {
		http.Error(w, "node_id and label required", http.StatusBadRequest)
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		http.Error(w, "label cannot be empty", http.StatusBadRequest)
		return
	}
	found := false
	for i := range s.cfg.Remotes {
		if s.cfg.Remotes[i].NodeID == req.NodeID {
			s.cfg.Remotes[i].Label = req.Label
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "remote not found", http.StatusNotFound)
		return
	}
	s.cfg.Save()
	respond(w, map[string]string{"status": "renamed"})
}

// GET /api/allowed — list peers allowed to reconnect to this machine.
func (s *Server) handleAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	trusted := dedupeTrustedPeers(s.cfg.Trusted)
	out := make([]map[string]any, 0, len(trusted))
	for _, p := range trusted {
		out = append(out, map[string]any{
			"node_id":                  p.NodeID,
			"label":                    p.Label,
			"added_at":                 p.AddedAt,
			"conn_type":                s.node.ConnTypeFor(p.NodeID),
			"identity_backend":         p.IdentityBackend,
			"identity_hardware_backed": p.HardwareBacked,
			"tpm_vendor":               p.TPMVendor,
			"tpm_version":              p.TPMVersion,
			"tpm_root_thumbprint":      p.TPMRootThumbprint,
		})
	}
	respond(w, out)
}

func dedupeTrustedPeers(in []config.TrustedPeer) []config.TrustedPeer {
	out := make([]config.TrustedPeer, 0, len(in))
	seen := make(map[string]int, len(in))
	for _, p := range in {
		key := trustedPeerDisplayKey(p)
		if idx, ok := seen[key]; ok {
			if p.AddedAt.After(out[idx].AddedAt) {
				out[idx] = p
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, p)
	}
	return out
}

func trustedPeerDisplayKey(p config.TrustedPeer) string {
	if p.TPMRootThumbprint != "" {
		return "tpm:" + p.TPMRootThumbprint
	}
	return "peer:" + p.NodeID
}

// PATCH /api/allowed/rename  body: { node_id, label }
func (s *Server) handleRenameAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "PATCH required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Label  string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" {
		http.Error(w, "node_id and label required", http.StatusBadRequest)
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		http.Error(w, "label cannot be empty", http.StatusBadRequest)
		return
	}

	for i := range s.cfg.Trusted {
		if s.cfg.Trusted[i].NodeID == req.NodeID {
			s.cfg.Trusted[i].Label = req.Label
			if err := s.cfg.Save(); err != nil {
				http.Error(w, "save failed", http.StatusInternalServerError)
				return
			}
			respond(w, map[string]string{"status": "renamed"})
			return
		}
	}
	http.Error(w, "allowed machine not found", http.StatusNotFound)
}

// DELETE /api/allowed/delete?node_id=<peerID>
func (s *Server) handleDeleteAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE required", http.StatusMethodNotAllowed)
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	filtered := s.cfg.Trusted[:0]
	removed := false
	for _, p := range s.cfg.Trusted {
		if p.NodeID == nodeID {
			removed = true
			continue
		}
		filtered = append(filtered, p)
	}
	if !removed {
		http.Error(w, "allowed machine not found", http.StatusNotFound)
		return
	}
	s.cfg.Trusted = filtered
	if err := s.cfg.Save(); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "removed"})
}

// GET /api/label  — returns this machine's display name
// PATCH /api/label  body: { label }  — update this machine's display name
func (s *Server) handleLabel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, map[string]string{"label": s.cfg.Node.Label})

	case http.MethodPatch:
		var req struct {
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Label = strings.TrimSpace(req.Label)
		if req.Label == "" {
			http.Error(w, "label cannot be empty", http.StatusBadRequest)
			return
		}
		s.cfg.Node.Label = req.Label
		s.cfg.Save()
		respond(w, map[string]string{"label": s.cfg.Node.Label})

	default:
		http.Error(w, "GET or PATCH required", http.StatusMethodNotAllowed)
	}
}

// GET /api/health?protocol=rdp  — checks readiness for a specific protocol
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Query().Get("protocol")
	if proto == "" {
		proto = s.cfg.RDP.Protocol
	}
	if proto == "" {
		proto = "rdp"
	}

	// Port: query param → config → protocol default
	port := rdpcheck.ParseProtocol(proto).DefaultPort()
	if portStr := r.URL.Query().Get("port"); portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	} else if s.cfg.RDP.TargetAddr != "" {
		fmt.Sscanf(s.cfg.RDP.TargetAddr[strings.LastIndex(s.cfg.RDP.TargetAddr, ":")+1:], "%d", &port)
	}

	hostStatus := rdpcheck.CheckHost(port)
	clientStatus := rdpcheck.CheckClient(rdpcheck.Protocol(proto))

	respond(w, map[string]any{
		"server": map[string]any{
			"listening": hostStatus.ServerListening,
			"port":      hostStatus.ServerPort,
			"protocol":  hostStatus.ServerProtocol,
			"setup_cmd": hostStatus.ServerSetupCmd,
		},
		"client": map[string]any{
			"available":   clientStatus.ClientAvailable,
			"bin":         clientStatus.ClientBin,
			"headless":    clientStatus.IsHeadless,
			"install_cmd": clientStatus.ClientInstallCmd,
		},
		"os": hostStatus.OS,
	})
}

// GET /api/scan?protocol=vnc  — scans localhost for open ports for a protocol.
// Returns all found ports so the UI can auto-select and show alternatives.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	proto := rdpcheck.ParseProtocol(r.URL.Query().Get("protocol"))
	candidates := rdpcheck.PortsForProtocol(proto)

	if len(candidates) == 0 {
		respond(w, map[string]any{"ports": []int{}, "found": false})
		return
	}

	results := rdpcheck.ScanPorts(candidates)

	ports := make([]int, len(results))
	for i, r := range results {
		ports[i] = r.Port
	}

	respond(w, map[string]any{
		"protocol": proto,
		"scanned":  candidates,
		"ports":    ports, // open ports found
		"found":    len(ports) > 0,
		"best":     bestPort(ports, proto), // recommended port
	})
}

// bestPort picks the most likely correct port from a list of open ports.
func bestPort(open []int, proto rdpcheck.Protocol) int {
	if len(open) == 0 {
		return proto.DefaultPort()
	}
	// For VNC: prefer :0 (5900) if open — it's the physical desktop
	// otherwise :1 (5901) — most common virtual session
	if proto == rdpcheck.ProtoVNC {
		for _, p := range open {
			if p == 5900 {
				return 5900
			}
		}
	}
	return open[0] // first open port
}

func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
