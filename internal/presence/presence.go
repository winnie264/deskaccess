package presence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/dht"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
)

var plog = logger.For(logger.CompPresence)

const (
	presenceTopic    = "/DeskAccess/presence/1.0.0"
	announceInterval = 20 * time.Second // announce every 20s
	offlineAfter     = 65 * time.Second // 3 missed = offline (20s × 3 + buffer)
	sweepInterval    = 10 * time.Second
)

// Announcement is the payload published to the presence topic.
// It carries the sender's current relay addrs so any subscriber can
// immediately connect without any DHT or discovery step.
type Announcement struct {
	NodeID     string    `json:"id"`
	Label      string    `json:"l"`
	RelayAddrs []string  `json:"a"`   // live circuit relay multiaddrs
	Timestamp  time.Time `json:"t"`
}

// Status is the current known state of a peer, as shown in the UI.
type Status struct {
	NodeID     string
	Label      string
	Online     bool
	LastSeen   time.Time
	RelayAddrs []string // most recently announced relay addrs — ready to dial
}

// Manager publishes this node's presence and tracks remote peers.
type Manager struct {
	mu            sync.RWMutex
	peers         map[string]*Status // nodeID → live status
	ps            *pubsub.PubSub
	topic         *pubsub.Topic
	sub           *pubsub.Subscription
	h             host.Host
	cfg           *config.Config
	getRelayAddrs func() []string // injected from node — returns current addrs
	onChange      func([]Status)
	dhtClient     *dht.Client // optional; nil = no DHT cold-start
}

// New creates a presence manager and starts announcing + receiving.
// getRelayAddrs is called each time we announce — always sends fresh addrs.
// dhtClient is optional: when non-nil, it enables cold-start DHT peer lookup
// so known remotes appear online faster before GossipSub propagates their presence.
func New(ctx context.Context, h host.Host, cfg *config.Config, getRelayAddrs func() []string, dhtClient *dht.Client) (*Manager, error) {
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("gossipsub: %w", err)
	}

	topic, err := ps.Join(presenceTopic)
	if err != nil {
		return nil, fmt.Errorf("join topic: %w", err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}

	m := &Manager{
		peers:         make(map[string]*Status),
		ps:            ps,
		topic:         topic,
		sub:           sub,
		h:             h,
		cfg:           cfg,
		getRelayAddrs: getRelayAddrs,
		dhtClient:     dhtClient,
	}

	go m.announceLoop(ctx)
	go m.receiveLoop(ctx)
	go m.sweepLoop(ctx)
	if dhtClient != nil {
		go m.dhtColdStart(ctx)
	}

	return m, nil
}

// dhtColdStart waits for the DHT routing table to populate, then tries to
// locate each configured remote peer. This surfaces their relay addrs before
// GossipSub has had time to deliver their presence announcement.
func (m *Manager) dhtColdStart(ctx context.Context) {
	// Give the DHT a moment to bootstrap before querying.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !m.dhtClient.WaitReady(waitCtx) {
		plog.Debug("DHT cold-start skipped: routing table still empty after 30s")
		return
	}

	m.mu.RLock()
	remotes := make([]config.RemoteConfig, len(m.cfg.Remotes))
	copy(remotes, m.cfg.Remotes)
	m.mu.RUnlock()

	for _, remote := range remotes {
		if ctx.Err() != nil {
			return
		}
		pid, err := peer.Decode(remote.NodeID)
		if err != nil {
			continue
		}
		// Skip peers already seen via GossipSub.
		m.mu.RLock()
		_, alreadyKnown := m.peers[remote.NodeID]
		m.mu.RUnlock()
		if alreadyKnown {
			continue
		}

		findCtx, findCancel := context.WithTimeout(ctx, 20*time.Second)
		info, err := m.dhtClient.FindPeer(findCtx, pid)
		findCancel()
		if err != nil {
			plog.Debug("DHT cold-start: peer not found", "peer", remote.NodeID[:12], "err", err)
			continue
		}

		// Connect to the peer so GossipSub can reach them.
		connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
		connErr := m.h.Connect(connCtx, info)
		connCancel()
		if connErr != nil {
			plog.Debug("DHT cold-start: connect failed", "peer", remote.NodeID[:12], "err", connErr)
			continue
		}
		plog.Info("DHT cold-start: connected to peer", "peer", remote.NodeID[:12], "label", remote.Label)

		// Record relay addrs from DHT-discovered info as initial presence.
		// GossipSub will update this with a fresh announcement shortly.
		var relayAddrs []string
		for _, addr := range info.Addrs {
			if strings.Contains(addr.String(), "p2p-circuit") {
				relayAddrs = append(relayAddrs, addr.String())
			}
		}
		if len(relayAddrs) == 0 {
			continue
		}
		m.mu.Lock()
		if _, exists := m.peers[remote.NodeID]; !exists {
			m.peers[remote.NodeID] = &Status{
				NodeID:     remote.NodeID,
				Label:      remote.Label,
				Online:     true,
				LastSeen:   time.Now(),
				RelayAddrs: relayAddrs,
			}
		}
		m.mu.Unlock()
		m.notify()
	}
}

// OnChange registers a callback fired whenever any peer's status changes.
func (m *Manager) OnChange(fn func([]Status)) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// AnnounceNow triggers an immediate out-of-cycle announcement.
// Called by the node when relay addrs change after a reconnect.
func (m *Manager) AnnounceNow(ctx context.Context) {
	m.announce(ctx)
}

// All returns the current status of every known remote in the config.
// Unknown remotes appear as offline.
func (m *Manager) All() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Status, 0, len(m.cfg.Remotes))
	for _, r := range m.cfg.Remotes {
		if s, ok := m.peers[r.NodeID]; ok {
			result = append(result, *s)
		} else {
			result = append(result, Status{
				NodeID: r.NodeID,
				Label:  r.Label,
				Online: false,
			})
		}
	}
	return result
}

// GetPeerAddrs returns the most recently announced relay addrs for a peer.
// Returns nil if the peer is unknown or offline.
// This is the VPN-like lookup: admin clicks "Connect" → get addrs → dial.
func (m *Manager) GetPeerAddrs(nodeID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.peers[nodeID]
	if !ok || !s.Online {
		return nil
	}
	out := make([]string, len(s.RelayAddrs))
	copy(out, s.RelayAddrs)
	return out
}

// IsOnline returns whether a peer is currently online.
func (m *Manager) IsOnline(nodeID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.peers[nodeID]
	return ok && s.Online
}

// --- announce ---

func (m *Manager) announceLoop(ctx context.Context) {
	ticker := time.NewTicker(announceInterval)
	defer ticker.Stop()
	m.announce(ctx) // immediate on start
	for {
		select {
		case <-ticker.C:
			m.announce(ctx)
		case <-ctx.Done():
			m.announceOffline(ctx) // best-effort goodbye
			return
		}
	}
}

func (m *Manager) announce(ctx context.Context) {
	msg := Announcement{
		NodeID:     m.h.ID().String(),
		Label:      m.cfg.Node.Label,
		RelayAddrs: m.getRelayAddrs(),
		Timestamp:  time.Now(),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	if err := m.topic.Publish(ctx, data); err != nil {
		plog.Warn("publish error", "err", err)
		return
	}
	plog.Debug("presence announced", "relay_addrs", len(msg.RelayAddrs))
}

// announceOffline sends a final announcement with no relay addrs
// so peers know we're going offline immediately rather than waiting for timeout.
func (m *Manager) announceOffline(ctx context.Context) {
	msg := Announcement{
		NodeID:     m.h.ID().String(),
		Label:      m.cfg.Node.Label,
		RelayAddrs: nil, // empty = offline signal
		Timestamp:  time.Now(),
	}
	data, _ := json.Marshal(msg)
	offlineCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m.topic.Publish(offlineCtx, data)
}

// --- receive ---

func (m *Manager) receiveLoop(ctx context.Context) {
	for {
		msg, err := m.sub.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if msg.ReceivedFrom == m.h.ID() {
			continue // ignore our own messages
		}

		var ann Announcement
		if err := json.Unmarshal(msg.Data, &ann); err != nil {
			continue
		}

		m.mu.Lock()
		existing, known := m.peers[ann.NodeID]

		// Offline signal: empty relay addrs from a peer we know
		if len(ann.RelayAddrs) == 0 && known {
			existing.Online = false
			existing.RelayAddrs = nil
			m.mu.Unlock()
			m.notify()
			continue
		}

		wasOnline := known && existing.Online
		s := &Status{
			NodeID:     ann.NodeID,
			Label:      ann.Label,
			Online:     true,
			LastSeen:   time.Now(),
			RelayAddrs: ann.RelayAddrs,
		}
		m.peers[ann.NodeID] = s

		// Also update stored relay addrs in config for this remote (persist across restarts)
		m.updateRemoteAddrs(ann.NodeID, ann.RelayAddrs)

		cb := m.onChange
		m.mu.Unlock()

		if !wasOnline {
			plog.Info("peer came online",
				"peer", ann.NodeID[:12], "label", ann.Label, "relay_addrs", len(ann.RelayAddrs))
		}
		if cb != nil {
			cb(m.All())
		}
	}
}

// updateRemoteAddrs persists the latest relay addrs for a paired remote.
// This means after a restart, the admin can still dial without a fresh invite.
func (m *Manager) updateRemoteAddrs(nodeID string, addrs []string) {
	for i, r := range m.cfg.Remotes {
		if r.NodeID == nodeID {
			m.cfg.Remotes[i].RelayAddrs = addrs
			// Save async so we don't block the receive loop
			go m.cfg.Save()
			return
		}
	}
}

// --- sweep ---

func (m *Manager) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.sweep()
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) sweep() {
	m.mu.Lock()
	changed := false
	for _, s := range m.peers {
		wasOnline := s.Online
		s.Online = s.Online && time.Since(s.LastSeen) < offlineAfter
		if wasOnline && !s.Online {
			plog.Info("peer went offline (timeout)", "peer", s.NodeID[:12], "label", s.Label)
			changed = true
		}
	}
	m.mu.Unlock()
	if changed {
		m.notify()
	}
}

func (m *Manager) notify() {
	m.mu.RLock()
	cb := m.onChange
	all := m.All()
	m.mu.RUnlock()
	if cb != nil {
		cb(all)
	}
}
