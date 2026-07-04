// Package btdht publishes and discovers relay addresses through the public
// BitTorrent DHT using BEP44 mutable records.
package btdht

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	adht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/bep44"
	"github.com/anacrolix/dht/v2/exts/getput"
	"github.com/anacrolix/dht/v2/krpc"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
)

var log = logger.For(logger.CompDHT)

const (
	salt            = "DeskAccess:presence:v1"
	defaultInterval = 60 * time.Second
	publishTimeout  = 25 * time.Second
	lookupTimeout   = 20 * time.Second
	recordMaxAge    = 2 * time.Hour
	recordSchema    = 1
)

// Record is the JSON payload stored in the BEP44 mutable item.
type Record struct {
	Version         int      `json:"v"`
	NodeID          string   `json:"id"`
	Label           string   `json:"l"`
	RelayAddrs      []string `json:"a,omitempty"`
	DirectQUICAddrs []string `json:"q,omitempty"`
	Timestamp       int64    `json:"t"`
}

// Client owns a BitTorrent DHT server and publishes this node's signed record.
type Client struct {
	server        *adht.Server
	priv          ed25519.PrivateKey
	pub           [32]byte
	nodeID        string
	label         func() string
	getRelayAddrs func() []string
	getQUICAddrs  func() []string
	interval      time.Duration

	mu             sync.RWMutex
	ready          bool
	lastError      string
	lastPublishErr string
	lastPublished  time.Time
}

// New creates a BitTorrent DHT client when cfg.Mode is enabled.
func New(ctx context.Context, cfg config.BTDHTConfig, priv ed25519.PrivateKey, nodeID string, label func() string, getRelayAddrs func() []string, getQUICAddrs ...func() []string) (*Client, error) {
	if cfg.Mode == "" || cfg.Mode == "disabled" {
		return nil, nil
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}

	pubKey, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("derive ed25519 public key")
	}

	sc := adht.NewDefaultServerConfig()
	if cfg.Mode == "custom" || cfg.Mode == "mixed" {
		custom := append([]string(nil), cfg.Bootstrap...)
		sc.StartingNodes = func() ([]adht.Addr, error) {
			var out []adht.Addr
			if cfg.Mode == "mixed" {
				pub, err := adht.GlobalBootstrapAddrs("udp")
				if err != nil {
					return nil, err
				}
				out = append(out, pub...)
			}
			if len(custom) > 0 {
				addrs, err := adht.ResolveHostPorts(custom)
				if err != nil {
					return nil, err
				}
				out = append(out, addrs...)
			}
			return out, nil
		}
	}

	server, err := adht.NewServer(sc)
	if err != nil {
		return nil, err
	}

	interval := defaultInterval
	if cfg.PublishIntervalSecs > 0 {
		interval = time.Duration(cfg.PublishIntervalSecs) * time.Second
	}
	c := &Client{
		server:        server,
		priv:          priv,
		nodeID:        nodeID,
		label:         label,
		getRelayAddrs: getRelayAddrs,
		interval:      interval,
	}
	if len(getQUICAddrs) > 0 {
		c.getQUICAddrs = getQUICAddrs[0]
	}
	copy(c.pub[:], pubKey)

	go c.bootstrap(ctx)
	go c.publishLoop(ctx)
	return c, nil
}

func (c *Client) Close() {
	if c != nil && c.server != nil {
		c.server.Close()
	}
}

func (c *Client) bootstrap(ctx context.Context) {
	bootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := c.server.BootstrapContext(bootCtx); err != nil && bootCtx.Err() == nil {
		c.setStatus(false, err.Error())
		log.Warn("BitTorrent DHT bootstrap failed", "err", err)
		return
	}
	c.setStatus(true, "")
	log.Info("BitTorrent DHT ready")
}

func (c *Client) publishLoop(ctx context.Context) {
	c.PublishNow(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.PublishNow(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// PublishNow publishes this node's current relay addresses as a signed BEP44 item.
func (c *Client) PublishNow(ctx context.Context) {
	if c == nil {
		return
	}
	started := time.Now()
	addrs := c.getRelayAddrs()
	var quicAddrs []string
	if c.getQUICAddrs != nil {
		quicAddrs = c.getQUICAddrs()
	}
	log.Info("BitTorrent DHT publish started", "relay_addrs", len(addrs), "direct_quic_addrs", len(quicAddrs))
	if len(addrs) == 0 && len(quicAddrs) == 0 {
		c.setPublishStatus("no relay or direct QUIC addresses available to publish", time.Time{})
		log.Warn("BitTorrent DHT publish skipped", "reason", "no relay or direct QUIC addresses available to publish")
		return
	}
	rec := Record{
		Version:         recordSchema,
		NodeID:          c.nodeID,
		Label:           c.label(),
		RelayAddrs:      addrs,
		DirectQUICAddrs: quicAddrs,
		Timestamp:       time.Now().Unix(),
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		c.setPublishStatus(err.Error(), time.Time{})
		log.Warn("BitTorrent DHT publish encode failed", "err", err)
		return
	}

	put := bep44.Put{
		V:    string(payload),
		K:    &c.pub,
		Salt: []byte(salt),
	}
	target := krpc.ID(put.Target())

	putCtx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	_, err = getput.Put(putCtx, target, c.server, []byte(salt), func(seq int64) bep44.Put {
		put.Seq = seq + 1
		put.Sign(c.priv)
		return put
	})
	if err != nil && putCtx.Err() == nil {
		c.setPublishStatus(err.Error(), time.Time{})
		log.Warn("BitTorrent DHT publish failed", "err", err, "duration", time.Since(started).String())
		return
	}
	c.setPublishStatus("", time.Now())
	log.Info("BitTorrent DHT record published", "relay_addrs", len(addrs), "direct_quic_addrs", len(quicAddrs), "duration", time.Since(started).String())
}

func (c *Client) Status() map[string]any {
	if c == nil {
		return map[string]any{"enabled": false, "running": false}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]any{
		"enabled":          true,
		"running":          c.server != nil,
		"ready":            c.ready,
		"last_error":       c.lastError,
		"last_publish_err": c.lastPublishErr,
		"last_published":   c.lastPublished,
	}
}

func (c *Client) WaitReady(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("BitTorrent DHT disabled")
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		c.mu.RLock()
		ready := c.ready
		lastErr := c.lastError
		c.mu.RUnlock()
		if ready {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			if lastErr != "" {
				return fmt.Errorf("BitTorrent DHT not ready: %s", lastErr)
			}
			return fmt.Errorf("BitTorrent DHT not ready")
		}
	}
}

func (c *Client) setStatus(ready bool, err string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ready = ready
	c.lastError = err
}

func (c *Client) setPublishStatus(err string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastPublishErr = err
	if !at.IsZero() {
		c.lastPublished = at
	}
}

// Lookup fetches a peer's signed BEP44 record by its 32-byte Ed25519 public key.
func (c *Client) Lookup(ctx context.Context, publicKeyHex string, expectedNodeID string) ([]string, error) {
	rec, err := c.LookupRecord(ctx, publicKeyHex, expectedNodeID)
	if err != nil {
		return nil, err
	}
	if len(rec.RelayAddrs) == 0 {
		return nil, fmt.Errorf("record has no relay addresses")
	}
	out := make([]string, len(rec.RelayAddrs))
	copy(out, rec.RelayAddrs)
	return out, nil
}

// LookupDirectQUIC resolves the signed BitTorrent DHT record into the direct
// QUIC addresses used by the bittorrent_dht transport backend.
func (c *Client) LookupDirectQUIC(ctx context.Context, publicKeyHex string, expectedNodeID string) ([]string, []string, error) {
	rec, err := c.LookupRecord(ctx, publicKeyHex, expectedNodeID)
	if err != nil {
		return nil, nil, err
	}
	relayAddrs := append([]string(nil), rec.RelayAddrs...)
	directQUICAddrs := append([]string(nil), rec.DirectQUICAddrs...)
	return relayAddrs, directQUICAddrs, nil
}

// LookupRecord fetches a peer's signed BEP44 record by its 32-byte Ed25519 public key.
func (c *Client) LookupRecord(ctx context.Context, publicKeyHex string, expectedNodeID string) (*Record, error) {
	if c == nil {
		return nil, fmt.Errorf("BitTorrent DHT disabled")
	}
	started := time.Now()
	log.Info("BitTorrent DHT lookup started", "peer", shortID(expectedNodeID), "public_key", shortID(publicKeyHex))
	keyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Warn("BitTorrent DHT lookup failed", "peer", shortID(expectedNodeID), "err", err)
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		log.Warn("BitTorrent DHT lookup failed", "peer", shortID(expectedNodeID), "err", "invalid public key length")
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	var pub [32]byte
	copy(pub[:], keyBytes)

	target := bep44.MakeMutableTarget(pub, []byte(salt))
	getCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	result, _, err := getput.Get(getCtx, target, c.server, nil, []byte(salt))
	if err != nil {
		log.Warn("BitTorrent DHT lookup failed", "peer", shortID(expectedNodeID), "duration", time.Since(started).String(), "err", err)
		return nil, err
	}

	encoded, err := decodeBencodeBytes([]byte(result.V))
	if err != nil {
		log.Warn("BitTorrent DHT lookup decode failed", "peer", shortID(expectedNodeID), "err", err)
		return nil, fmt.Errorf("decode record: %w", err)
	}
	var rec Record
	if err := json.Unmarshal(encoded, &rec); err != nil {
		log.Warn("BitTorrent DHT lookup json decode failed", "peer", shortID(expectedNodeID), "err", err)
		return nil, fmt.Errorf("decode record json: %w", err)
	}
	if rec.Version != recordSchema {
		log.Warn("BitTorrent DHT lookup rejected record", "peer", shortID(expectedNodeID), "schema", rec.Version)
		return nil, fmt.Errorf("unsupported record schema %d", rec.Version)
	}
	if expectedNodeID != "" && rec.NodeID != expectedNodeID {
		log.Warn("BitTorrent DHT lookup rejected record", "peer", shortID(expectedNodeID), "record_peer", shortID(rec.NodeID), "err", "node mismatch")
		return nil, fmt.Errorf("record node mismatch")
	}
	if time.Since(time.Unix(rec.Timestamp, 0)) > recordMaxAge {
		log.Warn("BitTorrent DHT lookup rejected stale record", "peer", shortID(expectedNodeID), "record_age", time.Since(time.Unix(rec.Timestamp, 0)).String())
		return nil, fmt.Errorf("record is stale")
	}
	log.Info("BitTorrent DHT lookup succeeded",
		"peer", shortID(rec.NodeID),
		"relay_addrs", len(rec.RelayAddrs),
		"direct_quic_addrs", len(rec.DirectQUICAddrs),
		"record_age", time.Since(time.Unix(rec.Timestamp, 0)).String(),
		"duration", time.Since(started).String())
	return &rec, nil
}

func shortID(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

func decodeBencodeBytes(in []byte) ([]byte, error) {
	colon := -1
	for i, b := range in {
		if b == ':' {
			colon = i
			break
		}
		if b < '0' || b > '9' {
			return nil, fmt.Errorf("invalid byte string length")
		}
	}
	if colon <= 0 {
		return nil, fmt.Errorf("missing byte string separator")
	}
	n, err := strconv.Atoi(string(in[:colon]))
	if err != nil {
		return nil, err
	}
	start := colon + 1
	if n < 0 || start+n > len(in) {
		return nil, fmt.Errorf("byte string length exceeds payload")
	}
	return in[start : start+n], nil
}
