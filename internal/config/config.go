package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Network NetworkConfig  `toml:"network"`
	Node    NodeConfig     `toml:"node"`
	Relay   RelayConfig    `toml:"relay"`
	DHT     DHTConfig      `toml:"dht"`
	BTDHT   BTDHTConfig    `toml:"bittorrent_dht"`
	Iroh    IrohConfig     `toml:"iroh"`
	RDP     RDPConfig      `toml:"rdp"`
	Remotes []RemoteConfig `toml:"remotes"`
	Trusted []TrustedPeer  `toml:"trusted_peers"`
}

type NetworkConfig struct {
	ShareBackend string `toml:"share_backend"` // backend used when this machine creates invite links
}

type NodeConfig struct {
	PrivateKey string `toml:"private_key"` // hex-encoded ed25519
	Label      string `toml:"label"`       // friendly name for this machine
}

// RelayConfig controls which circuit relay v2 servers are used.
//
// mode = "disabled" — do not use relays
// mode = "public"   — use the built-in Amino DHT relay list
// mode = "custom"  — use only the servers listed in servers[]
// mode = "mixed"   — use both built-in and servers[]
type RelayConfig struct {
	Mode      string   `toml:"mode"`      // "disabled" | "public" | "custom" | "mixed"
	Servers   []string `toml:"servers"`   // relay multiaddrs (custom/mixed)
	Allowlist []string `toml:"allowlist"` // peer IDs for self-hosted relay ACL
}

// DHTConfig controls the Kademlia DHT used for relay fallback and peer lookup.
//
// mode = "public"   — bootstrap against Amino DHT nodes only (default)
// mode = "custom"   — bootstrap against bootstrap[] only (your own nodes)
// mode = "mixed"    — bootstrap against both Amino and bootstrap[]
// mode = "disabled" — no DHT; relay fallback and cold-start lookup unavailable
type DHTConfig struct {
	Mode      string   `toml:"mode"`      // "public" | "custom" | "mixed" | "disabled"
	Bootstrap []string `toml:"bootstrap"` // bootstrap node multiaddrs (custom/mixed)
}

// BTDHTConfig controls optional BitTorrent DHT BEP44 publish/discovery.
//
// mode = "disabled" — do not use the public BitTorrent DHT (default)
// mode = "public"   — bootstrap against public BitTorrent DHT routers
// mode = "custom"   — bootstrap against bootstrap[] only
// mode = "mixed"    — bootstrap against public routers plus bootstrap[]
type BTDHTConfig struct {
	Mode                string   `toml:"mode"`                  // "disabled" | "public" | "custom" | "mixed"
	Bootstrap           []string `toml:"bootstrap"`             // host:port bootstrap routers (custom/mixed)
	PublishIntervalSecs int      `toml:"publish_interval_secs"` // default: 60
}

// IrohConfig controls the go-iroh backend.
//
// mode = "disabled" — do not use iroh
// mode = "public"   — use the built-in n0 iroh relay map
// mode = "custom"   — use only relay URLs listed in servers[]
type IrohConfig struct {
	Mode    string   `toml:"mode"`    // "disabled" | "public" | "custom"
	Servers []string `toml:"servers"` // iroh relay URLs for custom mode
}

type RDPConfig struct {
	// ListenAddr is the local address the tunnel proxy listens on (client side).
	// Use port 0 to let the OS pick a free local port for each connection.
	ListenAddr string `toml:"listen_addr"` // default: 127.0.0.1:0

	// TargetAddr is what the tunnel connects to on the host side.
	// Defaults to 127.0.0.1:3389 (Windows RDP).
	// Change to 127.0.0.1:5900 for VNC, 127.0.0.1:22 for SSH, etc.
	TargetAddr string `toml:"target_addr"`

	// Protocol hints to the app which client to auto-launch.
	// "rdp" (default) | "vnc" | "ssh" | "custom"
	Protocol string `toml:"protocol"`
}

// RemoteConfig is a paired remote PC stored in the admin's app.
// RelayAddrs are refreshed each time we successfully connect — stored so
// the admin can reconnect even if the host is temporarily offline and we
// need to dial via relay without a fresh invite token.
type RemoteConfig struct {
	Label             string    `toml:"label"`
	NodeID            string    `toml:"node_id"`
	PublicKey         string    `toml:"public_key"`
	MachineID         string    `toml:"machine_id"`
	Backend           string    `toml:"backend"`
	Protocol          string    `toml:"protocol"`
	TargetPort        int       `toml:"target_port"`
	RelayAddrs        []string  `toml:"relay_addrs"`       // last known circuit relay addrs
	IrohTicket        string    `toml:"iroh_ticket"`       // last known iroh endpoint ticket
	DirectQUICAddrs   []string  `toml:"direct_quic_addrs"` // last known direct QUIC UDP addrs
	IdentityBackend   string    `toml:"identity_backend"`
	HardwareBacked    bool      `toml:"hardware_backed"`
	TPMVendor         string    `toml:"tpm_vendor"`
	TPMVersion        string    `toml:"tpm_version"`
	TPMRootThumbprint string    `toml:"tpm_root_thumbprint"`
	AddedAt           time.Time `toml:"added_at"`
}

// TrustedPeer is a peer allowed to connect to this machine without a one-time token
type TrustedPeer struct {
	NodeID            string    `toml:"node_id"`
	Label             string    `toml:"label"`
	PublicKey         string    `toml:"public_key"`
	MachineID         string    `toml:"machine_id"`
	Protocol          string    `toml:"protocol"`
	TargetPort        int       `toml:"target_port"`
	IdentityBackend   string    `toml:"identity_backend"`
	HardwareBacked    bool      `toml:"hardware_backed"`
	TPMVendor         string    `toml:"tpm_vendor"`
	TPMVersion        string    `toml:"tpm_version"`
	TPMRootThumbprint string    `toml:"tpm_root_thumbprint"`
	AddedAt           time.Time `toml:"added_at"`
}

var defaultConfig = Config{
	Node: NodeConfig{
		Label: hostname(),
	},
	Relay: RelayConfig{
		Mode: "disabled",
	},
	DHT: DHTConfig{
		Mode: "disabled",
	},
	BTDHT: BTDHTConfig{
		Mode:                "disabled",
		PublishIntervalSecs: 60,
	},
	Iroh: IrohConfig{
		Mode: "public",
	},
	RDP: RDPConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:3389",
		Protocol:   "rdp",
	},
}

func Load() (*Config, error) {
	path := configPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return initNew(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := defaultConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.NormalizeNetworkBackend()
	return &cfg, nil
}

func (c *Config) Save() error {
	c.NormalizeNetworkBackend()
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// NormalizeNetworkBackend keeps mode defaults valid. ShareBackend selects the
// backend used for new host invites. Connections use the backend embedded in
// the invite or saved paired remote.
func (c *Config) NormalizeNetworkBackend() {
	if c.BTDHT.PublishIntervalSecs <= 0 {
		c.BTDHT.PublishIntervalSecs = 60
	}
	if c.Relay.Mode == "" {
		c.Relay.Mode = "disabled"
	}
	if c.DHT.Mode == "" {
		c.DHT.Mode = "disabled"
	}
	if c.BTDHT.Mode == "" {
		c.BTDHT.Mode = "disabled"
	}
	if c.Iroh.Mode == "" {
		c.Iroh.Mode = "public"
	}
	c.Network.ShareBackend = CanonicalNetworkBackend(c.Network.ShareBackend)
	if !validNetworkBackend(c.Network.ShareBackend) {
		c.Network.ShareBackend = "iroh"
	}

	c.ensureBackendEnabled(c.Network.ShareBackend)
}

// ActiveNetworkBackend returns the backend selected for new host invites.
// Other enabled backends may still be running for client-side dialing.
func (c *Config) ActiveNetworkBackend() string {
	if c == nil {
		return "iroh"
	}
	backend := CanonicalNetworkBackend(c.Network.ShareBackend)
	if validNetworkBackend(backend) {
		return backend
	}
	return "iroh"
}

func CanonicalNetworkBackend(backend string) string {
	return backend
}

func validNetworkBackend(backend string) bool {
	switch CanonicalNetworkBackend(backend) {
	case "iroh", "bittorrent_dht", "libp2p_relay", "libp2p_dht":
		return true
	default:
		return false
	}
}

func (c *Config) inferActiveNetworkBackend() string {
	return "iroh"
}

func (c *Config) ensureBackendEnabled(backend string) {
	switch CanonicalNetworkBackend(backend) {
	case "iroh":
		if c.Iroh.Mode == "" || c.Iroh.Mode == "disabled" {
			c.Iroh.Mode = "public"
		}
	case "bittorrent_dht":
		if c.BTDHT.Mode == "" || c.BTDHT.Mode == "disabled" {
			c.BTDHT.Mode = "public"
		}
	case "libp2p_relay":
		if c.Relay.Mode == "" || c.Relay.Mode == "disabled" {
			c.Relay.Mode = "public"
		}
	case "libp2p_dht":
		if c.DHT.Mode == "" || c.DHT.Mode == "disabled" {
			c.DHT.Mode = "public"
		}
	}
}

func (c *Config) PrivateKeyBytes() (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(c.Node.PrivateKey)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(b), nil
}

func (c *Config) AddRemote(r RemoteConfig) {
	r.AddedAt = time.Now()
	for i := range c.Remotes {
		if c.Remotes[i].NodeID == r.NodeID {
			if r.Label != "" {
				c.Remotes[i].Label = r.Label
			}
			if r.PublicKey != "" {
				c.Remotes[i].PublicKey = r.PublicKey
			}
			if r.MachineID != "" {
				c.Remotes[i].MachineID = r.MachineID
			}
			if r.Backend != "" {
				c.Remotes[i].Backend = r.Backend
			}
			if r.Protocol != "" {
				c.Remotes[i].Protocol = r.Protocol
			}
			if r.TargetPort > 0 {
				c.Remotes[i].TargetPort = r.TargetPort
			}
			if len(r.RelayAddrs) > 0 {
				c.Remotes[i].RelayAddrs = r.RelayAddrs
			}
			if r.IrohTicket != "" {
				c.Remotes[i].IrohTicket = r.IrohTicket
			}
			if len(r.DirectQUICAddrs) > 0 {
				c.Remotes[i].DirectQUICAddrs = r.DirectQUICAddrs
			}
			mergeIdentityInfo(&c.Remotes[i].IdentityBackend, &c.Remotes[i].HardwareBacked, &c.Remotes[i].TPMVendor, &c.Remotes[i].TPMVersion, &c.Remotes[i].TPMRootThumbprint, r.IdentityBackend, r.HardwareBacked, r.TPMVendor, r.TPMVersion, r.TPMRootThumbprint)
			c.Remotes[i].AddedAt = r.AddedAt
			return
		}
	}
	c.Remotes = append(c.Remotes, r)
}

func (c *Config) RemoveRemote(nodeID string) bool {
	for i := range c.Remotes {
		if c.Remotes[i].NodeID == nodeID {
			c.Remotes = append(c.Remotes[:i], c.Remotes[i+1:]...)
			return true
		}
	}
	return false
}

func (c *Config) AddTrustedPeer(p TrustedPeer) {
	p.AddedAt = time.Now()
	for i := range c.Trusted {
		if sameTrustedMachine(c.Trusted[i], p) {
			mergeTrustedPeer(&c.Trusted[i], p)
			c.removeDuplicateTrustedPeers(i)
			return
		}
	}
	c.Trusted = append(c.Trusted, p)
}

func sameTrustedMachine(a, b TrustedPeer) bool {
	if a.NodeID != "" && b.NodeID != "" && a.NodeID == b.NodeID {
		return true
	}
	if a.MachineID != "" && b.MachineID != "" && a.MachineID == b.MachineID {
		return true
	}
	if a.TPMRootThumbprint != "" && b.TPMRootThumbprint != "" && a.TPMRootThumbprint == b.TPMRootThumbprint {
		return true
	}
	return false
}

func mergeTrustedPeer(dst *TrustedPeer, src TrustedPeer) {
	if src.NodeID != "" {
		dst.NodeID = src.NodeID
	}
	if src.Label != "" {
		dst.Label = src.Label
	}
	if src.PublicKey != "" {
		dst.PublicKey = src.PublicKey
	}
	if src.MachineID != "" {
		dst.MachineID = src.MachineID
	}
	if src.Protocol != "" {
		dst.Protocol = src.Protocol
	}
	if src.TargetPort > 0 {
		dst.TargetPort = src.TargetPort
	}
	mergeIdentityInfo(&dst.IdentityBackend, &dst.HardwareBacked, &dst.TPMVendor, &dst.TPMVersion, &dst.TPMRootThumbprint, src.IdentityBackend, src.HardwareBacked, src.TPMVendor, src.TPMVersion, src.TPMRootThumbprint)
	dst.AddedAt = src.AddedAt
}

func (c *Config) removeDuplicateTrustedPeers(keep int) {
	for i := len(c.Trusted) - 1; i >= 0; i-- {
		if i != keep && sameTrustedMachine(c.Trusted[keep], c.Trusted[i]) {
			c.Trusted = append(c.Trusted[:i], c.Trusted[i+1:]...)
			if i < keep {
				keep--
			}
		}
	}
}

func (c *Config) RemoveTrustedPeer(nodeID string) bool {
	for i := range c.Trusted {
		if c.Trusted[i].NodeID == nodeID {
			c.Trusted = append(c.Trusted[:i], c.Trusted[i+1:]...)
			return true
		}
	}
	return false
}

func mergeIdentityInfo(backend *string, hardware *bool, vendor *string, version *string, rootThumbprint *string, newBackend string, newHardware bool, newVendor string, newVersion string, newRootThumbprint string) {
	if newBackend != "" {
		*backend = newBackend
		*hardware = newHardware
	}
	if newHardware {
		*hardware = true
	}
	if newVendor != "" {
		*vendor = newVendor
	}
	if newVersion != "" {
		*version = newVersion
	}
	if newRootThumbprint != "" {
		*rootThumbprint = newRootThumbprint
	}
}

func (c *Config) IsTrusted(nodeID string) bool {
	for _, p := range c.Trusted {
		if p.NodeID == nodeID {
			return true
		}
	}
	return false
}

func (c *Config) TrustedPeer(nodeID string) (TrustedPeer, bool) {
	for _, p := range c.Trusted {
		if p.NodeID == nodeID {
			return p, true
		}
	}
	return TrustedPeer{}, false
}

// initNew generates a new keypair and writes default config
func initNew(path string) (*Config, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cfg := defaultConfig
	cfg.Node.PrivateKey = hex.EncodeToString(priv)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func configPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "DeskAccess", "config.toml")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "DeskAccess", "config.toml")
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "my-pc"
	}
	return h
}
