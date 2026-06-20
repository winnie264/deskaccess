package identity

import (
	"log/slog"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

// LoadOrCreateSoftware loads an existing ed25519 key from disk or generates one.
// Used when no TPM is available.
func LoadOrCreateSoftware(keyPath string) (*Identity, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(keyPath)
	if err == nil {
		privBytes, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
		priv, err := libp2pcrypto.UnmarshalEd25519PrivateKey(privBytes)
		if err != nil {
			return nil, fmt.Errorf("unmarshal key: %w", err)
		}
		return &Identity{PrivKey: priv, Backend: BackendSoftware}, nil
	}

	// Generate new key
	_, raw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	priv, err := libp2pcrypto.UnmarshalEd25519PrivateKey(raw)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(raw)), 0600); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}
	slog.Info("identity: generated new software ed25519 key")
	return &Identity{PrivKey: priv, Backend: BackendSoftware}, nil
}
