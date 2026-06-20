//go:build !windows && !linux

package identity

import "fmt"

// LoadOrCreateTPM is a placeholder for builds without a TPM provider.
// Platform-specific implementations should create/load a non-exportable TPM key
// and return an attestation bundle.
func LoadOrCreateTPM(identityDir string) (*Identity, error) {
	return nil, fmt.Errorf("TPM backend is not implemented for this build")
}
