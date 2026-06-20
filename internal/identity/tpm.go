//go:build ignore
// +build ignore

// tpm.go is excluded from the build.
// The TPM integration requires go-tpm v0.9.x API alignment
// and hardware access — implement when targeting specific TPM hardware.
// For now, identity/load.go falls back to the software backend on all platforms.
package identity
