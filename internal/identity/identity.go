// Package identity manages the peer's cryptographic identity.
//
// Two backends:
//
//  1. TPM (hardware) — key generated in TPM, never extractable.
//     Provides a certificate chain: App Key ← EK ← Manufacturer CA.
//     Other peers can verify the key is hardware-bound.
//
//  2. Software (fallback) — ed25519 key in config file.
//     Used when no TPM is present (VMs, older hardware, Raspberry Pi
//     without TPM add-on).
//
// libp2p uses the identity key for:
//   - Deriving the PeerID (hash of public key)
//   - Noise protocol handshake (authenticating every stream)
//
// TPM key type: ECDSA P-256 (universally supported by TPM 2.0).
// Software key type: ed25519 (current default).
//
// When TPM is available the PairRequest includes an AttestationBundle
// so the other peer can verify hardware binding.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

// Backend describes how the identity key is stored.
type Backend string

const (
	BackendTPM      Backend = "tpm"      // hardware-backed, non-extractable
	BackendSoftware Backend = "software" // file-backed ed25519
)

// Identity holds the peer's signing key and optional TPM attestation.
type Identity struct {
	// PrivKey is the libp2p private key used for PeerID + Noise handshake.
	// For TPM backend this is a P-256 key whose private part lives in the TPM.
	PrivKey libp2pcrypto.PrivKey

	// Signer is set for TPM-backed identities. The private key remains inside
	// the platform TPM/KSP, but can sign freshness proofs.
	Signer crypto.Signer

	// Backend tells callers how the key is stored.
	Backend Backend

	// Attestation is non-nil when Backend == BackendTPM.
	Attestation *AttestationBundle
}

// AttestationBundle carries everything needed for the remote peer to verify
// that this identity key was generated inside a real TPM.
type AttestationBundle struct {
	// AKCert is the Attestation Key certificate, DER-encoded.
	// Signed by the EK (or by a Privacy CA in enterprise setups).
	AKCert []byte

	// EKCert is the Endorsement Key certificate, DER-encoded.
	// Signed by the TPM manufacturer's CA.
	EKCert []byte

	// ManufacturerCA is the root CA cert from the TPM manufacturer, DER-encoded.
	// e.g. Infineon OPTIGA TPM RSA Root CA, STMicro TPM EK Root CA.
	ManufacturerCA []byte

	// Manufacturer is a human-readable string: "Infineon", "STMicroelectronics", etc.
	Manufacturer string

	// TPMVersion is "2.0" for all modern TPMs.
	TPMVersion string
}

// AttestationKeyThumbprint returns a stable SHA-256 thumbprint of the TPM
// attestation key public material. It hashes the AK certificate public key
// rather than the certificate itself, so reissuing the certificate around the
// same TPM key does not change the identifier.
func (a *AttestationBundle) AttestationKeyThumbprint() string {
	if a == nil || len(a.AKCert) == 0 {
		return ""
	}
	cert, err := x509.ParseCertificate(a.AKCert)
	if err != nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func PublicKeyThumbprint(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func (id *Identity) MachineID() string {
	if id == nil {
		return ""
	}
	if id.Attestation != nil {
		if thumb := id.Attestation.AttestationKeyThumbprint(); thumb != "" {
			return thumb
		}
	}
	if id.PrivKey == nil {
		return ""
	}
	raw, err := id.PrivKey.GetPublic().Raw()
	if err != nil {
		return ""
	}
	return PublicKeyThumbprint(raw)
}

func (id *Identity) PublicKeyRaw() []byte {
	if id == nil || id.PrivKey == nil {
		return nil
	}
	raw, err := id.PrivKey.GetPublic().Raw()
	if err != nil {
		return nil
	}
	return raw
}

func (id *Identity) SignProof(message []byte) ([]byte, error) {
	if id == nil {
		return nil, fmt.Errorf("identity unavailable")
	}
	if id.Signer != nil {
		sum := sha256.Sum256(message)
		return id.Signer.Sign(crand.Reader, sum[:], crypto.SHA256)
	}
	if id.PrivKey == nil {
		return nil, fmt.Errorf("identity private key unavailable")
	}
	return id.PrivKey.Sign(message)
}

func VerifyTPMProof(att *AttestationBundle, machineID string, message []byte, signature []byte) error {
	if att == nil || len(att.AKCert) == 0 {
		return fmt.Errorf("missing TPM attestation certificate")
	}
	if got := att.AttestationKeyThumbprint(); got == "" || !strings.EqualFold(got, machineID) {
		return fmt.Errorf("TPM attestation key thumbprint does not match machine ID")
	}
	cert, err := x509.ParseCertificate(att.AKCert)
	if err != nil {
		return fmt.Errorf("parse AK cert: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("AK cert public key is %T, want ECDSA", cert.PublicKey)
	}
	sum := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(pub, sum[:], signature) {
		return fmt.Errorf("TPM identity signature invalid")
	}
	return nil
}

func VerifySoftwareProof(publicKeyRaw []byte, machineID string, message []byte, signature []byte) error {
	if len(publicKeyRaw) == 0 {
		return fmt.Errorf("missing software public key")
	}
	if got := PublicKeyThumbprint(publicKeyRaw); got == "" || !strings.EqualFold(got, machineID) {
		return fmt.Errorf("software public key thumbprint does not match machine ID")
	}
	pub, err := libp2pcrypto.UnmarshalEd25519PublicKey(publicKeyRaw)
	if err != nil {
		return fmt.Errorf("decode software public key: %w", err)
	}
	ok, err := pub.Verify(message, signature)
	if err != nil {
		return fmt.Errorf("verify software identity signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("software identity signature invalid")
	}
	return nil
}

// Verify checks the certificate chain in the bundle.
// Returns nil if the chain is valid and the AK cert's public key matches
// the identity's public key.
func (a *AttestationBundle) Verify(id *Identity) error {
	if a == nil {
		return fmt.Errorf("no attestation bundle")
	}

	// Parse certs
	mfrCA, err := x509.ParseCertificate(a.ManufacturerCA)
	if err != nil {
		return fmt.Errorf("parse manufacturer CA: %w", err)
	}
	ekCert, err := x509.ParseCertificate(a.EKCert)
	if err != nil {
		return fmt.Errorf("parse EK cert: %w", err)
	}
	akCert, err := x509.ParseCertificate(a.AKCert)
	if err != nil {
		return fmt.Errorf("parse AK cert: %w", err)
	}

	// Verify EK cert is signed by manufacturer CA
	roots := x509.NewCertPool()
	roots.AddCert(mfrCA)
	if _, err := ekCert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		return fmt.Errorf("EK cert not signed by manufacturer CA: %w", err)
	}

	// Verify AK cert is signed by EK (or intermediate)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(ekCert)
	if _, err := akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return fmt.Errorf("AK cert chain invalid: %w", err)
	}

	// Verify AK cert public key matches our identity public key
	idPub, err := id.PrivKey.GetPublic().Raw()
	if err != nil {
		return fmt.Errorf("get identity public key: %w", err)
	}
	akPub, err := x509.MarshalPKIXPublicKey(akCert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal AK public key: %w", err)
	}
	// Compare raw bytes
	rawAKPub := akCert.PublicKey.(crypto.PublicKey)
	_ = rawAKPub
	if !equalPublicKeys(idPub, akCert) {
		return fmt.Errorf("identity public key does not match AK cert public key")
	}
	_ = akPub

	return nil
}

// equalPublicKeys checks that the raw libp2p public key bytes match the
// public key in the x509 certificate.
func equalPublicKeys(libp2pPubRaw []byte, cert *x509.Certificate) bool {
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	// libp2p raw P-256 key is the uncompressed point (65 bytes).
	// x509 PKIX wraps it in an AlgorithmIdentifier + BIT STRING.
	// Compare by re-parsing the libp2p key and the cert key.
	libp2pPub, err := libp2pcrypto.UnmarshalECDSAPublicKey(libp2pPubRaw)
	if err != nil {
		return false
	}
	libp2pPubDER, err := x509.MarshalPKIXPublicKey(libp2pPub)
	if err != nil {
		return false
	}
	if len(certPubDER) != len(libp2pPubDER) {
		return false
	}
	for i := range certPubDER {
		if certPubDER[i] != libp2pPubDER[i] {
			return false
		}
	}
	return true
}

// KnownManufacturerCAs is the set of trusted TPM manufacturer root CA subjects.
// Used to decide whether to trust an attestation bundle from a remote peer.
var KnownManufacturerCAs = []string{
	"Infineon OPTIGA(TM) TPM 2.0 ECC CA 032",
	"Infineon OPTIGA(TM) TPM RSA Root CA",
	"STMicroelectronics TPM EK Intermediate CA 02",
	"STMicroelectronics TPM EK Root CA 02",
	"NXP TPM EK Root CA 05",
	"Intel Platform Firmware TPM CA",
	"NPCT TPM EK Root CA", // Nuvoton
	"IFX TPM EK Root CA",  // Infineon alternate
}
