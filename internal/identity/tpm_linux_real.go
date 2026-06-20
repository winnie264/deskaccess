//go:build linux

package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	linuxTPMCertFile = "tpm_identity.cer"
)

// LoadOrCreateTPM creates/loads an ECC TPM key using tpm2-tools. This supports
// Linux desktops and Raspberry Pi devices with a TPM 2.0 module exposed as
// /dev/tpmrm0 or /dev/tpm0.
func LoadOrCreateTPM(identityDir string) (*Identity, error) {
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return nil, err
	}
	if !hasTPMDevice() {
		return nil, fmt.Errorf("no TPM device found")
	}
	if _, err := exec.LookPath("tpm2_createprimary"); err != nil {
		return nil, fmt.Errorf("tpm2-tools not installed: %w", err)
	}
	key, err := loadOrCreateLinuxTPMKey(identityDir)
	if err != nil {
		return nil, err
	}
	certPath := filepath.Join(identityDir, linuxTPMCertFile)
	certDER, _, err := loadOrCreateLinuxTPMCert(certPath, key)
	if err != nil {
		return nil, err
	}
	manufacturer := linuxTPMManufacturer()
	return &Identity{
		Backend: BackendTPM,
		Signer:  key,
		Attestation: &AttestationBundle{
			AKCert:       certDER,
			Manufacturer: manufacturer,
			TPMVersion:   "2.0",
		},
	}, nil
}

func hasTPMDevice() bool {
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return true
	}
	return false
}

func loadOrCreateLinuxTPMKey(dir string) (*tpm2ToolKey, error) {
	primary := filepath.Join(dir, "tpm_primary.ctx")
	pubFile := filepath.Join(dir, "tpm_key.pub")
	privFile := filepath.Join(dir, "tpm_key.priv")
	keyCtx := filepath.Join(dir, "tpm_key.ctx")
	pubPEM := filepath.Join(dir, "tpm_public.pem")

	if fileExists(keyCtx) && fileExists(pubPEM) {
		return newTPM2ToolKey(keyCtx, pubPEM)
	}
	if err := runTPM2("tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", primary); err != nil {
		return nil, fmt.Errorf("create TPM primary: %w", err)
	}
	if err := runTPM2("tpm2_create", "-C", primary, "-G", "ecc", "-u", pubFile, "-r", privFile); err != nil {
		return nil, fmt.Errorf("create TPM key: %w", err)
	}
	if err := runTPM2("tpm2_load", "-C", primary, "-u", pubFile, "-r", privFile, "-c", keyCtx); err != nil {
		return nil, fmt.Errorf("load TPM key: %w", err)
	}
	if err := runTPM2("tpm2_readpublic", "-c", keyCtx, "-o", pubPEM, "-f", "pem"); err != nil {
		return nil, fmt.Errorf("read TPM public key: %w", err)
	}
	return newTPM2ToolKey(keyCtx, pubPEM)
}

func loadOrCreateLinuxTPMCert(path string, key *tpm2ToolKey) ([]byte, *x509.Certificate, error) {
	if der, err := os.ReadFile(path); err == nil {
		cert, err := x509.ParseCertificate(der)
		if err == nil && time.Now().Before(cert.NotAfter) {
			return der, cert, nil
		}
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "DeskAccess TPM Identity",
			Organization: []string{"DeskAccess"},
		},
		Issuer: pkix.Name{
			CommonName: linuxTPMManufacturer(),
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("create TPM cert: %w", err)
	}
	if err := os.WriteFile(path, der, 0600); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, cert, nil
}

type tpm2ToolKey struct {
	ctxPath string
	pub     *ecdsa.PublicKey
}

func newTPM2ToolKey(ctxPath, pubPEM string) (*tpm2ToolKey, error) {
	data, err := os.ReadFile(pubPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode TPM public PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("TPM public key is %T, want ECDSA", pubAny)
	}
	return &tpm2ToolKey{ctxPath: ctxPath, pub: pub}, nil
}

func (k *tpm2ToolKey) Public() crypto.PublicKey {
	return k.pub
}

func (k *tpm2ToolKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) && len(digest) != opts.HashFunc().Size() {
		h := sha256.Sum256(digest)
		digest = h[:]
	}
	tmpDir, err := os.MkdirTemp("", "DeskAccess-tpm-sign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	digestFile := filepath.Join(tmpDir, "digest.bin")
	sigFile := filepath.Join(tmpDir, "sig.bin")
	if err := os.WriteFile(digestFile, digest, 0600); err != nil {
		return nil, err
	}
	hashAlg := "sha256"
	if opts != nil && opts.HashFunc() == crypto.SHA384 {
		hashAlg = "sha384"
	}
	if err := runTPM2("tpm2_sign", "-c", k.ctxPath, "-g", hashAlg, "-d", "-f", "plain", "-o", sigFile, digestFile); err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}
	raw, err := os.ReadFile(sigFile)
	if err != nil {
		return nil, err
	}
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("unexpected TPM signature length %d", len(raw))
	}
	half := len(raw) / 2
	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}

func runTPM2(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s: %s", name, msg)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func linuxTPMManufacturer() string {
	if data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major"); err == nil && len(bytes.TrimSpace(data)) > 0 {
		return "Linux TPM " + string(bytes.TrimSpace(data)) + ".0"
	}
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		return "Raspberry Pi TPM 2.0"
	}
	return "Linux TPM 2.0"
}
