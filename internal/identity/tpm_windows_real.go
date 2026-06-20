//go:build windows

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	tpmKeyName  = "DeskAccess TPM Identity"
	tpmCertFile = "tpm_identity.cer"

	errorSuccess    uintptr = 0
	nteBadKeyset    uintptr = 0x80090016
	bcryptECDSAP256 uint32  = 0x31534345
	ncryptOverwrite         = 0x00000080
)

var (
	ncrypt                  = syscall.NewLazyDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

// LoadOrCreateTPM creates/loads a non-exportable P-256 key in the Windows TPM
// KSP and creates a self-signed app identity certificate from it.
func LoadOrCreateTPM(identityDir string) (*Identity, error) {
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return nil, err
	}
	key, err := openOrCreatePlatformKey(tpmKeyName)
	if err != nil {
		return nil, err
	}

	certPath := filepath.Join(identityDir, tpmCertFile)
	certDER, cert, err := loadOrCreateTPMCert(certPath, key)
	if err != nil {
		key.Close()
		return nil, err
	}
	manufacturer := cert.Issuer.CommonName
	if manufacturer == "" {
		manufacturer = "Microsoft Platform Crypto Provider"
	}
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

func openOrCreatePlatformKey(name string) (*ncryptKey, error) {
	providerName, _ := syscall.UTF16PtrFromString("Microsoft Platform Crypto Provider")
	keyName, _ := syscall.UTF16PtrFromString(name)
	algName, _ := syscall.UTF16PtrFromString("ECDSA_P256")

	var provider uintptr
	if st := ncryptStatus(procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(providerName)), 0)); st != nil {
		return nil, fmt.Errorf("open TPM provider: %w", st)
	}
	defer procFreeObject.Call(provider)

	var key uintptr
	st := ncryptStatus(procOpenKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(keyName)), 0, 0))
	if st == nil {
		return &ncryptKey{h: key}, nil
	}
	if st.code != nteBadKeyset {
		return nil, fmt.Errorf("open TPM key: %w", st)
	}

	if st := ncryptStatus(procCreatePersistedKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algName)), uintptr(unsafe.Pointer(keyName)), 0, ncryptOverwrite)); st != nil {
		return nil, fmt.Errorf("create TPM key: %w", st)
	}
	if st := ncryptStatus(procFinalizeKey.Call(key, 0)); st != nil {
		procFreeObject.Call(key)
		return nil, fmt.Errorf("finalize TPM key: %w", st)
	}
	return &ncryptKey{h: key}, nil
}

func loadOrCreateTPMCert(path string, key *ncryptKey) ([]byte, *x509.Certificate, error) {
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
			CommonName: "Microsoft Platform Crypto Provider",
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

type ncryptKey struct {
	h   uintptr
	pub *ecdsa.PublicKey
}

func (k *ncryptKey) Close() {
	if k != nil && k.h != 0 {
		procFreeObject.Call(k.h)
		k.h = 0
	}
}

func (k *ncryptKey) Public() crypto.PublicKey {
	if k.pub != nil {
		return k.pub
	}
	pub, err := k.exportPublic()
	if err != nil {
		return nil
	}
	k.pub = pub
	return pub
}

func (k *ncryptKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) && len(digest) != opts.HashFunc().Size() {
		h := sha256.Sum256(digest)
		digest = h[:]
	}
	var size uint32
	if st := ncryptStatus(procSignHash.Call(k.h, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0, uintptr(unsafe.Pointer(&size)), 0)); st != nil {
		return nil, fmt.Errorf("TPM sign size: %w", st)
	}
	raw := make([]byte, size)
	if st := ncryptStatus(procSignHash.Call(k.h, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&size)), 0)); st != nil {
		return nil, fmt.Errorf("TPM sign: %w", st)
	}
	raw = raw[:size]
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("unexpected ECDSA signature length %d", len(raw))
	}
	half := len(raw) / 2
	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}

func (k *ncryptKey) exportPublic() (*ecdsa.PublicKey, error) {
	blobType, _ := syscall.UTF16PtrFromString("ECCPUBLICBLOB")
	var size uint32
	if st := ncryptStatus(procExportKey.Call(k.h, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)); st != nil {
		return nil, fmt.Errorf("export TPM public size: %w", st)
	}
	blob := make([]byte, size)
	if st := ncryptStatus(procExportKey.Call(k.h, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&size)), 0)); st != nil {
		return nil, fmt.Errorf("export TPM public: %w", st)
	}
	if len(blob) < 8 {
		return nil, fmt.Errorf("invalid TPM public blob")
	}
	magic := uint32(blob[0]) | uint32(blob[1])<<8 | uint32(blob[2])<<16 | uint32(blob[3])<<24
	cbKey := uint32(blob[4]) | uint32(blob[5])<<8 | uint32(blob[6])<<16 | uint32(blob[7])<<24
	if magic != bcryptECDSAP256 || cbKey == 0 || len(blob) < int(8+2*cbKey) {
		return nil, fmt.Errorf("unsupported TPM public blob")
	}
	x := new(big.Int).SetBytes(blob[8 : 8+cbKey])
	y := new(big.Int).SetBytes(blob[8+cbKey : 8+2*cbKey])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("TPM public key is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

type ncryptError struct {
	code uintptr
}

func (e *ncryptError) Error() string {
	return fmt.Sprintf("NCrypt status 0x%08x", e.code)
}

func ncryptStatus(r1 uintptr, _ uintptr, _ error) *ncryptError {
	if r1 == errorSuccess {
		return nil
	}
	return &ncryptError{code: r1}
}
