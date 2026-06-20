package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestAttestationKeyThumbprintUsesAKPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certDER := selfSignedTestCert(t, key, big.NewInt(1))
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))

	got := (&AttestationBundle{AKCert: certDER}).AttestationKeyThumbprint()
	if got != want {
		t.Fatalf("AttestationKeyThumbprint() = %q, want %q", got, want)
	}

	reissuedDER := selfSignedTestCert(t, key, big.NewInt(2))
	reissued := (&AttestationBundle{AKCert: reissuedDER}).AttestationKeyThumbprint()
	if reissued != got {
		t.Fatalf("reissued cert thumbprint = %q, want stable %q", reissued, got)
	}
}

func TestVerifyTPMProofRejectsReplayMessage(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certDER := selfSignedTestCert(t, key, big.NewInt(1))
	att := &AttestationBundle{AKCert: certDER}
	message := []byte("fresh transcript")
	sum := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := VerifyTPMProof(att, att.AttestationKeyThumbprint(), message, sig); err != nil {
		t.Fatalf("VerifyTPMProof fresh message: %v", err)
	}
	if err := VerifyTPMProof(att, att.AttestationKeyThumbprint(), []byte("replayed transcript"), sig); err == nil {
		t.Fatal("VerifyTPMProof accepted replayed transcript")
	}
}

func selfSignedTestCert(t *testing.T, key *ecdsa.PrivateKey, serial *big.Int) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}
