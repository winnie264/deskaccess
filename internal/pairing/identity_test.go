package pairing

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/rdpanywhere/rdpanywhere/internal/protocol"
)

func TestIdentityInfoIncludesTPMRootThumbprint(t *testing.T) {
	root := []byte("manufacturer-root-cert")
	wantSum := sha256.Sum256(root)
	want := strings.ToUpper(hex.EncodeToString(wantSum[:]))

	backend, hardware, vendor, version, thumbprint := identityInfoFromAttestation(&protocol.TPMAttestation{
		Manufacturer:   "Test TPM",
		TPMVersion:     "2.0",
		ManufacturerCA: root,
	})

	if backend != "tpm" {
		t.Fatalf("backend = %q, want tpm", backend)
	}
	if !hardware {
		t.Fatal("hardware = false, want true")
	}
	if vendor != "Test TPM" {
		t.Fatalf("vendor = %q, want Test TPM", vendor)
	}
	if version != "2.0" {
		t.Fatalf("version = %q, want 2.0", version)
	}
	if thumbprint != want {
		t.Fatalf("thumbprint = %q, want %q", thumbprint, want)
	}
}
