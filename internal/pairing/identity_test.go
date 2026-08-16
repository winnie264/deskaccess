package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rdpanywhere/rdpanywhere/internal/identity"
	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
	"github.com/rdpanywhere/rdpanywhere/internal/protocol"
	"github.com/rdpanywhere/rdpanywhere/internal/rendezvous"
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

func TestVerifyStoredIdentityRejectsChangedIdentity(t *testing.T) {
	pub := []byte("software-public-key")
	proof := &protocol.IdentityProof{
		MachineID: "machine-a",
		PublicKey: pub,
	}

	if err := verifyStoredIdentity(hex.EncodeToString(pub), "machine-a", proof); err != nil {
		t.Fatalf("same identity rejected: %v", err)
	}
	if err := verifyStoredIdentity(hex.EncodeToString(pub), "machine-b", proof); err == nil {
		t.Fatal("changed machine ID accepted")
	}
	if err := verifyStoredIdentity(hex.EncodeToString([]byte("other-key")), "machine-a", proof); err == nil {
		t.Fatal("changed software public key accepted")
	}
	if err := verifyStoredIdentity("", "", proof); err == nil {
		t.Fatal("missing stored identity accepted")
	}
}

func TestCanRepairStoredSoftwarePublicKeyRequiresMachineIDMatch(t *testing.T) {
	proof := &protocol.IdentityProof{
		MachineID: "machine-a",
		PublicKey: []byte("software-public-key"),
	}
	err := verifyStoredIdentity(hex.EncodeToString([]byte("old-wrong-key")), "machine-a", proof)
	if err == nil {
		t.Fatal("expected public key mismatch")
	}
	if !canRepairStoredSoftwarePublicKey(err, "machine-a", proof) {
		t.Fatal("expected repair to be allowed when verified machine ID matches")
	}
	if canRepairStoredSoftwarePublicKey(err, "machine-b", proof) {
		t.Fatal("repair allowed for different machine ID")
	}
}

func TestPairRequestNodeIDAllowsIrohTransportPeerToDiffer(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	nodeID, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}

	got, err := pairRequestNodeID(protocol.PairRequest{NodeID: nodeID.String()}, "sidecar-transport-peer", netbackend.BackendIroh)
	if err != nil {
		t.Fatalf("pairRequestNodeID: %v", err)
	}
	if got != nodeID.String() {
		t.Fatalf("node id = %q, want %q", got, nodeID)
	}

	_, err = pairRequestNodeID(protocol.PairRequest{}, "sidecar-transport-peer", netbackend.BackendIroh)
	if err == nil || !strings.Contains(err.Error(), "upgrade DeskAccess") {
		t.Fatalf("missing node id error = %v, want upgrade guidance", err)
	}
}

func TestIdentityProofUsesDeskAccessNodeIDNotIrohTransportPeer(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	id := &identity.Identity{PrivKey: key, Backend: identity.BackendSoftware}
	nodeID, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}

	hostID := "12D3KooWHostNode"
	transportPeer := "abdb7df6403a"
	window := rendezvous.TimeWindow(time.Now())
	msg := identityProofMessage("request", nodeID.String(), hostID, nil, nil, nil, "pairing", window)
	proof := &protocol.IdentityProof{
		Backend:       string(identity.BackendSoftware),
		MachineID:     id.MachineID(),
		PublicKey:     id.PublicKeyRaw(),
		NodePublicKey: id.PublicKeyRaw(),
		TimeWindow:    window,
	}
	if err := signTestIdentityProof(id, key, msg, proof); err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	if err := verifyIdentityProof(proof, nil, "request", nodeID.String(), hostID, nil, nil, nil, "pairing"); err != nil {
		t.Fatalf("verify with DeskAccess node id: %v", err)
	}
	if err := verifyIdentityProof(proof, nil, "request", transportPeer, hostID, nil, nil, nil, "pairing"); err == nil {
		t.Fatal("verify unexpectedly succeeded with iroh transport peer id")
	}
}

func TestIdentityProofRejectsClaimedNodeIDFromDifferentKey(t *testing.T) {
	_, victimPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate victim key: %v", err)
	}
	victimKey, err := libp2pcrypto.UnmarshalEd25519PrivateKey(victimPriv)
	if err != nil {
		t.Fatalf("unmarshal victim key: %v", err)
	}
	victimID, err := peer.IDFromPrivateKey(victimKey)
	if err != nil {
		t.Fatalf("victim peer id: %v", err)
	}

	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	attackerKey, err := libp2pcrypto.UnmarshalEd25519PrivateKey(attackerPriv)
	if err != nil {
		t.Fatalf("unmarshal attacker key: %v", err)
	}
	attackerIdentity := &identity.Identity{PrivKey: attackerKey, Backend: identity.BackendSoftware}

	hostID := "12D3KooWHostNode"
	window := rendezvous.TimeWindow(time.Now())
	msg := identityProofMessage("request", victimID.String(), hostID, nil, nil, nil, "trusted", window)
	attackerPub, err := attackerKey.GetPublic().Raw()
	if err != nil {
		t.Fatalf("attacker public key: %v", err)
	}
	proof := &protocol.IdentityProof{
		Backend:       string(identity.BackendSoftware),
		MachineID:     attackerIdentity.MachineID(),
		PublicKey:     attackerIdentity.PublicKeyRaw(),
		NodePublicKey: attackerPub,
		TimeWindow:    window,
	}
	if err := signTestIdentityProof(attackerIdentity, attackerKey, msg, proof); err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	if err := verifyIdentityProof(proof, nil, "request", victimID.String(), hostID, nil, nil, nil, "trusted"); err == nil {
		t.Fatal("verify accepted attacker key claiming victim node id")
	}
}

func signTestIdentityProof(id *identity.Identity, nodeKey libp2pcrypto.PrivKey, proofMessage []byte, proof *protocol.IdentityProof) error {
	sig, err := id.SignProof(proofMessage)
	if err != nil {
		return err
	}
	proof.Signature = sig
	nodeSig, err := nodeKey.Sign(identityBindingMessage(proofMessage, proof))
	if err != nil {
		return err
	}
	proof.NodeSignature = nodeSig
	return nil
}
