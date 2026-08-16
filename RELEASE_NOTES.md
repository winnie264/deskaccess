# Release Notes

## 0.1.1

- Allow authenticated tunnel session tokens to open multiple short-lived app streams.
- Limit session tokens to 2 minutes and 16 uses to support RDP without restoring long-lived replay risk.
- Keep pairing links active until revoked or deleted.
- Continue consuming one-time links after first use.
- Tighten Windows IPC/dashboard process validation so local control requests must come from the trusted DeskAccess executable.
- Validate iroh sidecar tickets before using or storing them, including refreshed tickets returned during pairing and reconnect.
- Bind machine identity proofs to the DeskAccess node key to prevent transport-peer or crafted-invite identity confusion.
- Shorten tunnel session-token lifetime and protect SessionStore with internal locking.
- Clarify TPM support as hardware-backed identity-key proof, not full manufacturer-chain attestation.
- Update pairing and protocol tests for the new behavior.
