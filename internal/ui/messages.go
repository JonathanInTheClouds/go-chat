package ui

const VolatileIdentityNotice = "Keys shown here are generated in memory for this process only and are not persisted."
const PersistentIdentityCreatedNotice = "Persistent identity created at %s."
const PersistentIdentityLoadedNotice = "Using persistent identity at %s."
const MemoryOnlyIdentityNotice = "Memory-only mode is using an ephemeral in-memory identity for this session."
const MemoryOnlyModeNotice = "Memory-only mode enabled. App-managed disk persistence and file transfer are disabled for this session."
const MemoryOnlyPeerNotice = "Memory-only mode: peer %s is trusted only for this live session. Fingerprint: %s."
const WipeMessage = "Persistent identity removed from %s."
const SecureSessionReady = "Secure Noise session established. Encryption: ChaCha20-Poly1305. Forward secrecy enabled."
const PeerTrustNewNotice = "First contact for %s. Stored peer fingerprint %s."
const PeerTrustMatchNotice = "Peer identity for %s matches the stored fingerprint."
const PeerTrustMismatchNotice = "WARNING: peer identity for %s changed. expected %s but observed %s."
const PeerTrustNewBlockedNotice = "Untrusted peer %s with fingerprint %s. Re-run with --allow-untrusted to trust and continue."
const PeerTrustMismatchBlockedNotice = "Blocked peer %s because the fingerprint changed. expected %s but observed %s. Re-run with --allow-untrusted after verification to rotate trust."
const PeerTrustAllowedMismatchNotice = "Peer identity for %s was re-trusted with fingerprint %s."
const TrustSetNotice = "Stored peer fingerprint for %s as %s."
const TrustRemoveNotice = "Removed stored peer fingerprint for %s."
const TrustMissingNotice = "No stored peer fingerprint exists for %s."
const TrustEmptyNotice = "No known peers are stored."

func Usage() string {
	return `chat: encrypted terminal chat prototype

Usage:
  chat serve [--listen host:port] [--name name] [--ephemeral] [--identity path] [--known-peers path] [--peer label] [--allow-untrusted] [--memory-only]
  chat connect [--name name] [--ephemeral] [--identity path] [--known-peers path] [--peer label] [--allow-untrusted] [--memory-only] host:port
  chat genkey [--identity path] [--force]
  chat genkey --ephemeral
  chat fingerprint [--ephemeral] [--identity path]
  chat wipe [--identity path]
  chat trust list [--known-peers path]
  chat trust set [--known-peers path] <label> <fingerprint>
  chat trust remove [--known-peers path] <label>
`
}
