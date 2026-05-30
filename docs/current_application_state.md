# Current Application State

This document describes the current implementation state of the encrypted terminal chat application as of the latest commits on `main`.

## Project Summary

The application is a terminal-native encrypted chat tool written in Go. Its original flow is 1:1 chat, and it now has an initial host-relayed group room mode for live text chat with more than two people.

Current foundations:

- Go application with `cmd/chat` entrypoint
- Bubble Tea TUI for live chat
- Direct TCP transport
- Noise `XX` handshake
- `X25519` static key for Noise
- `Ed25519` identity signing key
- Encrypted framed transport after handshake
- Persistent or ephemeral identity modes
- Persistent trust store or strict memory-only runtime mode
- Encrypted in-band file transfer in normal mode
- Host-relayed group rooms for live text chat

## Major Features Implemented

### Encrypted Session Establishment

- A peer-to-peer TCP connection is established with either:
  - `chat serve`
  - `chat connect host:port`
- The connection performs a Noise `XX` handshake.
- Each side exchanges signed identity material after the handshake.
- The app derives a peer fingerprint from:
  - `Ed25519` signing public key
  - `X25519` static public key

### Terminal UI

- Bubble Tea TUI is used for the live chat session.
- The UI includes:
  - header with mode, peer address, and fingerprints
  - scrollable transcript viewport
  - status banners
  - input field
  - status bar
- Quit paths:
  - `Esc`
  - `Ctrl+C`
  - `/quit`

### Trust Model

- The app supports persistent known-peer trust state.
- First contact and identity rotation are blocked by default.
- A session is only admitted automatically when the peer fingerprint matches the stored fingerprint.
- `--allow-untrusted` explicitly permits:
  - first contact
  - trust rotation after fingerprint change
- Trust management commands exist:
  - `chat trust list`
  - `chat trust set <label> <fingerprint>`
  - `chat trust remove <label>`

### Explicit Session Admission

- After the encrypted session is established and trust is checked, peers exchange an explicit session admission decision.
- Protocol messages:
  - `session_accept`
  - `session_reject`
- This prevents the previously bad UX where one side briefly entered chat before learning the remote side had rejected the session.

### Reconnect / Multi-Session Server Behavior

- `chat serve` now keeps listening across sequential sessions.
- When a chat session ends:
  - the client exits cleanly
  - the server returns to `waiting for peer...`
- This fixes the earlier one-session-only server behavior.

### Group Rooms

- `chat room serve <room-name>` starts a room host.
- `chat room join <host:port> <room-name>` joins an existing room.
- Each room member connects to the host with the existing Noise XX encrypted session and identity verification flow.
- The host admits trusted peers, maintains the member list, and relays group text messages to all other connected members.
- The group UI shows room metadata, member names, membership notices, and sender-attributed messages.
- Group file transfer is not implemented yet.
- Same-machine manual testing should use memory-only clients or separate identity paths so each terminal has a distinct cryptographic identity.

### File Transfer

- Normal mode supports encrypted in-band file transfer.
- TUI command:
  - `/send /full/path/to/file`
- File transfer uses chunked protocol messages:
  - `file_start`
  - `file_chunk`
  - `file_complete`
- Received files are saved under a local `received/` directory in the current working directory.

## Runtime Modes

### Normal Persistent Mode

Default behavior:

- persistent identity is loaded or created on disk
- persistent trust store is loaded or updated on disk
- file transfer is enabled

Persistent state currently includes:

- identity file
- known peers file

### Memory-Only Mode

Enabled with:

- `chat serve --memory-only`
- `chat connect --memory-only host:port`

Behavior:

- uses ephemeral in-memory identity only
- does not use persistent trust storage for the live session
- treats peer trust as live-session-only
- disables file transfer
- does not create the `received/` directory

Important consequence:

- A persistent peer will see a memory-only peer as a rotating identity across runs.
- Reconnects from a memory-only peer to a persistent peer will therefore require explicit trust approval on the persistent side if the same peer label is reused.

## Panic Wipe

The TUI supports panic wipe with:

- `Ctrl+W`

Current behavior:

- closes the active session immediately
- clears UI/session state on a best-effort basis
- deletes persistent identity and known-peers files if they exist
- exits the app

Scope:

- destructive for app-managed identity and trust state
- does not attempt to delete arbitrary user files
- does not attempt to delete already saved received files outside that specific app-managed identity/trust scope

## Current Command Surface

### Session Commands

- `chat serve [--listen host:port] [--peer label] [--allow-untrusted] [--memory-only]`
- `chat connect [--peer label] [--allow-untrusted] [--memory-only] host:port`
- `chat room serve <room-name> [--listen host:port] [--allow-untrusted] [--memory-only]`
- `chat room join <host:port> <room-name> [--peer label] [--allow-untrusted] [--memory-only]`

### Identity Commands

- `chat genkey [--identity path] [--force]`
- `chat genkey --ephemeral`
- `chat fingerprint [--ephemeral] [--identity path]`
- `chat wipe [--identity path]`

### Trust Commands

- `chat trust list [--known-peers path]`
- `chat trust set [--known-peers path] <label> <fingerprint>`
- `chat trust remove [--known-peers path] <label>`

## Storage and Memory Characteristics

### In-Memory

- live chat transcript
- live text input
- active session keys
- active encrypted/decrypted message payloads
- memory-only identity for `--memory-only` runs

### On Disk

In normal mode:

- persistent identity file
- known peers file
- received files from file transfer

### Important Security Note

The app is not “secure-memory” hardened yet.

Current limitations:

- no guaranteed cryptographic zeroization of all buffers
- Go GC still controls object lifetime
- UI transcript and message payloads remain in normal process memory while the app runs

So the app currently supports:

- no plaintext message persistence by default in chat history
- optional persistent identity/trust state
- a stricter `--memory-only` runtime mode

It does **not** yet guarantee full secure-memory semantics for all transient data.

## Known Good Behaviors Verified

Verified recently:

- normal first contact without `--allow-untrusted` is blocked
- normal first contact with `--allow-untrusted` succeeds and persists trust
- trusted reconnect succeeds without `--allow-untrusted`
- server continues listening across disconnects
- memory-only client can connect to a persistent peer at the transport level
- persistent peer correctly blocks changed fingerprints from a memory-only peer unless explicitly allowed
- explicit remote rejection is surfaced cleanly instead of flashing the TUI
- encrypted file transfer works in normal mode

## Important Constraints / Current UX Rules

- Trust is enforced on both peers independently.
- If both peers are persistent and neither has prior trust, both sides need explicit trust approval for the first session if they enforce first-contact blocking.
- Memory-only mode is intentionally incompatible with persistent trust continuity.
- File transfer is intentionally disabled in memory-only mode.

## Source Areas

Main implementation areas:

- `cmd/chat/main.go`
- `internal/app/app.go`
- `internal/net/session.go`
- `internal/protocol/frame.go`
- `internal/protocol/message.go`
- `internal/crypto/identity.go`
- `internal/crypto/store.go`
- `internal/trust/store.go`
- `internal/ui/chat.go`
- `internal/ui/messages.go`

## Recent Commit Landmarks

- `9527bda` Add project architecture docs
- `e79ab54` Build encrypted terminal chat prototype
- `b0fc7c6` Add memory-only mode and panic wipe
- `c203384` Keep server listening across sessions
- `b5a6bc2` Enforce peer trust failures
- `ae35141` Add explicit session admission rejection
