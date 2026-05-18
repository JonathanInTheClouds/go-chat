# chat

A terminal-native encrypted 1:1 chat tool written in Go.

## Features

- **End-to-end encryption** via [Noise XX](https://noiseprotocol.org/) handshake (ChaCha20-Poly1305, forward secrecy)
- **Mutual authentication** — each peer proves ownership of their identity keys before the session opens
- **Trust-on-first-use (TOFU)** with persistent known-peers store and fingerprint pinning
- **Explicit session admission** — both sides must accept before entering the chat UI
- **Encrypted file transfer** in-band over the established session
- **Memory-only mode** — ephemeral identity, no disk state, no file transfer
- **Panic wipe** (`Ctrl+W`) — destroys identity and trust files and exits immediately
- **Terminal UI** powered by [Bubble Tea](https://github.com/charmbracelet/bubbletea)

## Installation

```bash
go install chat@latest
```

Or build from source:

```bash
git clone https://github.com/JonathanInTheClouds/go-chat.git
cd go-chat
go build -o chat ./cmd/chat
```

## Quick Start

### Step 1 — Find your IP address

```bash
ipconfig getifaddr en0
```

### Step 2 — First time connecting (both sides run this)

**Person hosting:**
```bash
go run ./cmd/chat serve --name Alice --peer bob --allow-untrusted --listen 0.0.0.0:8888
```

**Person connecting** (replace `192.168.1.10` with the host's IP):
```bash
go run ./cmd/chat connect --name Bob --peer alice --allow-untrusted 192.168.1.10:8888
```

`--allow-untrusted` is only needed the first time. It pins the peer's fingerprint so future connections are verified automatically.

### Step 3 — Reconnecting (after first contact)

**Person hosting:**
```bash
go run ./cmd/chat serve --name Alice --peer bob --listen 0.0.0.0:8888
```

**Person connecting:**
```bash
go run ./cmd/chat connect --name Bob --peer alice 192.168.1.10:8888
```

### Local testing (two terminals, same machine)

**Terminal 1:**
```bash
go run ./cmd/chat serve --name Alice --peer bob --allow-untrusted --listen 0.0.0.0:8888
```

**Terminal 2:**
```bash
go run ./cmd/chat connect --name Bob --peer alice --allow-untrusted localhost:8888
```

## Usage

```
chat serve [--listen host:port] [--ephemeral] [--identity path] [--known-peers path]
           [--peer label] [--allow-untrusted] [--memory-only]

chat connect [--ephemeral] [--identity path] [--known-peers path]
             [--peer label] [--allow-untrusted] [--memory-only] host:port

chat genkey [--identity path] [--force]
chat genkey --ephemeral
chat fingerprint [--ephemeral] [--identity path]
chat wipe [--identity path]

chat trust list   [--known-peers path]
chat trust set    [--known-peers path] <label> <fingerprint>
chat trust remove [--known-peers path] <label>
```

### Flags

| Flag | Description |
|---|---|
| `--name name` | Your display name shown to the peer in chat (defaults to system username) |
| `--listen host:port` | Address to listen on (default `0.0.0.0:7777`) |
| `--peer label` | Local label for the remote peer used in the trust store |
| `--allow-untrusted` | Accept first contact or a changed peer fingerprint and persist trust |
| `--memory-only` | Use an ephemeral identity; disable disk persistence and file transfer |
| `--ephemeral` | Use a throwaway in-memory identity (does not affect trust store) |
| `--identity path` | Override the default identity file path |
| `--known-peers path` | Override the default known peers file path |
| `--force` | Overwrite an existing persistent identity when running `genkey` |

## In-Chat Commands

| Command | Description |
|---|---|
| `/send <path>` | Send a file to the peer (disabled in memory-only mode) |
| `/quit` | End the session and exit |
| `Esc` / `Ctrl+C` | End the session and exit |
| `Ctrl+W` | **Panic wipe** — delete identity + trust files and exit immediately |
| `PgUp` / `PgDn` | Scroll the message transcript |

## Identity and Trust

Each peer has two keys:

- **Ed25519** signing key — used to prove identity
- **X25519** key agreement key — used as the Noise static key for the handshake

A **fingerprint** is derived as `SHA-256(ed25519_pub || x25519_pub)`, displayed as colon-separated hex pairs (e.g., `AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90`).

Trust entries are stored at `~/.config/chat/known_peers.json`. The identity file lives at `~/.config/chat/identity.json`. Both paths can be overridden with flags.

### First Contact

Neither side trusts an unknown peer by default. Pass `--allow-untrusted` on both sides the first time:

```bash
# Alice (hosting)
go run ./cmd/chat serve --name Alice --peer bob --allow-untrusted --listen 0.0.0.0:8888

# Bob (connecting)
go run ./cmd/chat connect --name Bob --peer alice --allow-untrusted 192.168.1.10:8888
```

After the first session, the fingerprint is pinned. Future connections succeed without `--allow-untrusted`.

### Fingerprint Rotation

If a peer's fingerprint changes (key rotation, new device), the connection is blocked until `--allow-untrusted` is passed again to accept and re-pin the new fingerprint.

## Runtime Modes

### Normal (persistent)

Default behavior. Identity and trust state persist across runs. Received files are saved to `./received/`.

### Memory-only (`--memory-only`)

```bash
chat serve --memory-only
chat connect --memory-only host:port
```

- Ephemeral in-memory identity (rotates every run)
- No trust state written to disk
- File transfer disabled
- No `received/` directory created

A persistent peer will see a memory-only peer as a new identity on every connection and will require `--allow-untrusted` each time unless trust is managed manually with `chat trust set`.

## File Transfer

Send a file during an active chat session:

```
/send /path/to/file.pdf
```

Files are transferred encrypted, in-band, over the established Noise session. The receiver saves them under `./received/` in the current working directory. Filename collisions are resolved automatically (`file_1.pdf`, `file_2.pdf`, etc.).

File transfer is disabled in memory-only mode.

## Security Notes

- All traffic after the handshake is encrypted with ChaCha20-Poly1305.
- The Noise XX pattern provides mutual authentication and forward secrecy.
- No message history is written to disk; the transcript exists only in process memory for the duration of the session.
- The app does not yet implement cryptographic memory zeroization — Go's GC controls object lifetime.
- Panic wipe (`Ctrl+W`) destroys the identity and trust files but does not attempt to delete previously received files.
