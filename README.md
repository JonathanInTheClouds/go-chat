# chat

A terminal-native encrypted 1:1 chat tool written in Go.

## Features

- **End-to-end encryption** via [Noise XX](https://noiseprotocol.org/) handshake (ChaCha20-Poly1305, forward secrecy)
- **Mutual authentication** — each peer proves ownership of their identity keys before the session opens
- **Trust-on-first-use (TOFU)** with persistent known-peers store and fingerprint pinning
- **Fingerprint confirmation prompt** — verify peer identity out-of-band before connecting
- **Passphrase-protected identity** — keys at rest are encrypted with argon2id + AES-256-GCM
- **Explicit session admission** — both sides must accept before entering the chat UI
- **Encrypted file transfer** in-band over the established session
- **Memory-only mode** — ephemeral identity, no disk state, no file transfer
- **Panic wipe** (`Ctrl+W`) — destroys identity, trust files, and received directory and exits immediately
- **Per-IP rate limiting** on the server to block reconnect spam
- **Terminal UI** powered by [Bubble Tea](https://github.com/charmbracelet/bubbletea)
- **Tab completion** for shell commands and in-chat file paths

## Installation

### Option 1 — Install script (recommended)

Auto-detects your OS and architecture, downloads the right binary, and puts it on your PATH.

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/JonathanInTheClouds/go-chat/main/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/JonathanInTheClouds/go-chat/main/install.ps1 | iex
```

Or grab a binary directly from the [releases page](https://github.com/JonathanInTheClouds/go-chat/releases).

### Option 2 — go install

Requires Go 1.21+:

```bash
go install github.com/JonathanInTheClouds/go-chat/cmd/chat@latest
```

### Option 3 — Build from source

```bash
git clone https://github.com/JonathanInTheClouds/go-chat.git
cd go-chat
go build -o chat ./cmd/chat
```

## Shell Completion

Enable tab completion for commands and flags. Shell is auto-detected when no argument is given.

```bash
# bash — add to ~/.bashrc
eval "$(chat completion bash)"

# zsh — add to ~/.zshrc
eval "$(chat completion zsh)"

# fish — add to ~/.config/fish/config.fish
chat completion fish | source

# PowerShell — add to $PROFILE
Invoke-Expression (& chat completion powershell)
```

## Quick Start

### Step 1 — Find your IP address

```bash
# macOS
ipconfig getifaddr en0

# Linux
ip route get 1 | awk '{print $7; exit}'
```

### Step 2 — First time connecting (both sides run this)

**Person hosting:**
```bash
chat serve -n Alice -u
```

**Person connecting** (replace `192.168.1.10` with the host's IP):
```bash
chat connect -n Bob -u 192.168.1.10:7777
```

`-u` (`--allow-untrusted`) is only needed the first time. It pins each other's fingerprint so future connections are verified automatically. The peer's display name is used as their trust label automatically — no need to set `--peer` unless you want a custom label.

### Step 3 — Reconnecting (after first contact)

**Person hosting:**
```bash
chat serve -n Alice
```

**Person connecting:**
```bash
chat connect -n Bob 192.168.1.10:7777
```

### Local testing (two terminals, same machine)

**Terminal 1:**
```bash
chat serve -n Alice -u
```

**Terminal 2:**
```bash
chat connect -n Bob -u localhost:7777
```

### Connect over the internet via tunnel

No port forwarding required. The host gets a public address via [bore.pub](https://bore.pub):

**Person hosting:**
```bash
chat serve -n Alice -u --tunnel
```

The tunnel URL is printed on startup — share it with your peer:

```
tunnel ready: bore.pub:12345
share with your friend:
  chat connect -n <name> -u bore.pub:12345
```

### Memory-only mode (no identity or trust saved to disk)

Use this when you want a session that leaves no trace. Nothing is written to disk and file transfer is disabled.

**Person hosting:**
```bash
chat serve -n Alice -m -u
```

**Person connecting:**
```bash
chat connect -n Bob -m -u 192.168.1.10:7777
```

## Usage

```
chat serve [-n name] [-p peer] [-u] [-m] [--listen host:port] [--tunnel]
chat connect [-n name] [-p peer] [-u] [-m] host:port

chat genkey [--ephemeral] [--force]
chat fingerprint [--ephemeral]
chat wipe [--peers]

chat trust list
chat trust set <label> <fingerprint>
chat trust remove <label>

chat completion [bash|zsh|fish|powershell]
```

### Flags

| Flag | Short | Description |
|---|---|---|
| `--name name` | `-n` | Your display name shown to the peer (defaults to system username) |
| `--peer label` | `-p` | Label for the remote peer in the trust store (defaults to the peer's display name) |
| `--allow-untrusted` | `-u` | Accept first contact or a changed peer fingerprint and persist trust |
| `--memory-only` | `-m` | Ephemeral identity, no disk state, no file transfer |
| `--no-passphrase` | | Skip passphrase protection for the identity file |
| `--listen host:port` | | Address to listen on, serve only (default `0.0.0.0:7777`) |
| `--tunnel` | | Expose the server via a bore.pub tunnel (serve only) |
| `--ephemeral` | | Throwaway in-memory identity for `genkey` / `fingerprint` |
| `--force` | | Overwrite an existing persistent identity when running `genkey` |
| `--peers` | | Also delete the trust store when running `wipe` |
| `--received` | | Also securely wipe the `received/` directory when running `wipe` |

### Advanced flags

These are hidden from `--help` but work on any command that reads from disk:

| Flag | Description |
|---|---|
| `--identity path` | Override the default identity file location |
| `--known-peers path` | Override the default known peers file location |

## In-Chat Commands

| Command | Description |
|---|---|
| `/send <path>` | Send a file to the peer (Tab completes paths; disabled in memory-only mode) |
| `/quit` | End the session and exit |
| `Tab` | Complete `/send` paths and slash commands |
| `Esc` / `Ctrl+C` | End the session and exit |
| `Ctrl+W` | **Panic wipe** — securely wipe identity, trust store, and received/ then exit |
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
chat serve --name Alice --peer bob --allow-untrusted

# Bob (connecting)
chat connect --name Bob --peer alice --allow-untrusted 192.168.1.10:7777
```

After the first session, the fingerprint is pinned. Future connections succeed without `--allow-untrusted`.

### Fingerprint Rotation

If a peer's fingerprint changes (key rotation, new device), the connection is blocked until `--allow-untrusted` is passed again to accept and re-pin the new fingerprint.

## Passphrase Protection

By default, `chat` encrypts your identity file at rest using a passphrase you choose when the identity is first created. The file format uses **argon2id** (time=4, memory=128 MiB) to derive a key, then **AES-256-GCM** to encrypt the key material.

### First run

The first time you run `chat serve` or `chat connect` (or explicitly with `chat genkey`), you are prompted for a new passphrase:

```
new identity passphrase (leave blank to skip encryption):
confirm passphrase:
```

Leaving the prompt blank skips encryption and saves the identity as plaintext.

### Subsequent runs

Every command that loads your identity (serve, connect, fingerprint) prompts for the passphrase if the file is encrypted:

```
identity passphrase:
```

### Skipping passphrase protection

Pass `--no-passphrase` to any command to skip the prompt entirely and store or load the identity as plaintext:

```bash
chat genkey --no-passphrase
chat serve --no-passphrase -n Alice -p bob -u
chat connect --no-passphrase -n Bob -p alice -u 192.168.1.10:7777
```

### Upgrading an existing plaintext identity

If you created an identity before v0.3.0 (or used `--no-passphrase`), you can add passphrase protection by regenerating with `--force`:

```bash
chat genkey --force    # prompts for a new passphrase, overwrites the identity file
```

Note: regenerating creates a new keypair. Your peer will need to re-trust your new fingerprint with `--allow-untrusted`.

## Wiping State

```bash
chat wipe                        # delete identity only
chat wipe --peers                # delete identity + trust store
chat wipe --received             # delete identity + received/ directory
chat wipe --peers --received     # full reset: identity + trust + received/
```

`Ctrl+W` inside a chat session wipes identity, trust store, and the `received/` directory, then exits immediately.

## Runtime Modes

### Normal (persistent)

Default behavior. Identity and trust state persist across runs. Received files are saved to `./received/`.

### Memory-only (`-m` / `--memory-only`)

```bash
chat serve -m
chat connect -m host:port
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
- Identity keys at rest are encrypted with AES-256-GCM, derived via argon2id (time=4, memory=128 MiB). Pass `--no-passphrase` to store keys as plaintext.
- No message history is written to disk; the transcript exists only in process memory for the duration of the session.
- Panic wipe (`Ctrl+W`) overwrites identity, trust store, and received files with zeros before removing them.
- The app does not yet implement cryptographic memory zeroization — Go's GC controls object lifetime.
