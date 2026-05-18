# chat

> **Encrypted, peer-to-peer terminal chat — no servers, no accounts, no metadata.**

```
Alice                                        Bob
─────────────────────────────────────────────────────
$ chat serve -n Alice -u               $ chat connect -n Bob -u 192.168.1.10:7777

identity passphrase: ****              identity passphrase: ****
listening on 0.0.0.0:7777

waiting for peer...
peer connected from 192.168.1.20       First contact with Alice
                                       Fingerprint: 12:34:56:78:90:AB:CD:EF:...
First contact with Bob                 Verify out-of-band. Proceed? [y/N] y
Fingerprint: AB:CD:EF:12:34:56:78:90
Verify out-of-band. Proceed? [y/N] y

┌─────────────────────────────── chat ───────────────────────────────┐
│ Bob: hey Alice                                                      │
│ Alice: hey! this connection is end-to-end encrypted                 │
│ Bob: nice — no Signal, no accounts, just us                         │
│ Alice: exactly                                                      │
│                                                                     │
│ > _                                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Why `chat`?

Most secure messaging tools require a phone number, an account, or a third-party server holding your metadata. `chat` skips all of that.

| | `chat` | Signal / iMessage | IRC / Matrix |
|---|---|---|---|
| Account required | No | Yes | Yes |
| Server in the middle | No | Yes | Yes |
| E2E encrypted | Yes | Yes | Varies |
| No metadata on disk | Yes (memory mode) | No | No |
| Works over LAN | Yes | No | No |
| Panic wipe | Yes | No | No |
| File transfer (E2E) | Yes | Yes | No |

Two terminals. One command each. Fully encrypted from the first byte.

---

## Features

### End-to-end encryption, always on

Every session is encrypted with **ChaCha20-Poly1305** using keys negotiated via the **[Noise XX](https://noiseprotocol.org/) protocol** — the same protocol used by WireGuard and Signal's X3DH. Both peers authenticate before the chat UI opens. Forward secrecy means past sessions stay private even if long-term keys are compromised.

### Zero-trust identity verification

Each peer has a cryptographic fingerprint derived from their Ed25519 signing key and X25519 key agreement key. On first contact you verify the fingerprint out-of-band (phone call, Signal message, etc.) and pin it. Future connections are verified automatically — a changed fingerprint is flagged and blocked until you re-verify with `--allow-untrusted`.

### No disk trace — memory-only mode

Run with `-m` and nothing touches the filesystem. Identity is generated fresh each session, no trust store is written, and file transfer is disabled. When you quit, the session is gone.

### Panic wipe

Press `Ctrl+W` from inside any chat session. The identity file, trust store, and received-files directory are overwritten with zeros, then deleted. The process exits immediately.

### Internet-ready without port forwarding

Pass `--tunnel` when hosting and `chat` opens a public bore.pub tunnel automatically. Share the printed address with your peer — no router configuration needed.

### Encrypted file transfer

Send files directly through the established encrypted session with `/send`. The receiver saves them to `./received/`. No third-party storage, no links, no size limits imposed by the tool.

### Passphrase-protected keys at rest

Your identity file is encrypted with **AES-256-GCM**, the key derived via **argon2id** (time=4, memory=128 MiB). Leave the prompt blank to skip encryption. Pass `--no-passphrase` to bypass the prompt entirely in scripts or CI.

### Polished terminal UI

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea). Scrollable message transcript, tab-completion for `/send` paths and slash commands, and a clean two-pane layout.

---

## Installation

### Option 1 — Install script (recommended)

Auto-detects OS and architecture, downloads the right binary, and puts it on your `PATH`.

**macOS / Linux**
```bash
curl -fsSL https://raw.githubusercontent.com/JonathanInTheClouds/go-chat/main/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://raw.githubusercontent.com/JonathanInTheClouds/go-chat/main/install.ps1 | iex
```

### Option 2 — `go install`

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

Grab a pre-built binary from the [releases page](https://github.com/JonathanInTheClouds/go-chat/releases).

---

## Quick Start

### LAN — two people on the same network

**Step 1** — Find your IP address.

```bash
# macOS
ipconfig getifaddr en0

# Linux
ip route get 1 | awk '{print $7; exit}'
```

**Step 2 — First contact** (both sides run this; `-u` is only needed once to exchange fingerprints).

```bash
# Host (Alice)
chat serve -n Alice -u

# Peer (Bob) — replace with Alice's IP
chat connect -n Bob -u 192.168.1.10:7777
```

Each side is shown the other's fingerprint. Verify it out-of-band (voice call, text, etc.), type `y`, and the chat opens.

**Step 3 — Reconnecting** (no `-u` needed; fingerprints are verified automatically).

```bash
# Host
chat serve -n Alice

# Peer
chat connect -n Bob 192.168.1.10:7777
```

---

### Internet — no port forwarding

```bash
# Host
chat serve -n Alice -u --tunnel
```

Output:
```
tunnel ready: bore.pub:12345
share with your friend:
  chat connect -n <name> -u bore.pub:12345
```

```bash
# Peer
chat connect -n Bob -u bore.pub:12345
```

---

### Local testing — two terminals, one machine

```bash
# Terminal 1
chat serve -n Alice -u

# Terminal 2
chat connect -n Bob -u localhost:7777
```

---

### Leave no trace — memory-only mode

Nothing is written to disk. Identity rotates every session. File transfer is disabled.

```bash
# Host
chat serve -n Alice -m -u

# Peer
chat connect -n Bob -m -u 192.168.1.10:7777
```

---

## Usage Reference

```
chat serve   [-n name] [-p label] [-u] [-m] [--listen host:port] [--tunnel]
chat connect [-n name] [-p label] [-u] [-m] host:port

chat genkey      [--ephemeral] [--force]
chat fingerprint [--ephemeral]
chat wipe        [--peers] [--received]

chat trust list
chat trust set    <label> <fingerprint>
chat trust remove <label>

chat completion [bash|zsh|fish|powershell]
```

### Flags

| Flag | Short | Description |
|---|---|---|
| `--name name` | `-n` | Display name shown to the peer (defaults to system username) |
| `--peer label` | `-p` | Trust store label for the remote peer (defaults to peer's display name) |
| `--allow-untrusted` | `-u` | Accept first contact or a changed fingerprint and persist trust |
| `--memory-only` | `-m` | Ephemeral identity, no disk state, no file transfer |
| `--no-passphrase` | | Skip passphrase protection for the identity file |
| `--listen host:port` | | Address to listen on (serve only; default `0.0.0.0:7777`) |
| `--tunnel` | | Expose the server via a bore.pub tunnel (serve only) |
| `--ephemeral` | | Throwaway in-memory identity for `genkey` / `fingerprint` |
| `--force` | | Overwrite an existing persistent identity when running `genkey` |
| `--peers` | | Also delete the trust store when running `wipe` |
| `--received` | | Also wipe the `received/` directory when running `wipe` |

**Advanced flags** (hidden from `--help`):

| Flag | Description |
|---|---|
| `--identity path` | Override the default identity file location |
| `--known-peers path` | Override the default known peers file location |

### In-chat commands

| Key / Command | Action |
|---|---|
| `/send <path>` | Send a file (Tab completes paths; disabled in memory-only mode) |
| `/quit` | End the session and exit |
| `Tab` | Complete `/send` paths and slash commands |
| `Esc` / `Ctrl+C` | End the session and exit |
| `Ctrl+W` | **Panic wipe** — zero-wipe identity, trust store, and `received/`, then exit |
| `PgUp` / `PgDn` | Scroll the message transcript |

---

## Shell Completion

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

---

## Identity and Trust

Each peer has two keys:

- **Ed25519** signing key — proves identity
- **X25519** key agreement key — Noise static key for the handshake

The **fingerprint** is `SHA-256(ed25519_pub || x25519_pub)`, shown as colon-separated hex (e.g., `AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90`).

Default file locations:

| File | Path |
|---|---|
| Identity | `~/.config/chat/identity.json` |
| Trust store | `~/.config/chat/known_peers.json` |
| Received files | `./received/` |

### Trust store operations

```bash
# List trusted peers
chat trust list

# Manually pin a fingerprint (useful for memory-only peers or pre-provisioning)
chat trust set alice 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF

# Remove a peer
chat trust remove alice
```

---

## Example Sessions

### First contact

```
$ chat serve -n Alice -u

identity passphrase:
Using persistent identity at ~/.config/chat/identity.json.
listening on 0.0.0.0:7777
waiting for peer...
peer connected from 192.168.1.20:54321

First contact with Bob
Their fingerprint: AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90

Verify this fingerprint with your peer out-of-band before continuing.
Proceed? [y/N] y
First contact for Bob. Stored fingerprint AB:CD:EF:...
[chat opens]
```

After first contact, the trust store has an entry for `Bob`:

```
$ chat trust list
Bob   AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90   first-seen=2025-01-01T12:00:00Z
```

### Reconnecting (verified automatically)

```
$ chat serve -n Alice

identity passphrase:
listening on 0.0.0.0:7777
waiting for peer...
Peer identity for Bob matches the stored fingerprint.
[chat opens]
```

### Peer changes display name

The trust label defaults to the peer's display name. If Bob reconnects as `-n Robert`, his label doesn't match:

```
peer connected from 192.168.1.20:54321
Untrusted peer Robert with fingerprint AB:CD:EF:...
Re-run with --allow-untrusted to trust and continue.
```

Use `--peer` on both sides to pin a label independent of the display name:

```bash
chat serve   -n Alice -p bob   -u
chat connect -n Bob   -p alice -u 192.168.1.10:7777
```

### Fingerprint changed (new device or key rotation)

Without `-u`, the connection is blocked:

```
Blocked peer Bob because the fingerprint changed.
  expected AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
  observed 99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA
Re-run with --allow-untrusted after verifying out-of-band.
```

With `-u`, you are shown the change and can confirm:

```
WARNING: fingerprint for Bob has changed.
Expected: AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
Observed: 99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA

Only proceed if you have verified this fingerprint out-of-band.
Proceed? [y/N] y
Peer identity for Bob re-trusted with fingerprint 99:88:77:...
```

### Declining a fingerprint prompt

Type `n` or press Enter — the session is rejected and nothing is stored:

```
Proceed? [y/N] n
session rejected; returning to listener
```

---

## Passphrase Protection

Your identity is encrypted at rest using **AES-256-GCM**, the key derived via **argon2id** (time=4, memory=128 MiB).

**First run** — prompted to set a passphrase (leave blank for plaintext):

```
new identity passphrase (leave blank to skip encryption):
confirm passphrase:
```

**Subsequent runs** — prompted to unlock:

```
identity passphrase:
```

**Skip the prompt entirely** (scripting, CI):

```bash
chat serve --no-passphrase -n Alice -u
```

**Add passphrase to an existing plaintext identity** — regenerates the keypair:

```bash
chat genkey --force
```

> Note: your peer will need to re-trust your new fingerprint.

---

## Wiping State

```bash
chat wipe                        # delete identity only
chat wipe --peers                # delete identity + trust store
chat wipe --received             # delete identity + received/ directory
chat wipe --peers --received     # full reset
```

`Ctrl+W` inside a session wipes identity, trust store, and `received/`, then exits immediately.

---

## Security Notes

- All traffic is encrypted with **ChaCha20-Poly1305** after the Noise XX handshake.
- The Noise XX pattern provides **mutual authentication** and **forward secrecy**.
- Identity keys at rest are protected with **AES-256-GCM + argon2id**.
- No message history is written to disk — the transcript lives only in process memory.
- Panic wipe (`Ctrl+W`) overwrites files with zeros before deletion.
- Cryptographic memory zeroization is not yet implemented — Go's GC controls object lifetime.
