package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cryptopkg "github.com/JonathanInTheClouds/go-chat/internal/crypto"
	netpkg "github.com/JonathanInTheClouds/go-chat/internal/net"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"
	"github.com/JonathanInTheClouds/go-chat/internal/trust"
	tunnelpkg "github.com/JonathanInTheClouds/go-chat/internal/tunnel"
	"github.com/JonathanInTheClouds/go-chat/internal/ui"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type runtimeConfig struct {
	MemoryOnly     bool
	IdentityPath   string
	KnownPeersPath string
}

type trustBlockedError struct {
	reason string
}

func (e *trustBlockedError) Error() string {
	if e == nil || e.reason == "" {
		return "peer trust blocked"
	}
	return e.reason
}

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	root := buildRoot(stdin, stdout, stderr)
	root.SetArgs(args)
	return root.Execute()
}

// globals holds flags that apply across multiple commands.
type globals struct {
	IdentityPath   string
	KnownPeersPath string
}

func buildRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	g := &globals{}

	root := &cobra.Command{
		Use:           "chat",
		Short:         "Encrypted terminal chat",
		Long:          "A terminal-native encrypted 1:1 chat tool.\n\nAll sessions use Noise XX with ChaCha20-Poly1305 encryption and mutual authentication.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	// These override the default paths and are rarely needed, so keep them
	// persistent (available to all subcommands) but out of the default help.
	root.PersistentFlags().StringVar(&g.IdentityPath, "identity", "", "path to persistent identity file")
	root.PersistentFlags().StringVar(&g.KnownPeersPath, "known-peers", "", "path to known peers file")
	_ = root.PersistentFlags().MarkHidden("identity")
	_ = root.PersistentFlags().MarkHidden("known-peers")

	root.AddCommand(
		newServeCmd(stdin, stdout, g),
		newConnectCmd(stdin, stdout, g),
		newRoomCmd(stdin, stdout, g),
		newGenKeyCmd(stdout, g),
		newFingerprintCmd(stdout, g),
		newWipeCmd(stdout, g),
		newTrustCmd(stdout, g),
		newCompletionCmd(root, stdout),
	)

	return root
}

func newServeCmd(stdin io.Reader, stdout io.Writer, g *globals) *cobra.Command {
	var (
		listen         string
		peerLabel      string
		allowUntrusted bool
		memoryOnly     bool
		noPassphrase   bool
		localName      string
		tunnel         bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a chat server and wait for a peer to connect",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(stdin, stdout, listen, g.IdentityPath, g.KnownPeersPath, peerLabel, allowUntrusted, memoryOnly, noPassphrase, localName, tunnel)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:7777", "address to listen on")
	cmd.Flags().StringVarP(&peerLabel, "peer", "p", "", "label for the remote peer in the trust store")
	cmd.Flags().BoolVarP(&allowUntrusted, "allow-untrusted", "u", false, "accept first contact or changed peer fingerprints")
	cmd.Flags().BoolVarP(&memoryOnly, "memory-only", "m", false, "ephemeral identity, no disk state, no file transfer")
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false, "skip passphrase protection for the identity file")
	cmd.Flags().StringVarP(&localName, "name", "n", defaultName(), "your display name shown to the peer")
	cmd.Flags().BoolVar(&tunnel, "tunnel", false, "expose the server via a bore.pub tunnel")

	return cmd
}

func newConnectCmd(stdin io.Reader, stdout io.Writer, g *globals) *cobra.Command {
	var (
		peerLabel      string
		allowUntrusted bool
		memoryOnly     bool
		noPassphrase   bool
		localName      string
	)

	cmd := &cobra.Command{
		Use:   "connect <host:port>",
		Short: "Connect to a chat server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(stdin, stdout, args[0], g.IdentityPath, g.KnownPeersPath, peerLabel, allowUntrusted, memoryOnly, noPassphrase, localName)
		},
	}

	cmd.Flags().StringVarP(&peerLabel, "peer", "p", "", "label for the remote peer in the trust store")
	cmd.Flags().BoolVarP(&allowUntrusted, "allow-untrusted", "u", false, "accept first contact or changed peer fingerprints")
	cmd.Flags().BoolVarP(&memoryOnly, "memory-only", "m", false, "ephemeral identity, no disk state, no file transfer")
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false, "skip passphrase protection for the identity file")
	cmd.Flags().StringVarP(&localName, "name", "n", defaultName(), "your display name shown to the peer")

	return cmd
}

func newGenKeyCmd(stdout io.Writer, g *globals) *cobra.Command {
	var (
		ephemeral    bool
		force        bool
		noPassphrase bool
	)

	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a new identity keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenKey(stdout, ephemeral, noPassphrase, g.IdentityPath, force)
		},
	}

	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "generate a throwaway in-memory identity (not saved)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing persistent identity")
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false, "save the identity without passphrase protection")

	return cmd
}

func newFingerprintCmd(stdout io.Writer, g *globals) *cobra.Command {
	var (
		ephemeral    bool
		noPassphrase bool
	)

	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Show your identity fingerprint",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFingerprint(stdout, ephemeral, noPassphrase, g.IdentityPath)
		},
	}

	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "show a throwaway in-memory fingerprint")
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false, "skip passphrase prompt (only works with unencrypted identity files)")

	return cmd
}

func newWipeCmd(stdout io.Writer, g *globals) *cobra.Command {
	var (
		peers    bool
		received bool
	)

	cmd := &cobra.Command{
		Use:   "wipe",
		Short: "Delete your persistent identity and optionally trust store",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWipe(stdout, g.IdentityPath, g.KnownPeersPath, peers, received)
		},
	}

	cmd.Flags().BoolVar(&peers, "peers", false, "also delete the known peers trust store")
	cmd.Flags().BoolVar(&received, "received", false, "also securely wipe the received/ directory")

	return cmd
}

func newTrustCmd(stdout io.Writer, g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage trusted peer fingerprints",
	}

	cmd.AddCommand(
		newTrustListCmd(stdout, g),
		newTrustSetCmd(stdout, g),
		newTrustRemoveCmd(stdout, g),
	)

	return cmd
}

func newTrustListCmd(stdout io.Writer, g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all trusted peers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustList(stdout, g.KnownPeersPath)
		},
	}
}

func newTrustSetCmd(stdout io.Writer, g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "set <label> <fingerprint>",
		Short: "Add or update a trusted peer fingerprint",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustSet(stdout, g.KnownPeersPath, args[0], args[1])
		},
	}
}

func newTrustRemoveCmd(stdout io.Writer, g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <label>",
		Short: "Remove a trusted peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustRemove(stdout, g.KnownPeersPath, args[0])
		},
	}
}

func newCompletionCmd(root *cobra.Command, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script and source it to enable tab completion.
Shell is auto-detected from $SHELL (or $PSModulePath on Windows) when omitted.

Bash:
  eval "$(chat completion bash)"

Zsh:
  eval "$(chat completion zsh)"

Fish:
  chat completion fish | source

PowerShell (add to $PROFILE):
  Invoke-Expression (& chat completion powershell)`,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := ""
			if len(args) > 0 {
				shell = args[0]
			} else {
				shell = detectShell()
			}
			switch shell {
			case "bash":
				return root.GenBashCompletion(stdout)
			case "zsh":
				return root.GenZshCompletion(stdout)
			case "fish":
				return root.GenFishCompletion(stdout, true)
			case "powershell", "pwsh":
				return root.GenPowerShellCompletionWithDesc(stdout)
			case "":
				return fmt.Errorf("could not detect shell; specify one: bash, zsh, fish, powershell")
			default:
				return fmt.Errorf("unsupported shell %q — use bash, zsh, fish, or powershell", shell)
			}
		},
	}
}

func detectShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		switch filepath.Base(s) {
		case "bash", "zsh", "fish":
			return filepath.Base(s)
		}
	}
	if os.Getenv("PSModulePath") != "" {
		return "powershell"
	}
	return ""
}

// --- command implementations ---

func runServe(stdin io.Reader, stdout io.Writer, listen, identityPath, knownPeersPath, peerLabel string, allowUntrusted, memoryOnly, noPassphrase bool, localName string, tunnel bool) error {
	runtime, err := resolveRuntimeConfig(identityPath, knownPeersPath, memoryOnly)
	if err != nil {
		return err
	}

	session := netpkg.ListenerConfig{ListenAddress: listen}
	if err := session.Validate(); err != nil {
		return err
	}

	var (
		identity   *cryptopkg.Identity
		modeNotice string
	)
	if runtime.MemoryOnly {
		identity, modeNotice, err = resolveIdentityForMemoryOnly()
	} else {
		identity, modeNotice, err = resolveIdentity(identityPath, false, noPassphrase, stdout)
	}
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, modeNotice); err != nil {
		return err
	}
	if runtime.MemoryOnly {
		if _, err := fmt.Fprintln(stdout, ui.MemoryOnlyModeNotice); err != nil {
			return err
		}
	}

	listener, err := netpkg.Listen(session, stdout)
	if err != nil {
		return err
	}
	defer listener.Close()

	if tunnel {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		_, portStr, err := net.SplitHostPort(listen)
		if err != nil {
			return fmt.Errorf("parse listen address: %w", err)
		}
		localPort, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("parse listen port: %w", err)
		}

		publicAddr, err := tunnelpkg.Start(ctx, localPort)
		if err != nil {
			return fmt.Errorf("start tunnel: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "tunnel ready: %s\n", publicAddr); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "share with your friend:\n  chat connect -n <name> -u %s\n\n", publicAddr); err != nil {
			return err
		}
	}

	const rateLimitWindow = 2 * time.Second
	ipLastSeen := make(map[string]time.Time)

	for {
		conn, peer, err := listener.Accept(identity, stdout)
		if err != nil {
			return err
		}

		now := time.Now()
		// prune stale entries to prevent unbounded map growth
		for ip, t := range ipLastSeen {
			if now.Sub(t) > 60*time.Second {
				delete(ipLastSeen, ip)
			}
		}
		remoteIP, _, splitErr := net.SplitHostPort(conn.RemoteAddress())
		if splitErr == nil {
			if now.Sub(ipLastSeen[remoteIP]) < rateLimitWindow {
				_, _ = fmt.Fprintf(stdout, "rate-limited connection from %s; dropping\n", remoteIP)
				_ = conn.Close()
				continue
			}
			ipLastSeen[remoteIP] = now
		}

		peerName, err := exchangeNames(conn, false, localName)
		if err != nil {
			_ = conn.Close()
			if _, writeErr := fmt.Fprintln(stdout, "name exchange failed; returning to listener"); writeErr != nil {
				return writeErr
			}
			continue
		}

		fallbackLabel := peerName
		if fallbackLabel == "" {
			fallbackLabel = conn.RemoteAddress()
		}

		trustErr := reportPeerTrust(stdin, stdout, runtime, peerLabel, fallbackLabel, peer.Fingerprint, allowUntrusted)
		if err := coordinateSessionAdmission(conn, false, trustErr); err != nil {
			_ = conn.Close()
			if isSessionRejected(err) {
				if _, writeErr := fmt.Fprintln(stdout, "session rejected; returning to listener"); writeErr != nil {
					return writeErr
				}
				continue
			}
			return err
		}

		err = ui.RunChat(stdin, stdout, conn, peer, ui.RuntimeOptions{
			MemoryOnly:     runtime.MemoryOnly,
			IdentityPath:   runtime.IdentityPath,
			KnownPeersPath: runtime.KnownPeersPath,
			LocalName:      localName,
			PeerName:       peerName,
		})
		_ = conn.Close()

		var closedErr *ui.SessionClosedError
		if errors.As(err, &closedErr) {
			if _, writeErr := fmt.Fprintln(stdout, "session closed; returning to listener"); writeErr != nil {
				return writeErr
			}
			continue
		}
		return err
	}
}

func runConnect(stdin io.Reader, stdout io.Writer, address, identityPath, knownPeersPath, peerLabel string, allowUntrusted, memoryOnly, noPassphrase bool, localName string) error {
	runtime, err := resolveRuntimeConfig(identityPath, knownPeersPath, memoryOnly)
	if err != nil {
		return err
	}

	session := netpkg.DialConfig{RemoteAddress: address}
	if err := session.Validate(); err != nil {
		return err
	}

	var (
		identity   *cryptopkg.Identity
		modeNotice string
	)
	if runtime.MemoryOnly {
		identity, modeNotice, err = resolveIdentityForMemoryOnly()
	} else {
		identity, modeNotice, err = resolveIdentity(identityPath, false, noPassphrase, stdout)
	}
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, modeNotice); err != nil {
		return err
	}
	if runtime.MemoryOnly {
		if _, err := fmt.Fprintln(stdout, ui.MemoryOnlyModeNotice); err != nil {
			return err
		}
	}

	conn, peer, err := netpkg.Dial(session, identity, stdout)
	if err != nil {
		return err
	}
	defer conn.Close()

	peerName, err := exchangeNames(conn, true, localName)
	if err != nil {
		return err
	}

	fallbackLabel := peerName
	if fallbackLabel == "" {
		fallbackLabel = address
	}

	trustErr := reportPeerTrust(stdin, stdout, runtime, peerLabel, fallbackLabel, peer.Fingerprint, allowUntrusted)
	if err := coordinateSessionAdmission(conn, true, trustErr); err != nil {
		return err
	}

	err = ui.RunChat(stdin, stdout, conn, peer, ui.RuntimeOptions{
		MemoryOnly:     runtime.MemoryOnly,
		IdentityPath:   runtime.IdentityPath,
		KnownPeersPath: runtime.KnownPeersPath,
		LocalName:      localName,
		PeerName:       peerName,
	})
	var closedErr *ui.SessionClosedError
	if errors.As(err, &closedErr) {
		return nil
	}
	return err
}

func runGenKey(stdout io.Writer, ephemeral, noPassphrase bool, identityPath string, force bool) error {
	if ephemeral {
		identity, err := cryptopkg.GenerateIdentity()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(
			stdout,
			"%s\ned25519 public: %x\nx25519 public: %x\nfingerprint: %s\n",
			ui.VolatileIdentityNotice,
			identity.SigningPublicKey,
			identity.KeyAgreementPublicKey,
			identity.Fingerprint(),
		)
		return err
	}

	path, err := effectiveIdentityPath(identityPath)
	if err != nil {
		return err
	}

	if !force {
		if _, err := cryptopkg.LoadIdentity(path, nil); err == nil {
			return fmt.Errorf("identity already exists at %s; rerun with --force to rotate it", path)
		}
	}

	identity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		return err
	}

	if noPassphrase {
		if err := cryptopkg.SaveIdentity(path, identity); err != nil {
			return err
		}
	} else {
		passphrase, err := promptNewPassphrase(stdout)
		if err != nil {
			return err
		}
		defer func() {
			for i := range passphrase {
				passphrase[i] = 0
			}
		}()
		if err := cryptopkg.SaveEncryptedIdentity(path, identity, passphrase); err != nil {
			return err
		}
	}

	_, err = fmt.Fprintf(
		stdout,
		"persistent identity saved at %s\ned25519 public: %x\nx25519 public: %x\nfingerprint: %s\n",
		path,
		identity.SigningPublicKey,
		identity.KeyAgreementPublicKey,
		identity.Fingerprint(),
	)
	return err
}

func runFingerprint(stdout io.Writer, ephemeral, noPassphrase bool, identityPath string) error {
	identity, modeNotice, err := resolveIdentity(identityPath, ephemeral, noPassphrase, stdout)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "fingerprint: %s\n%s\n", identity.Fingerprint(), modeNotice)
	return err
}

func runWipe(stdout io.Writer, identityPath, knownPeersPath string, peers, received bool) error {
	path, err := effectiveIdentityPath(identityPath)
	if err != nil {
		return err
	}
	if err := cryptopkg.DeleteIdentity(path); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, ui.WipeMessage+"\n", path); err != nil {
		return err
	}
	if peers {
		peersPath, err := effectiveKnownPeersPath(knownPeersPath)
		if err != nil {
			return err
		}
		if err := trust.DeleteStore(peersPath); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "Removed known peers store at %s.\n", peersPath); err != nil {
			return err
		}
	}
	if received {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		receivedDir := filepath.Join(cwd, "received")
		if err := wipeDirectory(receivedDir); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, ui.WipeReceivedMessage+"\n", receivedDir); err != nil {
			return err
		}
	}
	return nil
}

func runTrustList(stdout io.Writer, knownPeersPath string) error {
	path, err := effectiveKnownPeersPath(knownPeersPath)
	if err != nil {
		return err
	}
	store, err := openTrustStore(path)
	if err != nil {
		return err
	}
	entries := store.List()
	if len(entries) == 0 {
		_, err := fmt.Fprintln(stdout, ui.TrustEmptyNotice)
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(
			stdout,
			"%s\t%s\tfirst-seen=%s\tlast-seen=%s\n",
			entry.Label,
			entry.Fingerprint,
			entry.FirstSeenAt.Format(time.RFC3339),
			entry.LastSeenAt.Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return nil
}

func runTrustSet(stdout io.Writer, knownPeersPath, label, fingerprint string) error {
	path, err := effectiveKnownPeersPath(knownPeersPath)
	if err != nil {
		return err
	}
	store, err := openTrustStore(path)
	if err != nil {
		return err
	}
	if err := store.Set(label, fingerprint, time.Now()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, ui.TrustSetNotice+"\n", label, fingerprint)
	return err
}

func runTrustRemove(stdout io.Writer, knownPeersPath, label string) error {
	path, err := effectiveKnownPeersPath(knownPeersPath)
	if err != nil {
		return err
	}
	store, err := openTrustStore(path)
	if err != nil {
		return err
	}
	removed, err := store.Remove(label)
	if err != nil {
		return err
	}
	if !removed {
		_, err := fmt.Fprintf(stdout, ui.TrustMissingNotice+"\n", label)
		return err
	}
	_, err = fmt.Fprintf(stdout, ui.TrustRemoveNotice+"\n", label)
	return err
}

// --- helpers ---

func resolveIdentity(identityPath string, ephemeral, noPassphrase bool, stdout io.Writer) (*cryptopkg.Identity, string, error) {
	if ephemeral {
		identity, err := cryptopkg.GenerateIdentity()
		if err != nil {
			return nil, "", err
		}
		return identity, ui.VolatileIdentityNotice, nil
	}

	path, err := effectiveIdentityPath(identityPath)
	if err != nil {
		return nil, "", err
	}

	var passphrase []byte
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	if !noPassphrase {
		_, statErr := os.Stat(path)
		fileExists := statErr == nil

		if fileExists {
			encrypted, probeErr := cryptopkg.IsEncryptedIdentity(path)
			if probeErr != nil {
				return nil, "", probeErr
			}
			if encrypted {
				passphrase, err = promptPassphrase("identity passphrase: ", stdout)
				if err != nil {
					return nil, "", err
				}
			}
		} else {
			passphrase, err = promptNewPassphrase(stdout)
			if err != nil {
				return nil, "", err
			}
		}
	}

	identity, created, err := cryptopkg.LoadOrCreateIdentity(path, passphrase)
	if err != nil {
		return nil, "", err
	}
	if created {
		return identity, fmt.Sprintf(ui.PersistentIdentityCreatedNotice, path), nil
	}
	return identity, fmt.Sprintf(ui.PersistentIdentityLoadedNotice, path), nil
}

func promptPassphrase(prompt string, w io.Writer) ([]byte, error) {
	_, _ = fmt.Fprint(w, prompt)
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(w)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return passphrase, nil
}

func promptNewPassphrase(w io.Writer) ([]byte, error) {
	first, err := promptPassphrase("new identity passphrase (leave blank to skip encryption): ", w)
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, nil
	}
	second, err := promptPassphrase("confirm passphrase: ", w)
	if err != nil {
		for i := range first {
			first[i] = 0
		}
		return nil, err
	}
	defer func() {
		for i := range second {
			second[i] = 0
		}
	}()
	if string(first) != string(second) {
		for i := range first {
			first[i] = 0
		}
		return nil, fmt.Errorf("passphrases do not match")
	}
	return first, nil
}

func secureDeleteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	zeros := make([]byte, info.Size())
	_, _ = f.Write(zeros)
	_ = f.Sync()
	_ = f.Close()
	return os.Remove(path)
}

func wipeDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		_ = secureDeleteFile(filepath.Join(dir, entry.Name()))
	}
	return os.Remove(dir)
}

func resolveIdentityForMemoryOnly() (*cryptopkg.Identity, string, error) {
	identity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		return nil, "", err
	}
	return identity, ui.MemoryOnlyIdentityNotice, nil
}

func effectiveIdentityPath(identityPath string) (string, error) {
	if identityPath != "" {
		return identityPath, nil
	}
	return cryptopkg.DefaultIdentityPath()
}

func effectiveKnownPeersPath(knownPeersPath string) (string, error) {
	if knownPeersPath != "" {
		return knownPeersPath, nil
	}
	return trust.DefaultPath()
}

func resolveRuntimeConfig(identityPath, knownPeersPath string, memoryOnly bool) (runtimeConfig, error) {
	effectiveIdentity, err := effectiveIdentityPath(identityPath)
	if err != nil {
		return runtimeConfig{}, err
	}
	effectiveKnownPeers, err := effectiveKnownPeersPath(knownPeersPath)
	if err != nil {
		return runtimeConfig{}, err
	}
	return runtimeConfig{
		MemoryOnly:     memoryOnly,
		IdentityPath:   effectiveIdentity,
		KnownPeersPath: effectiveKnownPeers,
	}, nil
}

func openTrustStore(path string) (*trust.Store, error) {
	return trust.Open(path)
}

func reportPeerTrust(stdin io.Reader, stdout io.Writer, runtime runtimeConfig, peerLabel, fallbackLabel, fingerprint string, allowUntrusted bool) error {
	if runtime.MemoryOnly {
		_, err := fmt.Fprintf(stdout, ui.MemoryOnlyPeerNotice+"\n", choosePeerLabel(peerLabel, fallbackLabel), fingerprint)
		return err
	}

	store, err := openTrustStore(runtime.KnownPeersPath)
	if err != nil {
		return err
	}

	label := choosePeerLabel(peerLabel, fallbackLabel)
	observation, err := store.Check(label, fingerprint)
	if err != nil {
		return err
	}

	switch observation.Status {
	case trust.StatusNew:
		if !allowUntrusted {
			if _, err := fmt.Fprintf(stdout, ui.PeerTrustNewBlockedNotice+"\n", observation.Label, observation.Observed); err != nil {
				return err
			}
			return &trustBlockedError{reason: fmt.Sprintf("untrusted peer %s", observation.Label)}
		}
		if _, err := fmt.Fprintf(stdout, "\nFirst contact with %s\nTheir fingerprint: %s\n\nVerify this fingerprint with your peer out-of-band (call, Signal, etc.)\nbefore continuing. Proceed? [y/N] ", observation.Label, observation.Observed); err != nil {
			return err
		}
		if !readYes(stdin) {
			return &trustBlockedError{reason: "fingerprint not confirmed by user"}
		}
		if err := store.Set(label, fingerprint, time.Now()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, ui.PeerTrustNewNotice+"\n", observation.Label, observation.Observed)
	case trust.StatusMatch:
		if _, observeErr := store.Observe(label, fingerprint, time.Now()); observeErr != nil {
			return observeErr
		}
		_, err = fmt.Fprintf(stdout, ui.PeerTrustMatchNotice+"\n", observation.Label)
	case trust.StatusMismatch:
		if !allowUntrusted {
			if _, err := fmt.Fprintf(stdout, ui.PeerTrustMismatchBlockedNotice+"\n", observation.Label, observation.Expected, observation.Observed); err != nil {
				return err
			}
			return &trustBlockedError{reason: fmt.Sprintf("peer fingerprint changed for %s", observation.Label)}
		}
		if _, err := fmt.Fprintf(stdout, "\nWARNING: fingerprint for %s has changed.\nExpected: %s\nObserved: %s\n\nOnly proceed if you have verified this new fingerprint out-of-band.\nProceed? [y/N] ", observation.Label, observation.Expected, observation.Observed); err != nil {
			return err
		}
		if !readYes(stdin) {
			return &trustBlockedError{reason: "fingerprint change not confirmed by user"}
		}
		if err := store.Set(label, fingerprint, time.Now()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, ui.PeerTrustAllowedMismatchNotice+"\n", observation.Label, observation.Observed)
	default:
		err = fmt.Errorf("unknown trust observation status: %d", observation.Status)
	}

	return err
}

func readYes(r io.Reader) bool {
	buf := make([]byte, 4)
	n, _ := r.Read(buf)
	answer := strings.TrimSpace(strings.ToLower(string(buf[:n])))
	return answer == "y" || answer == "yes"
}

func choosePeerLabel(peerLabel, fallbackLabel string) string {
	if peerLabel != "" {
		return peerLabel
	}
	return fallbackLabel
}

type remoteSessionRejectedError struct {
	reason string
}

func (e *remoteSessionRejectedError) Error() string {
	if e == nil || e.reason == "" {
		return "remote peer rejected the session"
	}
	return fmt.Sprintf("remote peer rejected the session: %s", e.reason)
}

func coordinateSessionAdmission(session *netpkg.SecureSession, initiator bool, localErr error) error {
	if initiator {
		if err := sendAdmissionDecision(session, localErr); err != nil {
			return err
		}
		peerMessage, err := session.ReceiveMessage()
		if err != nil {
			if localErr != nil {
				return localErr
			}
			return err
		}
		return evaluateAdmissionOutcome(localErr, peerMessage)
	}

	peerMessage, err := session.ReceiveMessage()
	if err != nil {
		return err
	}
	if err := sendAdmissionDecision(session, localErr); err != nil {
		return err
	}
	return evaluateAdmissionOutcome(localErr, peerMessage)
}

func sendAdmissionDecision(session *netpkg.SecureSession, localErr error) error {
	if localErr != nil {
		return session.SendSessionReject(localErr.Error())
	}
	return session.SendSessionAccept()
}

func evaluateAdmissionOutcome(localErr error, peerMessage protocol.Message) error {
	switch peerMessage.Type {
	case protocol.MessageTypeSessionAccept:
		if localErr != nil {
			return localErr
		}
		return nil
	case protocol.MessageTypeSessionReject:
		if localErr != nil {
			return localErr
		}
		return &remoteSessionRejectedError{reason: peerMessage.Text}
	default:
		return fmt.Errorf("unexpected session admission message type %q", peerMessage.Type)
	}
}

func defaultName() string {
	u, err := user.Current()
	if err != nil {
		return "user"
	}
	if u.Username != "" {
		return u.Username
	}
	return "user"
}

func exchangeNames(session *netpkg.SecureSession, initiator bool, localName string) (string, error) {
	if initiator {
		if err := session.SendName(localName); err != nil {
			return "", fmt.Errorf("send name: %w", err)
		}
		msg, err := session.ReceiveMessage()
		if err != nil {
			return "", fmt.Errorf("receive peer name: %w", err)
		}
		if msg.Type != protocol.MessageTypeHandshakeName {
			return "", fmt.Errorf("expected handshake_name, got %q", msg.Type)
		}
		return msg.Text, nil
	}

	msg, err := session.ReceiveMessage()
	if err != nil {
		return "", fmt.Errorf("receive peer name: %w", err)
	}
	if msg.Type != protocol.MessageTypeHandshakeName {
		return "", fmt.Errorf("expected handshake_name, got %q", msg.Type)
	}
	if err := session.SendName(localName); err != nil {
		return "", fmt.Errorf("send name: %w", err)
	}
	return msg.Text, nil
}

func isSessionRejected(err error) bool {
	var localBlocked *trustBlockedError
	if errors.As(err, &localBlocked) {
		return true
	}
	var remoteBlocked *remoteSessionRejectedError
	return errors.As(err, &remoteBlocked)
}
