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
	"time"

	cryptopkg "github.com/JonathanInTheClouds/go-chat/internal/crypto"
	netpkg "github.com/JonathanInTheClouds/go-chat/internal/net"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"
	tunnelpkg "github.com/JonathanInTheClouds/go-chat/internal/tunnel"
	"github.com/JonathanInTheClouds/go-chat/internal/trust"
	"github.com/JonathanInTheClouds/go-chat/internal/ui"

	"github.com/spf13/cobra"
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

func buildRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "chat",
		Short:         "Encrypted terminal chat",
		Long:          "A terminal-native encrypted 1:1 chat tool.\n\nAll sessions use Noise XX with ChaCha20-Poly1305 encryption and mutual authentication.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	root.AddCommand(
		newServeCmd(stdin, stdout),
		newConnectCmd(stdin, stdout),
		newGenKeyCmd(stdout),
		newFingerprintCmd(stdout),
		newWipeCmd(stdout),
		newTrustCmd(stdout),
		newCompletionCmd(root, stdout),
	)

	return root
}

func newServeCmd(stdin io.Reader, stdout io.Writer) *cobra.Command {
	var (
		listen         string
		ephemeral      bool
		identityPath   string
		knownPeersPath string
		peerLabel      string
		allowUntrusted bool
		memoryOnly     bool
		localName      string
		tunnel         bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a chat server and wait for a peer to connect",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(stdin, stdout, listen, ephemeral, identityPath, knownPeersPath, peerLabel, allowUntrusted, memoryOnly, localName, tunnel)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:7777", "address to listen on")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "use a throwaway in-memory identity")
	cmd.Flags().StringVar(&identityPath, "identity", "", "path to persistent identity file")
	cmd.Flags().StringVar(&knownPeersPath, "known-peers", "", "path to known peers file")
	cmd.Flags().StringVar(&peerLabel, "peer", "", "stable label for the remote peer in the trust store")
	cmd.Flags().BoolVar(&allowUntrusted, "allow-untrusted", false, "accept first contact or changed peer fingerprints and persist trust")
	cmd.Flags().BoolVar(&memoryOnly, "memory-only", false, "disable disk persistence for this session")
	cmd.Flags().StringVar(&localName, "name", defaultName(), "your display name shown to the peer")
	cmd.Flags().BoolVar(&tunnel, "tunnel", false, "expose the server via a bore.pub tunnel")

	return cmd
}

func newConnectCmd(stdin io.Reader, stdout io.Writer) *cobra.Command {
	var (
		ephemeral      bool
		identityPath   string
		knownPeersPath string
		peerLabel      string
		allowUntrusted bool
		memoryOnly     bool
		localName      string
	)

	cmd := &cobra.Command{
		Use:   "connect <host:port>",
		Short: "Connect to a chat server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(stdin, stdout, args[0], ephemeral, identityPath, knownPeersPath, peerLabel, allowUntrusted, memoryOnly, localName)
		},
	}

	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "use a throwaway in-memory identity")
	cmd.Flags().StringVar(&identityPath, "identity", "", "path to persistent identity file")
	cmd.Flags().StringVar(&knownPeersPath, "known-peers", "", "path to known peers file")
	cmd.Flags().StringVar(&peerLabel, "peer", "", "stable label for the remote peer in the trust store")
	cmd.Flags().BoolVar(&allowUntrusted, "allow-untrusted", false, "accept first contact or changed peer fingerprints and persist trust")
	cmd.Flags().BoolVar(&memoryOnly, "memory-only", false, "disable disk persistence for this session")
	cmd.Flags().StringVar(&localName, "name", defaultName(), "your display name shown to the peer")

	return cmd
}

func newGenKeyCmd(stdout io.Writer) *cobra.Command {
	var (
		ephemeral    bool
		identityPath string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a new identity keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenKey(stdout, ephemeral, identityPath, force)
		},
	}

	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "generate a throwaway in-memory identity (not saved)")
	cmd.Flags().StringVar(&identityPath, "identity", "", "path to persistent identity file")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing persistent identity")

	return cmd
}

func newFingerprintCmd(stdout io.Writer) *cobra.Command {
	var (
		ephemeral    bool
		identityPath string
	)

	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Show your identity fingerprint",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFingerprint(stdout, ephemeral, identityPath)
		},
	}

	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "show a throwaway in-memory fingerprint")
	cmd.Flags().StringVar(&identityPath, "identity", "", "path to persistent identity file")

	return cmd
}

func newWipeCmd(stdout io.Writer) *cobra.Command {
	var identityPath string

	cmd := &cobra.Command{
		Use:   "wipe",
		Short: "Delete your persistent identity file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWipe(stdout, identityPath)
		},
	}

	cmd.Flags().StringVar(&identityPath, "identity", "", "path to persistent identity file")

	return cmd
}

func newTrustCmd(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage trusted peer fingerprints",
	}

	cmd.AddCommand(
		newTrustListCmd(stdout),
		newTrustSetCmd(stdout),
		newTrustRemoveCmd(stdout),
	)

	return cmd
}

func newTrustListCmd(stdout io.Writer) *cobra.Command {
	var knownPeersPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all trusted peers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustList(stdout, knownPeersPath)
		},
	}

	cmd.Flags().StringVar(&knownPeersPath, "known-peers", "", "path to known peers file")

	return cmd
}

func newTrustSetCmd(stdout io.Writer) *cobra.Command {
	var knownPeersPath string

	cmd := &cobra.Command{
		Use:   "set <label> <fingerprint>",
		Short: "Add or update a trusted peer fingerprint",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustSet(stdout, knownPeersPath, args[0], args[1])
		},
	}

	cmd.Flags().StringVar(&knownPeersPath, "known-peers", "", "path to known peers file")

	return cmd
}

func newTrustRemoveCmd(stdout io.Writer) *cobra.Command {
	var knownPeersPath string

	cmd := &cobra.Command{
		Use:   "remove <label>",
		Short: "Remove a trusted peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustRemove(stdout, knownPeersPath, args[0])
		},
	}

	cmd.Flags().StringVar(&knownPeersPath, "known-peers", "", "path to known peers file")

	return cmd
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

func runServe(stdin io.Reader, stdout io.Writer, listen string, ephemeral bool, identityPath, knownPeersPath, peerLabel string, allowUntrusted, memoryOnly bool, localName string, tunnel bool) error {
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
		identity, modeNotice, err = resolveIdentity(identityPath, ephemeral)
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
		if _, err := fmt.Fprintf(stdout, "share with your friend:\n  chat connect --name <their-name> --peer <label> --allow-untrusted %s\n\n", publicAddr); err != nil {
			return err
		}
	}

	for {
		conn, peer, err := listener.Accept(identity, stdout)
		if err != nil {
			return err
		}

		trustErr := reportPeerTrust(stdout, runtime, peerLabel, conn.RemoteAddress(), peer.Fingerprint, allowUntrusted)
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

		peerName, err := exchangeNames(conn, false, localName)
		if err != nil {
			_ = conn.Close()
			if _, writeErr := fmt.Fprintln(stdout, "name exchange failed; returning to listener"); writeErr != nil {
				return writeErr
			}
			continue
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

func runConnect(stdin io.Reader, stdout io.Writer, address string, ephemeral bool, identityPath, knownPeersPath, peerLabel string, allowUntrusted, memoryOnly bool, localName string) error {
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
		identity, modeNotice, err = resolveIdentity(identityPath, ephemeral)
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

	trustErr := reportPeerTrust(stdout, runtime, peerLabel, address, peer.Fingerprint, allowUntrusted)
	if err := coordinateSessionAdmission(conn, true, trustErr); err != nil {
		return err
	}

	peerName, err := exchangeNames(conn, true, localName)
	if err != nil {
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

func runGenKey(stdout io.Writer, ephemeral bool, identityPath string, force bool) error {
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
		if _, err := cryptopkg.LoadIdentity(path); err == nil {
			return fmt.Errorf("identity already exists at %s; rerun with --force to rotate it", path)
		}
	}

	identity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		return err
	}
	if err := cryptopkg.SaveIdentity(path, identity); err != nil {
		return err
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

func runFingerprint(stdout io.Writer, ephemeral bool, identityPath string) error {
	identity, modeNotice, err := resolveIdentity(identityPath, ephemeral)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "fingerprint: %s\n%s\n", identity.Fingerprint(), modeNotice)
	return err
}

func runWipe(stdout io.Writer, identityPath string) error {
	path, err := effectiveIdentityPath(identityPath)
	if err != nil {
		return err
	}
	if err := cryptopkg.DeleteIdentity(path); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, ui.WipeMessage+"\n", path)
	return err
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

func resolveIdentity(identityPath string, ephemeral bool) (*cryptopkg.Identity, string, error) {
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

	identity, created, err := cryptopkg.LoadOrCreateIdentity(path)
	if err != nil {
		return nil, "", err
	}
	if created {
		return identity, fmt.Sprintf(ui.PersistentIdentityCreatedNotice, path), nil
	}
	return identity, fmt.Sprintf(ui.PersistentIdentityLoadedNotice, path), nil
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

func reportPeerTrust(stdout io.Writer, runtime runtimeConfig, peerLabel, fallbackLabel, fingerprint string, allowUntrusted bool) error {
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
		if err := store.Set(label, fingerprint, time.Now()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, ui.PeerTrustAllowedMismatchNotice+"\n", observation.Label, observation.Observed)
	default:
		err = fmt.Errorf("unknown trust observation status: %d", observation.Status)
	}

	return err
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
