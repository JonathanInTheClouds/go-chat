package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	cryptopkg "chat/internal/crypto"
	netpkg "chat/internal/net"
	"chat/internal/trust"
	"chat/internal/ui"
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
	if len(args) == 0 {
		_, err := fmt.Fprint(stdout, ui.Usage())
		return err
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:], stdin, stdout)
	case "connect":
		return runConnect(args[1:], stdin, stdout)
	case "genkey":
		return runGenKey(args[1:], stdout)
	case "fingerprint":
		return runFingerprint(args[1:], stdout)
	case "wipe":
		return runWipe(args[1:], stdout)
	case "trust":
		return runTrust(args[1:], stdout)
	case "help", "-h", "--help":
		_, err := fmt.Fprint(stdout, ui.Usage())
		return err
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		_, err := fmt.Fprint(stderr, ui.Usage())
		return err
	}
}

func runServe(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	listen := fs.String("listen", "0.0.0.0:7777", "listen address")
	ephemeral := fs.Bool("ephemeral", false, "use a throwaway in-memory identity")
	identityPath := fs.String("identity", "", "path to persistent identity file")
	knownPeersPath := fs.String("known-peers", "", "path to known peers file")
	peerLabel := fs.String("peer", "", "stable label for the remote peer")
	allowUntrusted := fs.Bool("allow-untrusted", false, "allow first-contact or changed peer fingerprints and persist trust")
	memoryOnly := fs.Bool("memory-only", false, "disable app-managed disk persistence for this session")
	if err := fs.Parse(args); err != nil {
		return err
	}

	runtime, err := resolveRuntimeConfig(*identityPath, *knownPeersPath, *memoryOnly)
	if err != nil {
		return err
	}

	session := netpkg.ListenerConfig{
		ListenAddress: *listen,
	}

	if err := session.Validate(); err != nil {
		return err
	}

	var (
		identity   *cryptopkg.Identity
		modeNotice string
	)
	if runtime.MemoryOnly {
		identity, modeNotice, err = resolveIdentityForMemoryOnly()
		if err != nil {
			return err
		}
	} else {
		identity, modeNotice, err = resolveIdentity(*identityPath, *ephemeral)
		if err != nil {
			return err
		}
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

	for {
		conn, peer, err := listener.Accept(identity, stdout)
		if err != nil {
			return err
		}

		if err := reportPeerTrust(stdout, runtime, *peerLabel, conn.RemoteAddress(), peer.Fingerprint, *allowUntrusted); err != nil {
			_ = conn.Close()
			var blocked *trustBlockedError
			if errors.As(err, &blocked) {
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

func runConnect(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	ephemeral := fs.Bool("ephemeral", false, "use a throwaway in-memory identity")
	identityPath := fs.String("identity", "", "path to persistent identity file")
	knownPeersPath := fs.String("known-peers", "", "path to known peers file")
	peerLabel := fs.String("peer", "", "stable label for the remote peer")
	allowUntrusted := fs.Bool("allow-untrusted", false, "allow first-contact or changed peer fingerprints and persist trust")
	memoryOnly := fs.Bool("memory-only", false, "disable app-managed disk persistence for this session")

	if err := fs.Parse(args); err != nil {
		return err
	}

	runtime, err := resolveRuntimeConfig(*identityPath, *knownPeersPath, *memoryOnly)
	if err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return errors.New("connect requires exactly one peer address argument")
	}

	session := netpkg.DialConfig{
		RemoteAddress: fs.Arg(0),
	}

	if err := session.Validate(); err != nil {
		return err
	}

	var (
		identity   *cryptopkg.Identity
		modeNotice string
	)
	if runtime.MemoryOnly {
		identity, modeNotice, err = resolveIdentityForMemoryOnly()
		if err != nil {
			return err
		}
	} else {
		identity, modeNotice, err = resolveIdentity(*identityPath, *ephemeral)
		if err != nil {
			return err
		}
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

	if err := reportPeerTrust(stdout, runtime, *peerLabel, session.RemoteAddress, peer.Fingerprint, *allowUntrusted); err != nil {
		_ = conn.Close()
		return err
	}

	err = ui.RunChat(stdin, stdout, conn, peer, ui.RuntimeOptions{
		MemoryOnly:     runtime.MemoryOnly,
		IdentityPath:   runtime.IdentityPath,
		KnownPeersPath: runtime.KnownPeersPath,
	})
	var closedErr *ui.SessionClosedError
	if errors.As(err, &closedErr) {
		return nil
	}
	return err
}

func runGenKey(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("genkey", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	ephemeral := fs.Bool("ephemeral", false, "generate a throwaway in-memory identity")
	identityPath := fs.String("identity", "", "path to persistent identity file")
	force := fs.Bool("force", false, "overwrite an existing persistent identity")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *ephemeral {
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

	path, err := effectiveIdentityPath(*identityPath)
	if err != nil {
		return err
	}

	if !*force {
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

func runFingerprint(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	ephemeral := fs.Bool("ephemeral", false, "show a throwaway in-memory fingerprint")
	identityPath := fs.String("identity", "", "path to persistent identity file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	identity, modeNotice, err := resolveIdentity(*identityPath, *ephemeral)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "fingerprint: %s\n%s\n", identity.Fingerprint(), modeNotice)
	return err
}

func runWipe(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("wipe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	identityPath := fs.String("identity", "", "path to persistent identity file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path, err := effectiveIdentityPath(*identityPath)
	if err != nil {
		return err
	}
	if err := cryptopkg.DeleteIdentity(path); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, ui.WipeMessage+"\n", path)
	return err
}

func runTrust(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("trust requires a subcommand: list, set, or remove")
	}

	switch args[0] {
	case "list":
		return runTrustList(args[1:], stdout)
	case "set":
		return runTrustSet(args[1:], stdout)
	case "remove":
		return runTrustRemove(args[1:], stdout)
	default:
		return fmt.Errorf("unknown trust subcommand %q", args[0])
	}
}

func runTrustList(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("trust list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	knownPeersPath := fs.String("known-peers", "", "path to known peers file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path, err := effectiveKnownPeersPath(*knownPeersPath)
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

func runTrustSet(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("trust set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	knownPeersPath := fs.String("known-peers", "", "path to known peers file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("trust set requires exactly two arguments: <label> <fingerprint>")
	}

	path, err := effectiveKnownPeersPath(*knownPeersPath)
	if err != nil {
		return err
	}

	store, err := openTrustStore(path)
	if err != nil {
		return err
	}

	label := fs.Arg(0)
	fingerprint := fs.Arg(1)
	if err := store.Set(label, fingerprint, time.Now()); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, ui.TrustSetNotice+"\n", label, fingerprint)
	return err
}

func runTrustRemove(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("trust remove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	knownPeersPath := fs.String("known-peers", "", "path to known peers file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("trust remove requires exactly one argument: <label>")
	}

	path, err := effectiveKnownPeersPath(*knownPeersPath)
	if err != nil {
		return err
	}

	store, err := openTrustStore(path)
	if err != nil {
		return err
	}

	label := fs.Arg(0)
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
