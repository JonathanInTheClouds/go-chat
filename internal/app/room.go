package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	cryptopkg "github.com/JonathanInTheClouds/go-chat/internal/crypto"
	grouppkg "github.com/JonathanInTheClouds/go-chat/internal/group"
	netpkg "github.com/JonathanInTheClouds/go-chat/internal/net"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"
	"github.com/JonathanInTheClouds/go-chat/internal/trust"
	tunnelpkg "github.com/JonathanInTheClouds/go-chat/internal/tunnel"
	"github.com/JonathanInTheClouds/go-chat/internal/ui"

	"github.com/spf13/cobra"
)

func newRoomCmd(stdin io.Reader, stdout io.Writer, g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "room",
		Short: "Host or join an encrypted group chat room",
	}
	cmd.AddCommand(
		newRoomServeCmd(stdin, stdout, g),
		newRoomJoinCmd(stdin, stdout, g),
	)
	return cmd
}

func newRoomServeCmd(stdin io.Reader, stdout io.Writer, g *globals) *cobra.Command {
	var (
		listen         string
		allowUntrusted bool
		memoryOnly     bool
		noPassphrase   bool
		localName      string
		tunnel         bool
	)

	cmd := &cobra.Command{
		Use:   "serve <room-name>",
		Short: "Start a group chat room and accept multiple peers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoomServe(stdin, stdout, args[0], listen, g.IdentityPath, g.KnownPeersPath, allowUntrusted, memoryOnly, noPassphrase, localName, tunnel)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:7777", "address to listen on")
	cmd.Flags().BoolVarP(&allowUntrusted, "allow-untrusted", "u", false, "accept first contact or changed peer fingerprints")
	cmd.Flags().BoolVarP(&memoryOnly, "memory-only", "m", false, "ephemeral identity, no disk state, no file transfer")
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false, "skip passphrase protection for the identity file")
	cmd.Flags().StringVarP(&localName, "name", "n", defaultName(), "your display name shown to room members")
	cmd.Flags().BoolVar(&tunnel, "tunnel", false, "expose the room via a bore.pub tunnel")
	return cmd
}

func newRoomJoinCmd(stdin io.Reader, stdout io.Writer, g *globals) *cobra.Command {
	var (
		peerLabel      string
		allowUntrusted bool
		memoryOnly     bool
		noPassphrase   bool
		localName      string
	)

	cmd := &cobra.Command{
		Use:   "join <host:port> <room-name>",
		Short: "Join an encrypted group chat room",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoomJoin(stdin, stdout, args[0], args[1], g.IdentityPath, g.KnownPeersPath, peerLabel, allowUntrusted, memoryOnly, noPassphrase, localName)
		},
	}

	cmd.Flags().StringVarP(&peerLabel, "peer", "p", "", "label for the room host in the trust store")
	cmd.Flags().BoolVarP(&allowUntrusted, "allow-untrusted", "u", false, "accept first contact or changed peer fingerprints")
	cmd.Flags().BoolVarP(&memoryOnly, "memory-only", "m", false, "ephemeral identity, no disk state, no file transfer")
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false, "skip passphrase protection for the identity file")
	cmd.Flags().StringVarP(&localName, "name", "n", defaultName(), "your display name shown to room members")
	return cmd
}

func runRoomServe(stdin io.Reader, stdout io.Writer, roomName, listen, identityPath, knownPeersPath string, allowUntrusted, memoryOnly, noPassphrase bool, localName string, tunnel bool) error {
	runtime, identity, err := resolveSessionIdentity(stdout, identityPath, knownPeersPath, memoryOnly, noPassphrase)
	if err != nil {
		return err
	}

	config := netpkg.ListenerConfig{ListenAddress: listen}
	if err := config.Validate(); err != nil {
		return err
	}

	listener, err := netpkg.Listen(config, stdout)
	if err != nil {
		return err
	}
	defer listener.Close()

	if tunnel {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		publicAddr, err := startRoomTunnel(ctx, listen)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "tunnel ready: %s\nshare with your room:\n  chat room join -n <name> -u %s %s\n\n", publicAddr, publicAddr, roomName); err != nil {
			return err
		}
	}

	room, err := grouppkg.NewServer(roomName, localName, identity.Fingerprint())
	if err != nil {
		return err
	}
	defer room.Close()

	go acceptRoomMembers(listener, identity, stdin, stdout, runtime, room, roomName, allowUntrusted, localName)

	err = ui.RunGroupChat(stdin, stdout, room)
	var closedErr *ui.SessionClosedError
	if errors.As(err, &closedErr) {
		return nil
	}
	return err
}

func runRoomJoin(stdin io.Reader, stdout io.Writer, address, roomName, identityPath, knownPeersPath, peerLabel string, allowUntrusted, memoryOnly, noPassphrase bool, localName string) error {
	runtime, identity, err := resolveSessionIdentity(stdout, identityPath, knownPeersPath, memoryOnly, noPassphrase)
	if err != nil {
		return err
	}

	config := netpkg.DialConfig{RemoteAddress: address}
	if err := config.Validate(); err != nil {
		return err
	}

	conn, peer, err := netpkg.Dial(config, identity, stdout)
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

	if err := conn.SendMessage(protocol.Message{
		Type:     protocol.MessageTypeGroupHello,
		RoomName: roomName,
		Name:     localName,
	}); err != nil {
		return err
	}

	list, err := conn.ReceiveMessage()
	if err != nil {
		return fmt.Errorf("receive room member list: %w", err)
	}
	if list.Type != protocol.MessageTypeGroupMemberList {
		return fmt.Errorf("expected group member list, got %q", list.Type)
	}

	room := grouppkg.NewClientWithMemberList(roomName, localName, conn, list)
	err = ui.RunGroupChat(stdin, stdout, room)
	var closedErr *ui.SessionClosedError
	if errors.As(err, &closedErr) {
		return nil
	}
	return err
}

func acceptRoomMembers(listener *netpkg.SessionListener, identity *cryptopkg.Identity, stdin io.Reader, stdout io.Writer, runtime runtimeConfig, room *grouppkg.Server, roomName string, allowUntrusted bool, localName string) {
	for {
		conn, peer, err := listener.Accept(identity, io.Discard)
		if err != nil {
			return
		}

		peerName, err := exchangeNames(conn, false, localName)
		if err != nil {
			_ = conn.Close()
			continue
		}

		fallbackLabel := peerName
		if fallbackLabel == "" {
			fallbackLabel = conn.RemoteAddress()
		}

		trustErr := checkRoomPeerTrust(runtime, fallbackLabel, peer.Fingerprint, allowUntrusted)
		if err := coordinateSessionAdmission(conn, false, trustErr); err != nil {
			_ = conn.Close()
			continue
		}

		hello, err := conn.ReceiveMessage()
		if err != nil {
			_ = conn.Close()
			continue
		}
		if hello.Type != protocol.MessageTypeGroupHello || hello.RoomName != roomName {
			_ = conn.Close()
			continue
		}
		if hello.Name != "" {
			peerName = hello.Name
		}

		if err := room.AddMember(conn, peerName, peer); err != nil {
			_ = conn.Close()
		}
	}
}

func checkRoomPeerTrust(runtime runtimeConfig, fallbackLabel, fingerprint string, allowUntrusted bool) error {
	if runtime.MemoryOnly {
		return nil
	}

	store, err := openTrustStore(runtime.KnownPeersPath)
	if err != nil {
		return err
	}

	observation, err := store.Check(fallbackLabel, fingerprint)
	if err != nil {
		return err
	}

	switch observation.Status {
	case trust.StatusNew:
		if !allowUntrusted {
			return &trustBlockedError{reason: fmt.Sprintf("untrusted peer %s", observation.Label)}
		}
		return store.Set(observation.Label, observation.Observed, time.Now())
	case trust.StatusMatch:
		_, err := store.Observe(observation.Label, observation.Observed, time.Now())
		return err
	case trust.StatusMismatch:
		if !allowUntrusted {
			return &trustBlockedError{reason: fmt.Sprintf("peer fingerprint changed for %s", observation.Label)}
		}
		return store.Set(observation.Label, observation.Observed, time.Now())
	default:
		return fmt.Errorf("unknown trust observation status: %d", observation.Status)
	}
}

func resolveSessionIdentity(stdout io.Writer, identityPath, knownPeersPath string, memoryOnly, noPassphrase bool) (runtimeConfig, *cryptopkg.Identity, error) {
	runtime, err := resolveRuntimeConfig(identityPath, knownPeersPath, memoryOnly)
	if err != nil {
		return runtimeConfig{}, nil, err
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
		return runtimeConfig{}, nil, err
	}
	if _, err := fmt.Fprintln(stdout, modeNotice); err != nil {
		return runtimeConfig{}, nil, err
	}
	if runtime.MemoryOnly {
		if _, err := fmt.Fprintln(stdout, ui.MemoryOnlyModeNotice); err != nil {
			return runtimeConfig{}, nil, err
		}
	}
	return runtime, identity, nil
}

func startRoomTunnel(ctx context.Context, listen string) (string, error) {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("parse listen address: %w", err)
	}
	localPort, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("parse listen port: %w", err)
	}
	return tunnelpkg.Start(ctx, localPort)
}
