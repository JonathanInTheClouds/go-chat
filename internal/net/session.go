package net

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"path/filepath"
	"strings"
	"time"

	cryptopkg "github.com/JonathanInTheClouds/go-chat/internal/crypto"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"

	"github.com/flynn/noise"
)

type ListenerConfig struct {
	ListenAddress string
}

type SessionListener struct {
	listener stdnet.Listener
}

func (c ListenerConfig) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen address is required")
	}

	if _, err := stdnet.ResolveTCPAddr("tcp", c.ListenAddress); err != nil {
		return err
	}

	return nil
}

type DialConfig struct {
	RemoteAddress string
}

func (c DialConfig) Validate() error {
	if c.RemoteAddress == "" {
		return errors.New("remote address is required")
	}

	if _, err := stdnet.ResolveTCPAddr("tcp", c.RemoteAddress); err != nil {
		return err
	}

	return nil
}

func Listen(config ListenerConfig, status io.Writer) (*SessionListener, error) {
	listener, err := stdnet.Listen("tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	if _, err := fmt.Fprintf(status, "listening on %s\n", config.ListenAddress); err != nil {
		listener.Close()
		return nil, err
	}

	return &SessionListener{listener: listener}, nil
}

func (l *SessionListener) Close() error {
	return l.listener.Close()
}

func (l *SessionListener) Accept(identity *cryptopkg.Identity, status io.Writer) (*SecureSession, PeerIdentity, error) {
	if _, err := fmt.Fprintln(status, "waiting for peer..."); err != nil {
		return nil, PeerIdentity{}, err
	}

	conn, err := l.listener.Accept()
	if err != nil {
		return nil, PeerIdentity{}, fmt.Errorf("accept peer: %w", err)
	}

	session, err := establishSession(conn, identity, false)
	if err != nil {
		conn.Close()
		return nil, PeerIdentity{}, err
	}

	if _, err := fmt.Fprintf(status, "peer connected from %s\n", conn.RemoteAddr().String()); err != nil {
		session.Close()
		return nil, PeerIdentity{}, err
	}

	return session, session.PeerIdentity(), nil
}

type PeerIdentity struct {
	SigningPublicKey      ed25519.PublicKey
	KeyAgreementPublicKey []byte
	Fingerprint           string
}

type SecureSession struct {
	conn    stdnet.Conn
	send    *noise.CipherState
	receive *noise.CipherState
	local   *cryptopkg.Identity
	peer    PeerIdentity
}

func (s *SecureSession) Close() error {
	return s.conn.Close()
}

func (s *SecureSession) LocalFingerprint() string {
	return s.local.Fingerprint()
}

func (s *SecureSession) PeerIdentity() PeerIdentity {
	return s.peer
}

func (s *SecureSession) RemoteAddress() string {
	return s.conn.RemoteAddr().String()
}

func (s *SecureSession) Send(message string) error {
	return s.SendChat(message)
}

func (s *SecureSession) SendChat(message string) error {
	return s.sendProtocolMessage(protocol.Message{
		Type: protocol.MessageTypeChat,
		Text: message,
	})
}

func (s *SecureSession) SendName(name string) error {
	return s.sendProtocolMessage(protocol.Message{
		Type: protocol.MessageTypeHandshakeName,
		Text: name,
	})
}

func (s *SecureSession) SendTyping() error {
	return s.sendProtocolMessage(protocol.Message{
		Type: protocol.MessageTypeTyping,
	})
}

func (s *SecureSession) SendSessionAccept() error {
	return s.sendProtocolMessage(protocol.Message{
		Type: protocol.MessageTypeSessionAccept,
	})
}

func (s *SecureSession) SendSessionReject(reason string) error {
	return s.sendProtocolMessage(protocol.Message{
		Type: protocol.MessageTypeSessionReject,
		Text: reason,
	})
}

func (s *SecureSession) SendFile(path string) (string, string, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", 0, fmt.Errorf("file transfer only supports regular files: %s", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	fileID, err := randomFileID()
	if err != nil {
		return "", "", 0, err
	}

	name := filepath.Base(path)
	size := info.Size()
	if err := s.sendProtocolMessage(protocol.Message{
		Type:   protocol.MessageTypeFileStart,
		FileID: fileID,
		Name:   name,
		Size:   size,
	}); err != nil {
		return "", "", 0, err
	}

	buffer := make([]byte, protocol.FileChunkSize)
	index := 0
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			if err := s.sendProtocolMessage(protocol.Message{
				Type:   protocol.MessageTypeFileChunk,
				FileID: fileID,
				Index:  index,
				Chunk:  chunk,
			}); err != nil {
				return "", "", 0, err
			}
			index++
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", "", 0, fmt.Errorf("read file chunk: %w", readErr)
		}
	}

	if err := s.sendProtocolMessage(protocol.Message{
		Type:   protocol.MessageTypeFileComplete,
		FileID: fileID,
	}); err != nil {
		return "", "", 0, err
	}

	return fileID, name, size, nil
}

func (s *SecureSession) SaveIncomingFile(fileID, name string, expectedSize int64, destinationDir string) (string, int64, error) {
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		return "", 0, fmt.Errorf("create destination directory: %w", err)
	}

	safeName := filepath.Base(name)
	if safeName == "." || safeName == "" {
		safeName = "received.bin"
	}
	targetPath, err := nextAvailableFilePath(destinationDir, safeName)
	if err != nil {
		return "", 0, err
	}

	file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, fmt.Errorf("create destination file: %w", err)
	}
	defer file.Close()

	var (
		written   int64
		nextIndex int
	)

	for {
		message, err := s.ReceiveMessage()
		if err != nil {
			_ = os.Remove(targetPath)
			return "", 0, err
		}

		switch message.Type {
		case protocol.MessageTypeFileChunk:
			if message.FileID != fileID {
				_ = os.Remove(targetPath)
				return "", 0, fmt.Errorf("received chunk for unexpected file id %s", message.FileID)
			}
			if message.Index != nextIndex {
				_ = os.Remove(targetPath)
				return "", 0, fmt.Errorf("received out-of-order chunk index %d; expected %d", message.Index, nextIndex)
			}
			n, err := file.Write(message.Chunk)
			if err != nil {
				_ = os.Remove(targetPath)
				return "", 0, fmt.Errorf("write received chunk: %w", err)
			}
			written += int64(n)
			nextIndex++
		case protocol.MessageTypeFileComplete:
			if message.FileID != fileID {
				_ = os.Remove(targetPath)
				return "", 0, fmt.Errorf("received file completion for unexpected file id %s", message.FileID)
			}
			if written != expectedSize {
				_ = os.Remove(targetPath)
				return "", 0, fmt.Errorf("received size mismatch: wrote %d bytes, expected %d", written, expectedSize)
			}
			return targetPath, written, nil
		default:
			_ = os.Remove(targetPath)
			return "", 0, fmt.Errorf("received unexpected message type %q during file transfer", message.Type)
		}
	}
}

func (s *SecureSession) sendProtocolMessage(message protocol.Message) error {
	payload, err := protocol.EncodeMessage(message)
	if err != nil {
		return err
	}

	ciphertext, err := s.send.Encrypt(nil, nil, payload)
	if err != nil {
		return fmt.Errorf("encrypt message: %w", err)
	}

	frame, err := protocol.EncodeFrame(ciphertext)
	if err != nil {
		return err
	}

	if _, err := s.conn.Write(frame); err != nil {
		return fmt.Errorf("write encrypted frame: %w", err)
	}

	return nil
}

func (s *SecureSession) Receive() (string, error) {
	message, err := s.ReceiveMessage()
	if err != nil {
		return "", err
	}
	if message.Type != protocol.MessageTypeChat {
		return "", fmt.Errorf("unexpected protocol message type %q", message.Type)
	}
	return message.Text, nil
}

func (s *SecureSession) ReceiveMessage() (protocol.Message, error) {
	frame, err := protocol.DecodeFrame(s.conn)
	if err != nil {
		return protocol.Message{}, fmt.Errorf("read encrypted frame: %w", err)
	}

	plaintext, err := s.receive.Decrypt(nil, nil, frame)
	if err != nil {
		return protocol.Message{}, fmt.Errorf("decrypt message: %w", err)
	}

	return protocol.DecodeMessage(plaintext)
}

func ListenAndAccept(config ListenerConfig, identity *cryptopkg.Identity, status io.Writer) (*SecureSession, PeerIdentity, error) {
	listener, err := Listen(config, status)
	if err != nil {
		return nil, PeerIdentity{}, err
	}
	defer listener.Close()
	return listener.Accept(identity, status)
}

func Dial(config DialConfig, identity *cryptopkg.Identity, status io.Writer) (*SecureSession, PeerIdentity, error) {
	if _, err := fmt.Fprintf(status, "dialing %s\n", config.RemoteAddress); err != nil {
		return nil, PeerIdentity{}, err
	}

	conn, err := stdnet.DialTimeout("tcp", config.RemoteAddress, 10*time.Second)
	if err != nil {
		return nil, PeerIdentity{}, fmt.Errorf("dial peer: %w", err)
	}

	session, err := establishSession(conn, identity, true)
	if err != nil {
		conn.Close()
		return nil, PeerIdentity{}, err
	}

	return session, session.PeerIdentity(), nil
}

func establishSession(conn stdnet.Conn, identity *cryptopkg.Identity, initiator bool) (*SecureSession, error) {
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		StaticKeypair: identity.NoiseStaticKeypair(),
	})
	if err != nil {
		return nil, fmt.Errorf("create handshake state: %w", err)
	}

	sendCipher, receiveCipher, err := runHandshake(conn, handshake, initiator)
	if err != nil {
		return nil, err
	}
	if !initiator {
		sendCipher, receiveCipher = receiveCipher, sendCipher
	}

	peer, err := exchangePeerIdentity(conn, sendCipher, receiveCipher, identity, handshake.PeerStatic(), initiator)
	if err != nil {
		return nil, err
	}

	return &SecureSession{
		conn:    conn,
		send:    sendCipher,
		receive: receiveCipher,
		local:   identity,
		peer:    peer,
	}, nil
}

func runHandshake(conn stdnet.Conn, handshake *noise.HandshakeState, initiator bool) (*noise.CipherState, *noise.CipherState, error) {
	var (
		writeCipher *noise.CipherState
		readCipher  *noise.CipherState
		err         error
	)

	if initiator {
		if writeCipher, readCipher, err = writeHandshakeMessage(conn, handshake, []byte("github.com/JonathanInTheClouds/go-chat/v1")); err != nil {
			return nil, nil, err
		}
		if writeCipher == nil && readCipher == nil {
			if writeCipher, readCipher, err = readHandshakeMessage(conn, handshake); err != nil {
				return nil, nil, err
			}
		}
		if writeCipher == nil && readCipher == nil {
			if writeCipher, readCipher, err = writeHandshakeMessage(conn, handshake, nil); err != nil {
				return nil, nil, err
			}
		}
	} else {
		if writeCipher, readCipher, err = readHandshakeMessage(conn, handshake); err != nil {
			return nil, nil, err
		}
		if writeCipher == nil && readCipher == nil {
			if writeCipher, readCipher, err = writeHandshakeMessage(conn, handshake, []byte("github.com/JonathanInTheClouds/go-chat/v1")); err != nil {
				return nil, nil, err
			}
		}
		if writeCipher == nil && readCipher == nil {
			if writeCipher, readCipher, err = readHandshakeMessage(conn, handshake); err != nil {
				return nil, nil, err
			}
		}
	}

	if writeCipher == nil || readCipher == nil {
		return nil, nil, errors.New("handshake did not produce transport cipher states")
	}

	return writeCipher, readCipher, nil
}

func writeHandshakeMessage(conn stdnet.Conn, handshake *noise.HandshakeState, payload []byte) (*noise.CipherState, *noise.CipherState, error) {
	message, sendCipher, recvCipher, err := handshake.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("write handshake message: %w", err)
	}

	frame, err := protocol.EncodeFrame(message)
	if err != nil {
		return nil, nil, err
	}

	if _, err := conn.Write(frame); err != nil {
		return nil, nil, fmt.Errorf("send handshake frame: %w", err)
	}

	return sendCipher, recvCipher, nil
}

func readHandshakeMessage(conn stdnet.Conn, handshake *noise.HandshakeState) (*noise.CipherState, *noise.CipherState, error) {
	frame, err := protocol.DecodeFrame(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read handshake frame: %w", err)
	}

	_, sendCipher, recvCipher, err := handshake.ReadMessage(nil, frame)
	if err != nil {
		return nil, nil, fmt.Errorf("read handshake message: %w", err)
	}

	return sendCipher, recvCipher, nil
}

func exchangePeerIdentity(conn stdnet.Conn, sendCipher, receiveCipher *noise.CipherState, identity *cryptopkg.Identity, peerStatic []byte, initiator bool) (PeerIdentity, error) {
	localIdentityFrame, err := encodeIdentityFrame(identity)
	if err != nil {
		return PeerIdentity{}, err
	}

	if initiator {
		if err := sendEncryptedFrame(conn, sendCipher, localIdentityFrame); err != nil {
			return PeerIdentity{}, err
		}

		peer, err := readAndVerifyPeerIdentity(conn, receiveCipher, peerStatic)
		if err != nil {
			return PeerIdentity{}, err
		}

		return peer, nil
	}

	peer, err := readAndVerifyPeerIdentity(conn, receiveCipher, peerStatic)
	if err != nil {
		return PeerIdentity{}, err
	}

	if err := sendEncryptedFrame(conn, sendCipher, localIdentityFrame); err != nil {
		return PeerIdentity{}, err
	}

	return peer, nil
}

type encodedPeerIdentity struct {
	SigningPublicKey      ed25519.PublicKey
	KeyAgreementPublicKey []byte
	signature             []byte
}

func sendEncryptedFrame(conn stdnet.Conn, sendCipher *noise.CipherState, payload []byte) error {
	ciphertext, err := sendCipher.Encrypt(nil, nil, payload)
	if err != nil {
		return fmt.Errorf("encrypt identity frame: %w", err)
	}

	frame, err := protocol.EncodeFrame(ciphertext)
	if err != nil {
		return err
	}

	if _, err := conn.Write(frame); err != nil {
		return fmt.Errorf("send identity frame: %w", err)
	}

	return nil
}

func readAndVerifyPeerIdentity(conn stdnet.Conn, receiveCipher *noise.CipherState, peerStatic []byte) (PeerIdentity, error) {
	peerFrame, err := protocol.DecodeFrame(conn)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("read identity frame: %w", err)
	}

	plaintext, err := receiveCipher.Decrypt(nil, nil, peerFrame)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("decrypt identity frame: %w", err)
	}

	peer, err := decodePeerIdentity(plaintext)
	if err != nil {
		return PeerIdentity{}, err
	}

	if !bytes.Equal(peer.KeyAgreementPublicKey, peerStatic) {
		return PeerIdentity{}, errors.New("peer identity key does not match Noise static key")
	}

	if !cryptopkg.VerifySignedStaticKey(peer.SigningPublicKey, peer.KeyAgreementPublicKey, peer.signature) {
		return PeerIdentity{}, errors.New("peer signature over static key is invalid")
	}

	verified := cryptopkg.Identity{
		SigningPublicKey:      append(ed25519.PublicKey(nil), peer.SigningPublicKey...),
		KeyAgreementPublicKey: append([]byte(nil), peer.KeyAgreementPublicKey...),
	}

	return PeerIdentity{
		SigningPublicKey:      peer.SigningPublicKey,
		KeyAgreementPublicKey: peer.KeyAgreementPublicKey,
		Fingerprint:           verified.Fingerprint(),
	}, nil
}

func encodeIdentityFrame(identity *cryptopkg.Identity) ([]byte, error) {
	signature := identity.SignedStaticKey()
	payload := make([]byte, 0, 2+len(identity.SigningPublicKey)+2+len(identity.KeyAgreementPublicKey)+2+len(signature))
	payload = appendLengthPrefixed(payload, identity.SigningPublicKey)
	payload = appendLengthPrefixed(payload, identity.KeyAgreementPublicKey)
	payload = appendLengthPrefixed(payload, signature)
	return payload, nil
}

func decodePeerIdentity(payload []byte) (encodedPeerIdentity, error) {
	signingKey, rest, err := consumeLengthPrefixed(payload)
	if err != nil {
		return encodedPeerIdentity{}, err
	}

	staticKey, rest, err := consumeLengthPrefixed(rest)
	if err != nil {
		return encodedPeerIdentity{}, err
	}

	signature, rest, err := consumeLengthPrefixed(rest)
	if err != nil {
		return encodedPeerIdentity{}, err
	}

	if len(rest) != 0 {
		return encodedPeerIdentity{}, errors.New("identity payload has trailing bytes")
	}

	if len(signingKey) != ed25519.PublicKeySize {
		return encodedPeerIdentity{}, errors.New("invalid ed25519 public key size")
	}

	return encodedPeerIdentity{
		SigningPublicKey:      ed25519.PublicKey(signingKey),
		KeyAgreementPublicKey: staticKey,
		signature:             signature,
	}, nil
}

func appendLengthPrefixed(dst, value []byte) []byte {
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(value)))
	dst = append(dst, header[:]...)
	dst = append(dst, value...)
	return dst
}

func consumeLengthPrefixed(payload []byte) ([]byte, []byte, error) {
	if len(payload) < 2 {
		return nil, nil, errors.New("truncated length-prefixed field")
	}

	size := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if len(payload) < size {
		return nil, nil, errors.New("truncated length-prefixed value")
	}

	return append([]byte(nil), payload[:size]...), payload[size:], nil
}

func randomFileID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate file id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func nextAvailableFilePath(destinationDir, baseName string) (string, error) {
	target := filepath.Join(destinationDir, baseName)
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		return target, nil
	}

	ext := filepath.Ext(baseName)
	stem := strings.TrimSuffix(baseName, ext)
	for idx := 1; idx < 10000; idx++ {
		candidate := filepath.Join(destinationDir, fmt.Sprintf("%s_%d%s", stem, idx, ext))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not allocate destination path for %s", baseName)
}
