package net

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptopkg "github.com/JonathanInTheClouds/go-chat/internal/crypto"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"
)

func TestEstablishSessionAndExchangeMessages(t *testing.T) {
	serverIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}

	clientIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		session *SecureSession
		err     error
	}

	serverResult := make(chan result, 1)
	clientResult := make(chan result, 1)

	go func() {
		session, err := establishSession(serverConn, serverIdentity, false)
		serverResult <- result{session: session, err: err}
	}()

	go func() {
		session, err := establishSession(clientConn, clientIdentity, true)
		clientResult <- result{session: session, err: err}
	}()

	serverSession := <-serverResult
	clientSession := <-clientResult

	if serverSession.err != nil {
		t.Fatalf("server handshake failed: %v", serverSession.err)
	}
	if clientSession.err != nil {
		t.Fatalf("client handshake failed: %v", clientSession.err)
	}

	if serverSession.session.PeerIdentity().Fingerprint != clientIdentity.Fingerprint() {
		t.Fatalf("server saw wrong peer fingerprint: got %s want %s", serverSession.session.PeerIdentity().Fingerprint, clientIdentity.Fingerprint())
	}
	if clientSession.session.PeerIdentity().Fingerprint != serverIdentity.Fingerprint() {
		t.Fatalf("client saw wrong peer fingerprint: got %s want %s", clientSession.session.PeerIdentity().Fingerprint, serverIdentity.Fingerprint())
	}

	go func() {
		if err := clientSession.session.Send("hello from client"); err != nil {
			t.Errorf("client send failed: %v", err)
		}
	}()

	serverMessage, err := serverSession.session.Receive()
	if err != nil {
		t.Fatalf("server receive failed: %v", err)
	}
	if serverMessage != "hello from client" {
		t.Fatalf("server got wrong message: %q", serverMessage)
	}

	go func() {
		if err := serverSession.session.Send("hello from server"); err != nil {
			t.Errorf("server send failed: %v", err)
		}
	}()

	clientMessage, err := clientSession.session.Receive()
	if err != nil {
		t.Fatalf("client receive failed: %v", err)
	}
	if clientMessage != "hello from server" {
		t.Fatalf("client got wrong message: %q", clientMessage)
	}
}

func TestEncryptedFileTransfer(t *testing.T) {
	serverIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate server identity: %v", err)
	}

	clientIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		session *SecureSession
		err     error
	}

	serverResult := make(chan result, 1)
	clientResult := make(chan result, 1)

	go func() {
		session, err := establishSession(serverConn, serverIdentity, false)
		serverResult <- result{session: session, err: err}
	}()

	go func() {
		session, err := establishSession(clientConn, clientIdentity, true)
		clientResult <- result{session: session, err: err}
	}()

	serverSession := <-serverResult
	clientSession := <-clientResult
	if serverSession.err != nil || clientSession.err != nil {
		t.Fatalf("handshake failed: server=%v client=%v", serverSession.err, clientSession.err)
	}

	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "sample.txt")
	sourceData := []byte(strings.Repeat("file payload\n", 800))
	if err := os.WriteFile(sourcePath, sourceData, 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	type transferResult struct {
		path string
		size int64
		err  error
	}
	saveResult := make(chan transferResult, 1)

	go func() {
		message, err := serverSession.session.ReceiveMessage()
		if err != nil {
			saveResult <- transferResult{err: err}
			return
		}
		if message.Type != protocol.MessageTypeFileStart {
			saveResult <- transferResult{err: fmt.Errorf("unexpected message type %q", message.Type)}
			return
		}
		path, size, err := serverSession.session.SaveIncomingFile(message.FileID, message.Name, message.Size, filepath.Join(t.TempDir(), "incoming"))
		saveResult <- transferResult{path: path, size: size, err: err}
	}()

	fileID, name, size, err := clientSession.session.SendFile(sourcePath)
	if err != nil {
		t.Fatalf("send file: %v", err)
	}
	if fileID == "" || name != "sample.txt" || size != int64(len(sourceData)) {
		t.Fatalf("unexpected send metadata: id=%q name=%q size=%d", fileID, name, size)
	}

	resultData := <-saveResult
	if resultData.err != nil {
		t.Fatalf("save incoming file: %v", resultData.err)
	}
	if resultData.size != int64(len(sourceData)) {
		t.Fatalf("unexpected saved size: %d", resultData.size)
	}

	saved, err := os.ReadFile(resultData.path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if string(saved) != string(sourceData) {
		t.Fatalf("saved file contents do not match source")
	}
}
