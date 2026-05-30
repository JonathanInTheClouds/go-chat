package group

import (
	"io"
	"testing"
	"time"

	cryptopkg "github.com/JonathanInTheClouds/go-chat/internal/crypto"
	netpkg "github.com/JonathanInTheClouds/go-chat/internal/net"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"
)

func TestServerRelaysMessagesBetweenThreeMembers(t *testing.T) {
	hostIdentity := mustIdentity(t)
	bobIdentity := mustIdentity(t)
	carolIdentity := mustIdentity(t)

	listener, err := netpkg.Listen(netpkg.ListenerConfig{ListenAddress: "127.0.0.1:0"}, io.Discard)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	room, err := NewServer("lab", "Alice", hostIdentity.Fingerprint())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer room.Close()

	namesByFingerprint := map[string]string{
		bobIdentity.Fingerprint():   "Bob",
		carolIdentity.Fingerprint(): "Carol",
	}
	acceptErr := make(chan error, 1)
	go acceptTestMembers(t, listener, room, hostIdentity, namesByFingerprint, acceptErr)

	bobSession, _, err := netpkg.Dial(netpkg.DialConfig{RemoteAddress: listener.Addr().String()}, bobIdentity, io.Discard)
	if err != nil {
		t.Fatalf("dial bob: %v", err)
	}
	defer bobSession.Close()

	carolSession, _, err := netpkg.Dial(netpkg.DialConfig{RemoteAddress: listener.Addr().String()}, carolIdentity, io.Discard)
	if err != nil {
		t.Fatalf("dial carol: %v", err)
	}
	defer carolSession.Close()

	if err := <-acceptErr; err != nil {
		t.Fatalf("accept members: %v", err)
	}

	bobClient := clientFromInitialList(t, "lab", "Bob", bobSession)
	carolClient := clientFromInitialList(t, "lab", "Carol", carolSession)

	if err := bobClient.SendChat("hello from bob"); err != nil {
		t.Fatalf("bob send: %v", err)
	}
	bobOwnEvent := waitForGroupEvent(t, bobClient.Events(), EventMessage)
	if bobOwnEvent.Member.Name != "Bob" || bobOwnEvent.Text != "hello from bob" {
		t.Fatalf("bob saw wrong local echo: member=%q text=%q", bobOwnEvent.Member.Name, bobOwnEvent.Text)
	}

	serverEvent := waitForGroupEvent(t, room.Events(), EventMessage)
	if serverEvent.Member.Name != "Bob" || serverEvent.Text != "hello from bob" {
		t.Fatalf("server saw wrong message: member=%q text=%q", serverEvent.Member.Name, serverEvent.Text)
	}

	carolEvent := waitForGroupEvent(t, carolClient.Events(), EventMessage)
	if carolEvent.Member.Name != "Bob" || carolEvent.Text != "hello from bob" {
		t.Fatalf("carol saw wrong message: member=%q text=%q", carolEvent.Member.Name, carolEvent.Text)
	}

	if err := room.SendChat("hello from host"); err != nil {
		t.Fatalf("host send: %v", err)
	}

	bobEvent := waitForGroupEvent(t, bobClient.Events(), EventMessage)
	if bobEvent.Member.Name != "Alice" || bobEvent.Text != "hello from host" {
		t.Fatalf("bob saw wrong host message: member=%q text=%q", bobEvent.Member.Name, bobEvent.Text)
	}
	carolEvent = waitForGroupEvent(t, carolClient.Events(), EventMessage)
	if carolEvent.Member.Name != "Alice" || carolEvent.Text != "hello from host" {
		t.Fatalf("carol saw wrong host message: member=%q text=%q", carolEvent.Member.Name, carolEvent.Text)
	}
}

func TestReplacingSameMemberDoesNotRemoveNewConnection(t *testing.T) {
	hostIdentity := mustIdentity(t)
	sharedIdentity := mustIdentity(t)

	listener, err := netpkg.Listen(netpkg.ListenerConfig{ListenAddress: "127.0.0.1:0"}, io.Discard)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	room, err := NewServer("lab", "Alice", hostIdentity.Fingerprint())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer room.Close()

	acceptErr := make(chan error, 2)
	go acceptNamedTestMember(listener, room, hostIdentity, "Bob", acceptErr)

	firstSession, _, err := netpkg.Dial(netpkg.DialConfig{RemoteAddress: listener.Addr().String()}, sharedIdentity, io.Discard)
	if err != nil {
		t.Fatalf("dial first member: %v", err)
	}
	_ = clientFromInitialList(t, "lab", "Bob", firstSession)
	if err := <-acceptErr; err != nil {
		t.Fatalf("accept first member: %v", err)
	}

	go acceptNamedTestMember(listener, room, hostIdentity, "Carol", acceptErr)
	secondSession, _, err := netpkg.Dial(netpkg.DialConfig{RemoteAddress: listener.Addr().String()}, sharedIdentity, io.Discard)
	if err != nil {
		t.Fatalf("dial replacement member: %v", err)
	}
	defer secondSession.Close()

	replacementClient := clientFromInitialList(t, "lab", "Carol", secondSession)
	if err := <-acceptErr; err != nil {
		t.Fatalf("accept replacement member: %v", err)
	}

	if err := replacementClient.SendChat("still here"); err != nil {
		t.Fatalf("replacement send: %v", err)
	}
	event := waitForGroupEvent(t, room.Events(), EventMessage)
	if event.Member.Name != "Carol" || event.Text != "still here" {
		t.Fatalf("server saw wrong replacement message: member=%q text=%q", event.Member.Name, event.Text)
	}
}

func acceptTestMembers(t *testing.T, listener *netpkg.SessionListener, room *Server, hostIdentity *cryptopkg.Identity, namesByFingerprint map[string]string, result chan<- error) {
	t.Helper()
	for i := 0; i < len(namesByFingerprint); i++ {
		session, peer, err := listener.Accept(hostIdentity, io.Discard)
		if err != nil {
			result <- err
			return
		}
		name, ok := namesByFingerprint[peer.Fingerprint]
		if !ok {
			_ = session.Close()
			result <- nil
			return
		}
		if err := room.AddMember(session, name, peer); err != nil {
			result <- err
			return
		}
	}
	result <- nil
}

func acceptNamedTestMember(listener *netpkg.SessionListener, room *Server, hostIdentity *cryptopkg.Identity, name string, result chan<- error) {
	session, peer, err := listener.Accept(hostIdentity, io.Discard)
	if err != nil {
		result <- err
		return
	}
	result <- room.AddMember(session, name, peer)
}

func clientFromInitialList(t *testing.T, roomName, localName string, session *netpkg.SecureSession) *Client {
	t.Helper()
	list, err := session.ReceiveMessage()
	if err != nil {
		t.Fatalf("receive initial member list: %v", err)
	}
	if list.Type != protocol.MessageTypeGroupMemberList {
		t.Fatalf("expected member list, got %q", list.Type)
	}
	return NewClientWithMemberList(roomName, localName, session, list)
}

func waitForGroupEvent(t *testing.T, events <-chan Event, eventType EventType) Event {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Type == eventType {
				return event
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event type %d", eventType)
		}
	}
}

func mustIdentity(t *testing.T) *cryptopkg.Identity {
	t.Helper()
	identity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return identity
}
