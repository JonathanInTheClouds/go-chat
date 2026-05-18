package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	boreServer = "bore.pub:7835"
)

type serverMsg struct {
	Hello      *uint16
	Connection *string
	Error      *string
	Heartbeat  bool
}

func sendMsg(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(data)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func recvServerMsg(conn net.Conn) (serverMsg, error) {
	var lenBuf [8]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return serverMsg{}, err
	}
	size := binary.LittleEndian.Uint64(lenBuf[:])
	if size > 64*1024 {
		return serverMsg{}, fmt.Errorf("message too large: %d bytes", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return serverMsg{}, err
	}

	// unit variant serializes as a plain JSON string e.g. "Heartbeat"
	var s string
	if json.Unmarshal(data, &s) == nil {
		if s == "Heartbeat" {
			return serverMsg{Heartbeat: true}, nil
		}
		return serverMsg{}, fmt.Errorf("unknown string message: %q", s)
	}

	// tuple variants serialize as {"Hello":port}, {"Connection":"uuid"}, {"Error":"msg"}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return serverMsg{}, fmt.Errorf("decode server message: %w", err)
	}

	var msg serverMsg
	if raw, ok := obj["Hello"]; ok {
		var port uint16
		if err := json.Unmarshal(raw, &port); err != nil {
			return serverMsg{}, err
		}
		msg.Hello = &port
	} else if raw, ok := obj["Connection"]; ok {
		var uuid string
		if err := json.Unmarshal(raw, &uuid); err != nil {
			return serverMsg{}, err
		}
		msg.Connection = &uuid
	} else if raw, ok := obj["Error"]; ok {
		var errMsg string
		if err := json.Unmarshal(raw, &errMsg); err != nil {
			return serverMsg{}, err
		}
		msg.Error = &errMsg
	} else {
		return serverMsg{}, fmt.Errorf("unknown message: %s", data)
	}

	return msg, nil
}

// Start opens a tunnel on bore.pub for localPort and returns the public
// address (e.g. "bore.pub:49152"). The tunnel runs until ctx is cancelled.
func Start(ctx context.Context, localPort int) (string, error) {
	controlConn, err := net.DialTimeout("tcp", boreServer, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("connect to bore.pub: %w", err)
	}

	if err := sendMsg(controlConn, map[string]any{"Hello": 0}); err != nil {
		controlConn.Close()
		return "", fmt.Errorf("send hello: %w", err)
	}

	msg, err := recvServerMsg(controlConn)
	if err != nil {
		controlConn.Close()
		return "", fmt.Errorf("receive hello: %w", err)
	}
	if msg.Error != nil {
		controlConn.Close()
		return "", fmt.Errorf("bore.pub error: %s", *msg.Error)
	}
	if msg.Hello == nil {
		controlConn.Close()
		return "", fmt.Errorf("expected hello response from bore.pub")
	}

	publicAddr := fmt.Sprintf("bore.pub:%d", *msg.Hello)

	go runControlLoop(ctx, controlConn, localPort)

	return publicAddr, nil
}

func runControlLoop(ctx context.Context, controlConn net.Conn, localPort int) {
	defer controlConn.Close()

	msgCh := make(chan serverMsg, 8)
	errCh := make(chan error, 1)

	go func() {
		for {
			msg, err := recvServerMsg(controlConn)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-errCh:
			return
		case msg := <-msgCh:
			if msg.Heartbeat {
				// respond to keep the control connection alive
				if err := sendMsg(controlConn, "Heartbeat"); err != nil {
					return
				}
				continue
			}
			if msg.Connection != nil {
				go forwardConnection(*msg.Connection, localPort)
			}
		}
	}
}

func forwardConnection(uuid string, localPort int) {
	relayConn, err := net.DialTimeout("tcp", boreServer, 10*time.Second)
	if err != nil {
		return
	}

	if err := sendMsg(relayConn, map[string]any{"Accept": uuid}); err != nil {
		relayConn.Close()
		return
	}

	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", localPort), 5*time.Second)
	if err != nil {
		relayConn.Close()
		return
	}

	pipe(relayConn, localConn)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(a, b)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(b, a)
	}()
	<-done
	a.Close()
	b.Close()
}
