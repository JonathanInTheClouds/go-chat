package group

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	netpkg "github.com/JonathanInTheClouds/go-chat/internal/net"
	"github.com/JonathanInTheClouds/go-chat/internal/protocol"
)

type EventType int

const (
	EventMemberList EventType = iota
	EventMemberJoined
	EventMemberLeft
	EventMessage
	EventTyping
	EventClosed
	EventError
)

type Member struct {
	ID          string
	Name        string
	Fingerprint string
	Address     string
}

type Event struct {
	Type    EventType
	Member  Member
	Members []Member
	Text    string
	Err     error
}

type Transport interface {
	RoomName() string
	GroupID() string
	InviteAddress() string
	LocalMember() Member
	Members() []Member
	Events() <-chan Event
	SendChat(text string) error
	SendTyping() error
	Close() error
}

type Server struct {
	mu         sync.Mutex
	roomName   string
	groupID    string
	local      Member
	invite     string
	senderKey  []byte
	senderSeq  uint64
	senderKeys map[string][]byte
	senderSeqs map[string]uint64
	epoch      uint64
	members    map[string]*serverMember
	events     chan Event
	closed     bool
}

type serverMember struct {
	member   Member
	session  *netpkg.SecureSession
	outbound chan protocol.Message
}

func NewServer(roomName, localName, localFingerprint string) (*Server, error) {
	groupID, err := randomID()
	if err != nil {
		return nil, err
	}
	senderKey, err := NewSenderKey()
	if err != nil {
		return nil, err
	}
	local := Member{
		ID:          MemberID(localFingerprint),
		Name:        localName,
		Fingerprint: localFingerprint,
		Address:     "local",
	}
	return &Server{
		roomName:   roomName,
		groupID:    groupID,
		local:      local,
		senderKey:  senderKey,
		senderSeq:  0,
		senderKeys: map[string][]byte{local.ID: cloneBytes(senderKey)},
		senderSeqs: map[string]uint64{local.ID: 0},
		epoch:      1,
		members:    map[string]*serverMember{},
		events:     make(chan Event, 64),
	}, nil
}

func (s *Server) RoomName() string {
	return s.roomName
}

func (s *Server) GroupID() string {
	return s.groupID
}

func (s *Server) InviteAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.invite
}

func (s *Server) SetInviteAddress(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invite = address
}

func (s *Server) LocalMember() Member {
	return s.local
}

func (s *Server) Members() []Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.membersLocked()
}

func (s *Server) Events() <-chan Event {
	return s.events
}

func (s *Server) AddMember(session *netpkg.SecureSession, name string, peer netpkg.PeerIdentity, senderKey []byte) error {
	if err := validateSenderKey(senderKey); err != nil {
		return err
	}

	member := Member{
		ID:          MemberID(peer.Fingerprint),
		Name:        name,
		Fingerprint: peer.Fingerprint,
		Address:     session.RemoteAddress(),
	}

	joined := protocol.Message{
		Type:        protocol.MessageTypeGroupMemberJoined,
		GroupID:     s.groupID,
		MemberID:    member.ID,
		Name:        member.Name,
		Fingerprint: member.Fingerprint,
		Address:     member.Address,
		SenderKey:   cloneBytes(senderKey),
	}

	wrapped := &serverMember{
		member:   member,
		session:  session,
		outbound: make(chan protocol.Message, 32),
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("group room is closed")
	}
	if old := s.members[member.ID]; old != nil {
		_ = old.session.Close()
		close(old.outbound)
	}
	s.members[member.ID] = wrapped
	s.senderKeys[member.ID] = cloneBytes(senderKey)
	s.senderSeqs[member.ID] = 0
	s.epoch++
	list := protocol.Message{
		Type:    protocol.MessageTypeGroupMemberList,
		GroupID: s.groupID,
		Epoch:   s.epoch,
		Members: s.protocolMembersLocked(),
	}
	wrapped.outbound <- list
	s.broadcastExceptLocked(joined, member.ID)
	members := s.membersLocked()
	s.mu.Unlock()

	s.emit(Event{Type: EventMemberJoined, Member: member, Members: members})
	go s.writeLoop(wrapped)
	go s.readLoop(wrapped)
	return nil
}

func (s *Server) SendChat(text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	messageID, err := randomID()
	if err != nil {
		return err
	}
	msg := protocol.Message{
		Type:     protocol.MessageTypeGroupChat,
		GroupID:  s.groupID,
		SenderID: s.local.ID,
	}
	if err := s.encryptLocalText(&msg, messageID, text); err != nil {
		return err
	}
	s.broadcast(msg)
	s.emit(Event{Type: EventMessage, Member: s.local, Text: text})
	return nil
}

func (s *Server) SendTyping() error {
	msg := protocol.Message{
		Type:     protocol.MessageTypeGroupTyping,
		GroupID:  s.groupID,
		SenderID: s.local.ID,
		Epoch:    s.currentEpoch(),
	}
	s.broadcast(msg)
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for id, member := range s.members {
		_ = member.session.Close()
		close(member.outbound)
		delete(s.members, id)
	}
	s.mu.Unlock()
	s.emit(Event{Type: EventClosed})
	return nil
}

func (s *Server) readLoop(member *serverMember) {
	for {
		msg, err := member.session.ReceiveMessage()
		if err != nil {
			s.removeMember(member)
			return
		}
		switch msg.Type {
		case protocol.MessageTypeGroupChat:
			if msg.MessageID == "" || len(msg.Ciphertext) == 0 || len(msg.Nonce) == 0 {
				continue
			}
			msg.GroupID = s.groupID
			msg.SenderID = member.member.ID
			msg.Epoch = s.currentEpoch()
			relayed := protocol.Message{
				Type:       protocol.MessageTypeGroupChat,
				GroupID:    msg.GroupID,
				SenderID:   msg.SenderID,
				SenderSeq:  msg.SenderSeq,
				MessageID:  msg.MessageID,
				Ciphertext: cloneBytes(msg.Ciphertext),
				Nonce:      cloneBytes(msg.Nonce),
				Epoch:      msg.Epoch,
			}
			s.broadcastExcept(relayed, member.member.ID)
			text, err := s.decryptText(relayed)
			if err != nil {
				s.emit(Event{Type: EventError, Member: member.member, Err: err})
				continue
			}
			s.emit(Event{Type: EventMessage, Member: member.member, Text: text})
		case protocol.MessageTypeGroupTyping:
			relayed := protocol.Message{
				Type:     protocol.MessageTypeGroupTyping,
				GroupID:  s.groupID,
				SenderID: member.member.ID,
				Epoch:    s.currentEpoch(),
			}
			s.broadcastExcept(relayed, member.member.ID)
			s.emit(Event{Type: EventTyping, Member: member.member})
		default:
			s.emit(Event{Type: EventError, Member: member.member, Err: fmt.Errorf("unexpected group message type %q", msg.Type)})
		}
	}
}

func (s *Server) writeLoop(member *serverMember) {
	for msg := range member.outbound {
		if err := member.session.SendMessage(msg); err != nil {
			s.removeMember(member)
			return
		}
	}
}

func (s *Server) removeMember(member *serverMember) {
	s.mu.Lock()
	current, ok := s.members[member.member.ID]
	if !ok || current != member {
		s.mu.Unlock()
		return
	}
	delete(s.members, member.member.ID)
	delete(s.senderKeys, member.member.ID)
	delete(s.senderSeqs, member.member.ID)
	s.epoch++
	_ = member.session.Close()
	close(member.outbound)
	left := protocol.Message{
		Type:     protocol.MessageTypeGroupMemberLeft,
		GroupID:  s.groupID,
		MemberID: member.member.ID,
		Epoch:    s.epoch,
	}
	s.broadcastExceptLocked(left, member.member.ID)
	members := s.membersLocked()
	s.mu.Unlock()
	s.emit(Event{Type: EventMemberLeft, Member: member.member, Members: members})
}

func (s *Server) broadcast(msg protocol.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broadcastExceptLocked(msg, "")
}

func (s *Server) broadcastExcept(msg protocol.Message, exceptID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broadcastExceptLocked(msg, exceptID)
}

func (s *Server) broadcastExceptLocked(msg protocol.Message, exceptID string) {
	for id, member := range s.members {
		if id == exceptID {
			continue
		}
		select {
		case member.outbound <- msg:
		default:
			s.emit(Event{Type: EventError, Member: member.member, Err: errors.New("member outbound queue is full")})
		}
	}
}

func (s *Server) membersLocked() []Member {
	members := make([]Member, 0, len(s.members)+1)
	members = append(members, s.local)
	for _, member := range s.members {
		members = append(members, member.member)
	}
	return members
}

func (s *Server) protocolMembersLocked() []protocol.GroupMember {
	members := s.membersLocked()
	result := make([]protocol.GroupMember, 0, len(members))
	for _, member := range members {
		result = append(result, protocol.GroupMember{
			ID:          member.ID,
			Name:        member.Name,
			Fingerprint: member.Fingerprint,
			Address:     member.Address,
			SenderKey:   cloneBytes(s.senderKeys[member.ID]),
			SenderSeq:   s.senderSeqs[member.ID],
		})
	}
	return result
}

func (s *Server) currentEpoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

func (s *Server) emit(event Event) {
	select {
	case s.events <- event:
	default:
	}
}

func (s *Server) decryptText(message protocol.Message) (string, error) {
	s.mu.Lock()
	key := cloneBytes(s.senderKeys[message.SenderID])
	expectedSeq := s.senderSeqs[message.SenderID]
	s.mu.Unlock()
	text, err := decryptGroupMessage(message, key, expectedSeq)
	if err != nil {
		return "", err
	}
	s.advanceSenderKey(message.SenderID, expectedSeq)
	return text, nil
}

func (s *Server) encryptLocalText(message *protocol.Message, messageID, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	message.Epoch = s.epoch
	if err := encryptGroupMessage(message, s.senderKey, s.senderSeq, messageID, text); err != nil {
		return err
	}
	s.senderKey = ratchetSenderKey(s.senderKey)
	s.senderSeq++
	s.senderKeys[s.local.ID] = cloneBytes(s.senderKey)
	s.senderSeqs[s.local.ID] = s.senderSeq
	return nil
}

func (s *Server) advanceSenderKey(memberID string, sequence uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.senderSeqs[memberID] != sequence {
		return
	}
	s.senderKeys[memberID] = ratchetSenderKey(s.senderKeys[memberID])
	s.senderSeqs[memberID]++
}

type Client struct {
	mu         sync.Mutex
	roomName   string
	groupID    string
	local      Member
	senderKey  []byte
	senderSeq  uint64
	senderKeys map[string][]byte
	senderSeqs map[string]uint64
	members    map[string]Member
	session    *netpkg.SecureSession
	events     chan Event
}

func NewClient(roomName, localName string, session *netpkg.SecureSession) *Client {
	client := newClient(roomName, localName, session)
	go client.readLoop()
	return client
}

func NewClientWithMemberList(roomName, localName string, session *netpkg.SecureSession, list protocol.Message) *Client {
	client := newClient(roomName, localName, session)
	members := membersFromProtocol(list.Members)
	senderKeys := senderKeysFromProtocol(list.Members)
	client.groupID = list.GroupID
	client.members = map[string]Member{}
	for _, member := range members {
		client.members[member.ID] = member
	}
	client.senderKeys = senderKeys
	client.senderSeqs = senderSeqsFromProtocol(list.Members)
	if senderKey := senderKeys[client.local.ID]; len(senderKey) > 0 {
		client.senderKey = cloneBytes(senderKey)
		client.senderSeq = client.senderSeqs[client.local.ID]
	}
	client.emit(Event{Type: EventMemberList, Members: members})
	go client.readLoop()
	return client
}

func newClient(roomName, localName string, session *netpkg.SecureSession) *Client {
	senderKey, err := NewSenderKey()
	if err != nil {
		panic(err)
	}
	local := Member{
		ID:          MemberID(session.LocalFingerprint()),
		Name:        localName,
		Fingerprint: session.LocalFingerprint(),
		Address:     "local",
	}
	client := &Client{
		roomName:   roomName,
		local:      local,
		senderKey:  senderKey,
		senderSeq:  0,
		senderKeys: map[string][]byte{local.ID: cloneBytes(senderKey)},
		senderSeqs: map[string]uint64{local.ID: 0},
		members:    map[string]Member{local.ID: local},
		session:    session,
		events:     make(chan Event, 64),
	}
	return client
}

func (c *Client) RoomName() string {
	return c.roomName
}

func (c *Client) GroupID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.groupID
}

func (c *Client) InviteAddress() string {
	return ""
}

func (c *Client) LocalMember() Member {
	return c.local
}

func (c *Client) Members() []Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	members := make([]Member, 0, len(c.members))
	for _, member := range c.members {
		members = append(members, member)
	}
	return members
}

func (c *Client) Events() <-chan Event {
	return c.events
}

func (c *Client) SendChat(text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	messageID, err := randomID()
	if err != nil {
		return err
	}
	msg := protocol.Message{
		Type:     protocol.MessageTypeGroupChat,
		GroupID:  c.GroupID(),
		SenderID: c.local.ID,
	}
	if err := c.encryptLocalText(&msg, messageID, text); err != nil {
		return err
	}
	if err := c.session.SendMessage(msg); err != nil {
		return err
	}
	c.emit(Event{Type: EventMessage, Member: c.local, Text: text})
	return nil
}

func (c *Client) SendTyping() error {
	return c.session.SendMessage(protocol.Message{
		Type:     protocol.MessageTypeGroupTyping,
		GroupID:  c.GroupID(),
		SenderID: c.local.ID,
	})
}

func (c *Client) Close() error {
	err := c.session.Close()
	c.emit(Event{Type: EventClosed})
	return err
}

func (c *Client) readLoop() {
	for {
		msg, err := c.session.ReceiveMessage()
		if err != nil {
			c.emit(Event{Type: EventClosed, Err: err})
			return
		}
		switch msg.Type {
		case protocol.MessageTypeGroupMemberList:
			members := membersFromProtocol(msg.Members)
			c.mu.Lock()
			c.groupID = msg.GroupID
			c.members = map[string]Member{}
			for _, member := range members {
				c.members[member.ID] = member
			}
			c.senderKeys = senderKeysFromProtocol(msg.Members)
			c.senderSeqs = senderSeqsFromProtocol(msg.Members)
			if senderKey := c.senderKeys[c.local.ID]; len(senderKey) > 0 {
				c.senderKey = cloneBytes(senderKey)
				c.senderSeq = c.senderSeqs[c.local.ID]
			}
			c.mu.Unlock()
			c.emit(Event{Type: EventMemberList, Members: members})
		case protocol.MessageTypeGroupMemberJoined:
			member := Member{
				ID:          msg.MemberID,
				Name:        msg.Name,
				Fingerprint: msg.Fingerprint,
				Address:     msg.Address,
			}
			c.mu.Lock()
			c.members[member.ID] = member
			c.senderKeys[member.ID] = cloneBytes(msg.SenderKey)
			c.senderSeqs[member.ID] = msg.SenderSeq
			members := c.membersLocked()
			c.mu.Unlock()
			c.emit(Event{Type: EventMemberJoined, Member: member, Members: members})
		case protocol.MessageTypeGroupMemberLeft:
			c.mu.Lock()
			member := c.members[msg.MemberID]
			delete(c.members, msg.MemberID)
			delete(c.senderKeys, msg.MemberID)
			delete(c.senderSeqs, msg.MemberID)
			members := c.membersLocked()
			c.mu.Unlock()
			c.emit(Event{Type: EventMemberLeft, Member: member, Members: members})
		case protocol.MessageTypeGroupChat:
			text, err := c.decryptText(msg)
			if err != nil {
				c.emit(Event{Type: EventError, Err: err})
				continue
			}
			c.emit(Event{Type: EventMessage, Member: c.memberByID(msg.SenderID), Text: text})
		case protocol.MessageTypeGroupTyping:
			c.emit(Event{Type: EventTyping, Member: c.memberByID(msg.SenderID)})
		default:
			c.emit(Event{Type: EventError, Err: fmt.Errorf("unexpected group message type %q", msg.Type)})
		}
	}
}

func (c *Client) memberByID(memberID string) Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	if member, ok := c.members[memberID]; ok {
		return member
	}
	return Member{ID: memberID, Name: memberID}
}

func (c *Client) membersLocked() []Member {
	members := make([]Member, 0, len(c.members))
	for _, member := range c.members {
		members = append(members, member)
	}
	return members
}

func (c *Client) emit(event Event) {
	select {
	case c.events <- event:
	default:
	}
}

func (c *Client) SenderKey() []byte {
	return cloneBytes(c.senderKey)
}

func (c *Client) decryptText(message protocol.Message) (string, error) {
	c.mu.Lock()
	key := cloneBytes(c.senderKeys[message.SenderID])
	expectedSeq := c.senderSeqs[message.SenderID]
	c.mu.Unlock()
	text, err := decryptGroupMessage(message, key, expectedSeq)
	if err != nil {
		return "", err
	}
	c.advanceSenderKey(message.SenderID, expectedSeq)
	return text, nil
}

func (c *Client) encryptLocalText(message *protocol.Message, messageID, text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := encryptGroupMessage(message, c.senderKey, c.senderSeq, messageID, text); err != nil {
		return err
	}
	c.senderKey = ratchetSenderKey(c.senderKey)
	c.senderSeq++
	c.senderKeys[c.local.ID] = cloneBytes(c.senderKey)
	c.senderSeqs[c.local.ID] = c.senderSeq
	return nil
}

func (c *Client) advanceSenderKey(memberID string, sequence uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.senderSeqs[memberID] != sequence {
		return
	}
	c.senderKeys[memberID] = ratchetSenderKey(c.senderKeys[memberID])
	c.senderSeqs[memberID]++
}

func senderKeysFromProtocol(members []protocol.GroupMember) map[string][]byte {
	result := make(map[string][]byte, len(members))
	for _, member := range members {
		if len(member.SenderKey) > 0 {
			result[member.ID] = cloneBytes(member.SenderKey)
		}
	}
	return result
}

func senderSeqsFromProtocol(members []protocol.GroupMember) map[string]uint64 {
	result := make(map[string]uint64, len(members))
	for _, member := range members {
		result[member.ID] = member.SenderSeq
	}
	return result
}

func membersFromProtocol(members []protocol.GroupMember) []Member {
	result := make([]Member, 0, len(members))
	for _, member := range members {
		result = append(result, Member{
			ID:          member.ID,
			Name:        member.Name,
			Fingerprint: member.Fingerprint,
			Address:     member.Address,
		})
	}
	return result
}

func MemberID(fingerprint string) string {
	id := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	if len(id) > 16 {
		return id[:16]
	}
	return id
}

func randomID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func NewSenderKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate sender key: %w", err)
	}
	return key, nil
}

func validateSenderKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("sender key must be 32 bytes, got %d", len(key))
	}
	return nil
}

func encryptGroupMessage(message *protocol.Message, key []byte, sequence uint64, messageID, text string) error {
	if err := validateSenderKey(key); err != nil {
		return err
	}
	if message == nil {
		return errors.New("message is nil")
	}
	if message.GroupID == "" || message.SenderID == "" {
		return errors.New("group id and sender id are required")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	message.MessageID = messageID
	message.SenderSeq = sequence
	message.Nonce = nonce
	message.Ciphertext = aead.Seal(nil, nonce, []byte(text), groupMessageAAD(*message))
	message.Text = ""
	return nil
}

func decryptGroupMessage(message protocol.Message, key []byte, expectedSeq uint64) (string, error) {
	if err := validateSenderKey(key); err != nil {
		return "", err
	}
	if message.SenderSeq != expectedSeq {
		return "", fmt.Errorf("unexpected sender sequence %d; expected %d", message.SenderSeq, expectedSeq)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(message.Nonce) != aead.NonceSize() {
		return "", fmt.Errorf("invalid nonce size: %d", len(message.Nonce))
	}
	plaintext, err := aead.Open(nil, message.Nonce, message.Ciphertext, groupMessageAAD(message))
	if err != nil {
		return "", fmt.Errorf("decrypt group message: %w", err)
	}
	return string(plaintext), nil
}

func groupMessageAAD(message protocol.Message) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", message.GroupID, message.SenderID, message.MessageID, message.SenderSeq))
}

func ratchetSenderKey(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("github.com/JonathanInTheClouds/go-chat/group-sender-key/v1"))
	return mac.Sum(nil)
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}
