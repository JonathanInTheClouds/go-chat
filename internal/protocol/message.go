package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
)

const FileChunkSize = 32 * 1024

const (
	MessageTypeChat              = "chat"
	MessageTypeFileStart         = "file_start"
	MessageTypeFileChunk         = "file_chunk"
	MessageTypeFileComplete      = "file_complete"
	MessageTypeSessionAccept     = "session_accept"
	MessageTypeSessionReject     = "session_reject"
	MessageTypeTyping            = "typing"
	MessageTypeHandshakeName     = "handshake_name"
	MessageTypeGroupHello        = "group_hello"
	MessageTypeGroupMemberList   = "group_member_list"
	MessageTypeGroupMemberJoined = "group_member_joined"
	MessageTypeGroupMemberLeft   = "group_member_left"
	MessageTypeGroupChat         = "group_chat"
	MessageTypeGroupTyping       = "group_typing"
)

type Message struct {
	Type        string        `json:"type"`
	Text        string        `json:"text,omitempty"`
	FileID      string        `json:"file_id,omitempty"`
	Name        string        `json:"name,omitempty"`
	Size        int64         `json:"size,omitempty"`
	Index       int           `json:"index,omitempty"`
	Chunk       []byte        `json:"chunk,omitempty"`
	Ciphertext  []byte        `json:"ciphertext,omitempty"`
	Nonce       []byte        `json:"nonce,omitempty"`
	GroupID     string        `json:"group_id,omitempty"`
	RoomName    string        `json:"room_name,omitempty"`
	MemberID    string        `json:"member_id,omitempty"`
	SenderID    string        `json:"sender_id,omitempty"`
	SenderSeq   uint64        `json:"sender_seq,omitempty"`
	MessageID   string        `json:"message_id,omitempty"`
	Epoch       uint64        `json:"epoch,omitempty"`
	Members     []GroupMember `json:"members,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Address     string        `json:"address,omitempty"`
	SenderKey   []byte        `json:"sender_key,omitempty"`
}

type GroupMember struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Address     string `json:"address,omitempty"`
	SenderKey   []byte `json:"sender_key,omitempty"`
	SenderSeq   uint64 `json:"sender_seq,omitempty"`
}

func EncodeMessage(message Message) ([]byte, error) {
	if err := ValidateMessage(message); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal protocol message: %w", err)
	}
	return payload, nil
}

func DecodeMessage(payload []byte) (Message, error) {
	var message Message
	if err := json.Unmarshal(payload, &message); err != nil {
		return Message{}, fmt.Errorf("unmarshal protocol message: %w", err)
	}
	if err := ValidateMessage(message); err != nil {
		return Message{}, err
	}
	return message, nil
}

func ValidateMessage(message Message) error {
	switch message.Type {
	case MessageTypeChat:
		if message.Text == "" {
			return errors.New("chat message text is required")
		}
	case MessageTypeFileStart:
		if message.FileID == "" || message.Name == "" || message.Size < 0 {
			return errors.New("file start requires file id, name, and non-negative size")
		}
	case MessageTypeFileChunk:
		if message.FileID == "" || len(message.Chunk) == 0 || message.Index < 0 {
			return errors.New("file chunk requires file id, chunk bytes, and non-negative index")
		}
	case MessageTypeFileComplete:
		if message.FileID == "" {
			return errors.New("file complete requires file id")
		}
	case MessageTypeSessionAccept:
	case MessageTypeSessionReject:
		if message.Text == "" {
			return errors.New("session reject requires reason text")
		}
	case MessageTypeTyping:
	case MessageTypeHandshakeName:
		if message.Text == "" {
			return errors.New("handshake name requires text")
		}
	case MessageTypeGroupHello:
		if message.RoomName == "" || message.Name == "" || len(message.SenderKey) == 0 {
			return errors.New("group hello requires room name, member name, and sender key")
		}
	case MessageTypeGroupMemberList:
		if message.GroupID == "" || len(message.Members) == 0 {
			return errors.New("group member list requires group id and members")
		}
		if err := validateGroupMembers(message.Members); err != nil {
			return err
		}
	case MessageTypeGroupMemberJoined:
		if message.GroupID == "" || message.MemberID == "" || message.Name == "" || message.Fingerprint == "" || len(message.SenderKey) == 0 {
			return errors.New("group member joined requires group id, member id, name, fingerprint, and sender key")
		}
	case MessageTypeGroupMemberLeft:
		if message.GroupID == "" || message.MemberID == "" {
			return errors.New("group member left requires group id and member id")
		}
	case MessageTypeGroupChat:
		if message.GroupID == "" || message.SenderID == "" || message.MessageID == "" || len(message.Ciphertext) == 0 || len(message.Nonce) == 0 {
			return errors.New("group chat requires group id, sender id, message id, ciphertext, and nonce")
		}
	case MessageTypeGroupTyping:
		if message.GroupID == "" || message.SenderID == "" {
			return errors.New("group typing requires group id and sender id")
		}
	default:
		return fmt.Errorf("unknown protocol message type %q", message.Type)
	}

	return nil
}

func validateGroupMembers(members []GroupMember) error {
	for _, member := range members {
		if member.ID == "" || member.Fingerprint == "" || len(member.SenderKey) == 0 {
			return errors.New("group members require id, fingerprint, and sender key")
		}
	}
	return nil
}
