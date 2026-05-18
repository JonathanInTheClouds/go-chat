package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
)

const FileChunkSize = 32 * 1024

const (
	MessageTypeChat          = "chat"
	MessageTypeFileStart     = "file_start"
	MessageTypeFileChunk     = "file_chunk"
	MessageTypeFileComplete  = "file_complete"
	MessageTypeSessionAccept = "session_accept"
	MessageTypeSessionReject = "session_reject"
	MessageTypeTyping        = "typing"
)

type Message struct {
	Type   string `json:"type"`
	Text   string `json:"text,omitempty"`
	FileID string `json:"file_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Index  int    `json:"index,omitempty"`
	Chunk  []byte `json:"chunk,omitempty"`
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
	default:
		return fmt.Errorf("unknown protocol message type %q", message.Type)
	}

	return nil
}
