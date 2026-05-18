package crypto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const defaultIdentityFileName = "identity.json"

type identityRecord struct {
	SigningPrivateKey      string `json:"signing_private_key"`
	SigningPublicKey       string `json:"signing_public_key"`
	KeyAgreementPrivateKey string `json:"key_agreement_private_key"`
	KeyAgreementPublicKey  string `json:"key_agreement_public_key"`
}

func DefaultIdentityPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}

	return filepath.Join(configDir, "chat", defaultIdentityFileName), nil
}

func LoadOrCreateIdentity(path string) (*Identity, bool, error) {
	identity, err := LoadIdentity(path)
	if err == nil {
		return identity, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	identity, err = GenerateIdentity()
	if err != nil {
		return nil, false, err
	}
	if err := SaveIdentity(path, identity); err != nil {
		return nil, false, err
	}

	return identity, true, nil
}

func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	var record identityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode identity file: %w", err)
	}

	identity := &Identity{}
	if identity.SigningPrivateKey, err = decodeBytes(record.SigningPrivateKey); err != nil {
		return nil, fmt.Errorf("decode signing private key: %w", err)
	}
	if identity.SigningPublicKey, err = decodeBytes(record.SigningPublicKey); err != nil {
		return nil, fmt.Errorf("decode signing public key: %w", err)
	}
	if identity.KeyAgreementPrivateKey, err = decodeBytes(record.KeyAgreementPrivateKey); err != nil {
		return nil, fmt.Errorf("decode key agreement private key: %w", err)
	}
	if identity.KeyAgreementPublicKey, err = decodeBytes(record.KeyAgreementPublicKey); err != nil {
		return nil, fmt.Errorf("decode key agreement public key: %w", err)
	}

	if err := identity.Validate(); err != nil {
		return nil, err
	}

	return identity, nil
}

func SaveIdentity(path string, identity *Identity) error {
	if err := identity.Validate(); err != nil {
		return err
	}

	record := identityRecord{
		SigningPrivateKey:      hex.EncodeToString(identity.SigningPrivateKey),
		SigningPublicKey:       hex.EncodeToString(identity.SigningPublicKey),
		KeyAgreementPrivateKey: hex.EncodeToString(identity.KeyAgreementPrivateKey),
		KeyAgreementPublicKey:  hex.EncodeToString(identity.KeyAgreementPublicKey),
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity file: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}

	return nil
}

func DeleteIdentity(path string) error {
	if err := secureDelete(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete identity file: %w", err)
	}
	return nil
}

// secureDelete overwrites the file with zeros before removing it to reduce
// the chance of key material being recovered from disk.
func secureDelete(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	zeros := make([]byte, info.Size())
	_, _ = f.Write(zeros)
	_ = f.Sync()
	_ = f.Close()
	return os.Remove(path)
}

func decodeBytes(value string) ([]byte, error) {
	data, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}
