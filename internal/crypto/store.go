package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const defaultIdentityFileName = "identity.json"

type identityRecord struct {
	SigningPrivateKey      string `json:"signing_private_key"`
	SigningPublicKey       string `json:"signing_public_key"`
	KeyAgreementPrivateKey string `json:"key_agreement_private_key"`
	KeyAgreementPublicKey  string `json:"key_agreement_public_key"`
}

type encryptedIdentityRecord struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type versionProbe struct {
	Version int `json:"version"`
}

func DefaultIdentityPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}

	return filepath.Join(configDir, "chat", defaultIdentityFileName), nil
}

func IsEncryptedIdentity(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read identity file: %w", err)
	}
	var probe versionProbe
	if err := json.Unmarshal(data, &probe); err != nil {
		return false, fmt.Errorf("probe identity file: %w", err)
	}
	return probe.Version == 2, nil
}

func LoadOrCreateIdentity(path string, passphrase []byte) (*Identity, bool, error) {
	identity, err := LoadIdentity(path, passphrase)
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

	if len(passphrase) > 0 {
		if err := SaveEncryptedIdentity(path, identity, passphrase); err != nil {
			return nil, false, err
		}
	} else {
		if err := SaveIdentity(path, identity); err != nil {
			return nil, false, err
		}
	}

	return identity, true, nil
}

func LoadIdentity(path string, passphrase []byte) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	var probe versionProbe
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("decode identity file: %w", err)
	}

	if probe.Version == 2 {
		return loadEncryptedIdentity(data, passphrase)
	}
	return loadPlaintextIdentity(data)
}

func loadPlaintextIdentity(data []byte) (*Identity, error) {
	var record identityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode identity file: %w", err)
	}

	identity := &Identity{}
	var err error
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

func loadEncryptedIdentity(data []byte, passphrase []byte) (*Identity, error) {
	var enc encryptedIdentityRecord
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, fmt.Errorf("decode encrypted identity file: %w", err)
	}

	salt, err := hex.DecodeString(enc.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := hex.DecodeString(enc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := deriveKey(passphrase, salt)
	defer wipeBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt identity: wrong passphrase or corrupted file")
	}
	defer wipeBytes(plaintext)

	return loadPlaintextIdentity(plaintext)
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

func SaveEncryptedIdentity(path string, identity *Identity, passphrase []byte) error {
	if err := identity.Validate(); err != nil {
		return err
	}

	plain := identityRecord{
		SigningPrivateKey:      hex.EncodeToString(identity.SigningPrivateKey),
		SigningPublicKey:       hex.EncodeToString(identity.SigningPublicKey),
		KeyAgreementPrivateKey: hex.EncodeToString(identity.KeyAgreementPrivateKey),
		KeyAgreementPublicKey:  hex.EncodeToString(identity.KeyAgreementPublicKey),
	}
	plaintext, err := json.Marshal(plain)
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	defer wipeBytes(plaintext)

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(passphrase, salt)
	defer wipeBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	enc := encryptedIdentityRecord{
		Version:    2,
		Salt:       hex.EncodeToString(salt),
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
	}

	data, err := json.MarshalIndent(enc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode encrypted identity file: %w", err)
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

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 4, 128*1024, 4, 32)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
