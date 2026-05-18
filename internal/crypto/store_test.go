package crypto

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIdentityRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	first, created, err := LoadOrCreateIdentity(path, nil)
	if err != nil {
		t.Fatalf("load or create identity: %v", err)
	}
	if !created {
		t.Fatalf("expected first load to create an identity")
	}

	second, created, err := LoadOrCreateIdentity(path, nil)
	if err != nil {
		t.Fatalf("load existing identity: %v", err)
	}
	if created {
		t.Fatalf("expected second load to reuse existing identity")
	}

	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("fingerprints differ after round-trip: %s vs %s", first.Fingerprint(), second.Fingerprint())
	}
}

func TestEncryptedIdentityRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	passphrase := []byte("correct horse battery staple")

	first, created, err := LoadOrCreateIdentity(path, passphrase)
	if err != nil {
		t.Fatalf("create encrypted identity: %v", err)
	}
	if !created {
		t.Fatalf("expected first load to create an identity")
	}

	encrypted, err := IsEncryptedIdentity(path)
	if err != nil {
		t.Fatalf("probe identity: %v", err)
	}
	if !encrypted {
		t.Fatalf("expected identity file to be encrypted (version 2)")
	}

	second, created, err := LoadOrCreateIdentity(path, passphrase)
	if err != nil {
		t.Fatalf("load encrypted identity: %v", err)
	}
	if created {
		t.Fatalf("expected second load to reuse existing identity")
	}

	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("fingerprints differ after encrypted round-trip: %s vs %s", first.Fingerprint(), second.Fingerprint())
	}
}

func TestEncryptedIdentityWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	passphrase := []byte("correct passphrase")

	_, _, err := LoadOrCreateIdentity(path, passphrase)
	if err != nil {
		t.Fatalf("create encrypted identity: %v", err)
	}

	_, err = LoadIdentity(path, []byte("wrong passphrase"))
	if err == nil {
		t.Fatal("expected error when loading with wrong passphrase, got nil")
	}
}

func TestPlaintextIdentityBackwardCompat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	// create plaintext (v1) identity
	first, created, err := LoadOrCreateIdentity(path, nil)
	if err != nil {
		t.Fatalf("create plaintext identity: %v", err)
	}
	if !created {
		t.Fatalf("expected identity to be created")
	}

	encrypted, err := IsEncryptedIdentity(path)
	if err != nil {
		t.Fatalf("probe identity: %v", err)
	}
	if encrypted {
		t.Fatalf("expected plaintext identity to not be encrypted")
	}

	// load v1 file with nil passphrase
	second, err := LoadIdentity(path, nil)
	if err != nil {
		t.Fatalf("load plaintext identity: %v", err)
	}

	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("fingerprints differ: %s vs %s", first.Fingerprint(), second.Fingerprint())
	}
}
