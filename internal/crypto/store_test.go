package crypto

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIdentityRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	first, created, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("load or create identity: %v", err)
	}
	if !created {
		t.Fatalf("expected first load to create an identity")
	}

	second, created, err := LoadOrCreateIdentity(path)
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
