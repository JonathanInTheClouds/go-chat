package trust

import (
	"path/filepath"
	"testing"
	"time"
)

func TestObserveLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)

	observation, err := store.Observe("alice", "AA:BB", now)
	if err != nil {
		t.Fatalf("observe new: %v", err)
	}
	if observation.Status != StatusNew {
		t.Fatalf("expected new status, got %v", observation.Status)
	}

	store, err = Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}

	observation, err = store.Observe("alice", "AA:BB", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("observe match: %v", err)
	}
	if observation.Status != StatusMatch {
		t.Fatalf("expected match status, got %v", observation.Status)
	}

	observation, err = store.Observe("alice", "CC:DD", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("observe mismatch: %v", err)
	}
	if observation.Status != StatusMismatch {
		t.Fatalf("expected mismatch status, got %v", observation.Status)
	}
	if observation.Expected != "AA:BB" {
		t.Fatalf("expected stored fingerprint to remain AA:BB, got %s", observation.Expected)
	}
}

func TestSetListAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	if err := store.Set("alice", "AA:BB", now); err != nil {
		t.Fatalf("set alice: %v", err)
	}
	if err := store.Set("bob", "CC:DD", now); err != nil {
		t.Fatalf("set bob: %v", err)
	}
	if err := store.Set("alice", "EE:FF", now.Add(time.Minute)); err != nil {
		t.Fatalf("update alice: %v", err)
	}

	entries := store.List()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Label != "alice" || entries[0].Fingerprint != "EE:FF" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}

	removed, err := store.Remove("alice")
	if err != nil {
		t.Fatalf("remove alice: %v", err)
	}
	if !removed {
		t.Fatalf("expected alice to be removed")
	}

	removed, err = store.Remove("missing")
	if err != nil {
		t.Fatalf("remove missing: %v", err)
	}
	if removed {
		t.Fatalf("did not expect missing entry to be removed")
	}
}

func TestCheckDoesNotMutateOnNewOrMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_peers.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	observation, err := store.Check("alice", "AA:BB")
	if err != nil {
		t.Fatalf("check new: %v", err)
	}
	if observation.Status != StatusNew {
		t.Fatalf("expected new status, got %v", observation.Status)
	}
	if len(store.List()) != 0 {
		t.Fatalf("check should not persist a new entry")
	}

	if err := store.Set("alice", "AA:BB", time.Now()); err != nil {
		t.Fatalf("set alice: %v", err)
	}

	observation, err = store.Check("alice", "CC:DD")
	if err != nil {
		t.Fatalf("check mismatch: %v", err)
	}
	if observation.Status != StatusMismatch {
		t.Fatalf("expected mismatch status, got %v", observation.Status)
	}

	entries := store.List()
	if len(entries) != 1 || entries[0].Fingerprint != "AA:BB" {
		t.Fatalf("check should not overwrite stored trust: %+v", entries)
	}
}
