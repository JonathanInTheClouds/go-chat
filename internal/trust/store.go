package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const defaultKnownPeersFileName = "known_peers.json"

type Entry struct {
	Label       string    `json:"label"`
	Fingerprint string    `json:"fingerprint"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type Store struct {
	path    string
	entries map[string]Entry
}

type Status int

const (
	StatusNew Status = iota
	StatusMatch
	StatusMismatch
)

type Observation struct {
	Status   Status
	Label    string
	Expected string
	Observed string
}

func DefaultPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}

	return filepath.Join(configDir, "chat", defaultKnownPeersFileName), nil
}

func Open(path string) (*Store, error) {
	entries, err := loadEntries(path)
	if err != nil {
		return nil, err
	}

	return &Store{
		path:    path,
		entries: entries,
	}, nil
}

func DeleteStore(path string) error {
	if err := secureDelete(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete known peers file: %w", err)
	}
	return nil
}

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

func (s *Store) Observe(label, fingerprint string, now time.Time) (Observation, error) {
	observation, err := s.Check(label, fingerprint)
	if err != nil {
		return Observation{}, err
	}

	switch observation.Status {
	case StatusNew:
		s.entries[label] = Entry{
			Label:       label,
			Fingerprint: fingerprint,
			FirstSeenAt: now.UTC(),
			LastSeenAt:  now.UTC(),
		}
	case StatusMatch:
		entry := s.entries[label]
		entry.LastSeenAt = now.UTC()
		s.entries[label] = entry
	case StatusMismatch:
		return observation, nil
	}

	if err := s.save(); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func (s *Store) Check(label, fingerprint string) (Observation, error) {
	if label == "" {
		return Observation{}, errors.New("peer label is required")
	}
	if fingerprint == "" {
		return Observation{}, errors.New("peer fingerprint is required")
	}

	entry, ok := s.entries[label]
	if !ok {
		return Observation{
			Status:   StatusNew,
			Label:    label,
			Observed: fingerprint,
		}, nil
	}

	if entry.Fingerprint != fingerprint {
		return Observation{
			Status:   StatusMismatch,
			Label:    label,
			Expected: entry.Fingerprint,
			Observed: fingerprint,
		}, nil
	}

	return Observation{
		Status:   StatusMatch,
		Label:    label,
		Expected: fingerprint,
		Observed: fingerprint,
	}, nil
}

func (s *Store) List() []Entry {
	keys := make([]string, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	entries := make([]Entry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, s.entries[key])
	}
	return entries
}

func (s *Store) Set(label, fingerprint string, now time.Time) error {
	if label == "" {
		return errors.New("peer label is required")
	}
	if fingerprint == "" {
		return errors.New("peer fingerprint is required")
	}

	entry, ok := s.entries[label]
	if ok {
		entry.Fingerprint = fingerprint
		entry.LastSeenAt = now.UTC()
		s.entries[label] = entry
		return s.save()
	}

	s.entries[label] = Entry{
		Label:       label,
		Fingerprint: fingerprint,
		FirstSeenAt: now.UTC(),
		LastSeenAt:  now.UTC(),
	}
	return s.save()
}

func (s *Store) Remove(label string) (bool, error) {
	if label == "" {
		return false, errors.New("peer label is required")
	}
	if _, ok := s.entries[label]; !ok {
		return false, nil
	}
	delete(s.entries, label)
	if err := s.save(); err != nil {
		return false, err
	}
	return true, nil
}

func loadEntries(path string) (map[string]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]Entry{}, nil
		}
		return nil, fmt.Errorf("read known peers file: %w", err)
	}

	var entries map[string]Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode known peers file: %w", err)
	}
	if entries == nil {
		entries = map[string]Entry{}
	}
	return entries, nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create known peers directory: %w", err)
	}

	ordered := make(map[string]Entry, len(s.entries))
	keys := make([]string, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ordered[key] = s.entries[key]
	}

	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return fmt.Errorf("encode known peers file: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write known peers file: %w", err)
	}
	return nil
}
