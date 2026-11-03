package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type digestStore struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

func newDigestStore(dir string) *digestStore {
	p := filepath.Join(dir, "agent_digests.json")
	s := &digestStore{path: p, data: map[string]string{}}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	if s.data == nil {
		s.data = map[string]string{}
	}
	return s
}

func (s *digestStore) get(module string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[module]
}

func (s *digestStore) set(module, dig string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[module] = dig
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.path, b, 0600)
}

func digestItems(items []any) string {
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
