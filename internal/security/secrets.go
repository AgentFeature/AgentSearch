package security

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
)

// Secret is a shared handle to owned mutable bytes. Formatting and serialization
// are redacted. Consume and Destroy clear the owned buffer in every handle.
// This is best-effort lifetime control, not a secure-memory/GC erasure guarantee.
// Reveal creates an immutable copy and is reserved for reusable API credentials.
type Secret struct{ state *secretState }
type secretState struct {
	mu    sync.Mutex
	value []byte
}

func NewSecret(value string) Secret { return NewSecretBytes([]byte(value)) }

// NewSecretBytes takes ownership. The caller must not read or retain the buffer.
func NewSecretBytes(value []byte) Secret { return Secret{state: &secretState{value: value}} }
func (s Secret) Empty() bool {
	if s.state == nil {
		return true
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return len(s.state.value) == 0
}
func (s Secret) Reveal() string {
	if s.state == nil {
		return ""
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return string(s.state.value)
}

// Consume runs a local operation while the bytes are available, then clears
// them even on error. The callback must not retain the bytes or reenter s.
func (s Secret) Consume(use func([]byte) error) error {
	if s.state == nil {
		return errors.New("secret input is empty or already consumed")
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	defer func() { clear(s.state.value); s.state.value = nil }()
	if len(s.state.value) == 0 {
		return errors.New("secret input is empty or already consumed")
	}
	return use(s.state.value)
}
func (s Secret) Destroy() {
	if s.state == nil {
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	clear(s.state.value)
	s.state.value = nil
}
func (Secret) String() string               { return Redacted }
func (Secret) GoString() string             { return Redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(Redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }
func (Secret) MarshalYAML() (any, error)    { return Redacted, nil }
