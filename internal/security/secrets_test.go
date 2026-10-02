package security

import (
	"errors"
	"sync"
	"testing"
)

func TestConsumeClearsEveryHandle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		buffer := []byte("test-password") // Public test fixture only.
		secret := NewSecretBytes(buffer)
		other := secret
		called := false
		err := secret.Consume(func(value []byte) error {
			called = true
			if string(value) != "test-password" {
				t.Error("unexpected input")
			}
			if fail {
				return errors.New("fixture failure")
			}
			return nil
		})
		if !called || (err != nil) != fail || !other.Empty() || other.Reveal() != "" {
			t.Fatal("consume did not clear shared input")
		}
		for _, b := range buffer {
			if b != 0 {
				t.Fatal("owned buffer was not cleared")
			}
		}
		if other.Consume(func([]byte) error { t.Error("consumed twice"); return nil }) == nil {
			t.Fatal("reused consumed input")
		}
	}
}
func TestConcurrentDestroy(t *testing.T) {
	secret := NewSecret("test-password")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = secret.Empty(); secret.Destroy() }()
	}
	wg.Wait()
	if !secret.Empty() {
		t.Fatal("destroy failed")
	}
}
