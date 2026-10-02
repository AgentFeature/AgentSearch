package security

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPromptRestorationAndSafeFailures(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		readError, empty, restoreError bool
	}{
		{"success", false, false, false}, {"read-error", true, false, false}, {"empty", false, true, false}, {"restore-error", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var restored int
			var output bytes.Buffer
			input := NewSecret("correct horse battery staple")
			got, err := readPrompt(context.Background(), &output, func() (func() error, error) {
				return func() error {
					restored++
					if tc.restoreError {
						return errors.New("fixture")
					}
					return nil
				}, nil
			}, func() (Secret, error) {
				if tc.readError {
					return input, errors.New(input.Reveal())
				}
				if tc.empty {
					input.Destroy()
					return Secret{}, nil
				}
				return input, nil
			})
			defer got.Destroy()
			if restored != 1 || (err != nil) != (tc.readError || tc.empty || tc.restoreError) {
				t.Fatal("prompt cleanup failed")
			}
			if err != nil && !input.Empty() {
				t.Fatal("failed prompt retained input")
			}
			if strings.Contains(output.String(), "correct horse battery staple") || err != nil && strings.Contains(err.Error(), "correct horse battery staple") {
				t.Fatal("prompt leaked input")
			}
		})
	}
}
func TestPromptCancellationRestoresBeforeLateRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	input := NewSecret("correct horse battery staple")
	var restored atomic.Int32
	go func() {
		defer close(returned)
		secret, err := readPrompt(ctx, io.Discard, func() (func() error, error) { return func() error { restored.Add(1); return nil }, nil }, func() (Secret, error) { close(entered); <-release; return input, nil })
		secret.Destroy()
		if !errors.Is(err, context.Canceled) {
			t.Error("cancellation lost")
		}
	}()
	<-entered
	cancel()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("prompt did not cancel")
	}
	if restored.Load() != 1 {
		t.Fatal("terminal not restored on cancellation")
	}
	close(release)
	// Wait for the abandoned result's destruction without reading any plaintext.
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !input.Empty() {
		select {
		case <-deadline:
			t.Fatal("late input was retained")
		case <-ticker.C:
		}
	}
	if restored.Load() != 1 {
		t.Fatal("late reader changed terminal settings")
	}
}
func TestPromptFailsBeforeReading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	read := func() (Secret, error) { t.Error("unexpected terminal read"); return Secret{}, nil }
	if _, err := readPrompt(ctx, io.Discard, func() (func() error, error) { t.Error("changed terminal after cancellation"); return nil, nil }, read); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled prompt accepted")
	}
	if _, err := readPrompt(context.Background(), io.Discard, func() (func() error, error) { return nil, errors.New("fixture") }, read); err == nil {
		t.Fatal("unsafe terminal accepted")
	}
}
