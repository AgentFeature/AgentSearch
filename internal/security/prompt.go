package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// PasswordPrompt is injectable so CLI tests never require a real terminal.
type PasswordPrompt func(context.Context) (Secret, error)

// ReadPasswordPrompt is for the single-shot CLI. Terminal mode is changed
// synchronously and restored before returning, including on cancellation.
// No echo/line-editor output is ever forwarded; only static labels are printed.
// On cancellation a blocked input reader may remain until the CLI exits. It
// cannot change terminal mode, print input or retain a late completed secret.
func ReadPasswordPrompt(ctx context.Context) (Secret, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return Secret{}, errors.New("password prompt requires an interactive terminal; redirected input is not supported")
	}
	return readPrompt(ctx, os.Stderr, func() (func() error, error) {
		state, err := term.MakeRaw(fd)
		if err != nil {
			return nil, err
		}
		return func() error { return term.Restore(fd, state) }, nil
	}, func() (Secret, error) {
		// Budget includes Enter and editing bytes, preventing the line editor's
		// 4096-rune limit from silently truncating a password into a valid lookup.
		terminal := term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{io.LimitReader(os.Stdin, 4096), io.Discard}, "")
		value, err := terminal.ReadPassword("")
		if errors.Is(err, term.ErrPasteIndicator) {
			err = nil
		}
		if err != nil {
			return Secret{}, errors.New("password input cancelled, unavailable, or over the input limit")
		}
		return NewSecret(value), nil
	})
}

func readPrompt(ctx context.Context, output io.Writer, enter func() (func() error, error), read func() (Secret, error)) (secret Secret, err error) {
	if ctx.Err() != nil {
		return Secret{}, ctx.Err()
	}
	restore, err := enter()
	if err != nil {
		return Secret{}, errors.New("cannot disable terminal echo")
	}
	defer func() {
		if restore() != nil {
			secret.Destroy()
			secret = Secret{}
			err = errors.New("could not restore terminal settings")
		}
		fmt.Fprint(output, "\r\n")
	}()
	fmt.Fprint(output, "Password: ")
	type answer struct {
		secret Secret
		err    error
	}
	ready := make(chan answer)
	go func() {
		value, readErr := read()
		select {
		case ready <- answer{value, readErr}:
		case <-ctx.Done():
			value.Destroy()
		}
	}()
	select {
	case <-ctx.Done():
		return Secret{}, ctx.Err()
	case result := <-ready:
		if result.err != nil {
			result.secret.Destroy()
			return Secret{}, errors.New("password input cancelled, unavailable, or over the input limit")
		}
		if result.secret.Empty() {
			result.secret.Destroy()
			return Secret{}, errors.New("password input must not be empty")
		}
		return result.secret, nil
	}
}
