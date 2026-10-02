package sources

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

type usernameSource struct {
	name string
	fail bool
}

func (s *usernameSource) Name() string          { return s.name }
func (*usernameSource) Type() models.SourceType { return models.SourceLocal }
func (s *usernameSource) SearchUsername(ctx context.Context, v string, emit Emit) error {
	if err := emit(models.Result{Status: models.StatusFound}); err != nil {
		return err
	}
	if s.fail {
		return errors.New("lookup failed")
	}
	return ctx.Err()
}

type passwordSource struct{}

func (*passwordSource) Name() string            { return "password-test" }
func (*passwordSource) Type() models.SourceType { return models.SourceLocal }
func (*passwordSource) SearchPassword(ctx context.Context, s security.Secret, emit Emit) error {
	if err := emit(models.Result{Error: s.Reveal(), Metadata: map[string]string{"input": s.Reveal()}, Evidence: []models.Evidence{{Kind: "detail", Value: s.Reveal()}}}); err != nil {
		return err
	}
	return errors.New("failed " + s.Reveal())
}
func TestRegistryAndCapabilities(t *testing.T) {
	r := NewRegistry()
	s := &usernameSource{name: "one"}
	var nilSource *usernameSource
	for _, bad := range []Source{nil, nilSource, &usernameSource{}} {
		if r.Register(bad) == nil {
			t.Fatal("bad registration accepted")
		}
	}
	if err := r.Register(s); err != nil {
		t.Fatal(err)
	}
	if r.Register(s) == nil {
		t.Fatal("duplicate accepted")
	}
	if got, ok := r.Lookup("one"); !ok || got != s {
		t.Fatal("lookup failed")
	}
	if _, ok := r.Lookup("missing"); ok {
		t.Fatal("unknown found")
	}
	for _, tt := range []struct {
		kind models.TargetType
		want bool
	}{{models.TargetUsername, true}, {models.TargetEmail, false}, {models.TargetPassword, false}, {models.TargetPasswordHash, false}} {
		if Supports(s, tt.kind) != tt.want {
			t.Fatal(tt.kind)
		}
	}
	snapshot := r.All()
	snapshot[0] = nil
	if r.All()[0] == nil {
		t.Fatal("mutable registry exposed")
	}
}
func TestDispatch(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&usernameSource{name: "first", fail: true})
	_ = r.Register(&usernameSource{name: "second"})
	target, _ := models.NewTarget(models.TargetUsername, "alice")
	var results []models.Result
	err := NewManager(r).Search(context.Background(), target, func(r models.Result) error { results = append(results, r); return nil })
	if err == nil || len(results) != 2 || results[0].Source != "first" || results[1].Target != "alice" || !results[1].Found {
		t.Fatal("dispatch lost results", err)
	}
	email, _ := models.NewTarget(models.TargetEmail, "a@b")
	if !errors.Is(NewManager(r).Search(context.Background(), email, func(models.Result) error { return nil }), ErrUnsupportedTarget) {
		t.Fatal("unsupported accepted")
	}
	stop := errors.New("stop")
	n := 0
	err = NewManager(r).Search(context.Background(), target, func(models.Result) error { n++; return stop })
	if !errors.Is(err, stop) || n != 1 {
		t.Fatal("consumer error ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(NewManager(r).Search(ctx, target, func(models.Result) error { return nil }), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
func TestSensitiveDispatch(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&passwordSource{})
	target, _ := models.NewTarget(models.TargetPassword, "never-persist-this")
	err := NewManager(r).Search(context.Background(), target, func(r models.Result) error {
		if r.Target != security.Redacted || strings.Contains(r.Error, target.Value()) || r.Metadata["input"] != security.Redacted || r.Evidence[0].Value != security.Redacted {
			t.Fatal("leaked sensitive result")
		}
		return nil
	})
	if err == nil || strings.Contains(err.Error(), "never-persist-this") {
		t.Fatal("unsafe error")
	}
	if !target.Secret().Empty() {
		t.Fatal("dispatcher retained sensitive input")
	}
}

type emailHashSource struct{}

func (emailHashSource) Name() string            { return "email-hash-test" }
func (emailHashSource) Type() models.SourceType { return models.SourceLocal }
func (emailHashSource) SearchEmail(ctx context.Context, email string, emit Emit) error {
	return emit(models.Result{Status: models.StatusFound, Metadata: map[string]string{"email": email}})
}
func (emailHashSource) SearchPasswordHash(ctx context.Context, hash security.Secret, emit Emit) error {
	return emit(models.Result{Status: models.StatusNotFound, Metadata: map[string]string{"password_hash": hash.Reveal()}})
}
func TestEmailAndHashDispatch(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(emailHashSource{}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		kind  models.TargetType
		value string
	}{{models.TargetEmail, "alice@example.test"}, {models.TargetPasswordHash, "sensitive-hash"}} {
		target, _ := models.NewTarget(tt.kind, tt.value)
		count := 0
		if err := NewManager(r).Search(context.Background(), target, func(result models.Result) error {
			count++
			if result.TargetType != tt.kind || result.Source != "email-hash-test" {
				t.Error("wrong capability selected")
			}
			if tt.kind.Sensitive() && (result.Target != security.Redacted || result.Metadata["password_hash"] != security.Redacted) {
				t.Error("hash exposed")
			}
			return nil
		}); err != nil || count != 1 {
			t.Fatal(err, count)
		}
	}
}
