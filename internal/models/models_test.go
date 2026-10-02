package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/security"
	"gopkg.in/yaml.v3"
)

func TestTargets(t *testing.T) {
	for _, kind := range []TargetType{TargetUsername, TargetEmail, TargetPassword, TargetPasswordHash} {
		t.Run(string(kind), func(t *testing.T) {
			target, err := NewTarget(kind, "unique-input")
			if err != nil || target.Type() != kind || target.Value() != "unique-input" {
				t.Fatal("target mismatch", err)
			}
			if kind.Sensitive() {
				j, _ := json.Marshal(target)
				y, _ := yaml.Marshal(target)
				for _, out := range []string{string(j), string(y), fmt.Sprintf("%v %+v %#v", target, target, target), target.LogValue().String()} {
					if strings.Contains(out, target.Value()) {
						t.Fatal("input leaked")
					}
				}
			}
		})
	}
	for _, tt := range []struct {
		kind  TargetType
		value string
	}{{"bogus", "x"}, {TargetUsername, ""}} {
		if _, err := NewTarget(tt.kind, tt.value); err == nil {
			t.Fatal("invalid target accepted")
		}
	}
	if (Target{}).Valid() {
		t.Fatal("zero target valid")
	}
}
func TestResultNormalization(t *testing.T) {
	for _, tt := range []struct {
		r      Result
		status ResultStatus
	}{{Result{Found: true}, StatusFound}, {Result{Error: "failed"}, StatusError}, {Result{}, StatusNotFound}, {Result{Found: true, Status: StatusBlocked}, StatusBlocked}} {
		r := tt.r
		r.SiteName = "site"
		r.Target = "alice"
		n := r.Normalized()
		if n.Source != "site" || n.TargetType != TargetUsername || n.Status != tt.status || n.Found != (tt.status == StatusFound) {
			t.Fatalf("bad normalization: %+v", n)
		}
	}
	target, _ := NewTarget(TargetPassword, "secret-input")
	r := NewResult("provider", SourceLocal, target)
	if r.Target != security.Redacted {
		t.Fatal("raw input copied")
	}
	r.Target = target.Value()
	r.Error = "lookup " + target.Value()
	r.Metadata = map[string]string{"detail": target.Value(), "api_key": "key"}
	r.Evidence = []Evidence{{"password", target.Value()}}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), target.Value()) || strings.Contains(string(b), `"key"`) {
		t.Fatal("leaked result", err)
	}
	if r.Metadata["api_key"] != "key" {
		t.Fatal("mutated input")
	}
}

func TestEmailTargets(t *testing.T) {
	for _, tt := range []struct{ value, want string }{{" Alice+tag@Example.test ", "Alice+tag@Example.test"}, {"a@example.test", "a@example.test"}} {
		target, err := NewEmailTarget(tt.value)
		if err != nil || target.Type() != TargetEmail || target.Value() != tt.want {
			t.Fatal("email changed or rejected", err)
		}
	}
	for _, value := range []string{"", "no-at", "a@", "@b", "Name <a@b.test>", "a b@example.test", "a@example.test\nBcc:someone"} {
		if _, err := NewEmailTarget(value); err == nil {
			t.Error("invalid email accepted")
		}
	}
}

func TestEmailRejectsInvalidUTF8(t *testing.T) {
	if _, err := NewEmailTarget("\xff@example.test"); err == nil {
		t.Fatal("malformed UTF-8 accepted by canonical email validator")
	}
}
