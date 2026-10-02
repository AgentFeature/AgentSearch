package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"testing"
)

const publicPassword = "correct horse battery staple"

func TestPasswordFlags(t *testing.T) {
	for _, args := range [][]string{{"-password", " " + publicPassword + " "}, {"--password=" + " " + publicPassword + " "}} {
		cfg, err := ParseArgs(args)
		if err != nil {
			t.Fatal("password flags rejected")
		}
		if cfg.Mode != ModePassword || len(cfg.Targets) != 0 || cfg.PasswordPrompt || cfg.ServicesFile != "" {
			t.Fatal("password mode configuration is not isolated")
		}
		b, _ := json.Marshal(cfg)
		if strings.Contains(string(b)+fmt.Sprintf("%+v %#v", cfg, cfg), publicPassword) {
			t.Fatal("configuration formatting leaked input")
		}
		if cfg.Password.Consume(func(b []byte) error {
			if string(b) != " "+publicPassword+" " {
				t.Error("password input was normalized")
			}
			return nil
		}) != nil {
			t.Fatal("password input unavailable")
		}
	}
	cfg, err := ParseArgs([]string{"-password-prompt", "-services", "custom.yaml", "-rf", "", "-rt", "2s"})
	if err != nil || cfg.Mode != ModePassword || !cfg.PasswordPrompt || !cfg.Password.Empty() || cfg.ServicesFile != "custom.yaml" || len(cfg.Targets) != 0 {
		t.Fatal("prompt flags not isolated")
	}
}
func TestPasswordFlagsRejectAmbiguityWithoutLeaks(t *testing.T) {
	for i, args := range [][]string{
		{"-password", ""}, {"-password"}, {"-password", publicPassword, "-password", publicPassword},
		{"-password", publicPassword, "-password-prompt"}, {"-password-prompt=false"},
		{"-password", publicPassword, "-email", "alice@example.test"}, {"-password", publicPassword, "-u", publicPassword},
		{"-password-prompt", "-f", "missing"}, {"-password-prompt", "-retries", "2"},
		{"-password", publicPassword, "-rt", "0s"}, {"-password-prompt", "-tt", "-1s"},
		{"-password", publicPassword, "-p", publicPassword}, {"-password", publicPassword, "extra"},
		{"-password", publicPassword, "-rt", publicPassword},
		{"-password", publicPassword, "-of", publicPassword}, {"-password-prompt", "-rf", publicPassword}, {"-rt", publicPassword, "-password", publicPassword},
		{"-unknown=" + publicPassword, "-password", publicPassword},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			cfg, err := ParseArgs(args)
			if err == nil || cfg != nil {
				t.Fatal("invalid password mode accepted")
			}
			if strings.Contains(err.Error(), publicPassword) {
				t.Fatal("parser error leaked input")
			}
		})
	}
	_, err := ParseArgs([]string{"-password", publicPassword, "-h"})
	if err != flag.ErrHelp {
		t.Fatal("help did not succeed")
	}
}
func TestRepeatedPasswordFlagClearsOriginalOnFailure(t *testing.T) {
	p := &passwordFlag{}
	if p.Set(publicPassword) != nil {
		t.Fatal("fixture flag rejected")
	}
	copy := p.value
	if p.Set(publicPassword) == nil {
		t.Fatal("duplicate accepted")
	}
	p.value.Destroy()
	if !copy.Empty() {
		t.Fatal("shared flag input retained")
	}
}

func TestPasswordBackendSelection(t *testing.T) {
	for _, args := range [][]string{
		{"-password-prompt", "-password-backend", "local"},
		{"-password-prompt", "-password-db", "data"},
		{"-password-prompt", "-password-backend", "other"},
		{"-password-prompt", "-password-backend", "api", "-password-backend", "local"},
		{"-u", "alice", "-password-backend", "local"},
	} {
		if cfg, err := ParseArgs(args); err == nil {
			cfg.Password.Destroy()
			t.Fatal("invalid backend arguments accepted")
		}
	}
	cfg, err := ParseArgs([]string{"-password-prompt"})
	if err != nil || cfg.PasswordBackend != PasswordBackendAPI {
		t.Fatal("API default changed")
	}
	cfg, err = ParseArgs([]string{"-password-prompt", "-password-backend", "local", "-password-db", "data"})
	if err != nil || cfg.PasswordBackend != PasswordBackendLocal || cfg.PasswordDatabasePath != "data" {
		t.Fatal("explicit local backend rejected")
	}
}
