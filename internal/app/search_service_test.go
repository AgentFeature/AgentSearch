package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestUnifiedServiceReusesProviders(t *testing.T) {
	var web, email, password atomic.Int32
	key := "test-key-created-for-service-test"
	t.Setenv("AGENTSEARCH_SERVICE_TEST_KEY", key)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/example":
			web.Add(1)
			w.WriteHeader(200)
		case strings.HasPrefix(r.URL.Path, "/api/v3/breachedaccount/"):
			email.Add(1)
			if r.Header.Get("hibp-api-key") != key {
				t.Error("email authentication lost")
			}
			fmt.Fprint(w, "[]")
		case r.URL.Path == "/range/555DA":
			password.Add(1)
			if r.Header.Get("hibp-api-key") != "" {
				t.Error("email key sent for password")
			}
			fmt.Fprint(w, "20DF20D4172E00F1B73D7C3943802055270:42\r\n")
		default:
			t.Error("unexpected provider request")
		}
	}))
	defer upstream.Close()
	dir := t.TempDir()
	sites := filepath.Join(dir, "sites.yaml")
	services := filepath.Join(dir, "services.yaml")
	if e := os.WriteFile(sites, []byte(fmt.Sprintf("- name: Fixture\n  url: %s/users/{username}\n", upstream.URL)), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(services, []byte(fmt.Sprintf("services:\n  hibp:\n    enabled: true\n    api_key_env: AGENTSEARCH_SERVICE_TEST_KEY\n    api_url: %s/api/v3\n    passwords_api_url: %s/range\n", upstream.URL, upstream.URL)), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := config.DefaultServerConfig().Engine
	cfg.SitesFile = sites
	cfg.ServicesFile = services
	cfg.RateLimitPerHost = 0
	service, e := NewSearchService(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	for _, kind := range []string{"username", "email", "password"} {
		value := "example"
		var bytes []byte
		if kind == "email" {
			value = "user@example.test"
		}
		if kind == "password" {
			value = ""
			bytes = []byte("example-password")
		}
		target, e := NewSearchTarget(kind, value, bytes)
		if e != nil {
			t.Fatal(e)
		}
		secret := target.Secret()
		rows := 0
		e = service.Search(context.Background(), target, func(r models.Result) error {
			rows++
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "example-password") {
				t.Fatal("plaintext in result")
			}
			return nil
		})
		if e != nil || rows != 1 {
			t.Fatal("unified dispatch failed")
		}
		if kind == "password" && !secret.Empty() {
			t.Fatal("secret retained")
		}
	}
	if web.Load() != 1 || email.Load() != 1 || password.Load() != 1 {
		t.Fatal("cross-mode dispatch occurred")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatal("search service wrote output files")
	}
	service.Close()
	target, _ := models.NewSensitiveTarget(models.TargetPassword, security.NewSecret("example-password"))
	if e = service.Search(context.Background(), target, func(models.Result) error { return nil }); e != ErrSearchUnavailable || !target.Secret().Empty() {
		t.Fatal("closed service failed to clean input")
	}
}

func TestServiceStartupFailuresAndOwnedInput(t *testing.T) {
	cfg := config.DefaultServerConfig().Engine
	cfg.SitesFile = ""
	cfg.PasswordBackend = config.PasswordBackendLocal
	cfg.PasswordDatabasePath = filepath.Join(t.TempDir(), "missing")
	if service, e := NewSearchService(context.Background(), cfg); e == nil || service != nil {
		t.Fatal("missing local database did not fail startup")
	}
	cfg.PasswordBackend = config.PasswordBackendAPI
	cfg.PasswordDatabasePath = ""
	cfg.ServicesFile = filepath.Join(t.TempDir(), "services.yaml")
	t.Setenv("AGENTSEARCH_MISSING_SERVICE_KEY", "")
	if e := os.WriteFile(cfg.ServicesFile, []byte("services:\n  hibp:\n    enabled: true\n    api_key_env: AGENTSEARCH_MISSING_SERVICE_KEY\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if service, e := NewSearchService(context.Background(), cfg); e == nil || service != nil {
		t.Fatal("enabled email without key accepted")
	}
	b := []byte("example-password")
	if _, e := NewSearchTarget("unknown", "", b); e != ErrInvalidSearch {
		t.Fatal("invalid type accepted")
	}
	for _, v := range b {
		if v != 0 {
			t.Fatal("invalid target retained owned secret")
		}
	}
}
