package app

import (
	"fmt"
	"os"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/securitytrails"
)

// newDomainApp is the domain composition root. Register enabled compatible
// sources here; the existing Manager owns dispatch and partial-result behavior.
// Other modes do not initialize these clients or resolve their credentials.
func newDomainApp(cfg *config.AppConfig) (*App, error) {
	settings, err := config.LoadServices(cfg.ServicesFile)
	if err != nil {
		return nil, err
	}
	service := settings.Services["securitytrails"]
	if !service.Enabled {
		return nil, ErrSearchUnavailable
	}
	interval := time.Second
	if service.MinInterval != "" {
		interval, err = time.ParseDuration(service.MinInterval)
		if err != nil || interval <= 0 {
			return nil, fmt.Errorf("SecurityTrails min_interval must be a positive duration")
		}
	}
	keyEnv := service.APIKeyEnv
	if keyEnv == "" {
		keyEnv = config.DefaultSecurityTrailsKeyEnv
	}
	client, err := securitytrails.NewClient(service.APIURL, security.NewSecret(os.Getenv(keyEnv)), network.NewServiceClient(cfg.RequestTimeout), interval)
	if err != nil {
		return nil, err
	}
	source, err := securitytrails.NewSource(client)
	if err != nil {
		client.Close()
		return nil, err
	}
	registry := sources.NewRegistry()
	if err = registry.Register(source); err != nil {
		client.Close()
		return nil, err
	}
	application := NewWithSources(cfg, registry)
	application.close = func() error { client.Close(); return nil }
	return application, nil
}
