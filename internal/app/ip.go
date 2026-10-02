package app

import (
	"os"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/ipinfo"
)

func newIPApp(cfg *config.AppConfig) (*App, error) {
	settings, err := config.LoadServices(cfg.ServicesFile)
	if err != nil {
		return nil, err
	}
	service := settings.Services["ipinfo"]
	if !service.Enabled {
		return nil, ErrSearchUnavailable
	}
	env := service.APIKeyEnv
	if env == "" {
		env = config.DefaultIPinfoKeyEnv
	}
	client, err := ipinfo.NewClient(service.APIURL, security.NewSecret(os.Getenv(env)), network.NewServiceClient(cfg.RequestTimeout))
	if err != nil {
		return nil, err
	}
	source, err := ipinfo.NewSource(client)
	if err != nil {
		client.Close()
		return nil, err
	}
	registry := sources.NewRegistry()
	if err = registry.Register(source); err != nil {
		client.Close()
		return nil, err
	}
	a := NewWithSources(cfg, registry)
	a.close = func() error { client.Close(); return nil }
	return a, nil
}
