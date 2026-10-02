package app

import (
	"fmt"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/bitcoin"
)

func newBitcoinTransactionApp(cfg *config.AppConfig) (*App, error) {
	settings, err := config.LoadServices(cfg.ServicesFile)
	if err != nil {
		return nil, err
	}
	service := settings.Services["bitcoin_tx"]
	if !service.Enabled {
		return nil, ErrSearchUnavailable
	}
	if service.APIKeyEnv != "" {
		return nil, fmt.Errorf("Bitcoin transaction provider does not accept API keys")
	}
	interval := time.Second
	if service.MinInterval != "" {
		interval, err = time.ParseDuration(service.MinInterval)
		if err != nil || interval < time.Second || interval > 30*time.Second {
			return nil, fmt.Errorf("Bitcoin transaction min_interval must be between 1s and 30s")
		}
	}
	source, err := bitcoin.NewTransactionSource(service.APIURL, network.NewServiceClient(cfg.RequestTimeout), interval)
	if err != nil {
		return nil, err
	}
	registry := sources.NewRegistry()
	if err = registry.Register(source); err != nil {
		source.Close()
		return nil, err
	}
	a := NewWithSources(cfg, registry)
	a.close = func() error { source.Close(); return nil }
	return a, nil
}
