package app

import (
	"fmt"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/bitcoin"
	"github.com/AgentFeature/agentsearch/internal/sources/bitcoinlabels"
)

func newBitcoinApp(cfg *config.AppConfig) (a *App, err error) {
	settings, err := config.LoadServices(cfg.ServicesFile)
	if err != nil {
		return nil, err
	}
	chain, labels := settings.Services["bitcoin"], settings.Services["bitcoin_labels"]
	if !chain.Enabled && !labels.Enabled {
		return nil, ErrSearchUnavailable
	}
	registry := sources.NewRegistry()
	var closers []func()
	closeSources := func() error {
		for _, close := range closers {
			close()
		}
		return nil
	}
	defer func() {
		if err != nil {
			_ = closeSources()
		}
	}()
	if chain.Enabled {
		// The existing blockchain source remains independently configured.
		if chain.APIKeyEnv != "" {
			return nil, fmt.Errorf("Bitcoin provider does not accept API keys")
		}
		interval := time.Second
		if chain.MinInterval != "" {
			interval, err = time.ParseDuration(chain.MinInterval)
			if err != nil || interval < time.Second || interval > 30*time.Second {
				return nil, fmt.Errorf("Bitcoin min_interval must be between 1s and 30s")
			}
		}
		source, e := bitcoin.New(chain.APIURL, network.NewServiceClient(cfg.RequestTimeout), interval)
		if e != nil {
			return nil, e
		}
		closers = append(closers, source.Close)
		if err = registry.Register(source); err != nil {
			return nil, err
		}
	}
	if labels.Enabled {
		if labels.APIKeyEnv != "" {
			return nil, fmt.Errorf("WalletExplorer does not accept API keys")
		}
		interval := time.Second
		if labels.MinInterval != "" {
			interval, err = time.ParseDuration(labels.MinInterval)
			if err != nil || interval < time.Second || interval > 30*time.Second {
				return nil, fmt.Errorf("WalletExplorer min_interval must be between 1s and 30s")
			}
		}
		source, e := bitcoinlabels.New(labels.APIURL, network.NewServiceClient(cfg.RequestTimeout), interval)
		if e != nil {
			return nil, e
		}
		closers = append(closers, source.Close)
		if err = registry.Register(source); err != nil {
			return nil, err
		}
	}
	a = NewWithSources(cfg, registry)
	a.close = closeSources
	return a, nil
}
