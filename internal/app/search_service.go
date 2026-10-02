package app

import (
	"context"
	"errors"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

var ErrSearchUnavailable = errors.New("search type is unavailable")
var ErrInvalidSearch = errors.New("invalid search request")

const MaxUsernameBytes = 256
const MaxPasswordBytes = 4096

// NewSearchTarget takes ownership of password bytes, including on failure.
// Transport callers must distinguish absent fields and must not log their DTOs.
func NewSearchTarget(kind, value string, password []byte) (models.Target, error) {
	owned := true
	defer func() {
		if owned {
			clear(password)
		}
	}()
	switch models.TargetType(kind) {
	case models.TargetPassword:
		if value != "" || len(password) == 0 || len(password) > MaxPasswordBytes || !utf8.Valid(password) {
			return models.Target{}, ErrInvalidSearch
		}
		secret := security.NewSecretBytes(password)
		owned = false
		target, err := models.NewSensitiveTarget(models.TargetPassword, secret)
		if err != nil {
			secret.Destroy()
			return models.Target{}, ErrInvalidSearch
		}
		return target, nil
	case models.TargetUsername:
		if len(password) != 0 || len(value) == 0 || len(value) > MaxUsernameBytes || !utf8.ValidString(value) || value == "." || value == ".." {
			return models.Target{}, ErrInvalidSearch
		}
		// Restrict transport input to usernames, not URLs, authority/path injection,
		// query parameters or arbitrary template substitutions. CLI behavior is unchanged.
		for _, r := range value {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
				return models.Target{}, ErrInvalidSearch
			}
		}
		return models.NewTarget(models.TargetUsername, value)
	case models.TargetBitcoinTransaction:
		if len(password) != 0 {
			return models.Target{}, ErrInvalidSearch
		}
		target, err := models.NewBitcoinTransactionTarget(value)
		if err != nil {
			return models.Target{}, ErrInvalidSearch
		}
		return target, nil
	case models.TargetBitcoin:
		if len(password) != 0 {
			return models.Target{}, ErrInvalidSearch
		}
		target, err := models.NewBitcoinTarget(value)
		if err != nil {
			return models.Target{}, ErrInvalidSearch
		}
		return target, nil
	case models.TargetIP:
		if len(password) != 0 {
			return models.Target{}, ErrInvalidSearch
		}
		target, err := models.NewIPTarget(value)
		if err != nil {
			return models.Target{}, ErrInvalidSearch
		}
		return target, nil
	case models.TargetDomain:
		if len(password) != 0 {
			return models.Target{}, ErrInvalidSearch
		}
		target, err := models.NewDomainTarget(value)
		if err != nil {
			return models.Target{}, ErrInvalidSearch
		}
		return target, nil
	case models.TargetEmail:
		// The canonical validator applies its length limit after trimming, as CLI does.
		if len(password) != 0 {
			return models.Target{}, ErrInvalidSearch
		}
		target, err := models.NewEmailTarget(value)
		if err != nil {
			return models.Target{}, ErrInvalidSearch
		}
		return target, nil
	default:
		return models.Target{}, ErrInvalidSearch
	}
}

// SearchService composes the existing mode-specific apps once. Search uses only
// their Runner, never App.Run: no CLI targets, signals, result files or reports.
// Configuration and provider registration are immutable until Close.
type SearchService struct {
	mu     sync.RWMutex
	closed bool
	apps   map[models.TargetType]*App
}

func NewSearchService(ctx context.Context, base config.AppConfig) (s *SearchService, err error) {
	s = &SearchService{apps: make(map[models.TargetType]*App)}
	defer func() {
		if err != nil {
			s.Close()
			s = nil
		}
	}()
	// Request secrets never enter shared application configuration.
	base.Password = security.Secret{}
	base.Targets = nil
	base.OutputFormats = nil
	base.ReportFormats = nil
	add := func(kind models.TargetType, mode config.SearchMode) error {
		cfg := base
		cfg.Mode = mode
		a, e := NewWithContext(ctx, &cfg)
		if e != nil {
			return errors.New("configured search backend could not be initialized")
		}
		s.apps[kind] = a
		return nil
	}
	if base.SitesFile != "" {
		if err = add(models.TargetUsername, config.ModeWebsites); err != nil {
			return s, err
		}
	}
	if base.ServicesFile != "" {
		settings, e := config.LoadServices(base.ServicesFile)
		if e != nil {
			return s, errors.New("invalid service configuration")
		}
		if settings.Services["bitcoin_tx"].Enabled {
			if err = add(models.TargetBitcoinTransaction, config.ModeBitcoinTransaction); err != nil {
				return s, err
			}
		}
		if settings.Services["bitcoin"].Enabled || settings.Services["bitcoin_labels"].Enabled {
			if err = add(models.TargetBitcoin, config.ModeBitcoin); err != nil {
				return s, err
			}
		}
		if settings.Services["ipinfo"].Enabled {
			if err = add(models.TargetIP, config.ModeIP); err != nil {
				return s, err
			}
		}
		if settings.Services["securitytrails"].Enabled {
			if err = add(models.TargetDomain, config.ModeDomain); err != nil {
				return s, err
			}
		}
		if settings.Services["hibp"].Enabled {
			if err = add(models.TargetEmail, config.ModeEmail); err != nil {
				return s, err
			}
		}
	}
	if err = add(models.TargetPassword, config.ModePassword); err != nil {
		return s, err
	}
	if err = ctx.Err(); err != nil {
		return s, err
	}
	return s, nil
}
func (s *SearchService) Search(ctx context.Context, target models.Target, emit sources.Emit) error {
	if target.Type().Sensitive() {
		defer target.Secret().Destroy()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrSearchUnavailable
	}
	a := s.apps[target.Type()]
	if a == nil {
		return ErrSearchUnavailable
	}
	return a.runner.Search(ctx, target, emit)
}
func (s *SearchService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	for _, a := range s.apps {
		if e := a.Close(); e != nil {
			err = errors.New("search service cleanup failed")
		}
	}
	s.apps = nil
	return err
}

// Supports reports configured target capability without making a request.
func (s *SearchService) Supports(kind models.TargetType) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closed && s.apps[kind] != nil
}
