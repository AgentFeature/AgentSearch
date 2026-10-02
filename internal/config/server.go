package config

import (
	"errors"
	"flag"
	"io"
	"net"
	"strconv"
	"time"
)

// ServerConfig is operator-only. No HTTP request can change these settings.
// Engine options feed the existing App constructors without another engine.
type ServerConfig struct {
	AIConfig                                               string
	ShutdownTimeout                                        time.Duration
	Listen                                                 string
	TokenEnv                                               string
	ReadTimeout, WriteTimeout, IdleTimeout, RequestTimeout time.Duration
	MaxConcurrent                                          int
	Engine                                                 AppConfig
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{ShutdownTimeout: 10 * time.Second, Listen: "127.0.0.1:8080", TokenEnv: "AGENTSEARCH_API_TOKEN", ReadTimeout: 15 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 60 * time.Second, RequestTimeout: 60 * time.Second, MaxConcurrent: 8,
		Engine: AppConfig{SitesFile: "configs/sites.yaml", Workers: 10, RequestTimeout: 15 * time.Second, MaxIdleConns: 128, MaxIdleConnsPerHost: 16, RateLimitPerHost: 500 * time.Millisecond, MaxRetries: 2, PasswordBackend: PasswordBackendAPI}}
}
func ParseServerArgs(args []string) (ServerConfig, error) {
	cfg := DefaultServerConfig()
	f := flag.NewFlagSet("agentsearch-server", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&cfg.AIConfig, "ai-config", "", "Optional separate AI configuration; requests still require analysis:true")
	f.StringVar(&cfg.Listen, "listen", cfg.Listen, "HTTP listen address (private loopback by default)")
	f.StringVar(&cfg.TokenEnv, "token-env", cfg.TokenEnv, "Environment variable containing the bearer token")
	f.DurationVar(&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, "HTTP read timeout")
	f.DurationVar(&cfg.WriteTimeout, "write-timeout", cfg.WriteTimeout, "HTTP write timeout; greater than request-timeout")
	f.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "Grace period for in-flight requests before forced cancellation")
	f.DurationVar(&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, "HTTP idle timeout")
	f.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "Search request deadline")
	f.IntVar(&cfg.MaxConcurrent, "max-concurrent", cfg.MaxConcurrent, "Maximum admitted search requests")
	f.StringVar(&cfg.Engine.SitesFile, "s", cfg.Engine.SitesFile, "Operator-owned sites file; empty disables username searches")
	f.StringVar(&cfg.Engine.ServicesFile, "services", "", "Explicit services YAML; enabled email/domain providers require environment keys")
	f.StringVar(&cfg.Engine.PasswordBackend, "password-backend", PasswordBackendAPI, "api or local; no fallback")
	f.StringVar(&cfg.Engine.PasswordDatabasePath, "password-db", "", "Managed database root for local password mode")
	f.IntVar(&cfg.Engine.Workers, "w", cfg.Engine.Workers, "Website workers per request")
	f.StringVar(&cfg.Engine.ProxiesFile, "p", "", "Website proxy file")
	f.StringVar(&cfg.Engine.UserAgentFile, "ua", "", "Website User-Agent file")
	f.DurationVar(&cfg.Engine.RateLimitPerHost, "rl", cfg.Engine.RateLimitPerHost, "Website per-host delay")
	f.DurationVar(&cfg.Engine.RequestTimeout, "rt", cfg.Engine.RequestTimeout, "Existing provider HTTP timeout")
	f.IntVar(&cfg.Engine.MaxRetries, "retries", cfg.Engine.MaxRetries, "Existing website retry setting")
	f.BoolVar(&cfg.Engine.UseUTLS, "utls", false, "Existing experimental website uTLS")
	if e := f.Parse(args); e != nil {
		if e == flag.ErrHelp {
			return cfg, e
		}
		return cfg, errors.New("invalid server arguments; use -h")
	}
	if f.NArg() != 0 {
		return cfg, errors.New("unexpected server arguments")
	}
	if e := cfg.Validate(); e != nil {
		return cfg, e
	}
	if cfg.Engine.PasswordBackend == PasswordBackendLocal {
		path, e := LocalPasswordPath(&cfg.Engine)
		if e != nil {
			return cfg, e
		}
		cfg.Engine.PasswordDatabasePath = path
	}
	return cfg, nil
}
func (c ServerConfig) Validate() error {
	_, port, e := net.SplitHostPort(c.Listen)
	n, pe := strconv.Atoi(port)
	if e != nil || pe != nil || n < 0 || n > 65535 || !envName.MatchString(c.TokenEnv) {
		return errors.New("invalid listen address or token environment name")
	}
	if c.ShutdownTimeout <= 0 || c.ReadTimeout <= 0 || c.WriteTimeout <= c.RequestTimeout || c.IdleTimeout <= 0 || c.RequestTimeout <= 0 || c.MaxConcurrent < 1 || c.MaxConcurrent > 128 {
		return errors.New("invalid HTTP timeout or concurrency settings")
	}
	if c.Engine.Workers < 1 || c.Engine.Workers > 256 || c.Engine.RequestTimeout <= 0 || c.Engine.RateLimitPerHost < 0 || c.Engine.MaxRetries < 0 {
		return errors.New("invalid provider resource settings")
	}
	if c.Engine.PasswordBackend != PasswordBackendAPI && c.Engine.PasswordBackend != PasswordBackendLocal {
		return errors.New("password backend must be api or local")
	}
	if c.Engine.PasswordBackend == PasswordBackendAPI && c.Engine.PasswordDatabasePath != "" {
		return errors.New("database path requires local password backend")
	}
	return nil
}
