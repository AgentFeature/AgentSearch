package config

import (
	"bytes"
	"fmt"
	"io"
	"regexp"

	"gopkg.in/yaml.v3"
)

const DefaultIPinfoKeyEnv = "IPINFO_API_KEY"

const DefaultHIBPKeyEnv = "HIBP_API_KEY"
const DefaultSecurityTrailsKeyEnv = "SECURITYTRAILS_API_KEY"

// ServicesConfig is an opt-in configuration layer. Loading it neither registers
// providers nor reads environment variables or makes network requests.
type ServicesConfig struct {
	Services map[string]ServiceConfig `yaml:"services"`
}
type ServiceConfig struct {
	// MinInterval is parsed only by an enabled/selected provider using pacing.
	MinInterval           string `yaml:"min_interval"`
	PasswordsDatabasePath string `yaml:"passwords_database_path"`
	PasswordsAPIURL       string `yaml:"passwords_api_url"`
	Enabled               bool   `yaml:"enabled"`
	APIURL                string `yaml:"api_url"`
	APIKeyEnv             string `yaml:"api_key_env"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func LoadServices(path string) (*ServicesConfig, error) {
	data, err := readFileLimit(path, MaxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("read services: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var cfg ServicesConfig
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid services configuration (only environment variable references are supported)")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("services configuration must contain one document")
	}
	for _, service := range cfg.Services {
		if service.APIKeyEnv != "" && !envName.MatchString(service.APIKeyEnv) {
			return nil, fmt.Errorf("invalid API key environment variable name")
		}
	}
	return &cfg, nil
}

// LocalPasswordPath resolves only non-secret local settings. Relative paths use
// the working directory. There is no environment expansion or backend discovery.
func LocalPasswordPath(cfg *AppConfig) (string, error) {
	path := cfg.PasswordDatabasePath
	if cfg.ServicesFile != "" {
		services, err := LoadServices(cfg.ServicesFile)
		if err != nil {
			return "", fmt.Errorf("invalid local password services configuration")
		}
		if path == "" {
			path = services.Services["hibp"].PasswordsDatabasePath
		}
	}
	if path == "" {
		return "", fmt.Errorf("local password backend requires a database path")
	}
	return path, nil
}
