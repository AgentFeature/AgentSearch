package analysis

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/AgentFeature/agentsearch/internal/security"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Enabled         bool   `yaml:"enabled"`
	Provider        string `yaml:"provider"`
	Model           string `yaml:"model"`
	Endpoint        string `yaml:"endpoint"`
	KeyEnv          string `yaml:"api_key_env"`
	Timeout         string `yaml:"timeout"`
	MaxInputBytes   int    `yaml:"max_input_bytes"`
	MaxOutputTokens int    `yaml:"max_output_tokens"`
}

// FromFile is called only after explicit operator opt-in. All failures become
// safe analysis states; they do not fail deterministic reconnaissance startup.
func FromFile(path string) (*Service, func()) {
	unavailable := func(reason string) (*Service, func()) { return &Service{unavailable: reason}, func() {} }
	f, err := os.Open(path)
	if err != nil {
		return unavailable("ai_not_configured")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return unavailable("ai_not_configured")
	}
	var file struct {
		AI Config `yaml:"ai"`
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&file) != nil {
		return unavailable("ai_not_configured")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return unavailable("ai_not_configured")
	}
	c := file.AI
	if !c.Enabled {
		return unavailable("ai_disabled")
	}
	if c.Provider != "openai-compatible" {
		return unavailable("ai_not_configured")
	}
	if c.KeyEnv == "" {
		c.KeyEnv = "OPENAI_API_KEY"
	}
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`).MatchString(c.KeyEnv) {
		return unavailable("ai_not_configured")
	}
	timeout := 30 * time.Second
	if c.Timeout != "" {
		timeout, err = time.ParseDuration(c.Timeout)
		if err != nil {
			return unavailable("ai_not_configured")
		}
	}
	if c.MaxInputBytes == 0 {
		c.MaxInputBytes = MaxInputBytes
	}
	if c.MaxInputBytes < 4096 || c.MaxInputBytes > MaxInputBytes {
		return unavailable("ai_not_configured")
	}
	if c.MaxOutputTokens == 0 {
		c.MaxOutputTokens = 2048
	}
	key := security.NewSecret(os.Getenv(c.KeyEnv))
	provider, err := NewOpenAI(c.Endpoint, c.Model, key, timeout, c.MaxOutputTokens)
	if err != nil {
		key.Destroy()
		return unavailable("ai_not_configured")
	}
	service := New(provider, security.Redact(c.Model, key.Reveal()))
	service.providerName = "openai-compatible"
	service.timeout = timeout
	service.inputLimit = c.MaxInputBytes
	return service, provider.Close
}
