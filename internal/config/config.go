package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

const (
	PasswordBackendAPI   = "api"
	PasswordBackendLocal = "local"
)

type SearchMode string

const (
	ModeWatch              SearchMode = "watch"
	ModeWebsites           SearchMode = ""
	ModeEmail              SearchMode = "email"
	ModeBitcoinTransaction SearchMode = "bitcoin_tx"
	ModeBitcoin            SearchMode = "bitcoin"
	ModeIP                 SearchMode = "ip"
	ModeDomain             SearchMode = "domain"
	ModePassword           SearchMode = "password"
)

// AppConfig holds CLI options and runtime settings.
type AppConfig struct {
	AI                   bool
	AIConfig             string
	WatchFile            string
	WatchStateDir        string
	WatchInterval        time.Duration
	WatchConcurrency     int
	Mode                 SearchMode
	Password             security.Secret `json:"-" yaml:"-"`
	PasswordPrompt       bool
	PasswordBackend      string
	PasswordDatabasePath string
	ServicesFile         string
	Targets              []string
	SitesFile            string
	ProxiesFile          string
	OutputDir            string
	OutputFormats        []string
	ReportFormats        []string
	Workers              int
	RequestTimeout       time.Duration
	TotalTimeout         time.Duration
	MaxIdleConns         int
	MaxIdleConnsPerHost  int
	RateLimitPerHost     time.Duration
	UserAgentFile        string
	DeepSearch           bool
	UseUTLS              bool
	MaxRetries           int
}

// ParseFlags parses command-line options.
func ParseFlags() (*AppConfig, error) { return ParseArgs(os.Args[1:]) }

// ParseArgs preserves legacy flags while separating email breach lookups from
// website searches. A fresh FlagSet makes parsing repeatable in tests.
func ParseArgs(args []string) (cfg *AppConfig, parseErr error) {
	password := &passwordFlag{}
	defer func() {
		if cfg == nil {
			password.value.Destroy()
		}
	}()
	flags := flag.NewFlagSet("agentsearch", flag.ContinueOnError)
	sensitiveArgs := false
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name == "password" || name == "password-prompt" {
			sensitiveArgs = true
		}
	}
	// flag's diagnostics may echo arbitrary arguments. Keep errors out of logs;
	// explicit help is restored below and never prints supplied values.
	flags.SetOutput(io.Discard)
	ai := flags.Bool("ai", false, "Opt in to external analysis of sanitized investigation evidence")
	aiConfig := flags.String("ai-config", "configs/ai.yaml", "Separate operator AI configuration; used only with -ai")
	flags.Var(password, "password", "Single Pwned Passwords lookup; exposes the argument to shell history/process listings; prefer -password-prompt")
	passwordPrompt := flags.Bool("password-prompt", false, "Read one password from an interactive terminal without echo (recommended)")
	backend, database := PasswordBackendAPI, ""
	usedBackend, usedDatabase := false, false
	flags.Func("password-backend", "Password backend: api (default) or local; never automatically falls back", func(value string) error {
		if usedBackend {
			return fmt.Errorf("password backend must be supplied only once")
		}
		usedBackend = true
		backend = value
		return nil
	})
	flags.Func("password-db", "Managed offline database root; requires explicit local backend", func(value string) error {
		if usedDatabase {
			return fmt.Errorf("password database must be supplied only once")
		}
		usedDatabase = true
		database = value
		return nil
	})
	watchFile := flags.String("watch-file", "", "Continuously investigate a public-target YAML watchlist")
	watchInterval := flags.Duration("watch-interval", 60*time.Second, "Delay after each watch cycle (30s-299s)")
	watchDir := flags.String("watch-state-dir", "agentsearch-watch", "Private monitoring state and bounded JSONL logs directory")
	watchConcurrency := flags.Int("watch-concurrency", 4, "Concurrent watch targets (1-4)")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: agentsearch -watch-file YAML | -u TARGET | -f FILE | -email ADDRESS | -domain HOSTNAME | -ip ADDRESS | -bitcoin ADDRESS | -bitcoin-tx TXID | -password VALUE | -password-prompt [options]")
		fmt.Fprintln(flags.Output(), "Website flags never query HIBP. Email lookups require enabled service settings and an API key.")
		fmt.Fprintln(flags.Output(), "Password API lookups require no API key and transmit only five SHA-1 characters. Explicit local mode makes no requests.")
		flags.PrintDefaults()
	}
	var (
		bitcoinTX = flags.String("bitcoin-tx", "", "Passive Bitcoin mainnet transaction lookup by TXID")
		bitcoin   = flags.String("bitcoin", "", "Passive Bitcoin mainnet intelligence (confirmed activity; no wallet operations)")
		ip        = flags.String("ip", "", "Passive IP intelligence through configured IPinfo Lite (no scanning)")
		domain    = flags.String("domain", "", "Domain intelligence through configured external sources (not a website search)")
		email     = flags.String("email", "", "Email breach lookup through HIBP (not a website search)")
		services  = flags.String("services", "configs/services.yaml", "Service configuration for -email, -domain, -ip, -bitcoin, -bitcoin-tx or explicit password settings")
		u         = flags.String("u", "", "Target username or email")
		f         = flags.String("f", "", "File with targets (one per line)")
		s         = flags.String("s", "configs/sites.yaml", "Sites database YAML/JSON")
		p         = flags.String("p", "", "Proxies file (http://ip:port or socks5://ip:port)")
		o         = flags.String("o", "output", "Output directory")
		of        = flags.String("of", "json,csv,txt", "Output formats: json,csv,txt,html,pdf,docx (comma-separated)")
		rf        = flags.String("rf", "cli,html", "Legacy report outputs in ./output: cli,json,csv,txt,html,pdf,docx")
		w         = flags.Int("w", 50, "Number of concurrent workers")
		rt        = flags.Duration("rt", 15*time.Second, "HTTP request timeout")
		tt        = flags.Duration("tt", 10*time.Minute, "Total search timeout per batch")
		mc        = flags.Int("mc", 500, "Max idle connections in pool")
		mch       = flags.Int("mch", 100, "Max idle connections per host")
		rl        = flags.Duration("rl", 500*time.Millisecond, "Rate limit delay between requests to same host")
		ua        = flags.String("ua", "", "External User-Agent list file")
		d         = flags.Bool("d", false, "Enable deep search (dorking mode stub)")
		utls      = flags.Bool("utls", false, "Experimental browser-like TLS over HTTP/1.1; not an anti-bot bypass")
		retries   = flags.Int("retries", 2, "Max retries on eligible direct website failures (0 disables retries)")
	)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stderr)
			flags.Usage()
			return nil, err
		}
		if sensitiveArgs {
			return nil, fmt.Errorf("invalid password lookup arguments; use -h for options")
		}
		return nil, err
	}

	watchUsed, watchOptions := false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "watch-file" {
			watchUsed = true
		}
		if strings.HasPrefix(f.Name, "watch-") {
			watchOptions = true
		}
	})
	if watchOptions && !watchUsed {
		return nil, fmt.Errorf("watch options require -watch-file")
	}
	if watchUsed {
		allowed := map[string]bool{"watch-file": true, "watch-interval": true, "watch-state-dir": true, "watch-concurrency": true, "s": true, "services": true, "rt": true, "tt": true}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				invalid = true
			}
		})
		if invalid || flags.NArg() != 0 || *watchFile == "" || len(*watchFile) > 4096 || *watchDir == "" || len(*watchDir) > 4096 || *watchInterval < 30*time.Second || *watchInterval > 299*time.Second || *watchConcurrency < 1 || *watchConcurrency > 4 || *rt <= 0 || *rt > 15*time.Second || *tt <= 0 || *tt > 10*time.Minute {
			return nil, fmt.Errorf("invalid watch options; interval 30s-299s, concurrency 1-4, request timeout <=15s, cycle timeout <=10m")
		}
		return &AppConfig{Mode: ModeWatch, WatchFile: *watchFile, WatchStateDir: *watchDir, WatchInterval: *watchInterval, WatchConcurrency: *watchConcurrency, ServicesFile: *services, SitesFile: *s, RequestTimeout: *rt, TotalTimeout: *tt, Workers: 4, MaxIdleConns: 32, MaxIdleConnsPerHost: 4, RateLimitPerHost: time.Second, MaxRetries: 0}, nil
	}
	selectedEmail, selectedDomain, selectedIP, selectedBitcoin, selectedBitcoinTX := false, false, false, false, false
	selectedPrompt, usedServices := false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "bitcoin-tx" {
			selectedBitcoinTX = true
		}
		if f.Name == "bitcoin" {
			selectedBitcoin = true
		}
		if f.Name == "ip" {
			selectedIP = true
		}
		if f.Name == "domain" {
			selectedDomain = true
		}
		if f.Name == "email" {
			selectedEmail = true
		}
		if f.Name == "password-prompt" {
			selectedPrompt = true
		}
		if f.Name == "services" {
			usedServices = true
		}
	})

	selectedPassword := password.seen || selectedPrompt
	if !selectedPassword && (usedBackend || usedDatabase) {
		return nil, fmt.Errorf("password backend options require password mode")
	}
	if selectedPassword && backend != PasswordBackendAPI && backend != PasswordBackendLocal {
		return nil, fmt.Errorf("password backend must be api or local")
	}
	if selectedPassword && usedDatabase && (backend != PasswordBackendLocal || database == "") {
		return nil, fmt.Errorf("password database requires explicit local mode and a nonempty path")
	}

	if selectedPassword {
		if password.seen && selectedPrompt || selectedPrompt && !*passwordPrompt {
			return nil, fmt.Errorf("choose exactly one of -password or -password-prompt")
		}
		if password.seen && password.value.Empty() {
			return nil, fmt.Errorf("password input must not be empty")
		}
		allowed := map[string]bool{"password": true, "password-prompt": true, "password-backend": true, "password-db": true, "services": true, "rt": true, "tt": true, "o": true, "of": true, "rf": true, "ai": true, "ai-config": true}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				invalid = true
			}
		})
		if invalid || flags.NArg() != 0 {
			return nil, fmt.Errorf("password mode accepts one input and only backend, database, services, timeout, output and report options")
		}
		if *rt <= 0 || *tt <= 0 {
			return nil, fmt.Errorf("password lookup timeouts must be positive")
		}
	} else if selectedBitcoinTX {
		allowed := map[string]bool{"bitcoin-tx": true, "services": true, "rt": true, "tt": true, "o": true, "of": true, "rf": true, "ai": true, "ai-config": true}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				invalid = true
			}
		})
		if invalid || flags.NArg() != 0 {
			return nil, fmt.Errorf("Bitcoin transaction mode accepts one TXID and only services, timeout, output and report options")
		}
		if *rt <= 0 || *tt <= 0 {
			return nil, fmt.Errorf("Bitcoin lookup timeouts must be positive")
		}
	} else if selectedBitcoin {
		allowed := map[string]bool{"bitcoin": true, "services": true, "rt": true, "tt": true, "o": true, "of": true, "rf": true, "ai": true, "ai-config": true}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				invalid = true
			}
		})
		if invalid || flags.NArg() != 0 {
			return nil, fmt.Errorf("Bitcoin mode accepts one address and only services, timeout, output and report options")
		}
		if *rt <= 0 || *tt <= 0 {
			return nil, fmt.Errorf("Bitcoin lookup timeouts must be positive")
		}
	} else if selectedIP {
		allowed := map[string]bool{"ip": true, "services": true, "rt": true, "tt": true, "o": true, "of": true, "rf": true, "ai": true, "ai-config": true}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				invalid = true
			}
		})
		if invalid || flags.NArg() != 0 {
			return nil, fmt.Errorf("IP mode accepts one address and only services, timeout, output and report options")
		}
		if *rt <= 0 || *tt <= 0 {
			return nil, fmt.Errorf("IP lookup timeouts must be positive")
		}
	} else if selectedDomain {
		allowed := map[string]bool{"domain": true, "services": true, "rt": true, "tt": true, "o": true, "of": true, "rf": true, "ai": true, "ai-config": true}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				invalid = true
			}
		})
		if invalid || flags.NArg() != 0 {
			return nil, fmt.Errorf("domain mode accepts one hostname and only services, timeout, output and report options")
		}
		if *rt <= 0 || *tt <= 0 {
			return nil, fmt.Errorf("domain lookup timeouts must be positive")
		}
	} else if selectedEmail {
		allowed := map[string]bool{"email": true, "services": true, "rt": true, "tt": true, "o": true, "of": true, "rf": true, "ai": true, "ai-config": true}
		var unsupported string
		flags.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				unsupported = f.Name
			}
		})
		if unsupported != "" {
			return nil, fmt.Errorf("-%s is a website option and cannot be combined with -email", unsupported)
		}
		if flags.NArg() != 0 {
			return nil, fmt.Errorf("-email accepts one address; unexpected positional arguments")
		}
		if *rt <= 0 || *tt <= 0 {
			return nil, fmt.Errorf("email lookup timeouts must be positive")
		}
	} else {

		if usedServices {
			return nil, fmt.Errorf("-services is only used with -email, -domain, -ip, -bitcoin, -bitcoin-tx or password mode")
		}
	}

	if !selectedEmail && !selectedDomain && !selectedIP && !selectedBitcoin && !selectedBitcoinTX && !selectedPassword && *u == "" && *f == "" {
		return nil, fmt.Errorf("usage: agentsearch -u TARGET OR -f FILE OR -email ADDRESS OR -domain HOSTNAME OR -ip ADDRESS OR -bitcoin ADDRESS OR -bitcoin-tx TXID OR -password VALUE OR -password-prompt")
	}

	cfg = &AppConfig{
		AI: *ai, AIConfig: *aiConfig,
		SitesFile:           *s,
		ProxiesFile:         *p,
		OutputDir:           *o,
		Workers:             *w,
		RequestTimeout:      *rt,
		TotalTimeout:        *tt,
		MaxIdleConns:        *mc,
		MaxIdleConnsPerHost: *mch,
		RateLimitPerHost:    *rl,
		UserAgentFile:       *ua,
		DeepSearch:          *d,
		UseUTLS:             *utls,
		MaxRetries:          *retries,
	}

	if selectedPassword {
		cfg.Mode = ModePassword
		cfg.Password = password.value
		cfg.PasswordPrompt = *passwordPrompt
		cfg.PasswordBackend = backend
		cfg.PasswordDatabasePath = database
		if usedServices {
			cfg.ServicesFile = *services
		}
	}
	if selectedBitcoinTX {
		target, err := models.NewBitcoinTransactionTarget(*bitcoinTX)
		if err != nil {
			return nil, err
		}
		cfg.Mode = ModeBitcoinTransaction
		cfg.ServicesFile = *services
		cfg.Targets = []string{target.Value()}
	}
	if selectedBitcoin {
		target, err := models.NewBitcoinTarget(*bitcoin)
		if err != nil {
			return nil, err
		}
		cfg.Mode = ModeBitcoin
		cfg.ServicesFile = *services
		cfg.Targets = []string{target.Value()}
	}
	if selectedIP {
		target, err := models.NewIPTarget(*ip)
		if err != nil {
			return nil, err
		}
		cfg.Mode = ModeIP
		cfg.ServicesFile = *services
		cfg.Targets = []string{target.Value()}
	}
	if selectedDomain {
		target, err := models.NewDomainTarget(*domain)
		if err != nil {
			return nil, err
		}
		cfg.Mode = ModeDomain
		cfg.ServicesFile = *services
		cfg.Targets = []string{target.Value()}
	}
	if selectedEmail {
		target, err := models.NewEmailTarget(*email)
		if err != nil {
			return nil, err
		}
		cfg.Mode = ModeEmail
		cfg.ServicesFile = *services
		cfg.Targets = []string{target.Value()}
	}
	if *u != "" {
		cfg.Targets = append(cfg.Targets, *u)
	}
	if *f != "" {
		targets, err := ReadTargetList(*f)
		if err != nil {
			return nil, fmt.Errorf("read targets file: %w", err)
		}
		cfg.Targets = append(cfg.Targets, targets...)
	}

	for _, format := range strings.Split(*of, ",") {
		format = strings.TrimSpace(strings.ToLower(format))
		if format != "" {
			cfg.OutputFormats = append(cfg.OutputFormats, format)
		}
	}
	for _, format := range strings.Split(*rf, ",") {
		format = strings.TrimSpace(strings.ToLower(format))
		if format != "" {
			cfg.ReportFormats = append(cfg.ReportFormats, format)
		}
	}

	if cfg.Mode == ModePassword && cfg.PasswordBackend == PasswordBackendLocal {
		path, err := LocalPasswordPath(cfg)
		if err != nil {
			return nil, err
		}
		cfg.PasswordDatabasePath = path
	}
	valid := func(format string) bool {
		switch format {
		case "json", "csv", "txt", "html", "pdf", "docx":
			return true
		}
		return false
	}
	for _, format := range cfg.OutputFormats {
		if !valid(format) {
			return nil, fmt.Errorf("invalid output format; choose json,csv,txt,html,pdf,docx")
		}
	}
	for _, format := range cfg.ReportFormats {
		if format != "cli" && !valid(format) {
			return nil, fmt.Errorf("invalid report format")
		}
	}

	if cfg.AI && len(cfg.OutputFormats)+len(cfg.ReportFormats) == 0 {
		return nil, fmt.Errorf("AI analysis requires at least one report/output format")
	}
	return cfg, nil
}

// passwordFlag never retains an immutable copy or exposes its value in help.
type passwordFlag struct {
	value security.Secret
	seen  bool
}

func (*passwordFlag) String() string { return security.Redacted }
func (p *passwordFlag) Set(value string) error {
	if p.seen {
		return fmt.Errorf("password must be supplied only once")
	}
	p.seen = true
	p.value = security.NewSecret(value)
	return nil
}
