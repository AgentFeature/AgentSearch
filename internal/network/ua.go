package network

import (
	"bufio"
	"errors"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

// Built-in User-Agent values for website requests.
var defaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
}

// UARotator provides concurrency-safe User-Agent selection.
type UARotator struct {
	agents []string
	mu     sync.RWMutex
	r      *rand.Rand
}

// NewUARotator optionally extends the built-in list from a file.
func NewUARotator(filePath string) (*UARotator, error) {
	ua := &UARotator{
		agents: make([]string, len(defaultUserAgents)),
		r:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	copy(ua.agents, defaultUserAgents)

	if filePath != "" {
		if err := ua.loadFromFile(filePath); err != nil {
			return nil, err
		}
	}
	return ua, nil
}

func (ua *UARotator) loadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if len(ua.agents) >= 10000 {
				return errors.New("User-Agent list exceeds 10000 entries")
			}
			ua.agents = append(ua.agents, line)
		}
	}
	return scanner.Err()
}

// GetRandom returns a random User-Agent.
func (ua *UARotator) GetRandom() string {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	if len(ua.agents) == 0 {
		return ""
	}
	return ua.agents[ua.r.Intn(len(ua.agents))]
}
