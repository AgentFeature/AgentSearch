// Package monitor orchestrates existing normalized investigations, never providers.
package monitor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"gopkg.in/yaml.v3"
)

const (
	MaxTargets      = 256
	MaxWatchBytes   = 256 << 10
	DefaultInterval = time.Minute
	MinInterval     = 30 * time.Second
	MaxInterval     = 299 * time.Second
	MaxConcurrency  = 4
	CycleTimeout    = 10 * time.Minute
)

type TargetParser func(string, string) (models.Target, error)

func Identity(t models.Target) string {
	sum := sha256.Sum256([]byte(string(t.Type()) + "\x00" + t.Value()))
	return hex.EncodeToString(sum[:])
}
func ReadWatchlist(path string, parse TargetParser) ([]models.Target, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|safeOpenFlags(), 0)
	if err != nil {
		return nil, errors.New("cannot open watchlist")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("watchlist must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxWatchBytes+1))
	if err != nil {
		return nil, errors.New("cannot read watchlist")
	}
	return ParseWatchlist(raw, parse)
}
func ParseWatchlist(raw []byte, parse TargetParser) ([]models.Target, error) {
	bad := errors.New("invalid watchlist: expected 1-256 public type/value targets")
	if len(raw) > MaxWatchBytes || parse == nil {
		return nil, bad
	}
	var node yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&node) != nil {
		return nil, bad
	}
	count := 0
	var check func(*yaml.Node, int) bool
	check = func(n *yaml.Node, depth int) bool {
		count++
		if depth > 6 || count > 2048 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		if n.Kind == yaml.ScalarNode && n.Tag != "!!str" {
			return false
		}
		for _, c := range n.Content {
			if !check(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !check(&node, 0) {
		return nil, bad
	}
	var document struct {
		Targets []struct {
			Type  string `yaml:"type"`
			Value string `yaml:"value"`
		} `yaml:"targets"`
	}
	d = yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&document) != nil || len(document.Targets) == 0 || len(document.Targets) > MaxTargets {
		return nil, bad
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, bad
	}
	targets := []models.Target{}
	seen := map[string]bool{}
	for _, entry := range document.Targets {
		kind := models.TargetType(entry.Type)
		if !kind.Valid() || kind.Sensitive() || len(entry.Value) > 512 {
			return nil, bad
		}
		target, err := parse(entry.Type, entry.Value)
		if err != nil || !target.Valid() || target.Type().Sensitive() || target.Type() != kind {
			return nil, bad
		}
		key := Identity(target)
		if !seen[key] {
			targets = append(targets, target)
			seen[key] = true
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Type() != targets[j].Type() {
			return targets[i].Type() < targets[j].Type()
		}
		return targets[i].Value() < targets[j].Value()
	})
	return targets, nil
}
