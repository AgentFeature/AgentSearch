package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/AgentFeature/agentsearch/internal/config"
)

func main() {
	var (
		output = flag.String("o", "merged_sites.yaml", "Output YAML file")
	)
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: convert [-o output.yaml] <sherlock_data.json> [maigret_data.json] ...\n")
		fmt.Fprintf(os.Stderr, "  Supports Sherlock data.json and Maigret data.json formats.\n")
		os.Exit(1)
	}

	inputs := flag.Args()
	slog.Info("merging databases", "inputs", inputs, "output", *output)

	if err := config.MergeAndConvert(*output, inputs...); err != nil {
		slog.Error("conversion failed", "error", err)
		os.Exit(1)
	}

	slog.Info("conversion complete", "output", *output)
}
