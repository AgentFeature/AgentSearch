// Command agentsearch-corpus manages local hash/count datasets, not password queries.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AgentFeature/agentsearch/internal/passworddb"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
func run(ctx context.Context, args []string, out, diagnostics io.Writer) int {
	usage := func() {
		fmt.Fprintln(out, "Usage: agentsearch-corpus import|verify|activate|rollback|prune -db ROOT [options]\nimport: -input FILE -sha256 EXPECTED -acquired-at RFC3339 -complete\nverify/activate/rollback: -version ID\nImport prepares an unpublished version. Activation and rollback are explicit. No downloads or password queries.")
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return 0
	}
	operation := args[0]
	if operation != "import" && operation != "verify" && operation != "activate" && operation != "rollback" && operation != "prune" {
		fmt.Fprintln(diagnostics, "unknown corpus operation")
		return 1
	}
	flags := flag.NewFlagSet("agentsearch-corpus", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("db", "", "Managed database root")
	input := flags.String("input", "", "Ordered SHA-1 hash/count export, not passwords")
	expected := flags.String("sha256", "", "Expected SHA-256 of completed acquisition artifact")
	acquired := flags.String("acquired-at", "", "Acquisition completion time in RFC3339")
	complete := flags.Bool("complete", false, "Operator attests acquisition completed successfully")
	version := flags.String("version", "", "Retained generation ID")
	if e := flags.Parse(args[1:]); e == flag.ErrHelp {
		usage()
		return 0
	} else if e != nil {
		fmt.Fprintln(diagnostics, "invalid corpus arguments; use -h")
		return 1
	}
	valid := *root != "" && flags.NArg() == 0
	flags.Visit(func(f *flag.Flag) {
		allowed := f.Name == "db" || operation == "import" && (f.Name == "input" || f.Name == "sha256" || f.Name == "acquired-at" || f.Name == "complete") || (operation == "verify" || operation == "activate" || operation == "rollback") && f.Name == "version"
		if !allowed {
			valid = false
		}
	})
	if !valid {
		fmt.Fprintln(diagnostics, "invalid corpus option combination")
		return 1
	}
	var err error
	switch operation {
	case "import":
		when, e := time.Parse(time.RFC3339Nano, *acquired)
		if e != nil || *input == "" || !*complete {
			fmt.Fprintln(diagnostics, "import requires input, expected digest, acquisition time and completion attestation")
			return 1
		}
		var id string
		id, err = passworddb.Import(ctx, *root, *input, passworddb.ImportOptions{ExpectedSHA256: *expected, AcquiredAt: when, Complete: *complete})
		if err == nil {
			fmt.Fprintln(out, id)
		}
	case "verify":
		err = passworddb.Verify(ctx, *root, *version)
		if err == nil {
			fmt.Fprintln(out, "verified", *version)
		}
	case "activate", "rollback":
		err = passworddb.Activate(ctx, *root, *version)
		if err == nil {
			fmt.Fprintln(out, "activated", *version)
		}
	case "prune":
		var removed []string
		removed, err = passworddb.Prune(ctx, *root)
		for _, id := range removed {
			fmt.Fprintln(out, "removed", id)
		}
	}
	if err != nil {
		fmt.Fprintln(diagnostics, passworddb.SafeError(err))
		return 1
	}
	return 0
}
