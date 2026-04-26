package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/replay"
)

type getenvFunc func(string) string

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv getenvFunc, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "replay":
		return runReplay(args[1:], getenv, stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  cordclaw replay --since <duration> --with-policy <bundle.yaml> [--daemon-url URL] [--cordum-url URL] [--tenant TENANT] [--max-jobs N] [--json]")
}

func runReplay(args []string, getenv getenvFunc, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(stderr)

	sinceRaw := flags.String("since", "", "duration to replay, for example 1h or 24h")
	policyPath := flags.String("with-policy", "", "candidate policy bundle YAML path")
	daemonURL := flags.String("daemon-url", defaultEnv(getenv, "CORDCLAW_DAEMON_URL", "http://127.0.0.1:8787"), "CordClaw daemon URL")
	cordumURL := flags.String("cordum-url", defaultCordumURL(getenv), "Cordum gateway URL")
	tenant := flags.String("tenant", "default", "tenant to replay")
	maxJobs := flags.Int("max-jobs", 100, "maximum jobs to replay (1..1000)")
	jsonOut := flags.Bool("json", false, "emit JSON report")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*sinceRaw) == "" {
		fmt.Fprintln(stderr, "--since is required")
		return 2
	}
	sinceDur, err := time.ParseDuration(*sinceRaw)
	if err != nil || sinceDur <= 0 {
		fmt.Fprintf(stderr, "invalid --since %q: must be a positive duration\n", *sinceRaw)
		return 2
	}
	if strings.TrimSpace(*policyPath) == "" {
		fmt.Fprintln(stderr, "--with-policy is required")
		return 2
	}
	if *maxJobs <= 0 || *maxJobs > 1000 {
		fmt.Fprintln(stderr, "--max-jobs must be between 1 and 1000")
		return 2
	}

	until := time.Now().UTC()
	options := replay.Options{
		Since:               until.Add(-sinceDur),
		Until:               until,
		Tenant:              *tenant,
		MaxJobs:             *maxJobs,
		CandidatePolicyPath: *policyPath,
		DaemonURL:           *daemonURL,
		CordumURL:           *cordumURL,
		APIKey:              getenv("CORDUM_API_KEY"),
	}

	report, err := replay.NewRunner(options).Run(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "replay failed: %s\n", redact(err.Error(), options.APIKey))
		return 1
	}

	if *jsonOut {
		if err := report.WriteJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "write JSON report: %s\n", redact(err.Error(), options.APIKey))
			return 1
		}
		return 0
	}

	if err := report.WriteHuman(stdout); err != nil {
		fmt.Fprintf(stderr, "write report: %s\n", redact(err.Error(), options.APIKey))
		return 1
	}
	return 0
}

func defaultCordumURL(getenv getenvFunc) string {
	if v := strings.TrimSpace(getenv("CORDUM_GATEWAY_URL")); v != "" {
		return v
	}
	if v := strings.TrimSpace(getenv("CORDUM_URL")); v != "" {
		return v
	}
	return "http://127.0.0.1:8081"
}

func defaultEnv(getenv getenvFunc, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}

func redact(s, secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[REDACTED:api_key]")
}
