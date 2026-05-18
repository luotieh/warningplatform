package main

import (
	"flag"
	"fmt"
	"os"

	"vulnscan-backend/agent"
	"vulnscan-backend/pkg/nodeenroll"
)

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	out := fs.String("out", "node-enrollment.json", "enrollment JSON path (RSA private key is written alongside as .key, keep it on the node only)")
	_ = fs.Parse(args)
	if err := nodeenroll.WriteEnrollmentBundle(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	key := nodeenroll.EnrollmentKeyPath(*out)
	fmt.Fprintf(os.Stderr, "wrote %s\nwrote %s (do not upload; required for decrypt-credentials)\n", *out, key)
	return 0
}

func runDecryptCredentials(args []string) int {
	fs := flag.NewFlagSet("decrypt-credentials", flag.ExitOnError)
	envPath := fs.String("envelope", "", "envelope JSON file from master (encrypted)")
	keyPath := fs.String("key", "", "RSA private key PEM file from enroll (.key)")
	outPath := fs.String("out", "node-agent.credentials.json", "output cleartext credentials for AGENT_CREDENTIALS_FILE")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s decrypt-credentials -envelope <path> -key <path> [-out <path>]\n", os.Args[0])
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *envPath == "" || *keyPath == "" {
		fs.Usage()
		return 1
	}
	if err := agent.DecryptCredentialEnvelopeToFile(*envPath, *keyPath, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s — set AGENT_CREDENTIALS_FILE to this path and start the agent.\n", *outPath)
	return 0
}

func printAgentHelp() {
	fmt.Printf(`Unified scan/monitor agent.

Run without subcommands to start the agent (requires MASTER_URL / AGENT_TOKEN or AGENT_CREDENTIALS_FILE).

Subcommands:
  enroll [-out node-enrollment.json]
        Generate machine enrollment JSON + RSA key pair for onboarding.
        Upload only the .json to the master; keep the .key file on this machine.

  decrypt-credentials -envelope <file> -key <file> [-out credentials.json]
        Decrypt credential envelope from the master using the private .key from enroll.

`)
}
