package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/example/datavault/internal/server/enrollment"
)

// runKeyEnroll is an unprivileged client for the root-running Server daemon's
// local enrollment socket. The daemon derives the caller identity from
// SO_PEERCRED; this process has neither sudo privileges nor write access to
// the authorized-key directory.
func runKeyEnroll(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("key-enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socketPath := flags.String("socket", enrollment.DefaultSocketPath, "local server enrollment socket path")
	agentCN := flags.String("agent", "", "Agent certificate CN to authorize")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("key-enroll does not accept positional arguments")
	}
	if *agentCN == "" {
		return fmt.Errorf("--agent is required")
	}
	keyData, err := io.ReadAll(io.LimitReader(input, enrollment.MaxPublicKeyBytes+1))
	if err != nil {
		return fmt.Errorf("read public key from standard input: %w", err)
	}
	if len(keyData) == 0 || len(keyData) > enrollment.MaxPublicKeyBytes {
		return fmt.Errorf("public key must contain between 1 and %d bytes", enrollment.MaxPublicKeyBytes)
	}

	conn, err := net.DialTimeout("unix", *socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to local enrollment socket: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set local enrollment socket deadline: %w", err)
	}
	request := enrollment.LocalRequest{AgentCN: *agentCN, PublicKey: string(keyData)}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return fmt.Errorf("send enrollment request: %w", err)
	}
	var response enrollment.LocalResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return fmt.Errorf("read enrollment response: %w", err)
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	if response.Fingerprint == "" {
		return fmt.Errorf("invalid enrollment response")
	}

	_, err = fmt.Fprintf(output, "Enrolled key for your local OS account on %s: %s\n", strings.TrimSpace(*agentCN), response.Fingerprint)
	return err
}
