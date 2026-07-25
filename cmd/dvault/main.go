package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/pki"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

var (
	socketPath string
	client     agentpbv1.AgentServiceClient
	conn       *grpc.ClientConn
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dvault",
		Short: "datavault -- Linux cluster incremental backup system",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if strings.HasPrefix(cmd.CommandPath(), "dvault cert ") {
				return nil
			}
			var err error
			conn, err = grpc.Dial("unix://"+socketPath,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("connect to agent: %w", err)
			}
			client = agentpbv1.NewAgentServiceClient(conn)
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if conn != nil {
				conn.Close()
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "/var/run/datavault-agent.sock", "agent socket path")

	// Subcommands
	rootCmd.AddCommand(ruleCmd())
	rootCmd.AddCommand(syncCmd())
	rootCmd.AddCommand(quotaCmd())
	rootCmd.AddCommand(restoreCmd())
	rootCmd.AddCommand(adminCmd())
	rootCmd.AddCommand(certCmd())
	rootCmd.AddCommand(webCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func ruleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "Manage backup rules"}

	addCmd := &cobra.Command{
		Use:   "add <name> <path...>",
		Short: "Add a backup rule",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			exclude, _ := cmd.Flags().GetStringArray("exclude")
			_, err := client.AddUserRule(context.Background(), &agentpbv1.AddUserRuleRequest{
				Name:    args[0],
				Paths:   args[1:],
				Exclude: exclude,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Rule %q added\n", args[0])
			return nil
		},
	}
	addCmd.Flags().StringArray("exclude", nil, "glob patterns to exclude")
	cmd.AddCommand(addCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a backup rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.RemoveUserRule(context.Background(), &agentpbv1.RemoveUserRuleRequest{Name: args[0]})
			if err != nil {
				return err
			}
			fmt.Printf("Rule %q removed\n", args[0])
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List backup rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := client.ListUserRules(context.Background(), &agentpbv1.ListUserRulesRequest{})
			if err != nil {
				return err
			}
			for _, r := range resp.Rules {
				status := "enabled"
				if !r.Enabled {
					status = "disabled"
				}
				fmt.Printf("  %-20s [%s] paths=%v\n", r.Name, status, r.Paths)
			}
			return nil
		},
	})

	enableCmd := &cobra.Command{
		Use:  "enable <name>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.EnableUserRule(context.Background(), &agentpbv1.EnableUserRuleRequest{Name: args[0]})
			return err
		},
	}
	disableCmd := &cobra.Command{
		Use:  "disable <name>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.DisableUserRule(context.Background(), &agentpbv1.DisableUserRuleRequest{Name: args[0]})
			return err
		},
	}
	cmd.AddCommand(enableCmd, disableCmd)

	return cmd
}

func syncCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sync", Short: "Manage sync operations"}

	triggerCmd := &cobra.Command{
		Use:   "trigger",
		Short: "Manually trigger a sync",
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleName, _ := cmd.Flags().GetString("rule")
			sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
			if sshAuthSock == "" {
				return fmt.Errorf("SSH_AUTH_SOCK is required for user sync")
			}
			resp, err := client.TriggerSync(context.Background(), &agentpbv1.TriggerSyncRequest{
				RuleName:    ruleName,
				SshAuthSock: sshAuthSock,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Sync triggered: %s\n", resp.TaskId)
			return nil
		},
	}
	triggerCmd.Flags().String("rule", "", "specific rule to sync (empty = all)")
	cmd.AddCommand(triggerCmd)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "View sync progress",
		RunE: func(cmd *cobra.Command, args []string) error {
			taskID, _ := cmd.Flags().GetString("task")
			stream, err := client.GetSyncStatus(context.Background(), &agentpbv1.GetSyncStatusRequest{
				TaskId: taskID,
			})
			if err != nil {
				return err
			}
			for {
				update, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("receive sync status: %w", err)
				}
				fmt.Printf("\r[%s] %s: %d/%d files transferred (%d B/s)",
					update.TaskId, update.Phase,
					update.Stats.TransferredFiles, update.Stats.ChangedFiles,
					update.Stats.CurrentRateBps,
				)
				if update.Phase == "COMPLETED" || update.Phase == "FAILED" {
					if update.Error != "" {
						fmt.Printf(" — %s", update.Error)
					}
					fmt.Println()
					break
				}
			}
			return nil
		},
	}
	statusCmd.Flags().String("task", "", "task ID (empty = latest)")
	cmd.AddCommand(statusCmd)

	return cmd
}

func quotaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quota",
		Short: "Show quota usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			challenge, err := client.GetAuthChallenge(context.Background(), &agentpbv1.GetAuthChallengeRequest{Method: "GetQuotaUsage"})
			if err != nil {
				return err
			}
			signature, err := signServerRequest("GetQuotaUsage", challenge.Nonce, &backuppbv1.GetQuotaUsageRequest{Username: challenge.Username})
			if err != nil {
				return err
			}

			usage, err := client.GetQuotaUsage(context.Background(), &agentpbv1.GetQuotaUsageRequest{
				Nonce:     challenge.Nonce,
				Signature: signature,
				Server:    challenge.Server,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Server:  %s\n", usage.Server)
			fmt.Printf("Dataset: %s\n", usage.Dataset)
			fmt.Printf("Used:    %s\n", formatBytes(usage.UsedBytes))
			fmt.Printf("Quota:   %s\n", formatBytes(usage.QuotaBytes))
			return nil
		},
	}
}

func signServerRequest(method string, nonce []byte, msg proto.Message) ([]byte, error) {
	payload, err := auth.ServerRequestPayload(method, nonce, msg)
	if err != nil {
		return nil, err
	}
	_, sig, err := auth.SignWithSSHAgent(payload)
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(sig), nil
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func restoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore backup data",
		RunE: func(cmd *cobra.Command, args []string) error {
			targetPath, _ := cmd.Flags().GetString("path")
			challenge, err := client.GetAuthChallenge(context.Background(), &agentpbv1.GetAuthChallengeRequest{Method: "PullRestore"})
			if err != nil {
				return err
			}
			signature, err := signServerRequest("PullRestore", challenge.Nonce, &backuppbv1.PullRestoreRequest{Username: challenge.Username})
			if err != nil {
				return err
			}
			resp, err := client.RequestRestore(context.Background(), &agentpbv1.RequestRestoreRequest{
				TargetPath: targetPath,
				Nonce:      challenge.Nonce,
				Signature:  signature,
				Server:     challenge.Server,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Restore started: %s\n", resp.TaskId)
			return nil
		},
	}
	cmd.Flags().String("path", "", "target restore path (default: ~/restored/)")
	return cmd
}

func adminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrator commands (requires root)",
	}

	ruleCmd := &cobra.Command{Use: "rule", Short: "Manage machine backup rules"}

	addCmd := &cobra.Command{
		Use:   "add <name> <path...>",
		Short: "Add a machine backup rule",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			schedule, _ := cmd.Flags().GetString("schedule")
			exclude, _ := cmd.Flags().GetStringArray("exclude")
			_, err := client.AddMachineRule(context.Background(), &agentpbv1.AddMachineRuleRequest{
				Name:     args[0],
				Paths:    args[1:],
				Schedule: schedule,
				Exclude:  exclude,
			})
			return err
		},
	}
	addCmd.Flags().String("schedule", "0 3 * * *", "cron schedule")
	ruleCmd.AddCommand(addCmd)

	ruleCmd.AddCommand(&cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a machine backup rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.RemoveMachineRule(context.Background(), &agentpbv1.RemoveMachineRuleRequest{Name: args[0]})
			return err
		},
	})

	ruleCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List machine backup rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := client.ListMachineRules(context.Background(), &agentpbv1.ListMachineRulesRequest{})
			if err != nil {
				return err
			}
			for _, r := range resp.Rules {
				status := "enabled"
				if !r.Enabled {
					status = "disabled"
				}
				fmt.Printf("  %-20s [%s] paths=%v\n", r.Name, status, r.Paths)
			}
			return nil
		},
	})

	cmd.AddCommand(ruleCmd)
	return cmd
}

func certCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Provision the private CA and mTLS certificates (requires root)",
	}

	initCA := &cobra.Command{
		Use:   "init-ca",
		Short: "Create a new private certificate authority",
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return fmt.Errorf("dvault cert init-ca must run as root")
			}
			certPath, _ := cmd.Flags().GetString("cert")
			keyPath, _ := cmd.Flags().GetString("key")
			commonName, _ := cmd.Flags().GetString("common-name")
			validFor, _ := cmd.Flags().GetDuration("valid-for")
			certPEM, keyPEM, err := pki.CreateCA(pki.CAOptions{CommonName: commonName, ValidFor: validFor})
			if err != nil {
				return err
			}
			if err := pki.WritePair(certPath, keyPath, certPEM, keyPEM); err != nil {
				return fmt.Errorf("write CA: %w", err)
			}
			fmt.Printf("CA certificate: %s\nCA key: %s\n", certPath, keyPath)
			return nil
		},
	}
	initCA.Flags().String("cert", "/etc/datavault/pki/ca.crt", "CA certificate output path")
	initCA.Flags().String("key", "/etc/datavault/pki/ca.key", "CA private key output path")
	initCA.Flags().String("common-name", "datavault private CA", "CA common name")
	initCA.Flags().Duration("valid-for", pki.DefaultCAValidity, "CA validity")

	issue := &cobra.Command{
		Use:   "issue",
		Short: "Issue one mTLS client or server certificate from the private CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return fmt.Errorf("dvault cert issue must run as root")
			}
			caCertPath, _ := cmd.Flags().GetString("ca-cert")
			caKeyPath, _ := cmd.Flags().GetString("ca-key")
			certPath, _ := cmd.Flags().GetString("cert")
			keyPath, _ := cmd.Flags().GetString("key")
			commonName, _ := cmd.Flags().GetString("common-name")
			dnsNames, _ := cmd.Flags().GetStringSlice("dns")
			ipStrings, _ := cmd.Flags().GetStringSlice("ip")
			clientCert, _ := cmd.Flags().GetBool("client")
			serverCert, _ := cmd.Flags().GetBool("server")
			validFor, _ := cmd.Flags().GetDuration("valid-for")
			caCertPEM, err := os.ReadFile(caCertPath)
			if err != nil {
				return fmt.Errorf("read CA certificate: %w", err)
			}
			caKeyPEM, err := os.ReadFile(caKeyPath)
			if err != nil {
				return fmt.Errorf("read CA key: %w", err)
			}
			ips := make([]net.IP, 0, len(ipStrings))
			for _, value := range ipStrings {
				ip := net.ParseIP(value)
				if ip == nil {
					return fmt.Errorf("invalid --ip value %q", value)
				}
				ips = append(ips, ip)
			}
			certPEM, keyPEM, err := pki.Issue(caCertPEM, caKeyPEM, pki.IssueOptions{
				CommonName:  commonName,
				DNSNames:    dnsNames,
				IPAddresses: ips,
				Client:      clientCert,
				Server:      serverCert,
				ValidFor:    validFor,
			})
			if err != nil {
				return err
			}
			if err := pki.WritePair(certPath, keyPath, certPEM, keyPEM); err != nil {
				return fmt.Errorf("write issued certificate: %w", err)
			}
			fmt.Printf("Certificate: %s\nPrivate key: %s\n", certPath, keyPath)
			return nil
		},
	}
	issue.Flags().String("ca-cert", "/etc/datavault/pki/ca.crt", "CA certificate path")
	issue.Flags().String("ca-key", "/etc/datavault/pki/ca.key", "CA private key path")
	issue.Flags().String("cert", "", "issued certificate output path")
	issue.Flags().String("key", "", "issued private key output path")
	issue.Flags().String("common-name", "", "certificate common name")
	issue.Flags().StringSlice("dns", nil, "server DNS SAN (repeatable)")
	issue.Flags().StringSlice("ip", nil, "server IP SAN (repeatable)")
	issue.Flags().Bool("client", false, "issue a client-auth certificate")
	issue.Flags().Bool("server", false, "issue a server-auth certificate")
	issue.Flags().Duration("valid-for", pki.DefaultLeafValidity, "certificate validity")
	_ = issue.MarkFlagRequired("cert")
	_ = issue.MarkFlagRequired("key")
	_ = issue.MarkFlagRequired("common-name")

	cmd.AddCommand(initCA, issue)
	return cmd
}

func webCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "web", Short: "Manage web gateway delegations"}

	var gateway, delegationKey, server string
	var ttl time.Duration
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Authorize a web gateway to act for you until the TTL expires",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyLine, err := resolveDelegationKeyInput(delegationKey)
			if err != nil {
				return err
			}
			me, err := user.Current()
			if err != nil {
				return fmt.Errorf("resolve current user: %w", err)
			}
			challenge, err := client.GetAuthChallenge(context.Background(), &agentpbv1.GetAuthChallengeRequest{Method: "RegisterDelegationKey"})
			if err != nil {
				return fmt.Errorf("get auth challenge: %w", err)
			}
			if server == "" {
				server = challenge.Server
			}
			expiresAt := time.Now().Add(ttl).Unix()
			payload := auth.DelegationConsentPayload(challenge.Nonce, me.Username, gateway, keyLine, expiresAt)
			_, sig, err := auth.SignWithSSHAgent(payload)
			if err != nil {
				return fmt.Errorf("sign consent: %w", err)
			}
			resp, err := client.EnrollWebDelegation(context.Background(), &agentpbv1.EnrollWebDelegationRequest{
				GatewayCn:        gateway,
				DelegationPubkey: keyLine,
				TtlSeconds:       int64(ttl / time.Second),
				Server:           server,
				Nonce:            challenge.Nonce,
				Signature:        ssh.Marshal(sig),
			})
			if err != nil {
				return err
			}
			fmt.Printf("Delegation for gateway %q recorded, expires %s\n", gateway, time.Unix(resp.ExpiresAt, 0).Format(time.RFC3339))
			return nil
		},
	}
	enroll.Flags().StringVar(&gateway, "gateway", "", "gateway certificate CN (required)")
	enroll.Flags().StringVar(&delegationKey, "delegation-key", "", "gateway delegation public key (authorized_keys line or @file)")
	enroll.Flags().DurationVar(&ttl, "ttl", 720*time.Hour, "delegation lifetime")
	enroll.Flags().StringVar(&server, "server", "", "backup server address (default: from challenge)")
	_ = enroll.MarkFlagRequired("gateway")
	_ = enroll.MarkFlagRequired("delegation-key")
	cmd.AddCommand(enroll)

	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a gateway delegation",
		RunE: func(cmd *cobra.Command, args []string) error {
			me, err := user.Current()
			if err != nil {
				return fmt.Errorf("resolve current user: %w", err)
			}
			// Look up the delegation pubkey so the removal statement binds it.
			list, err := client.ListWebDelegations(context.Background(), &agentpbv1.ListWebDelegationsRequest{})
			if err != nil {
				return err
			}
			var keyLine string
			for _, d := range list.Delegations {
				if d.GatewayCn == gateway && !d.Revoked {
					keyLine = d.DelegationPubkey
				}
			}
			if keyLine == "" {
				return fmt.Errorf("no active delegation for gateway %q", gateway)
			}
			challenge, err := client.GetAuthChallenge(context.Background(), &agentpbv1.GetAuthChallengeRequest{Method: "RemoveDelegationKey"})
			if err != nil {
				return fmt.Errorf("get auth challenge: %w", err)
			}
			payload := auth.DelegationRemovalPayload(challenge.Nonce, me.Username, gateway, keyLine)
			_, sig, err := auth.SignWithSSHAgent(payload)
			if err != nil {
				return fmt.Errorf("sign removal: %w", err)
			}
			_, err = client.RevokeWebDelegation(context.Background(), &agentpbv1.RevokeWebDelegationRequest{
				GatewayCn: gateway,
				Server:    challenge.Server,
				Nonce:     challenge.Nonce,
				Signature: ssh.Marshal(sig),
			})
			if err != nil {
				return err
			}
			fmt.Printf("Delegation for gateway %q revoked\n", gateway)
			return nil
		},
	}
	revoke.Flags().StringVar(&gateway, "gateway", "", "gateway certificate CN (required)")
	_ = revoke.MarkFlagRequired("gateway")
	cmd.AddCommand(revoke)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List your web delegations",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := client.ListWebDelegations(context.Background(), &agentpbv1.ListWebDelegationsRequest{})
			if err != nil {
				return err
			}
			for _, d := range resp.Delegations {
				state := "active"
				if d.Revoked {
					state = "revoked"
				} else if time.Now().Unix() > d.ExpiresAt {
					state = "expired"
				}
				fmt.Printf("  %-20s [%s] expires=%s\n", d.GatewayCn, state, time.Unix(d.ExpiresAt, 0).Format(time.RFC3339))
			}
			return nil
		},
	})
	return cmd
}

// resolveDelegationKeyInput accepts an authorized_keys line directly or
// "@/path/to/key.pub" to read it from a file.
func resolveDelegationKeyInput(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("delegation key is required")
	}
	line := input
	if rest, ok := strings.CutPrefix(input, "@"); ok {
		data, err := os.ReadFile(filepath.Clean(rest))
		if err != nil {
			return "", fmt.Errorf("read delegation key file: %w", err)
		}
		line = string(data)
	}
	line = strings.TrimSpace(line)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		return "", fmt.Errorf("invalid delegation public key: %w", err)
	}
	return line, nil
}
