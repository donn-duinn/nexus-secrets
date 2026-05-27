package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// CLI handles command-line interface operations.
type CLI struct {
	vault *Vault
}

// NewCLI creates a new CLI instance.
func NewCLI(vault *Vault) *CLI {
	return &CLI{vault: vault}
}

// Run executes the CLI command based on arguments.
func (c *CLI) Run(args []string) error {
	if len(args) < 2 {
		return c.printUsage()
	}

	cmd := args[1]
	switch cmd {
	case "set":
		return c.handleSet(args[2:])
	case "get":
		return c.handleGet(args[2:])
	case "delete", "del":
		return c.handleDelete(args[2:])
	case "list", "ls":
		return c.handleList(args[2:])
	case "rotate":
		return c.handleRotate(args[2:])
	case "versions":
		return c.handleVersions(args[2:])
	case "export":
		return c.handleExport(args[2:])
	case "import":
		return c.handleImport(args[2:])
	case "sync":
		return c.handleSync(args[2:])
	case "generate-key":
		return c.handleGenerateKey()
	case "help", "--help", "-h":
		return c.printUsage()
	default:
		return fmt.Errorf("unknown command: %s\nRun 'nexus-secrets help' for usage", cmd)
	}
}

func (c *CLI) handleSet(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nexus-secrets set <namespace/key> <value>")
	}

	ns, key, err := parseKey(args[0])
	if err != nil {
		return err
	}

	value := strings.Join(args[1:], " ")
	if err := c.vault.SetSecret(ns, key, value); err != nil {
		return err
	}

	fmt.Printf("secret %s/%s stored successfully (version incremented)\n", ns, key)
	return nil
}

func (c *CLI) handleGet(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nexus-secrets get <namespace/key>")
	}

	ns, key, err := parseKey(args[0])
	if err != nil {
		return err
	}

	secret, err := c.vault.GetSecret(ns, key)
	if err != nil {
		return err
	}

	fmt.Println(secret.Value)
	return nil
}

func (c *CLI) handleDelete(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nexus-secrets delete <namespace/key>")
	}

	ns, key, err := parseKey(args[0])
	if err != nil {
		return err
	}

	rows, err := c.vault.DeleteSecret(ns, key)
	if err != nil {
		return err
	}

	fmt.Printf("deleted %s/%s (%d versions)\n", ns, key, rows)
	return nil
}

func (c *CLI) handleList(args []string) error {
	if len(args) > 0 {
		// List keys in a specific namespace
		ns := args[0]
		keys, err := c.vault.ListKeys(ns)
		if err != nil {
			return err
		}

		if len(keys) == 0 {
			fmt.Printf("no secrets in namespace %s\n", ns)
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "NAMESPACE\tKEY\tVERSION\tUPDATED\n")
		for _, s := range keys {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", s.Namespace, s.Key, s.Version, s.UpdatedAt.Format("2006-01-02 15:04:05"))
		}
		return w.Flush()
	}

	// List all secrets
	secrets, err := c.vault.ListAll()
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		fmt.Println("no secrets stored")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "NAMESPACE\tKEY\tVERSION\tUPDATED\n")
	for _, s := range secrets {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", s.Namespace, s.Key, s.Version, s.UpdatedAt.Format("2006-01-02 15:04:05"))
	}
	return w.Flush()
}

func (c *CLI) handleRotate(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nexus-secrets rotate <namespace/key> <new_value>")
	}

	ns, key, err := parseKey(args[0])
	if err != nil {
		return err
	}

	value := strings.Join(args[1:], " ")
	if err := c.vault.RotateSecret(ns, key, value); err != nil {
		return err
	}

	fmt.Printf("rotated %s/%s\n", ns, key)
	return nil
}

func (c *CLI) handleVersions(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nexus-secrets versions <namespace/key>")
	}

	ns, key, err := parseKey(args[0])
	if err != nil {
		return err
	}

	versions, err := c.vault.GetSecretVersions(ns, key)
	if err != nil {
		return err
	}

	if len(versions) == 0 {
		fmt.Printf("no versions found for %s/%s\n", ns, key)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "VERSION\tCREATED\tVALUE\n")
	for _, v := range versions {
		// Mask the value for security
		masked := v.Value
		if len(masked) > 8 {
			masked = masked[:4] + "..." + masked[len(masked)-4:]
		}
		fmt.Fprintf(w, "%d\t%s\t%s\n", v.Version, v.CreatedAt.Format("2006-01-02 15:04:05"), masked)
	}
	return w.Flush()
}

func (c *CLI) handleExport(args []string) error {
	format := "env"
	for i, arg := range args {
		if arg == "--format" && i+1 < len(args) {
			format = args[i+1]
		}
	}

	export, err := c.vault.ExportAll()
	if err != nil {
		return err
	}

	switch format {
	case "env":
		for k, v := range export {
			// Convert namespace/key to NAMESPACE_KEY format
			envKey := strings.ReplaceAll(strings.ToUpper(k), "/", "_")
			envKey = strings.ReplaceAll(envKey, ".", "_")
			envKey = strings.ReplaceAll(envKey, "-", "_")
			fmt.Printf("%s=%q\n", envKey, v)
		}
	case "json":
		fmt.Println("{")
		first := true
		for k, v := range export {
			if !first {
				fmt.Println(",")
			}
			fmt.Printf("  %q: %q", k, v)
			first = false
		}
		fmt.Println("\n}")
	default:
		return fmt.Errorf("unsupported format: %s (use env or json)", format)
	}

	return nil
}

func (c *CLI) handleImport(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nexus-secrets import <file>")
	}

	file, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	imported := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		envKey := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Remove quotes if present
		value = strings.Trim(value, "\"'")

		// Convert NAMESPACE_KEY to namespace/key
		keyParts := strings.SplitN(envKey, "_", 2)
		if len(keyParts) != 2 {
			continue
		}
		ns := strings.ToLower(keyParts[0])
		key := strings.ToLower(keyParts[1])
		key = strings.ReplaceAll(key, "_", ".")

		if err := c.vault.SetSecret(ns, key, value); err != nil {
			return fmt.Errorf("importing %s: %w", envKey, err)
		}
		imported++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	fmt.Printf("imported %d secrets\n", imported)
	return nil
}

func (c *CLI) handleSync(args []string) error {
	// Load config for K8s namespace mapping
	cfg, err := LoadConfig("")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	injector := NewK8sInjector(c.vault, cfg.K8s.Namespace, cfg.K8s.NamespaceMap)

	if len(args) > 0 && args[0] == "--namespace" {
		if len(args) < 2 {
			return fmt.Errorf("usage: nexus-secrets sync --namespace <namespace>")
		}
		return injector.SyncNamespace(args[1])
	}

	return injector.SyncAll()
}

func (c *CLI) handleGenerateKey() error {
	key, err := GenerateAPIKey()
	if err != nil {
		return err
	}

	fmt.Println(key)
	return nil
}

func (c *CLI) printUsage() error {
	fmt.Println(`nexus-secrets — Swarm-aware secrets management

USAGE:
  nexus-secrets <command> [arguments]

COMMANDS:
  set <namespace/key> <value>     Store or update a secret
  get <namespace/key>             Retrieve a secret's value
  delete <namespace/key>          Delete a secret (all versions)
  list [namespace]                List all secrets or keys in a namespace
  rotate <namespace/key> <value>  Rotate a secret (creates new version)
  versions <namespace/key>        Show version history of a secret
  export [--format env|json]      Export all secrets
  import <file>                   Import secrets from .env file
  sync [--namespace <ns>]         Sync secrets to Kubernetes
  generate-key                    Generate a new API key
  help                            Show this help

EXAMPLES:
  nexus-secrets set ollama/api_key sk-abc123
  nexus-secrets get ollama/api_key
  nexus-secrets list ollama
  nexus-secrets rotate telegram/bot_token new-token-value
  nexus-secrets export --format env > secrets.env
  nexus-secrets import secrets.env
  nexus-secrets sync --namespace telegram

KEY FORMAT:
  Secrets are organized as namespace/key, e.g.:
    ollama/api_key
    telegram/bot_token
    jellyfin/api_key
    cloudflare/tunnel_token`)
	return nil
}
