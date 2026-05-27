package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	// Load configuration
	cfg, err := LoadConfig("")
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	// Determine if we're running as CLI or server
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		if err := runServer(cfg); err != nil {
			log.Fatalf("server error: %v", err)
		}
		return
	}

	// Run as CLI
	if err := runCLI(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cfg *Config) error {
	// Get master key
	masterKey, err := GetMasterKey(cfg)
	if err != nil {
		return fmt.Errorf("getting master key: %w", err)
	}

	// Ensure database directory exists
	if err := EnsureDir(cfg.DBPath); err != nil {
		return fmt.Errorf("creating db directory: %w", err)
	}

	// Initialize vault
	vault, err := NewVault(cfg.DBPath, masterKey)
	if err != nil {
		return fmt.Errorf("initializing vault: %w", err)
	}
	defer vault.Close()

	// Initialize auth
	auth := NewAuthConfig(cfg.APIKeyEnv)

	// Determine listen address
	addr := ":" + strconv.Itoa(cfg.APIPort)
	if envAddr := os.Getenv("NEXUS_SECRETS_ADDR"); envAddr != "" {
		addr = envAddr
	}

	// Start API server with graceful shutdown
	srv := StartAPI(addr, vault, auth)

	// Channel to receive errors from ListenAndServe
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down gracefully", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}

	// Give active requests up to 10 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Println("server stopped cleanly")
	return nil
}

func runCLI(cfg *Config) error {
	// Handle init command separately (doesn't need vault)
	if len(os.Args) > 1 && os.Args[1] == "init" {
		return handleInit(cfg)
	}

	// Handle help command separately (doesn't need vault)
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		cli := &CLI{}
		return cli.printUsage()
	}

	// Get master key
	masterKey, err := GetMasterKey(cfg)
	if err != nil {
		return fmt.Errorf("getting master key: %w", err)
	}

	// Ensure database directory exists
	if err := EnsureDir(cfg.DBPath); err != nil {
		return fmt.Errorf("creating db directory: %w", err)
	}

	// Initialize vault
	vault, err := NewVault(cfg.DBPath, masterKey)
	if err != nil {
		return fmt.Errorf("initializing vault: %w", err)
	}
	defer vault.Close()

	// Run CLI
	cli := NewCLI(vault)
	return cli.Run(os.Args)
}

func handleInit(cfg *Config) error {
	// Create secrets directory
	if err := os.MkdirAll("/home/donn/.nexus/secrets", 0700); err != nil {
		return fmt.Errorf("creating secrets directory: %w", err)
	}

	// Generate master key if it doesn't exist
	if _, err := os.Stat(cfg.MasterKeyPath); os.IsNotExist(err) {
		key, err := GenerateMasterKey()
		if err != nil {
			return fmt.Errorf("generating master key: %w", err)
		}

		if err := os.WriteFile(cfg.MasterKeyPath, []byte(key), 0600); err != nil {
			return fmt.Errorf("writing master key: %w", err)
		}

		fmt.Printf("master key generated at %s\n", cfg.MasterKeyPath)
		fmt.Println("IMPORTANT: Back up this key securely!")
	} else {
		fmt.Println("master key already exists")
	}

	// Generate default API key
	apiKey, err := GenerateAPIKey()
	if err != nil {
		return fmt.Errorf("generating API key: %w", err)
	}

	fmt.Printf("\nGenerated API key: %s\n", apiKey)
	fmt.Println("\nAdd to your environment:")
	fmt.Printf("  export NEXUS_API_KEYS=\"cli:%s\"\n", apiKey)
	fmt.Printf("  export NEXUS_MASTER_KEY=$(cat %s)\n", cfg.MasterKeyPath)

	// Write default config if it doesn't exist
	configPath := "/home/donn/.nexus/secrets/config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configContent := `# nexus-secrets configuration
master_key_path: /home/donn/.nexus/secrets/master.key
db_path: /home/donn/.nexus/secrets/vault.db
api_port: 7438
api_key_env: NEXUS_API_KEY

k8s:
  namespace: nexus-secrets
  namespace_map:
    ollama: ai
    telegram: messaging
    jellyfin: media
    cloudflare: networking
    redis: infrastructure
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}
		fmt.Printf("\nDefault config written to %s\n", configPath)
	}

	// Create systemd service file
	serviceContent := `[Unit]
Description=Nexus Secrets API Server
After=network.target

[Service]
Type=simple
User=donn
Environment="NEXUS_MASTER_KEY=YOUR_MASTER_KEY_HERE"
Environment="NEXUS_API_KEYS=cli:YOUR_API_KEY_HERE"
ExecStart=/usr/local/bin/nexus-secrets serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	servicePath := "/home/donn/.nexus/secrets/nexus-secrets.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}
	fmt.Printf("\nSystemd service template at %s\n", servicePath)
	fmt.Println("Edit the service file with your keys, then:")
	fmt.Println("  sudo cp ~/.nexus/secrets/nexus-secrets.service /etc/systemd/system/")
	fmt.Println("  sudo systemctl enable --now nexus-secrets")

	return nil
}

func init() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[nexus-secrets] ")

	// Initialize HTTP routes for health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","service":"nexus-secrets"}`))
	})
}
