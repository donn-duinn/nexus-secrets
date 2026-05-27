package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration.
type Config struct {
	// MasterKeyPath is the path to the master key file.
	MasterKeyPath string `yaml:"master_key_path"`
	// DBPath is the path to the SQLite database.
	DBPath string `yaml:"db_path"`
	// APIPort is the port for the HTTP API server.
	APIPort int `yaml:"api_port"`
	// APIKeyEnv is the environment variable name for the API key.
	APIKeyEnv string `yaml:"api_key_env"`

	// K8s holds Kubernetes configuration.
	K8s K8sConfig `yaml:"k8s"`
}

// K8sConfig holds Kubernetes-specific configuration.
type K8sConfig struct {
	// Namespace is the default K8s namespace for secrets.
	Namespace string `yaml:"namespace"`
	// NamespaceMap maps vault namespaces to K8s namespaces.
	NamespaceMap map[string]string `yaml:"namespace_map"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		MasterKeyPath: filepath.Join(home, ".nexus", "secrets", "master.key"),
		DBPath:        filepath.Join(home, ".nexus", "secrets", "vault.db"),
		APIPort:       7438,
		APIKeyEnv:     "NEXUS_API_KEYS",
		K8s: K8sConfig{
			Namespace:    "nexus-secrets",
			NamespaceMap: make(map[string]string),
		},
	}
}

// LoadConfig loads configuration from a YAML file.
// If path is empty, it looks for config.yaml in the current directory
// and then in ~/.nexus/secrets/config.yaml.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		// Try current directory first
		if _, err := os.Stat("config.yaml"); err == nil {
			path = "config.yaml"
		} else {
			// Try home directory
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".nexus", "secrets", "config.yaml")
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

// GetMasterKey returns the master key from environment variable or file.
func GetMasterKey(cfg *Config) (string, error) {
	// Check environment variable first
	if key := os.Getenv("NEXUS_MASTER_KEY"); key != "" {
		return key, nil
	}

	// Read from file
	data, err := os.ReadFile(cfg.MasterKeyPath)
	if err != nil {
		return "", fmt.Errorf("reading master key from %s: %w\nSet NEXUS_MASTER_KEY environment variable or create the key file", cfg.MasterKeyPath, err)
	}

	key := string(data)
	// Trim whitespace
	for len(key) > 0 && (key[len(key)-1] == '\n' || key[len(key)-1] == '\r' || key[len(key)-1] == ' ') {
		key = key[:len(key)-1]
	}

	return key, nil
}

// EnsureDir creates the directory for the given path if it doesn't exist.
func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0700)
}
