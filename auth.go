package main

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// APIKeys is a map of key ID -> key value for authentication.
	APIKeys map[string]string
	// Enabled indicates whether authentication is required.
	Enabled bool
}

// NewAuthConfig creates an AuthConfig from environment variables.
// NEXUS_API_KEYS format: "id1:key1,id2:key2"
func NewAuthConfig() *AuthConfig {
	cfg := &AuthConfig{
		APIKeys: make(map[string]string),
	}

	keysEnv := os.Getenv("NEXUS_API_KEYS")
	if keysEnv == "" {
		cfg.Enabled = false
		return cfg
	}

	cfg.Enabled = true
	for _, pair := range strings.Split(keysEnv, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		cfg.APIKeys[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	return cfg
}

// AuthMiddleware returns an HTTP middleware that validates API keys.
func AuthMiddleware(auth *AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			apiKey := extractAPIKey(r)
			if apiKey == "" {
				http.Error(w, `{"error":"missing API key"}`, http.StatusUnauthorized)
				return
			}

			if !auth.ValidateKey(apiKey) {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateKey checks if the given key matches any configured API key.
func (auth *AuthConfig) ValidateKey(key string) bool {
	if !auth.Enabled {
		return true
	}

	for _, validKey := range auth.APIKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(validKey)) == 1 {
			return true
		}
	}
	return false
}

// GetKeyID returns the ID of the key that matches, or empty string.
func (auth *AuthConfig) GetKeyID(key string) string {
	for id, validKey := range auth.APIKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(validKey)) == 1 {
			return id
		}
	}
	return ""
}

// extractAPIKey extracts the API key from the request.
// Checks: Authorization: Bearer <key>, X-API-Key header, ?api_key query param.
func extractAPIKey(r *http.Request) string {
	// Check Authorization header (Bearer token)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// Check X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Check query parameter
	if key := r.URL.Query().Get("api_key"); key != "" {
		return key
	}

	return ""
}

// GenerateAPIKey generates a random API key and returns it hex-encoded.
func GenerateAPIKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating API key: %w", err)
	}
	return fmt.Sprintf("nxs_%x", key), nil
}

// GenerateMasterKey generates a random 32-byte master key and returns it hex-encoded.
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating master key: %w", err)
	}
	return fmt.Sprintf("%x", key), nil
}
