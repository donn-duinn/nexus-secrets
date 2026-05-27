package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// APIServer is the HTTP API server for nexus-secrets.
type APIServer struct {
	vault *Vault
	auth  *AuthConfig
	mux   *http.ServeMux
}

// NewAPIServer creates a new API server.
func NewAPIServer(vault *Vault, auth *AuthConfig) *APIServer {
	s := &APIServer{
		vault: vault,
		auth:  auth,
		mux:   http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// Handler returns the HTTP handler with auth middleware applied.
func (s *APIServer) Handler() http.Handler {
	return AuthMiddleware(s.auth)(s.mux)
}

func (s *APIServer) registerRoutes() {
	s.mux.HandleFunc("/api/secrets", s.handleListAll)
	s.mux.HandleFunc("/api/secrets/", s.handleSecretRoute)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/generate-key", s.handleGenerateKey)
}

// handleSecretRoute routes /api/secrets/* to the correct handler based on method and path.
func (s *APIServer) handleSecretRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	path = strings.TrimSuffix(path, "/")

	if path == "" {
		s.handleListAll(w, r)
		return
	}

	// Handle /api/secrets/rotate/:namespace/:key
	if strings.HasPrefix(path, "rotate/") {
		rest := strings.TrimPrefix(path, "rotate/")
		ns, key, err := parseKey(rest)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.handleRotate(ns, key, w, r)
		return
	}

	// Handle /api/secrets/:namespace/:key
	ns, key, err := parseKey(path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGet(ns, key, w, r)
	case http.MethodPost, http.MethodPut:
		s.handleSet(ns, key, w, r)
	case http.MethodDelete:
		s.handleDelete(ns, key, w, r)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) handleGet(namespace, key string, w http.ResponseWriter, r *http.Request) {
	secret, err := s.vault.GetSecret(namespace, key)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"namespace":  secret.Namespace,
		"key":        secret.Key,
		"value":      secret.Value,
		"version":    secret.Version,
		"updated_at": secret.UpdatedAt,
	})
}

func (s *APIServer) handleSet(namespace, key string, w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var body struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if body.Value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.vault.SetSecret(namespace, key, body.Value); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"status":    "ok",
		"namespace": namespace,
		"key":       key,
		"message":   "secret stored successfully",
	})
}

func (s *APIServer) handleDelete(namespace, key string, w http.ResponseWriter, r *http.Request) {
	rows, err := s.vault.DeleteSecret(namespace, key)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"status":       "ok",
		"namespace":    namespace,
		"key":          key,
		"rows_deleted": rows,
	})
}

func (s *APIServer) handleRotate(namespace, key string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var body struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if body.Value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.vault.RotateSecret(namespace, key, body.Value); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"status":    "ok",
		"namespace": namespace,
		"key":       key,
		"message":   "secret rotated successfully",
	})
}

func (s *APIServer) handleListAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	secrets, err := s.vault.ListAll()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"secrets": secrets,
		"count":   len(secrets),
	})
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"status":  "healthy",
		"service": "nexus-secrets",
	})
}

func (s *APIServer) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key, err := GenerateAPIKey()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"api_key": key,
		"message": "Store this key securely — it cannot be retrieved again",
	})
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

// StartAPI creates and returns a configured HTTP API server.
func StartAPI(addr string, vault *Vault, auth *AuthConfig) *http.Server {
	api := NewAPIServer(vault, auth)
	log.Printf("nexus-secrets API listening on %s", addr)
	return &http.Server{
		Addr:         addr,
		Handler:      api.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}
