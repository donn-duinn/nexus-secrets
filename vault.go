package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Secret represents a stored secret with metadata.
type Secret struct {
	Namespace string    `json:"namespace"`
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretVersion represents a historical version of a secret.
type SecretVersion struct {
	Version   int       `json:"version"`
	Value     string    `json:"value,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Vault manages encrypted secrets in a SQLite database.
type Vault struct {
	db        *sql.DB
	masterKey []byte
	gcm       cipher.AEAD
}

const maxVersions = 5

// NewVault creates a new Vault instance. masterKeyHex is the hex-encoded master key.
func NewVault(dbPath, masterKeyHex string) (*Vault, error) {
	key, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key (must be hex-encoded): %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	v := &Vault{db: db, masterKey: key, gcm: gcm}
	if err := v.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration: %w", err)
	}

	return v, nil
}

// Close closes the underlying database connection.
func (v *Vault) Close() error {
	return v.db.Close()
}

func (v *Vault) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		namespace TEXT NOT NULL,
		key TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		nonce BLOB NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(namespace, key, version)
	);
	CREATE INDEX IF NOT EXISTS idx_secrets_ns_key ON secrets(namespace, key);
	CREATE INDEX IF NOT EXISTS idx_secrets_version ON secrets(namespace, key, version DESC);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		namespace TEXT NOT NULL,
		key TEXT NOT NULL,
		action TEXT NOT NULL,
		api_key_id TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := v.db.Exec(schema)
	return err
}

// encrypt encrypts plaintext using AES-256-GCM with a random nonce.
func (v *Vault) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, v.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext = v.gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decrypt decrypts ciphertext using AES-256-GCM.
func (v *Vault) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	plaintext, err := v.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

// parseKey splits "namespace/key" into its two parts.
func parseKey(fullKey string) (namespace, key string, err error) {
	parts := strings.SplitN(fullKey, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid key format %q: expected namespace/key", fullKey)
	}
	return parts[0], parts[1], nil
}

// SetSecret stores or updates a secret. Increments the version and prunes old versions.
func (v *Vault) SetSecret(namespace, key, value string) error {
	// Get current max version
	var maxVer int
	err := v.db.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM secrets WHERE namespace = ? AND key = ?",
		namespace, key,
	).Scan(&maxVer)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("querying version: %w", err)
	}

	newVer := maxVer + 1
	ciphertext, nonce, err := v.encrypt([]byte(value))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	_, err = v.db.Exec(
		`INSERT INTO secrets (namespace, key, encrypted_value, nonce, version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		namespace, key, ciphertext, nonce, newVer, time.Now(), time.Now(),
	)
	if err != nil {
		return fmt.Errorf("inserting secret: %w", err)
	}

	// Prune old versions beyond maxVersions
	_, err = v.db.Exec(
		`DELETE FROM secrets WHERE namespace = ? AND key = ? AND version NOT IN
		 (SELECT version FROM secrets WHERE namespace = ? AND key = ? ORDER BY version DESC LIMIT ?)`,
		namespace, key, namespace, key, maxVersions,
	)
	if err != nil {
		return fmt.Errorf("pruning old versions: %w", err)
	}

	v.audit(namespace, key, "set", "")
	return nil
}

// GetSecret retrieves the latest version of a secret.
func (v *Vault) GetSecret(namespace, key string) (*Secret, error) {
	var s Secret
	var ciphertext, nonce []byte

	err := v.db.QueryRow(
		`SELECT namespace, key, encrypted_value, nonce, version, created_at, updated_at
		 FROM secrets WHERE namespace = ? AND key = ?
		 ORDER BY version DESC LIMIT 1`,
		namespace, key,
	).Scan(&s.Namespace, &s.Key, &ciphertext, &nonce, &s.Version, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret %s/%s not found", namespace, key)
	}
	if err != nil {
		return nil, fmt.Errorf("querying secret: %w", err)
	}

	plaintext, err := v.decrypt(ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}
	s.Value = string(plaintext)

	v.audit(namespace, key, "get", "")
	return &s, nil
}

// DeleteSecret removes all versions of a secret.
func (v *Vault) DeleteSecret(namespace, key string) (int64, error) {
	result, err := v.db.Exec(
		"DELETE FROM secrets WHERE namespace = ? AND key = ?",
		namespace, key,
	)
	if err != nil {
		return 0, fmt.Errorf("deleting secret: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return 0, fmt.Errorf("secret %s/%s not found", namespace, key)
	}

	v.audit(namespace, key, "delete", "")
	return rows, nil
}

// ListNamespaces returns all distinct namespaces.
func (v *Vault) ListNamespaces() ([]string, error) {
	rows, err := v.db.Query("SELECT DISTINCT namespace FROM secrets ORDER BY namespace")
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	defer rows.Close()

	var namespaces []string
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}
	return namespaces, rows.Err()
}

// ListKeys returns all keys in a namespace (latest version only).
func (v *Vault) ListKeys(namespace string) ([]Secret, error) {
	rows, err := v.db.Query(
		`SELECT namespace, key, version, created_at, updated_at
		 FROM secrets WHERE (namespace, key, version) IN
		 (SELECT namespace, key, MAX(version) FROM secrets WHERE namespace = ? GROUP BY namespace, key)
		 ORDER BY key`,
		namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var s Secret
		if err := rows.Scan(&s.Namespace, &s.Key, &s.Version, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

// ListAll returns all secrets (latest version of each, without values).
func (v *Vault) ListAll() ([]Secret, error) {
	rows, err := v.db.Query(
		`SELECT namespace, key, version, created_at, updated_at
		 FROM secrets WHERE (namespace, key, version) IN
		 (SELECT namespace, key, MAX(version) FROM secrets GROUP BY namespace, key)
		 ORDER BY namespace, key`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing all secrets: %w", err)
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var s Secret
		if err := rows.Scan(&s.Namespace, &s.Key, &s.Version, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

// GetSecretVersions returns all versions of a secret (newest first).
func (v *Vault) GetSecretVersions(namespace, key string) ([]SecretVersion, error) {
	rows, err := v.db.Query(
		`SELECT version, encrypted_value, nonce, created_at
		 FROM secrets WHERE namespace = ? AND key = ?
		 ORDER BY version DESC`,
		namespace, key,
	)
	if err != nil {
		return nil, fmt.Errorf("querying versions: %w", err)
	}
	defer rows.Close()

	var versions []SecretVersion
	for rows.Next() {
		var sv SecretVersion
		var ciphertext, nonce []byte
		if err := rows.Scan(&sv.Version, &ciphertext, &nonce, &sv.CreatedAt); err != nil {
			return nil, err
		}
		plaintext, err := v.decrypt(ciphertext, nonce)
		if err != nil {
			return nil, fmt.Errorf("decrypting version %d: %w", sv.Version, err)
		}
		sv.Value = string(plaintext)
		versions = append(versions, sv)
	}
	return versions, rows.Err()
}

// RotateSecret is an alias for SetSecret — rotation creates a new version.
func (v *Vault) RotateSecret(namespace, key, newValue string) error {
	v.audit(namespace, key, "rotate", "")
	return v.SetSecret(namespace, key, newValue)
}

// ExportAll returns all secrets as a map of "namespace/key" -> value for export.
func (v *Vault) ExportAll() (map[string]string, error) {
	secrets, err := v.ListAll()
	if err != nil {
		return nil, err
	}

	export := make(map[string]string, len(secrets))
	for _, s := range secrets {
		full, err := v.GetSecret(s.Namespace, s.Key)
		if err != nil {
			return nil, err
		}
		export[s.Namespace+"/"+s.Key] = full.Value
	}
	return export, nil
}

// audit logs an action to the audit_log table.
func (v *Vault) audit(namespace, key, action, apiKeyID string) {
	v.db.Exec(
		"INSERT INTO audit_log (namespace, key, action, api_key_id, created_at) VALUES (?, ?, ?, ?, ?)",
		namespace, key, action, apiKeyID, time.Now(),
	)
}
