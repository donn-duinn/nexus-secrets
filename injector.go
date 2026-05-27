package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// K8sInjector syncs secrets from the vault to Kubernetes Secrets.
type K8sInjector struct {
	vault    *Vault
	defaultNS string
	nsMap    map[string]string // vault namespace -> k8s namespace
}

// K8sNamespaceMapping defines how vault namespaces map to K8s namespaces.
type K8sNamespaceMapping struct {
	Default   string            `yaml:"default"`
	Namespace map[string]string `yaml:"namespace"`
}

// NewK8sInjector creates a new K8s injector.
func NewK8sInjector(vault *Vault, defaultNS string, nsMap map[string]string) *K8sInjector {
	if nsMap == nil {
		nsMap = make(map[string]string)
	}
	return &K8sInjector{
		vault:    vault,
		defaultNS: defaultNS,
		nsMap:    nsMap,
	}
}

// SyncAll syncs all secrets from the vault to K8s.
func (j *K8sInjector) SyncAll() error {
	secrets, err := j.vault.ListAll()
	if err != nil {
		return fmt.Errorf("listing secrets: %w", err)
	}

	// Group by namespace
	grouped := make(map[string][]Secret)
	for _, s := range secrets {
		grouped[s.Namespace] = append(grouped[s.Namespace], s)
	}

	var errs []string
	for ns, group := range grouped {
		if err := j.syncNamespace(ns, group); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ns, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sync errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// SyncNamespace syncs secrets for a specific vault namespace to K8s.
func (j *K8sInjector) SyncNamespace(namespace string) error {
	keys, err := j.vault.ListKeys(namespace)
	if err != nil {
		return fmt.Errorf("listing keys for %s: %w", namespace, err)
	}

	if len(keys) == 0 {
		return fmt.Errorf("no secrets found in namespace %s", namespace)
	}

	return j.syncNamespace(namespace, keys)
}

func (j *K8sInjector) syncNamespace(vaultNS string, secrets []Secret) error {
	k8sNS := j.resolveNamespace(vaultNS)
	secretName := fmt.Sprintf("nexus-%s", vaultNS)

	// Build the K8s Secret manifest
	data := make(map[string]string)
	for _, s := range secrets {
		val, err := j.vault.GetSecret(s.Namespace, s.Key)
		if err != nil {
			return fmt.Errorf("getting %s/%s: %w", s.Namespace, s.Key, err)
		}
		// K8s secret keys must be valid DNS subdomain names
		k8sKey := strings.ReplaceAll(s.Key, ".", "_")
		k8sKey = strings.ReplaceAll(k8sKey, "-", "_")
		data[k8sKey] = val.Value
	}

	// Create or update the K8s secret using kubectl
	return j.applySecret(k8sNS, secretName, data)
}

func (j *K8sInjector) applySecret(namespace, name string, data map[string]string) error {
	// Ensure namespace exists
	if err := j.ensureNamespace(namespace); err != nil {
		log.Printf("warning: could not ensure namespace %s: %v", namespace, err)
	}

	// Build kubectl command
	args := []string{
		"create", "secret", "generic", name,
		"-n", namespace,
		"--dry-run=client",
		"-o", "json",
	}

	for k, v := range data {
		args = append(args, fmt.Sprintf("--from-literal=%s=%s", k, v))
	}

	// Generate the secret manifest
	genCmd := exec.Command("kubectl", args...)
	manifest, err := genCmd.Output()
	if err != nil {
		return fmt.Errorf("generating manifest: %w", err)
	}

	// Apply with kubectl
	applyCmd := exec.Command("kubectl", "apply", "-f", "-", "-n", namespace)
	applyCmd.Stdin = strings.NewReader(string(manifest))
	output, err := applyCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying secret: %s: %w", string(output), err)
	}

	log.Printf("synced secret %s/%s (%d keys)", namespace, name, len(data))
	return nil
}

func (j *K8sInjector) ensureNamespace(namespace string) error {
	cmd := exec.Command("kubectl", "create", "namespace", namespace, "--dry-run=client", "-o", "json")
	manifest, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("generating namespace manifest: %w", err)
	}

	applyCmd := exec.Command("kubectl", "apply", "-f", "-")
	applyCmd.Stdin = strings.NewReader(string(manifest))
	output, err := applyCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating namespace: %s: %w", string(output), err)
	}
	return nil
}

func (j *K8sInjector) resolveNamespace(vaultNS string) string {
	if ns, ok := j.nsMap[vaultNS]; ok {
		return ns
	}
	return j.defaultNS
}

// Diff shows what would change without applying.
func (j *K8sInjector) Diff() (map[string]interface{}, error) {
	secrets, err := j.vault.ListAll()
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"total_secrets":  len(secrets),
		"namespaces":     make(map[string]int),
	}

	nsCount := result["namespaces"].(map[string]int)
	for _, s := range secrets {
		nsCount[s.Namespace]++
	}

	return result, nil
}

// ExportK8sManifest generates a K8s Secret manifest without applying.
func (j *K8sInjector) ExportK8sManifest(vaultNS string) (string, error) {
	keys, err := j.vault.ListKeys(vaultNS)
	if err != nil {
		return "", err
	}

	k8sNS := j.resolveNamespace(vaultNS)
	secretName := fmt.Sprintf("nexus-%s", vaultNS)

	data := make(map[string]string)
	for _, s := range keys {
		val, err := j.vault.GetSecret(s.Namespace, s.Key)
		if err != nil {
			return "", err
		}
		k8sKey := strings.ReplaceAll(s.Key, ".", "_")
		k8sKey = strings.ReplaceAll(k8sKey, "-", "_")
		data[k8sKey] = val.Value
	}

	manifest := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      secretName,
			"namespace": k8sNS,
			"labels": map[string]interface{}{
				"app.kubernetes.io/managed-by": "nexus-secrets",
				"nexus.io/vault-namespace":     vaultNS,
			},
		},
		"type":       "Opaque",
		"stringData": data,
	}

	jsonBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
