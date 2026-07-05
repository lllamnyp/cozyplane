/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// PluginKubeconfig is where the agent publishes a kubeconfig for the CNI plugin.
// The plugin runs in the host mount namespace and can't read the agent's
// in-pod service-account files, so the agent materializes a self-contained one.
const PluginKubeconfig = "/run/cozyplane/kubeconfig"

// PluginToken is the host-visible copy of the agent's projected SA token,
// referenced by the plugin kubeconfig (tokenFile) and refreshed by the agent
// as kubelet rotates the source.
const PluginToken = "/run/cozyplane/token"

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// WritePluginKubeconfig writes a kubeconfig (embedding the agent's SA token and
// CA) that the plugin uses to reach the API for VPC lookup and Port claims.
//
// NOTE: the projected SA token rotates; for the prototype this is written once
// at startup. Periodic refresh is a follow-up.
// SyncPluginToken copies the agent's (kubelet-refreshed) projected SA token to
// the host-visible path the plugin kubeconfig references. Returns true when
// the token changed. The kubeconfig embeds a tokenFile, not the token itself:
// bound tokens expire (~1h) and kubelet refreshes the projected file, so a
// once-embedded copy goes stale — it only kept working via the API server's
// grace for expired bound tokens. The plugin is short-lived and reads the
// file fresh on every invocation.
func SyncPluginToken() (bool, error) {
	token, err := os.ReadFile(filepath.Join(saDir, "token"))
	if err != nil {
		return false, fmt.Errorf("read SA token: %w", err)
	}
	if old, err := os.ReadFile(PluginToken); err == nil && string(old) == string(token) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(PluginToken), 0o755); err != nil {
		return false, err
	}
	tmp := PluginToken + ".tmp"
	if err := os.WriteFile(tmp, token, 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, PluginToken)
}

func WritePluginKubeconfig() error {
	if _, err := SyncPluginToken(); err != nil {
		return err
	}
	ca, err := os.ReadFile(filepath.Join(saDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read SA CA: %w", err)
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT not set")
	}

	kc := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cozyplane
  cluster:
    server: https://%s
    certificate-authority-data: %s
contexts:
- name: cozyplane
  context:
    cluster: cozyplane
    user: cozyplane
current-context: cozyplane
users:
- name: cozyplane
  user:
    tokenFile: %s
`, net.JoinHostPort(host, port), base64.StdEncoding.EncodeToString(ca), PluginToken)

	if err := os.MkdirAll(filepath.Dir(PluginKubeconfig), 0o755); err != nil {
		return err
	}
	tmp := PluginKubeconfig + ".tmp"
	if err := os.WriteFile(tmp, []byte(kc), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, PluginKubeconfig)
}
