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

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// WritePluginKubeconfig writes a kubeconfig (embedding the agent's SA token and
// CA) that the plugin uses to reach the API for VPC lookup and Port claims.
//
// NOTE: the projected SA token rotates; for the prototype this is written once
// at startup. Periodic refresh is a follow-up.
func WritePluginKubeconfig() error {
	token, err := os.ReadFile(filepath.Join(saDir, "token"))
	if err != nil {
		return fmt.Errorf("read SA token: %w", err)
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
    token: %s
`, net.JoinHostPort(host, port), base64.StdEncoding.EncodeToString(ca), string(token))

	if err := os.MkdirAll(filepath.Dir(PluginKubeconfig), 0o755); err != nil {
		return err
	}
	tmp := PluginKubeconfig + ".tmp"
	if err := os.WriteFile(tmp, []byte(kc), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, PluginKubeconfig)
}
