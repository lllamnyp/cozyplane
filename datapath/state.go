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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AgentState is the per-node datapath configuration the agent publishes to
// AgentStateFile for the CNI plugin to consume. It is intentionally small: the
// plugin needs only what it can't derive itself.
type AgentState struct {
	NodeName string `json:"nodeName"`
	// NodeIP is this node's host IP (the Geneve tunnel endpoint).
	NodeIP string `json:"nodeIP"`
	// PodCIDR is this node's slice of the cluster pod CIDR (default network).
	PodCIDR string `json:"podCIDR"`
	// MTU is the pod MTU (underlay MTU minus Geneve overhead).
	MTU int `json:"mtu"`
}

// Save atomically writes the agent state to AgentStateFile.
func (s *AgentState) Save() error {
	if err := os.MkdirAll(filepath.Dir(AgentStateFile), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := AgentStateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, AgentStateFile)
}

// LoadAgentState reads the agent state published for the CNI plugin.
func LoadAgentState() (*AgentState, error) {
	b, err := os.ReadFile(AgentStateFile)
	if err != nil {
		return nil, fmt.Errorf("read agent state (is the cozyplane agent running?): %w", err)
	}
	var s AgentState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse agent state: %w", err)
	}
	return &s, nil
}
