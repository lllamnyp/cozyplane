package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	rbacvalidation "k8s.io/component-helpers/auth/rbac/validation"
)

// Check the shipped manifest with Kubernetes' own rule coverage evaluator.
// This protects both the proxy's reads and the permissions removed from its token.
func TestKPRManifestPermissions(t *testing.T) {
	data, err := os.ReadFile("../deploy/kpr-daemonset.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var role rbacv1.ClusterRole
	var binding rbacv1.ClusterRoleBinding
	for {
		var doc struct {
			Kind string `json:"kind"`
			rbacv1.ClusterRole
			RoleRef  rbacv1.RoleRef   `json:"roleRef"`
			Subjects []rbacv1.Subject `json:"subjects"`
		}
		if err := decoder.Decode(&doc); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		switch doc.Kind {
		case "ClusterRole":
			role = doc.ClusterRole
		case "ClusterRoleBinding":
			binding.RoleRef = doc.RoleRef
			binding.Subjects = doc.Subjects
		}
	}
	if role.Name != "cozyplane-kpr" || binding.RoleRef != (rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name,
	}) {
		t.Fatalf("proxy must bind its own scoped role: %q, %+v", role.Name, binding.RoleRef)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0] != (rbacv1.Subject{
		Kind: "ServiceAccount", Namespace: "kube-system", Name: "cozyplane-kpr",
	}) {
		t.Fatalf("unexpected proxy subjects: %+v", binding.Subjects)
	}
	check := func(rule rbacv1.PolicyRule, want bool) {
		t.Helper()
		got, _ := rbacvalidation.Covers(role.Rules, []rbacv1.PolicyRule{rule})
		if got != want {
			t.Errorf("coverage=%v, want %v for %+v", got, want, rule)
		}
	}
	for _, resource := range []string{"services", "nodes", "pods", "namespaces"} {
		check(rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{"get", "list", "watch"}}, true)
	}
	check(rbacv1.PolicyRule{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"get", "list", "watch"}}, true)
	check(rbacv1.PolicyRule{NonResourceURLs: []string{"/readyz"}, Verbs: []string{"get"}}, true)
	for _, group := range []string{"", "discovery.k8s.io", "rbac.authorization.k8s.io", "cilium.io"} {
		for _, resource := range []string{"services", "nodes", "nodes/proxy", "pods", "pods/exec", "pods/attach", "pods/portforward", "namespaces", "endpointslices", "secrets", "serviceaccounts", "serviceaccounts/token", "clusterroles", "clusterrolebindings", "roles", "rolebindings", "ciliumlocalredirectpolicies"} {
			for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection", "bind", "escalate", "impersonate"} {
				check(rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: []string{verb}}, false)
			}
		}
	}
	for _, resource := range []string{"secrets", "nodes/proxy", "pods/exec", "pods/attach", "pods/portforward", "serviceaccounts/token"} {
		check(rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{"get"}}, false)
	}
	check(rbacv1.PolicyRule{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}, false)
	check(rbacv1.PolicyRule{NonResourceURLs: []string{"/readyz"}, Verbs: []string{"post"}}, false)
}
