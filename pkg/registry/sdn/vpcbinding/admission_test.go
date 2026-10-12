package vpcbinding

import (
	"io"
	"os"
	"strings"
	"testing"
	"text/template"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/library"
)

// Evaluate the shipped policy expressions with Kubernetes' real authorization
// CEL library. This asserts permission decisions, not manifest/source strings.
func TestBindingAdmissionRetargetAndOwnerChanges(t *testing.T) {
	for _, path := range []string{"../../../../deploy/authz.yaml", "../../../../chart/cozyplane/templates/authz.yaml"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(path, "/templates/") {
				tmpl, err := template.New("authz").Funcs(template.FuncMap{
					"include": func(string, any) string { return "app: cozyplane" },
					"nindent": func(n int, s string) string {
						return "\n" + strings.Repeat(" ", n) + strings.ReplaceAll(s, "\n", "\n"+strings.Repeat(" ", n))
					},
				}).Parse(string(data))
				if err != nil {
					t.Fatal(err)
				}
				var rendered strings.Builder
				if err := tmpl.Execute(&rendered, map[string]any{"Values": map[string]any{"exportPolicy": map[string]any{"enabled": true}}}); err != nil {
					t.Fatal(err)
				}
				data = []byte(rendered.String())
			}
			decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(string(data)), 4096)
			var policy admissionv1.ValidatingAdmissionPolicy
			for {
				if err := decoder.Decode(&policy); err != nil {
					if err == io.EOF {
						t.Fatal("binding admission policy missing")
					}
					t.Fatal(err)
				}
				if policy.Kind == "ValidatingAdmissionPolicy" && policy.Name == "cozyplane-vpcbinding-export" {
					break
				}
				policy = admissionv1.ValidatingAdmissionPolicy{}
			}
			env, err := cel.NewEnv(library.Authz(), cel.Variable("authorizer", library.AuthorizerType),
				cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType), cel.Variable("variables", cel.DynType))
			if err != nil {
				t.Fatal(err)
			}
			eval := func(expression string, activation map[string]any) ref.Val {
				t.Helper()
				ast, issues := env.Compile(expression)
				if issues.Err() != nil {
					t.Fatal(issues.Err())
				}
				program, err := env.Program(ast)
				if err != nil {
					t.Fatal(err)
				}
				value, _, err := program.Eval(activation)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			object := func(namespace, name string, forwarding, finalizer bool) map[string]any {
				metadata := map[string]any{"namespace": "consumer", "name": "grant"}
				if finalizer {
					metadata["finalizers"] = []string{"sdn.cozystack.io/reap-ports"}
				}
				return map[string]any{"metadata": metadata, "spec": map[string]any{
					"vpcRef": map[string]any{"namespace": namespace, "name": name}, "allowForwarding": forwarding}}
			}
			old := object("owner", "shared", false, true)
			for _, test := range []struct {
				name      string
				old, next any
				auth      authorizer.Authorizer
				want      bool
			}{
				{"consumer retarget", old, object("consumer", "owned", false, true), consumerVPCOnlyAuthorizer{}, false},
				{"retarget and remove barrier", old, object("consumer", "owned", false, false), consumerVPCOnlyAuthorizer{}, false},
				{"authorized retarget still loses reaping target", old, object("consumer", "owned", false, true), &recordingAuthorizer{allow: true}, false},
				{"unchanged grant metadata", old, object("owner", "shared", false, true), &recordingAuthorizer{}, true},
				{"owner forwarding update", old, object("owner", "shared", true, true), &recordingAuthorizer{allow: true}, true},
				{"consumer forwarding update", old, object("owner", "shared", true, true), consumerVPCOnlyAuthorizer{}, false},
				{"owner releases barrier", old, object("owner", "shared", false, false), &recordingAuthorizer{allow: true}, true},
				{"consumer releases barrier", old, object("owner", "shared", false, false), consumerVPCOnlyAuthorizer{}, false},
				{"create own grant", nil, object("consumer", "owned", false, true), consumerVPCOnlyAuthorizer{}, true},
			} {
				t.Run(test.name, func(t *testing.T) {
					variables := map[string]any{}
					activation := map[string]any{"object": test.next, "oldObject": test.old, "variables": variables,
						"authorizer": library.NewAuthorizerVal(&user.DefaultInfo{Name: "actor"}, test.auth)}
					for _, variable := range policy.Spec.Variables {
						variables[variable.Name] = eval(variable.Expression, activation)
					}
					allowed := true
					for _, validation := range policy.Spec.Validations {
						allowed = eval(validation.Expression, activation).Value() == true && allowed
					}
					if allowed != test.want {
						t.Fatalf("admitted=%v want=%v", allowed, test.want)
					}
				})
			}
		})
	}
}
