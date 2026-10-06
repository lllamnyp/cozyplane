package vpc

import (
	"context"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	admission "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/library"
)

type boundaryAdmissionAuthorizer struct {
	allow    bool
	resource string
}

func (a boundaryAdmissionAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	if a.allow && attrs.GetAPIGroup() == "sdn.cozystack.io" && attrs.GetResource() == a.resource && attrs.GetVerb() == "manage-boundary" && attrs.GetNamespace() == "tenant-test" && attrs.GetName() == "network-test" {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "", nil
}

func TestBoundaryAdmissionPoliciesMatchChartAndEnforceAuthorization(t *testing.T) {
	manifest, err := os.ReadFile("../../../../deploy/boundary-authz.yaml")
	if err != nil {
		t.Fatal(err)
	}
	chart, err := os.ReadFile("../../../../chart/cozyplane/templates/boundary-authz.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest, chart) {
		t.Fatal("CRD and chart policies diverged")
	}
	file, err := os.Open("../../../../deploy/boundary-authz.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
	for {
		var policy admission.ValidatingAdmissionPolicy
		if err := decoder.Decode(&policy); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if policy.Kind != "ValidatingAdmissionPolicy" {
			continue
		}
		for _, resource := range policy.Spec.MatchConstraints.ResourceRules[0].Resources {
			if resource == "vpcs/status" || resource == "vpcpeerings/status" || resource == "securitygroups/status" || resource == "vpcgateways/status" {
				continue
			}
			immutable := resource == "vpcpeerings"
			for _, allow := range []bool{false, true} {
				t.Run(policy.Name+"/"+resource, func(t *testing.T) {
					env, err := cel.NewEnv(library.Authz(), cel.Variable("authorizer", library.AuthorizerType), cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType), cel.Variable("request", cel.DynType), cel.Variable("variables", cel.DynType))
					if err != nil {
						t.Fatal(err)
					}
					managed := map[string]any{"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "neosequentia-portal"}}, "spec": map[string]any{"boundary": map[string]any{"revision": int64(1), "internet": false}, "cidrs": []any{"10.1.0.0/24"}}}
					unmanaged := map[string]any{"metadata": map[string]any{"labels": map[string]any{}}, "spec": map[string]any{"cidrs": []any{"10.1.0.0/24"}}}
					for _, tc := range []struct {
						name, operation, sub string
						old, new             any
						want                 bool
					}{
						{"managed create", "CREATE", "", nil, managed, allow},
						{"managed delete", "DELETE", "", managed, nil, allow},
						{"strip protection", "UPDATE", "", managed, unmanaged, !immutable && allow},
						{"ordinary create", "CREATE", "", nil, unmanaged, true},
						{"ordinary delete", "DELETE", "", unmanaged, nil, true},
						{"status observation", "UPDATE", "status", managed, managed, true},
						{"status strip protection", "UPDATE", "status", managed, unmanaged, !immutable && allow},
					} {
						t.Run(tc.name, func(t *testing.T) {
							vars := map[string]any{}
							activation := map[string]any{"object": tc.new, "oldObject": tc.old, "request": map[string]any{"operation": tc.operation, "subResource": tc.sub, "resource": map[string]any{"resource": resource}, "namespace": "tenant-test", "name": "network-test"}, "variables": vars, "authorizer": library.NewAuthorizerVal(&user.DefaultInfo{Name: "operator-test"}, boundaryAdmissionAuthorizer{allow, resource})}
							evaluate := func(expression string) any {
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
							for _, variable := range policy.Spec.Variables {
								vars[variable.Name] = evaluate(variable.Expression)
							}
							accepted := true
							for _, validation := range policy.Spec.Validations {
								if evaluate(validation.Expression) != types.True {
									accepted = false
								}
							}
							if accepted != tc.want {
								t.Fatalf("accepted=%v want=%v allow=%v", accepted, tc.want, allow)
							}
						})
					}
				})
			}
		}
	}
}
