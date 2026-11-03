package sdn

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apimachinery/pkg/util/yaml"
	admissioncel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/cel/environment"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func vpnHelm(t *testing.T, values ...string) ([]map[string]any, error) {
	t.Helper()
	helm := os.Getenv("HELM_BIN")
	if helm == "" {
		var err error
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("Helm is required for chart behavior tests; CI's helm job installs it")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append([]string{"template", "vpn-test", filepath.Join("..", "..", "..", "chart", "cozyplane"), "--namespace", "platform-test", "--kube-version", "1.30.0"}, values...)
	out, err := exec.CommandContext(ctx, helm, args...).CombinedOutput()
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	var objects []map[string]any
	for {
		var obj map[string]any
		if err := decoder.Decode(&obj); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode Helm manifests: %v", err)
		}
		if len(obj) != 0 {
			objects = append(objects, obj)
		}
	}
	return objects, nil
}

type vpnChartObjects struct {
	class      *nodev1.RuntimeClass
	policy     *admissionv1.ValidatingAdmissionPolicy
	binding    *admissionv1.ValidatingAdmissionPolicyBinding
	controller *appsv1.Deployment
}

func parseVPNChart(t *testing.T, objects []map[string]any) vpnChartObjects {
	t.Helper()
	var result vpnChartObjects
	for _, obj := range objects {
		convert := func(dst any) {
			t.Helper()
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj, dst); err != nil {
				t.Fatal(err)
			}
		}
		switch obj["kind"] {
		case "RuntimeClass":
			if result.class != nil {
				t.Fatal("multiple RuntimeClasses")
			}
			result.class = &nodev1.RuntimeClass{}
			convert(result.class)
		case "ValidatingAdmissionPolicy":
			policy := &admissionv1.ValidatingAdmissionPolicy{}
			convert(policy)
			for _, condition := range policy.Spec.MatchConditions {
				if condition.Name == "vpn-runtime-class" {
					if result.policy != nil {
						t.Fatal("multiple VPN admission policies")
					}
					result.policy = policy
				}
			}
		case "Deployment":
			deployment := &appsv1.Deployment{}
			convert(deployment)
			if deployment.Name == "cozyplane-controller" {
				result.controller = deployment
			}
		}
	}
	if result.policy != nil {
		for _, obj := range objects {
			if obj["kind"] != "ValidatingAdmissionPolicyBinding" {
				continue
			}
			binding := &admissionv1.ValidatingAdmissionPolicyBinding{}
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj, binding); err != nil {
				t.Fatal(err)
			}
			if binding.Spec.PolicyName == result.policy.Name {
				result.binding = binding
			}
		}
	}
	return result
}

func TestVPNRuntimeClassChartConditions(t *testing.T) {
	const class = "cozyplane-vpn"
	for _, tc := range []struct {
		name   string
		values []string
		class  string
		create bool
	}{
		{name: "defaults"},
		{name: "external class", values: []string{"--set", "vpn.runtimeClassName=" + class}, class: class},
		{name: "class flag with egress disabled", values: []string{"--set", "vpn.runtimeClassName=" + class, "--set", "egress.clusterCIDR="}, class: class},
		{name: "managed class", values: []string{"--set", "vpn.runtimeClassName=" + class, "--set", "vpn.runtimeClass.create=true", "--set", "vpn.hardenedAppliance=true"}, class: class, create: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects, err := vpnHelm(t, tc.values...)
			if err != nil {
				t.Fatal(err)
			}
			got := parseVPNChart(t, objects)
			if got.controller == nil {
				t.Fatal("controller deployment missing")
			}
			found := false
			for _, arg := range got.controller.Spec.Template.Spec.Containers[0].Args {
				if arg == "--vpn-runtime-class="+tc.class {
					found = true
				}
			}
			if found != (tc.class != "") {
				t.Fatal("runtime class flag was not conditional on the configured name")
			}
			if (got.class != nil) != tc.create || (got.policy != nil) != tc.create || (got.binding != nil) != tc.create {
				t.Fatalf("class/policy/binding conditional rendering is wrong: %+v", got)
			}
			if tc.create {
				if got.class.Name != class || got.class.Handler != "runc" || got.class.APIVersion != "node.k8s.io/v1" || got.class.Namespace != "" {
					t.Fatalf("unexpected RuntimeClass: %+v", got.class)
				}
				if got.policy.Spec.FailurePolicy == nil || *got.policy.Spec.FailurePolicy != admissionv1.Fail || !reflect.DeepEqual(got.binding.Spec.ValidationActions, []admissionv1.ValidationAction{admissionv1.Deny}) {
					t.Fatal("guard is not fail-closed/enforcing")
				}
				if got.policy.Annotations["helm.sh/resource-policy"] != "keep" || got.binding.Annotations["helm.sh/resource-policy"] != "keep" {
					t.Fatal("Helm teardown would remove the guard of existing exempt pods")
				}
				rules := got.policy.Spec.MatchConstraints.ResourceRules
				if len(rules) != 1 || !reflect.DeepEqual(rules[0].Resources, []string{"pods", "pods/ephemeralcontainers"}) || !reflect.DeepEqual(rules[0].Operations, []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}) {
					t.Fatal("guard must cover Pod creation, updates and ephemeral container insertion")
				}
			}
		})
	}
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"missing class", []string{"--set", "vpn.runtimeClass.create=true", "--set", "vpn.hardenedAppliance=true"}},
		{"compatibility mode", []string{"--set", "vpn.runtimeClass.create=true", "--set", "vpn.runtimeClassName=" + class}},
		{"old Kubernetes", []string{"--set", "vpn.runtimeClass.create=true", "--set", "vpn.runtimeClassName=" + class, "--set", "vpn.hardenedAppliance=true", "--kube-version", "1.29.0"}},
		{"invalid class", []string{"--set-string", "vpn.runtimeClassName=Bad/Name"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := vpnHelm(t, tc.values...); err == nil {
				t.Fatal("invalid RuntimeClass configuration rendered successfully")
			}
		})
	}
}

type vpnCELExpression string

func (e vpnCELExpression) GetExpression() string    { return string(e) }
func (e vpnCELExpression) ReturnTypes() []*cel.Type { return []*cel.Type{cel.BoolType} }

func TestVPNRuntimeClassChartAdmissionBehavior(t *testing.T) {
	const image = "example.invalid/cozyplane@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const class = "cozyplane-vpn-test"
	objects, err := vpnHelm(t, "--set-string", "image="+image, "--set", "vpn.hardenedAppliance=true", "--set", "vpn.runtimeClassName="+class, "--set", "vpn.runtimeClass.create=true")
	if err != nil {
		t.Fatal(err)
	}
	policy := parseVPNChart(t, objects).policy
	if policy == nil {
		t.Fatal("VPN policy missing")
	}
	// Use the Kubernetes admission compiler and the minimum supported CEL
	// compatibility environment, evaluating the expressions rendered by Helm.
	compiler := admissioncel.NewCompiler(environment.MustBaseEnvSet(version.MajorMinor(1, 30)))
	compile := func(expression string) cel.Program {
		t.Helper()
		result := compiler.CompileCELExpression(vpnCELExpression(expression), admissioncel.OptionalVariableDeclarations{}, environment.NewExpressions)
		if result.Error != nil {
			t.Fatalf("CEL compilation: %v", result.Error)
		}
		return result.Program
	}
	var conditions, validations []cel.Program
	for _, c := range policy.Spec.MatchConditions {
		conditions = append(conditions, compile(c.Expression))
	}
	for _, v := range policy.Spec.Validations {
		validations = append(validations, compile(v.Expression))
	}
	allowed := func(pod *corev1.Pod) bool {
		t.Helper()
		data, err := json.Marshal(pod)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		evaluate := func(program cel.Program) bool {
			t.Helper()
			value, _, err := program.Eval(map[string]any{"object": obj})
			if err != nil {
				t.Fatalf("CEL evaluation error (rather than an explicit verdict): %v", err)
			}
			return value == types.True
		}
		for _, p := range conditions {
			if !evaluate(p) {
				return true // This policy leaves other RuntimeClasses to their own admission.
			}
		}
		for _, p := range validations {
			if !evaluate(p) {
				return false
			}
		}
		return true
	}
	r := &VPNGatewayReconciler{Config: VPNGatewayConfig{Image: image, HardenedAppliance: true, RuntimeClassName: class}}
	for _, backend := range []string{backendWireGuard, backendIPsec} {
		for _, mode := range []sdnv1alpha1.VPNGatewayHAMode{"", sdnv1alpha1.VPNGatewayHAModeWarmStandby} {
			gw := runtimeClassGateway()
			gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: mode}
			tpl := r.deployment(gw, backend, "test").Spec.Template
			pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: tpl.ObjectMeta, Spec: tpl.Spec}
			if !allowed(pod) {
				t.Fatalf("actual %s/%s hardened appliance is refused", backend, mode)
			}
		}
	}
	// A workstation gateway (WireGuard with an address pool) loads its source
	// filter: it adds BPF and carries the config checksum, like IPsec.
	workstation := runtimeClassGateway()
	workstation.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{
		AddressPools: []sdnv1alpha1.VPNWireGuardAddressPool{{Name: "clients", CIDR: "100.64.0.0/24"}},
	}
	wtpl := r.deployment(workstation, backendWireGuard, "test").Spec.Template
	if !allowed(&corev1.Pod{ObjectMeta: wtpl.ObjectMeta, Spec: wtpl.Spec}) {
		t.Fatal("actual hardened workstation appliance is refused")
	}
	tpl := r.deployment(runtimeClassGateway(), backendIPsec, "test").Spec.Template
	base := &corev1.Pod{ObjectMeta: tpl.ObjectMeta, Spec: tpl.Spec}
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{"privileged", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = new(true) }},
		{"unconfined container seccomp", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}},
		{"unconfined pod seccomp", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}},
		{"unmasked proc", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.ProcMount = new(corev1.UnmaskedProcMount) }},
		{"unconfined container AppArmor", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		}},
		{"unconfined pod AppArmor", func(p *corev1.Pod) {
			p.Spec.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		}},
		{"unconfined legacy AppArmor", func(p *corev1.Pod) {
			p.Annotations["container.apparmor.security.beta.kubernetes.io/vpn-gateway"] = "unconfined"
		}},
		{"unconfined SELinux", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "unconfined_t"}
		}},
		{"SELinux role override", func(p *corev1.Pod) { p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Role: "sysadm_r"} }},
		{"Windows host process", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: new(true)}
		}},
		{"extra capability", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = append(p.Spec.Containers[0].SecurityContext.Capabilities.Add, "SYS_ADMIN")
		}},
		{"no drop ALL", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Capabilities.Drop = nil }},
		{"privilege escalation", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = new(true) }},
		{"missing security context", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext = nil }},
		{"extra container", func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, p.Spec.Containers[0]) }},
		{"wrong name", func(p *corev1.Pod) { p.Spec.Containers[0].Name = "other" }},
		{"wrong image", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "example.invalid/other:test" }},
		{"alternate entrypoint", func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"/bin/sh"} }},
		{"extra args", func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"extra"} }},
		{"host network", func(p *corev1.Pod) { p.Spec.HostNetwork = true }},
		{"host PID", func(p *corev1.Pod) { p.Spec.HostPID = true }},
		{"host IPC", func(p *corev1.Pod) { p.Spec.HostIPC = true }},
		{"host port", func(p *corev1.Pod) { p.Spec.Containers[0].Ports[0].HostPort = 9410 }},
		{"host path", func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}})
		}},
		{"init container", func(p *corev1.Pod) { p.Spec.InitContainers = []corev1.Container{{Name: "init", Image: image}} }},
		{"ephemeral container", func(p *corev1.Pod) {
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: image}}}
		}},
		{"API token", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = new(true) }},
		{"token default", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = nil }},
		{"sysctl override", func(p *corev1.Pod) {
			p.Spec.SecurityContext.Sysctls = append(p.Spec.SecurityContext.Sysctls, corev1.Sysctl{Name: "kernel.core_pattern", Value: "unsafe"})
		}},
		{"executable replacement", func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].MountPath = "/usr/local/bin" }},
		{"loader override", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, corev1.EnvVar{Name: "LD_PRELOAD", Value: "/etc/cozyplane-vpn/override.so"})
		}},
		{"checksum from a reference", func(p *corev1.Pod) {
			for i, e := range p.Spec.Containers[0].Env {
				if e.Name == "VPN_CONFIG_CHECKSUM" {
					p.Spec.Containers[0].Env[i] = corev1.EnvVar{Name: e.Name, ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "other"}, Key: "k"},
					}}
				}
			}
		}},
		{"envFrom override", func(p *corev1.Pod) {
			p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "override"}}}}
		}},
		{"lifecycle exec", func(p *corev1.Pod) {
			p.Spec.Containers[0].Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh"}}}}
		}},
		{"probe exec", func(p *corev1.Pod) {
			p.Spec.Containers[0].LivenessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh"}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := base.DeepCopy()
			tc.mutate(pod)
			if allowed(pod) {
				t.Fatal("unsafe appliance shape admitted")
			}
		})
	}
	// PSA baseline blocks probe host overrides since Kubernetes 1.34. A
	// RuntimeClass exemption must not let the kubelet probe an arbitrary host.
	for _, kind := range []string{"readiness", "liveness", "startup"} {
		for _, protocol := range []string{"http", "tcp"} {
			t.Run(kind+" "+protocol+" host override", func(t *testing.T) {
				pod := base.DeepCopy()
				probe := &corev1.Probe{}
				if protocol == "http" {
					probe.HTTPGet = &corev1.HTTPGetAction{Host: "127.0.0.1", Path: "/", Port: base.Spec.Containers[0].ReadinessProbe.HTTPGet.Port}
				} else {
					probe.TCPSocket = &corev1.TCPSocketAction{Host: "127.0.0.1", Port: base.Spec.Containers[0].ReadinessProbe.HTTPGet.Port}
				}
				switch kind {
				case "readiness":
					pod.Spec.Containers[0].ReadinessProbe = probe
				case "liveness":
					pod.Spec.Containers[0].LivenessProbe = probe
				case "startup":
					pod.Spec.Containers[0].StartupProbe = probe
				}
				if allowed(pod) {
					t.Fatal("kubelet probe host override admitted through PSA exemption")
				}
			})
		}
	}
	gw := runtimeClassGateway()
	gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeActiveActive}
	aa := r.statefulSet(gw, backendIPsec, "test").Spec.Template
	if allowed(&corev1.Pod{Spec: aa.Spec}) {
		t.Fatal("single-container guard silently allows active-active sidecar")
	}
	unrelated := base.DeepCopy()
	unrelated.Spec.RuntimeClassName = new("another-runtime")
	unrelated.Spec.HostNetwork = true
	if !allowed(unrelated) {
		t.Fatal("VPN guard applies to a different RuntimeClass")
	}
	unrelated.Spec.RuntimeClassName = nil
	if !allowed(unrelated) {
		t.Fatal("VPN guard applies to pods without RuntimeClass")
	}
}
