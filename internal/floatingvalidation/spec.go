// Package floatingvalidation checks inputs shared by FloatingIP admission and replay.
package floatingvalidation

import (
	"net"

	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Target returns the canonical address only when both target references are usable.
func Target(vpc, target string) string {
	if !vpnlimits.ObjectName(vpc) || len(target) > 64 {
		return ""
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.String()
	}
	return ""
}

// Validate rejects the first unusable field without including input in diagnostics.
func Validate(vpc, target, class, claim string) field.ErrorList {
	p := field.NewPath("spec")
	if errs := vpnlimits.ReferenceErrors(vpc, p.Child("vpcRef", "name"), true); len(errs) != 0 {
		return errs
	}
	if Target(vpc, target) == "" {
		return field.ErrorList{field.Invalid(p.Child("target"), nil, "must be an unzoned IP address of at most 64 bytes")}
	}
	if class != "" && (len(class) > 317 || len(validation.IsQualifiedName(class)) != 0) {
		return field.ErrorList{field.Invalid(p.Child("loadBalancerClass"), nil, "must be a qualified name of at most 317 bytes")}
	}
	return vpnlimits.ReferenceErrors(claim, p.Child("addressClaimName"), false)
}
