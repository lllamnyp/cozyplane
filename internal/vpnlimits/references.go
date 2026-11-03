package vpnlimits

import (
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ObjectName rejects unusable references before hashing, joining or retaining
// their contents. Check length first so even legacy large inputs cost O(1).
func ObjectName(name string) bool {
	return name != "" && len(name) <= validation.DNS1123SubdomainMaxLength && len(validation.IsDNS1123Subdomain(name)) == 0
}

// NamespaceName checks an actual namespace; optional reference defaults must
// be applied before calling this helper.
func NamespaceName(name string) bool {
	return name != "" && len(name) <= validation.DNS1123LabelMaxLength && len(validation.IsDNS1123Label(name)) == 0
}

// PeeringReferences checks both complete VPC identities before key construction.
func PeeringReferences(namespace, localName, peerNamespace, peerName string) bool {
	return NamespaceName(namespace) && ObjectName(localName) && NamespaceName(peerNamespace) && ObjectName(peerName)
}

// GroupReference allows either a local group or a complete explicit peer VPC.
func GroupReference(group, namespace, name string) bool {
	return ObjectName(group) && ((namespace == "" && name == "") || (NamespaceName(namespace) && ObjectName(name)))
}

// NamespaceReferenceErrors permits the empty, same-namespace reference default.
func NamespaceReferenceErrors(name string, path *field.Path) field.ErrorList {
	if name != "" && !NamespaceName(name) {
		return field.ErrorList{field.Invalid(path, nil, "must be a DNS label namespace of at most 63 bytes")}
	}
	return nil
}

// ReferenceErrors never retains or renders an unbounded invalid reference.
func ReferenceErrors(name string, path *field.Path, required bool) field.ErrorList {
	if name == "" {
		if required {
			return field.ErrorList{field.Required(path, "object name is required")}
		}
		return nil
	}
	if !ObjectName(name) {
		return field.ErrorList{field.Invalid(path, nil, "must be a DNS subdomain object name of at most 253 bytes")}
	}
	return nil
}
