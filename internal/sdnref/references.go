package sdnref

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
