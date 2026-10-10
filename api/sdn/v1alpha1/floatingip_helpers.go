package v1alpha1

import "net"

// EffectiveFloatingIP returns the oldest non-terminating binding for a target.
// Callers provide bindings from the same namespace; equivalent IP spellings
// identify the same target, independently of controller status.
func EffectiveFloatingIP(fips []FloatingIP, vpcName, target string) *FloatingIP {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil
	}
	var best *FloatingIP
	for i := range fips {
		f := &fips[i]
		if f.Spec.VPCRef.Name != vpcName || f.DeletionTimestamp != nil || !ip.Equal(net.ParseIP(f.Spec.Target)) {
			continue
		}
		if best == nil || f.CreationTimestamp.Before(&best.CreationTimestamp) || (f.CreationTimestamp.Equal(&best.CreationTimestamp) && f.Name < best.Name) {
			best = f
		}
	}
	return best
}
