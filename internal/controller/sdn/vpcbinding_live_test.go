package sdn

import (
	"context"
	"fmt"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type bindingCacheView struct {
	client.Client
	bindings  []sdn.VPCBinding
	hidePorts bool
}

type bindingReapPages struct {
	client.Reader
	bindings       [][]sdn.VPCBinding
	ports          [][]sdn.Port
	bCalls, pCalls int
	failPortPage   int
}

func (r *bindingReapPages) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	o := (&client.ListOptions{}).ApplyOptions(opts)
	if o.Limit != 128 {
		return fmt.Errorf("unbounded page: %d", o.Limit)
	}
	page := 0
	if o.Continue != "" {
		if _, err := fmt.Sscan(o.Continue, &page); err != nil || page <= 0 {
			return fmt.Errorf("bad continuation: %q", o.Continue)
		}
	}
	switch list := list.(type) {
	case *sdn.VPCBindingList:
		if r.bindings == nil {
			return r.Reader.List(ctx, list, opts...)
		}
		if page != r.bCalls || page >= len(r.bindings) || o.Namespace != "consumer" {
			return fmt.Errorf("bad binding page or scope")
		}
		r.bCalls++
		list.Items = r.bindings[page]
		if page+1 < len(r.bindings) {
			list.Continue = fmt.Sprint(page + 1)
		}
	case *sdn.PortList:
		if r.ports == nil {
			return r.Reader.List(ctx, list, opts...)
		}
		if page != r.pCalls || page >= len(r.ports) {
			return fmt.Errorf("bad Port page")
		}
		r.pCalls++
		if r.failPortPage > 0 && page == r.failPortPage {
			return fmt.Errorf("injected live page failure")
		}
		list.Items = r.ports[page]
		if page+1 < len(r.ports) {
			list.Continue = fmt.Sprint(page + 1)
		}
	default:
		return r.Reader.List(ctx, list, opts...)
	}
	return nil
}

func TestBindingReapConsumesCompleteLivePages(t *testing.T) {
	for _, tc := range []string{"later grant", "later Port", "failed later Port", "oversized grant page", "same-name replacement grant"} {
		t.Run(tc, func(t *testing.T) {
			scheme := testScheme(t)
			binding := vpcBinding("consumer", "removed", "owner", "net", true)
			binding.UID = "old-binding"
			other := vpcBinding("consumer", "other", "owner", "net", true)
			other.UID = "other-binding"
			p1 := portFor("one", "owner", "net", "consumer")
			p2 := portFor("two", "owner", "net", "consumer")
			p1.UID, p2.UID = "one-uid", "two-uid"
			api := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, p1, p2).Build()
			if err := api.Delete(t.Context(), binding); err != nil {
				t.Fatal(err)
			}
			if err := api.Get(t.Context(), client.ObjectKeyFromObject(binding), binding); err != nil {
				t.Fatal(err)
			}
			for _, port := range []*sdn.Port{p1, p2} {
				if err := api.Get(t.Context(), client.ObjectKeyFromObject(port), port); err != nil {
					t.Fatal(err)
				}
			}
			reader := &bindingReapPages{Reader: api, bindings: [][]sdn.VPCBinding{{*binding}}, ports: [][]sdn.Port{{*p1}, {*p2}}}
			keep, wantError := false, false
			switch tc {
			case "later grant":
				reader.bindings = append(reader.bindings, []sdn.VPCBinding{*other})
				keep = true
			case "same-name replacement grant":
				other.Name = binding.Name
				reader.bindings = [][]sdn.VPCBinding{{*other}}
				keep = true
			case "failed later Port":
				reader.failPortPage = 1
				keep, wantError = true, true
			case "oversized grant page":
				reader.bindings = [][]sdn.VPCBinding{make([]sdn.VPCBinding, 129)}
				keep, wantError = true, true
			}
			r := &VPCBindingReconciler{Client: api, Reader: reader}
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(binding)})
			if (err != nil) != wantError {
				t.Fatalf("reconcile error=%v wantError=%v", err, wantError)
			}
			for _, port := range []*sdn.Port{p1, p2} {
				err := api.Get(t.Context(), client.ObjectKeyFromObject(port), &sdn.Port{})
				if keep && err != nil || !keep && !apierrors.IsNotFound(err) {
					t.Fatalf("Port %s keep=%v err=%v", port.Name, keep, err)
				}
			}
			if wantError {
				if err := api.Get(t.Context(), client.ObjectKeyFromObject(binding), binding); err != nil || len(binding.Finalizers) == 0 {
					t.Fatal("failed scan released reap barrier", err)
				}
			}
			if tc == "later grant" && reader.bCalls != 2 || tc == "later Port" && reader.pCalls != 2 {
				t.Fatal("continuation was not consumed", reader.bCalls, reader.pCalls)
			}
		})
	}
}

func (c *bindingCacheView) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.bindings != nil {
		if bindings, ok := list.(*sdn.VPCBindingList); ok {
			bindings.Items = c.bindings
			return nil
		}
	}
	if c.hidePorts {
		if ports, ok := list.(*sdn.PortList); ok {
			ports.Items = nil
			return nil
		}
	}
	return c.Client.List(ctx, list, opts...)
}

func TestBindingReaperUsesLiveGrantsAndPorts(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		liveGrant, cachedGrant, hidePorts bool
	}{
		{"new grant absent from informer", true, false, false},
		{"revoked grant still in informer", false, true, false},
		{"new Port absent from informer", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := testScheme(t)
			binding := vpcBinding("consumer", "removed", "owner", "net", true)
			other := vpcBinding("consumer", "other", "owner", "net", true)
			port := portFor("port", "owner", "net", "consumer")
			port.UID = "port-uid"
			objects := []client.Object{binding, port}
			if tc.liveGrant {
				objects = append(objects, other)
			}
			api := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			cached := &bindingCacheView{Client: api, bindings: []sdn.VPCBinding{}, hidePorts: tc.hidePorts}
			if tc.cachedGrant {
				cached.bindings = []sdn.VPCBinding{*other}
			}
			r := &VPCBindingReconciler{Client: cached, Reader: api}
			count, err := r.reapPorts(t.Context(), binding)
			if err != nil {
				t.Fatal(err)
			}
			err = api.Get(t.Context(), client.ObjectKeyFromObject(port), &sdn.Port{})
			if tc.liveGrant {
				if err != nil || count != 0 {
					t.Fatalf("live grant lost its Port: count=%d err=%v", count, err)
				}
			} else if !apierrors.IsNotFound(err) || count != 1 {
				t.Fatalf("live revocation missed its Port: count=%d err=%v", count, err)
			}
		})
	}
}
