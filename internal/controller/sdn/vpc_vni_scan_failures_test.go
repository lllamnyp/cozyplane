package sdn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type vniPageReader struct {
	client.Reader
	list func(context.Context, client.ObjectList, client.ListOptions) error
}

func (r vniPageReader) List(ctx context.Context, out client.ObjectList, opts ...client.ListOption) error {
	options := client.ListOptions{}
	options.ApplyOptions(opts)
	return r.list(ctx, out, options)
}

func TestVNIIncompleteBootstrapNeverReserves(t *testing.T) {
	for _, failKind := range []string{"VPC", "Port", "ServiceVIP"} {
		for _, failure := range []string{"first error", "second error", "repeat token", "oversized page", "page budget"} {
			t.Run(failKind+"/"+failure, func(t *testing.T) {
				c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
				calls := map[string]int{}
				var commonDeadline time.Time
				reader := vniPageReader{Reader: c, list: func(ctx context.Context, out client.ObjectList, opts client.ListOptions) error {
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 30*time.Second || opts.Limit != 128 || opts.Namespace != "" {
						t.Fatal("VNI scan lacks bounded all-namespace pages/shared deadline")
					}
					if commonDeadline.IsZero() {
						commonDeadline = deadline
					} else if !deadline.Equal(commonDeadline) {
						t.Fatal("bootstrap resets its lifetime between scans/pages")
					}
					kind := ""
					switch rows := out.(type) {
					case *sdnv1alpha1.VPCList:
						kind = "VPC"
						rows.Items = []sdnv1alpha1.VPC{{Status: sdnv1alpha1.VPCStatus{VNI: 800}}}
					case *sdnv1alpha1.PortList:
						kind = "Port"
						rows.Items = []sdnv1alpha1.Port{{ObjectMeta: metav1.ObjectMeta{Name: "v900.10-0-0-2"}}}
					case *sdnv1alpha1.ServiceVIPList:
						kind = "ServiceVIP"
						rows.Items = []sdnv1alpha1.ServiceVIP{{ObjectMeta: metav1.ObjectMeta{Name: "sv1001.10-0-0-3"}}}
					default:
						t.Fatalf("unexpected VNI scan %T", out)
					}
					calls[kind]++
					if kind != failKind {
						return nil
					}
					if failure == "first error" || failure == "second error" && calls[kind] == 2 {
						return fmt.Errorf("transport unavailable")
					}
					switch failure {
					case "second error", "repeat token":
						out.SetContinue("same-token")
					case "oversized page":
						switch rows := out.(type) {
						case *sdnv1alpha1.VPCList:
							rows.Items = make([]sdnv1alpha1.VPC, 129)
						case *sdnv1alpha1.PortList:
							rows.Items = make([]sdnv1alpha1.Port, 129)
						case *sdnv1alpha1.ServiceVIPList:
							rows.Items = make([]sdnv1alpha1.ServiceVIP, 129)
						}
					case "page budget":
						out.SetContinue(strconv.Itoa(calls[kind]))
					}
					return nil
				}}
				r := &VPCReconciler{Client: c, Reader: reader}
				if allocated, err := r.allocateVNI(t.Context()); err == nil || allocated != 0 {
					t.Fatalf("partial bootstrap allocated VNI=%d err=%v", allocated, err)
				}
				if err := c.Get(t.Context(), client.ObjectKey{Namespace: vniCounterNamespace, Name: vniCounterName}, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
					t.Fatalf("partial bootstrap wrote durable reservation: %v", err)
				}
				want := 1
				if failure == "second error" || failure == "repeat token" {
					want = 2
				} else if failure == "page budget" {
					want = 512
				}
				if calls[failKind] != want {
					t.Fatalf("failed scan kept reading: calls=%d want=%d", calls[failKind], want)
				}
			})
		}
	}
}

func TestVNIDuplicateRejectsPartialVerdict(t *testing.T) {
	vpc := vpcWithVNI("current", 101)
	vpc.CreationTimestamp = metav1.NewTime(time.Unix(200, 0))
	older := vpc.DeepCopy()
	older.Namespace, older.Name = "tenant-b", "older"
	older.CreationTimestamp = metav1.NewTime(time.Unix(100, 0))
	for _, failure := range []string{"second error", "repeat token", "oversized page", "page budget"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			r := &VPCReconciler{Reader: vniPageReader{list: func(ctx context.Context, out client.ObjectList, opts client.ListOptions) error {
				calls++
				if _, ok := ctx.Deadline(); !ok || opts.Limit != 128 {
					t.Fatal("duplicate scan is unbounded")
				}
				rows := out.(*sdnv1alpha1.VPCList)
				rows.Items = []sdnv1alpha1.VPC{*older}
				rows.Continue = "same-token"
				switch failure {
				case "second error":
					if calls == 2 {
						return fmt.Errorf("transport unavailable")
					}
				case "oversized page":
					rows.Items = make([]sdnv1alpha1.VPC, 129)
				case "page budget":
					rows.Continue = strconv.Itoa(calls)
				}
				return nil
			}}}
			if lost, err := r.lostVNIToDuplicate(t.Context(), vpc); err == nil || lost {
				t.Fatalf("partial duplicate verdict published: lost=%v err=%v", lost, err)
			}
		})
	}
}

func TestVNIScanCancellation(t *testing.T) {
	for _, operation := range []string{"bootstrap", "duplicate"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			r := &VPCReconciler{Reader: vniPageReader{list: func(ctx context.Context, _ client.ObjectList, _ client.ListOptions) error {
				calls++
				<-ctx.Done()
				return ctx.Err()
			}}}
			run := func(ctx context.Context) error {
				if operation == "bootstrap" {
					_, err := r.initialVNIHighWater(ctx)
					return err
				}
				_, err := r.lostVNIToDuplicate(ctx, vpcWithVNI("current", 101))
				return err
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := run(ctx); !errors.Is(err, context.Canceled) || calls != 0 {
				t.Fatalf("cancelled VNI scan read calls=%d err=%v", calls, err)
			}
			ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if err := run(ctx); !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
				t.Fatalf("VNI scan ignored shorter parent: calls=%d err=%v", calls, err)
			}
		})
	}
}

type vniCounterLifetimeClient struct {
	client.Client
	op     string
	check  func(context.Context) error
	checks int
}

func (c *vniCounterLifetimeClient) Get(ctx context.Context, key client.ObjectKey, out client.Object, opts ...client.GetOption) error {
	if _, ok := out.(*coordinationv1.Lease); ok && c.op == "get" {
		c.checks++
		return c.check(ctx)
	}
	return c.Client.Get(ctx, key, out, opts...)
}

func (c *vniCounterLifetimeClient) Create(ctx context.Context, out client.Object, opts ...client.CreateOption) error {
	if _, ok := out.(*coordinationv1.Lease); ok && c.op == "create" {
		c.checks++
		return c.check(ctx)
	}
	return c.Client.Create(ctx, out, opts...)
}

func (c *vniCounterLifetimeClient) Update(ctx context.Context, out client.Object, opts ...client.UpdateOption) error {
	if _, ok := out.(*coordinationv1.Lease); ok && c.op == "update" {
		c.checks++
		return c.check(ctx)
	}
	return c.Client.Update(ctx, out, opts...)
}

func TestVNILeaseOperationLifetime(t *testing.T) {
	for _, op := range []string{"get", "create", "update"} {
		t.Run(op, func(t *testing.T) {
			var objects []client.Object
			if op == "update" {
				objects = append(objects, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: vniCounterNamespace, Name: vniCounterName, Annotations: map[string]string{vniCounterAnnotation: "300"}}})
			}
			c := &vniCounterLifetimeClient{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build(), op: op}
			c.check = func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 30*time.Second {
					t.Fatal("counter access has no operation lifetime")
				}
				return fmt.Errorf("transport unavailable")
			}
			r := &VPCReconciler{Client: c, Reader: c}
			if got, err := r.allocateVNI(t.Context()); err == nil || got != 0 || c.checks != 1 {
				t.Fatalf("failed counter operation published allocation: got=%d checks=%d err=%v", got, c.checks, err)
			}
			// A transport request may time out while the operation's parent lives.
			for _, requestErr := range []error{context.DeadlineExceeded, context.Canceled} {
				c.check = func(ctx context.Context) error {
					if ctx.Err() != nil {
						t.Fatal("request-timeout fixture unexpectedly cancelled parent")
					}
					return fmt.Errorf("request failed: %w", requestErr)
				}
				if got, err := r.allocateVNI(t.Context()); got != 0 || !errors.Is(err, requestErr) {
					t.Fatalf("interrupted request published VNI: got=%d err=%v", got, err)
				}
			}
			c.check = func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if got, err := r.allocateVNI(ctx); got != 0 || !errors.Is(err, context.DeadlineExceeded) || c.checks != 4 {
				t.Fatalf("counter access ignored shorter parent: got=%d checks=%d err=%v", got, c.checks, err)
			}
		})
	}
}

func TestVNIRequestTimeoutAfterConflictPreservesLastAttempt(t *testing.T) {
	for _, op := range []string{"create", "update"} {
		t.Run(op, func(t *testing.T) {
			var objects []client.Object
			if op == "update" {
				objects = append(objects, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: vniCounterNamespace, Name: vniCounterName, Annotations: map[string]string{vniCounterAnnotation: "300"}}})
			}
			c := &vniCounterLifetimeClient{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build(), op: op}
			attempts := 0
			c.check = func(ctx context.Context) error {
				attempts++
				if ctx.Err() != nil {
					t.Fatal("request-timeout fixture cancelled its parent")
				}
				if attempts == 1 {
					resource := schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}
					if op == "create" {
						return apierrors.NewAlreadyExists(resource, vniCounterName)
					}
					return apierrors.NewConflict(resource, vniCounterName, fmt.Errorf("version changed"))
				}
				return fmt.Errorf("request failed: %w", context.DeadlineExceeded)
			}
			r := &VPCReconciler{Client: c, Reader: c}
			if got, err := r.allocateVNI(t.Context()); got != 0 || !errors.Is(err, context.DeadlineExceeded) || attempts != 2 {
				t.Fatalf("last interrupted attempt was hidden: got=%d attempts=%d err=%v", got, attempts, err)
			}
		})
	}
}
