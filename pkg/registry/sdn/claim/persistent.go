package claim

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	clientv3 "go.etcd.io/etcd/client/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/etcd3"
)

const persistentCreateAttempts = 8
const persistentScanLimit = 65536
const persistentPageSize = 128
const claimMaxReceiveBytes = 16 << 20
const persistentScanBytes = 64 << 20

func IsPersistent(p *sdn.Port) bool { return p.Labels[sdnv1.LabelVMName] != "" }

// SamePersistentNIC deliberately includes the full VPC and consumer namespace.
// The VNI is enforced separately by the physical collection prefix.
func SamePersistentNIC(a, b *sdn.Port) bool {
	return IsPersistent(a) && IsPersistent(b) && a.Spec.PodNamespace == b.Spec.PodNamespace &&
		a.Spec.VPCRef == b.Spec.VPCRef && a.Labels[sdnv1.LabelVMName] == b.Labels[sdnv1.LabelVMName] &&
		a.Labels[sdnv1.LabelVMNIC] == b.Labels[sdnv1.LabelVMNIC]
}

func persistentContention() error {
	return apierrors.NewTimeoutError("persistent NIC allocation changed concurrently; retry ADD", 1)
}

func (s *atomicStorage) persistentGuard(ctx context.Context, prepared string, port *sdn.Port) (clientv3.Cmp, error) {
	vni, _, _ := sdn.ParseClaim(sdn.ClaimPrefixPort, port.Name)
	prefix := prepared[:strings.LastIndex(prepared, "/")+1] + fmt.Sprintf("v%d.", vni)
	end, start := clientv3.GetPrefixRangeEnd(prefix), prefix
	var revision int64
	var match string
	seen, bytesRead := 0, 0
	decoder := etcd3.NewDefaultDecoder(s.config.Codec, s.Versioner())
	for {
		if err := ctx.Err(); err != nil {
			return clientv3.Cmp{}, err
		}
		options := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(persistentPageSize), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend)}
		if revision != 0 {
			options = append(options, clientv3.WithRev(revision))
		}
		page, err := s.kv.Get(ctx, start, options...)
		if err != nil {
			return clientv3.Cmp{}, err
		}
		if page == nil || page.Header == nil || page.Header.Revision <= 0 {
			return clientv3.Cmp{}, fmt.Errorf("incomplete persistent NIC snapshot")
		}
		if len(page.Kvs) > persistentPageSize {
			return clientv3.Cmp{}, fmt.Errorf("persistent NIC snapshot exceeds its page budget")
		}
		if revision == 0 {
			revision = page.Header.Revision
		}
		for _, entry := range page.Kvs {
			if err := ctx.Err(); err != nil {
				return clientv3.Cmp{}, err
			}
			if entry == nil || len(entry.Value) > persistentScanBytes-bytesRead {
				return clientv3.Cmp{}, fmt.Errorf("persistent NIC snapshot exceeds its byte budget or has a missing entry")
			}
			bytesRead += len(entry.Value)
			seen++
			if seen > persistentScanLimit || !strings.HasPrefix(string(entry.Key), prefix) || string(entry.Key) < start {
				return clientv3.Cmp{}, fmt.Errorf("persistent NIC snapshot exceeds its scope or claim budget")
			}
			data, _, err := s.transformer.TransformFromStorage(ctx, entry.Value, authenticatedKey(entry.Key))
			if err != nil {
				return clientv3.Cmp{}, err
			}
			stored := &sdn.Port{}
			if err := decoder.Decode(data, stored, entry.ModRevision); err != nil {
				return clientv3.Cmp{}, err
			}
			if string(entry.Key) != prepared[:strings.LastIndex(prepared, "/")+1]+stored.Name {
				return clientv3.Cmp{}, fmt.Errorf("persistent NIC snapshot has inconsistent claim identity")
			}
			if SamePersistentNIC(port, stored) {
				if match != "" {
					return clientv3.Cmp{}, apierrors.NewInvalid(schema.GroupKind{Group: sdn.GroupName, Kind: "Port"}, port.Name, field.ErrorList{field.Forbidden(field.NewPath("metadata", "labels"), "multiple existing claims for this persistent NIC; repair required")})
				}
				match = stored.Name
			}
		}
		if !page.More {
			break
		}
		if len(page.Kvs) == 0 || seen >= persistentScanLimit {
			return clientv3.Cmp{}, fmt.Errorf("incomplete or oversized persistent NIC snapshot")
		}
		next := string(page.Kvs[len(page.Kvs)-1].Key) + "\x00"
		if next <= start || next >= end {
			return clientv3.Cmp{}, fmt.Errorf("persistent NIC snapshot did not advance")
		}
		start = next
	}
	if match != "" {
		return clientv3.Cmp{}, apierrors.NewAlreadyExists(sdn.Resource("ports"), match)
	}
	if revision == math.MaxInt64 {
		return clientv3.Cmp{}, persistentContention()
	}
	return clientv3.Compare(clientv3.ModRevision(prefix), "<", revision+1).WithRange(end), nil
}
