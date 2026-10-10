package podlabels

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestEncodePreservesCompleteLabels(t *testing.T) {
	for _, labels := range []map[string]string{
		nil, {}, {"role": "web", "tenant.example/identity": "vm", "empty": ""},
		{"escaped": "\"<>&\u2028\n", "unicode": "é"},
	} {
		encoded, err := Encode(labels)
		if err != nil {
			t.Fatal(err)
		}
		if len(labels) == 0 {
			if encoded != "" {
				t.Fatal("empty snapshot should be omitted")
			}
			continue
		}
		var decoded map[string]string
		if err := json.Unmarshal([]byte(encoded), &decoded); err != nil || !reflect.DeepEqual(decoded, labels) {
			t.Fatal("snapshot changed selector identity", decoded, err)
		}
	}
}

func labelSet(count, valueBytes int) map[string]string {
	labels := make(map[string]string, count)
	value := strings.Repeat("x", valueBytes)
	for i := range count {
		labels[fmt.Sprintf("label%05d", i)] = value
	}
	return labels
}

func TestEncodeLimitsRejectWithoutPartialSnapshot(t *testing.T) {
	for name, labels := range map[string]map[string]string{
		"count":              labelSet(MaxLabels+1, 0),
		"valid label bytes":  labelSet(2048, 63),
		"one large value":    {"key": strings.Repeat("x", MaxBytes)},
		"one large key":      {strings.Repeat("x", MaxBytes): "value"},
		"escaping expansion": {"key": strings.Repeat("<", MaxBytes/2)},
	} {
		t.Run(name, func(t *testing.T) {
			for range 10 {
				encoded, err := Encode(labels)
				if err == nil || encoded != "" || len(err.Error()) > 100 {
					t.Fatal("oversized input must return only a bounded error", len(encoded), err)
				}
			}
		})
	}
	if _, err := Encode(labelSet(MaxLabels, 0)); err != nil {
		t.Fatal("maximum count with a small payload should work", err)
	}
	// Exact JSON byte boundary, including braces, quotes and colon.
	labels := map[string]string{"k": strings.Repeat("x", MaxBytes-8)}
	encoded, err := Encode(labels)
	if err != nil || len(encoded) != MaxBytes {
		t.Fatal("exact byte boundary rejected", len(encoded), err)
	}
	labels["k"] += "x"
	if encoded, err := Encode(labels); err == nil || encoded != "" {
		t.Fatal("byte boundary exceeded")
	}
}

func TestEncodeRejectionDoesNotAllocatePayload(t *testing.T) {
	labels := labelSet(15000, 63)
	allocs := testing.AllocsPerRun(100, func() {
		if encoded, err := Encode(labels); err == nil || encoded != "" {
			t.Fatal("oversized snapshot accepted")
		}
	})
	if allocs > 1 {
		t.Fatalf("rejection allocated %.0f objects; must not copy/sort/serialize input", allocs)
	}
}

func BenchmarkLargeLabelSnapshot(b *testing.B) {
	labels := labelSet(15000, 63)
	b.Run("previousJSONWriter", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			encoded, err := json.Marshal(labels)
			if err != nil || len(encoded) < 1024*1024 {
				b.Fatal("invalid benchmark fixture", err)
			}
		}
	})
	b.Run("boundedWriter", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if encoded, err := Encode(labels); err == nil || encoded != "" {
				b.Fatal("oversized snapshot accepted")
			}
		}
	})
}
