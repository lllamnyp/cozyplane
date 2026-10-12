/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package admission

import (
	"context"
	"strings"
	"testing"
)

func TestJSONBudgetRejectsAmplificationBeforeTypedDecode(t *testing.T) {
	for _, body := range []string{"[" + strings.Repeat("0,", MaxReviewTokens) + "0]", strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33), `{"x":"` + strings.Repeat("x", (256<<10)+1) + `"}`} {
		if checkJSONBudget(context.Background(), []byte(body)) == nil {
			t.Fatal("oversized structure accepted")
		}
	}
	if e := checkJSONBudget(context.Background(), []byte(`{"object":{"spec":{"ports":[{"port":65535}]}}}`)); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if checkJSONBudget(ctx, []byte(`{}`)) == nil {
		t.Fatal("cancelled scan accepted")
	}
}

func BenchmarkJSONBudgetRejectsExpansion(b *testing.B) {
	body := []byte("[" + strings.Repeat("0,", MaxReviewTokens) + "0]")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if checkJSONBudget(context.Background(), body) == nil {
			b.Fatal("accepted")
		}
	}
}
