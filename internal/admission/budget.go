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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// Bound structure before typed decoding: bytes alone do not bound slice/map
// expansion, validation causes or JSON suffix trees.
const MaxReviewTokens = 20000

func checkJSONBudget(ctx context.Context, body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	depth, count := 0, 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		token, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		count++
		if count > MaxReviewTokens {
			return fmt.Errorf("admission structure exceeds token budget")
		}
		if text, ok := token.(string); ok && len(text) > 256<<10 {
			return fmt.Errorf("admission string exceeds byte budget")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			if depth > 32 {
				return fmt.Errorf("admission structure exceeds depth budget")
			}
		}
	}
}
