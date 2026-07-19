package compiler

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func toAny(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return v
}

// TestGolden compiles every example and compares it semantically against its
// golden JSON (key order and whitespace are irrelevant).
func TestGolden(t *testing.T) {
	examples, err := filepath.Glob("../../examples/*.rego")
	if err != nil || len(examples) == 0 {
		t.Fatalf("no examples found: %v", err)
	}

	for _, example := range examples {
		name := strings.TrimSuffix(filepath.Base(example), ".rego")
		t.Run(name, func(t *testing.T) {
			doc, err := CompileFile(example)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			compiled, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			golden, err := os.ReadFile(filepath.Join("../../testdata/golden", name+".json"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if diff := cmp.Diff(toAny(t, golden), toAny(t, compiled)); diff != "" {
				t.Errorf("compiled output differs from golden (-golden +compiled):\n%s", diff)
			}
		})
	}
}

// TestGoldenMatchesWorldPolicies cross-checks the goldens that were derived
// from world-policies against the sibling checkout, so drift is caught.
// private.json in world-policies writes the unconditional condition as
// {"const": true} without "op"; concrnt's Eval only prepends the const sugar
// as an *argument* and then fails on the empty operator name, so that spelling
// never fires. The golden intentionally uses the working form, and the
// comparison normalizes it.
func TestGoldenMatchesWorldPolicies(t *testing.T) {
	worldPolicies := "../../../world-policies"
	if _, err := os.Stat(worldPolicies); err != nil {
		t.Skipf("world-policies checkout not found: %v", err)
	}

	files := map[string]string{
		"private.json":           "private.json",
		"allow-writers.json":     "t/allow-writers.json",
		"write-public.json":      "t/write-public.json",
		"restrict-readers.json":  "t/restrict-readers.json",
		"inline-allow-deny.json": "t/inline-allow-deny.json",
		"inline-read-write.json": "t/inline-read-write.json",
	}

	for golden, source := range files {
		t.Run(golden, func(t *testing.T) {
			goldenData, err := os.ReadFile(filepath.Join("../../testdata/golden", golden))
			if err != nil {
				t.Fatal(err)
			}
			sourceData, err := os.ReadFile(filepath.Join(worldPolicies, source))
			if err != nil {
				t.Fatal(err)
			}

			goldenDoc := toAny(t, goldenData).(map[string]any)
			sourceDoc := toAny(t, sourceData).(map[string]any)
			body := sourceDoc["versions"].(map[string]any)[DefaultVersion].(map[string]any)
			normalized := maps.Clone(body)
			// paramSchema legitimately uses "const" as a JSON Schema keyword,
			// so only statement conditions are normalized.
			normalized["statements"] = normalizeConstSugar(body["statements"])
			want := map[string]any{
				"name": sourceDoc["name"],
				"versions": map[string]any{
					DefaultVersion: normalized,
				},
			}
			if diff := cmp.Diff(want, goldenDoc); diff != "" {
				t.Errorf("golden drifted from world-policies (-world-policies +golden):\n%s", diff)
			}
		})
	}
}

// normalizeConstSugar rewrites {"const": x} (no "op") to {"op": "Const", "const": x}.
func normalizeConstSugar(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range v {
			out[k] = normalizeConstSugar(val)
		}
		if _, hasConst := out["const"]; hasConst && len(out) == 1 {
			out["op"] = "Const"
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, el := range v {
			out[i] = normalizeConstSugar(el)
		}
		return out
	default:
		return v
	}
}
