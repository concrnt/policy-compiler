package compiler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const testHeader = `package test

deny if {
	input.action == "record:read"
	key_matches("./*")
`

// compileCondition compiles a single-statement policy whose body is the given
// literals and returns the condition as JSON-decoded data.
func compileCondition(t *testing.T, body string, extraRules string) any {
	t.Helper()
	src := testHeader + body + "\n}\n" + extraRules
	doc, err := Compile("test.rego", src)
	if err != nil {
		t.Fatalf("compile: %v\nsource:\n%s", err, src)
	}
	stmt := doc.Versions[DefaultVersion].Statements[0]
	data, err := json.Marshal(toExprJSON(stmt.Condition))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestExprTranslation(t *testing.T) {
	load := func(path string) map[string]any {
		return map[string]any{"op": "Load", "const": path}
	}

	cases := []struct {
		name  string
		body  string
		extra string
		want  any
	}{
		{
			name: "eq",
			body: `input.requester.ccid == input.self.author`,
			want: map[string]any{"op": "Eq", "args": []any{load("requester.ccid"), load("self.author")}},
		},
		{
			name: "neq becomes not-eq",
			body: `input.requester.ccid != input.self.author`,
			want: map[string]any{"op": "Not", "args": []any{
				map[string]any{"op": "Eq", "args": []any{load("requester.ccid"), load("self.author")}},
			}},
		},
		{
			name: "membership swaps to contains",
			body: `input.requester.ccid in input.params.entities`,
			want: map[string]any{"op": "Contains", "args": []any{load("params.entities"), load("requester.ccid")}},
		},
		{
			name: "negated membership",
			body: `not input.requester.ccid in input.params.entities`,
			want: map[string]any{"op": "Not", "args": []any{
				map[string]any{"op": "Contains", "args": []any{load("params.entities"), load("requester.ccid")}},
			}},
		},
		{
			name: "multiple literals become and",
			body: "input.params.flag\ninput.requester.ccid == input.self.author",
			want: map[string]any{"op": "And", "args": []any{
				load("params.flag"),
				map[string]any{"op": "Eq", "args": []any{load("requester.ccid"), load("self.author")}},
			}},
		},
		{
			name: "scalar constants",
			body: `input.params.role == "admin"`,
			want: map[string]any{"op": "Eq", "args": []any{
				load("params.role"),
				map[string]any{"op": "Const", "const": "admin"},
			}},
		},
		{
			name: "array literal",
			body: `input.params.role in ["admin", "moderator"]`,
			want: map[string]any{"op": "Contains", "args": []any{
				map[string]any{"op": "Const", "const": []any{"admin", "moderator"}},
				load("params.role"),
			}},
		},
		{
			name: "true literal",
			body: `true`,
			want: map[string]any{"op": "Const", "const": true},
		},
		{
			name: "ccuri owner",
			body: `input.requester.ccid == ccuri_owner(input.self.key)`,
			want: map[string]any{"op": "Eq", "args": []any{
				load("requester.ccid"),
				map[string]any{"op": "CCUriOwner", "args": []any{load("self.key")}},
			}},
		},
		{
			name:  "helper rule inlined with or",
			body:  `not can_read`,
			extra: "can_read if input.self.author == input.requester.ccid\ncan_read if input.params.open\n",
			want: map[string]any{"op": "Not", "args": []any{
				map[string]any{"op": "Or", "args": []any{
					map[string]any{"op": "Eq", "args": []any{load("self.author"), load("requester.ccid")}},
					load("params.open"),
				}},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compileCondition(t, tc.body, tc.extra)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("condition mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name:    "unification",
			src:     testHeader + "input.params.role = \"admin\"\n}\n",
			wantErr: "use `==`",
		},
		{
			name:    "numeric comparison",
			src:     testHeader + "input.params.count > 3\n}\n",
			wantErr: "numeric comparisons are not supported",
		},
		{
			name:    "arithmetic",
			src:     testHeader + "input.params.a == 1 + 2\n}\n",
			wantErr: "arithmetic is not supported",
		},
		{
			name:    "unknown builtin",
			src:     testHeader + "startswith(input.params.role, \"adm\")\n}\n",
			wantErr: `built-in function "startswith" is not supported`,
		},
		{
			name:    "iteration",
			src:     testHeader + "input.params.entities[_] == input.requester.ccid\n}\n",
			wantErr: "iteration",
		},
		{
			name:    "unknown context root",
			src:     testHeader + "input.foo.bar == \"x\"\n}\n",
			wantErr: `unknown context root "foo"`,
		},
		{
			name:    "undefined rule",
			src:     testHeader + "not missing_rule\n}\n",
			wantErr: `undefined rule or variable "missing_rule"`,
		},
		{
			name:    "circular reference",
			src:     testHeader + "not a\n}\na if b\nb if a\n",
			wantErr: "circular reference",
		},
		{
			name:    "default rule",
			src:     testHeader + "true\n}\ndefault deny := false\n",
			wantErr: "`default` rules are not supported",
		},
		{
			name:    "orphan helper rule",
			src:     testHeader + "true\n}\nunused_helper if { true }\n",
			wantErr: "never referenced by a statement",
		},
		{
			name:    "unsupported version",
			src:     "# METADATA\n# title: t\n# custom:\n#   version: \"2024-07-01\"\npackage test\n\ndeny if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"./*\")\n\ttrue\n}\n",
			wantErr: "unsupported policy version",
		},
		{
			name:    "every",
			src:     testHeader + "every x in input.params.entities { x == \"a\" }\n}\n",
			wantErr: "unsupported statement form",
		},
		{
			name:    "missing action",
			src:     "package test\n\ndeny if {\n\tkey_matches(\"./*\")\n\ttrue\n}\n",
			wantErr: "does not pin its action",
		},
		{
			name:    "duplicate action",
			src:     testHeader + "input.action == \"record:create\"\n}\n",
			wantErr: "duplicate action literal",
		},
		{
			name:    "negated action literal",
			src:     "package test\n\ndeny if {\n\tnot input.action == \"record:read\"\n\tkey_matches(\"*\")\n}\n",
			wantErr: "the action literal cannot be negated",
		},
		{
			name:    "action compared to non-constant",
			src:     "package test\n\ndeny if {\n\tinput.action == input.params.x\n\tkey_matches(\"*\")\n}\n",
			wantErr: "compared to a non-empty string constant",
		},
		{
			name:    "input.action outside the action literal",
			src:     testHeader + "input.action != \"record:create\"\n}\n",
			wantErr: "input.action can only be used as a top-level literal",
		},
		{
			name:    "input.key in condition",
			src:     testHeader + "input.key == \"x\"\n}\n",
			wantErr: "input.key is not available in conditions",
		},
		{
			name:    "missing key pattern",
			src:     "package test\n\ndeny if {\n\tinput.action == \"record:read\"\n\ttrue\n}\n",
			wantErr: "has no key pattern",
		},
		{
			name:    "key_matches arity",
			src:     "package test\n\ndeny if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"a\", \"b\")\n}\n",
			wantErr: "takes exactly one string literal",
		},
		{
			name:    "key_matches in helper rule",
			src:     testHeader + "not h\n}\nh if { key_matches(\"*\") }\n",
			wantErr: "top level of a statement rule body",
		},
		{
			name:    "unbound reason variable",
			src:     "package test\n\ndeny contains msg if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"*\")\n\ttrue\n}\n",
			wantErr: "is not bound to a string constant",
		},
		{
			name:    "reason bound to non-string",
			src:     "package test\n\ndeny contains msg if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"*\")\n\tmsg := 42\n}\n",
			wantErr: "must be bound to a string constant",
		},
		{
			name:    "non-scalar reason head",
			src:     "package test\n\ndeny contains {\"a\": 1} if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"*\")\n}\n",
			wantErr: "reason must be a string literal or a variable",
		},
		{
			name:    "statement with value",
			src:     "package test\n\ndeny := 1\n",
			wantErr: "statement rules cannot have a value",
		},
		{
			name:    "defaults not an object",
			src:     testHeader + "true\n}\ndefaults := \"ng\"\n",
			wantErr: "defaults must be an object literal",
		},
		{
			name:    "defaults invalid conclusion",
			src:     testHeader + "true\n}\ndefaults := {\"record:read\": \"nope\"}\n",
			wantErr: "invalid default conclusion",
		},
		{
			name:    "conditional defaults",
			src:     testHeader + "true\n}\ndefaults := {\"record:read\": \"ok\"} if { input.params.x }\n",
			wantErr: "defaults must be unconditional",
		},
		{
			name:    "duplicate defaults",
			src:     testHeader + "true\n}\ndefaults := {\"record:read\": \"ok\"}\ndefaults := {\"record:create\": \"ng\"}\n",
			wantErr: "duplicate defaults rule",
		},
		{
			name:    "defaults with unification",
			src:     testHeader + "true\n}\ndefaults = {\"record:read\": \"ok\"}\n",
			wantErr: "plain := assignment",
		},
		{
			name:    "reserved name key_matches",
			src:     testHeader + "true\n}\nkey_matches if { true }\n",
			wantErr: "reserved name",
		},
		{
			name:    "referencing a statement rule",
			src:     testHeader + "true\n}\n\nok if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"*\")\n\tnot deny\n}\n",
			wantErr: "statement rules (allow/deny/ok/ng) cannot be referenced",
		},
		{
			name:    "helper rule with contains",
			src:     testHeader + "not h\n}\nh contains \"x\" if { true }\n",
			wantErr: "helper rules cannot use `contains`",
		},
		{
			name:    "legacy statement metadata",
			src:     "package test\n\n# METADATA\n# custom:\n#   action: \"record:read\"\n#   emit: deny\nstmt if { true }\n",
			wantErr: "rule-scope METADATA statements are no longer supported",
		},
		{
			name:    "legacy package defaults",
			src:     "# METADATA\n# title: t\n# custom:\n#   defaults:\n#     \"record:read\": ok\npackage test\n\ndeny if {\n\tinput.action == \"record:read\"\n\tkey_matches(\"./*\")\n\ttrue\n}\n",
			wantErr: "custom.defaults in package METADATA is no longer supported",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile("test.rego", tc.src)
			if err == nil {
				t.Fatalf("expected error containing %q, got success", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got:\n%s", tc.wantErr, err.Error())
			}
		})
	}
}
