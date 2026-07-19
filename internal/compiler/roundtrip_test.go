package compiler

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/concrnt/concrnt/policy"
)

// toPolicy converts a compiled VersionBody into a concrnt policy.Policy by
// round-tripping through JSON, exactly as a server consuming the compiled
// document would.
func toPolicy(t *testing.T, body VersionBody) policy.Policy {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var p policy.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func compileExample(t *testing.T, name string) policy.Policy {
	t.Helper()
	doc, err := CompileFile("../../examples/" + name + ".rego")
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return toPolicy(t, doc.Versions[DefaultVersion])
}

func evaluate(t *testing.T, p policy.Policy, req policy.RequestContext, action, key string) policy.Conclusion {
	t.Helper()
	conclusion, _, err := policy.EvaluatePolicy(context.Background(), p, req, action, key)
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	return conclusion
}

// TestRoundtripRestrictReaders runs the compiled policy through concrnt's real
// evaluation engine and checks the conclusions.
func TestRoundtripRestrictReaders(t *testing.T) {
	p := compileExample(t, "restrict-readers")

	req := func(ccid string) policy.RequestContext {
		return policy.RequestContext{
			Requester: map[string]any{"ccid": ccid},
			Params:    map[string]any{"entities": []any{"con1member"}},
		}
	}

	if got := evaluate(t, p, req("con1member"), "record:read", "./post-1"); got != policy.UNSET {
		t.Errorf("member read: want unset (fall through), got %s", got)
	}
	if got := evaluate(t, p, req("con1stranger"), "record:read", "./post-1"); got != policy.DENY {
		t.Errorf("stranger read: want deny, got %s", got)
	}
	// key "." is the policy root itself, not covered by "./*"
	if got := evaluate(t, p, req("con1stranger"), "record:read", "."); got != policy.UNSET {
		t.Errorf("stranger read of root: want unset, got %s", got)
	}
}

func TestRoundtripWhisper(t *testing.T) {
	p := compileExample(t, "whisper")

	req := func(ccid string) policy.RequestContext {
		return policy.RequestContext{
			Requester: map[string]any{"ccid": ccid},
			Self:      map[string]any{"author": "con1author"},
			Params:    map[string]any{"participants": []any{"con1friend"}},
		}
	}

	if got := evaluate(t, p, req("con1author"), "record:read", "./msg"); got != policy.UNSET {
		t.Errorf("author read: want unset, got %s", got)
	}
	if got := evaluate(t, p, req("con1friend"), "record:read", "./msg"); got != policy.UNSET {
		t.Errorf("participant read: want unset, got %s", got)
	}
	if got := evaluate(t, p, req("con1stranger"), "record:read", "./msg"); got != policy.DENY {
		t.Errorf("stranger read: want deny, got %s", got)
	}
}

func TestRoundtripInlineReadWrite(t *testing.T) {
	p := compileExample(t, "inline-read-write")

	req := func(ccid string, readPublic bool) policy.RequestContext {
		return policy.RequestContext{
			Requester: map[string]any{"ccid": ccid},
			Params: map[string]any{
				"isReadPublic":  readPublic,
				"isWritePublic": false,
				"reader":        []any{"con1reader"},
				"writer":        []any{"con1writer"},
			},
		}
	}

	if got := evaluate(t, p, req("con1stranger", true), "record:read", "./m"); got != policy.OK {
		t.Errorf("public read: want ok, got %s", got)
	}
	if got := evaluate(t, p, req("con1stranger", false), "record:read", "./m"); got != policy.DENY {
		t.Errorf("private read by stranger: want deny, got %s", got)
	}
	if got := evaluate(t, p, req("con1reader", false), "record:read", "./m"); got != policy.UNSET {
		t.Errorf("private read by listed reader: want unset, got %s", got)
	}
	if got := evaluate(t, p, req("con1writer", false), "record:create", "./m"); got != policy.UNSET {
		t.Errorf("private write by listed writer: want unset, got %s", got)
	}
	if got := evaluate(t, p, req("con1stranger", false), "record:create", "./m"); got != policy.DENY {
		t.Errorf("private write by stranger: want deny, got %s", got)
	}
}

// TestRoundtripGlobalPolicy checks the compiled global policy against the same
// scenarios concrnt's own defaultPolicy tests cover, including CCUriOwner,
// globals.fqdn, and declared defaults.
func TestRoundtripGlobalPolicy(t *testing.T) {
	p := compileExample(t, "global-policy")

	req := func(ccid, domain, selfKey, author string) policy.RequestContext {
		return policy.RequestContext{
			Requester: map[string]any{"ccid": ccid, "domain": domain},
			Self:      map[string]any{"key": selfKey, "author": author, "associate": "cckv://con1parent/timeline"},
			Params:    map[string]any{},
			Globals:   map[string]any{"fqdn": "example.com"},
		}
	}

	// local requester creating under their own namespace
	got := evaluate(t, p, req("con1alice", "example.com", "cckv://con1alice/timeline/post", "con1alice"), "record:create", "*")
	if got != policy.ALLOW {
		t.Errorf("create own namespace: want allow, got %s", got)
	}
	// local requester creating under the server namespace
	got = evaluate(t, p, req("con1alice", "example.com", "cckv://example.com/registry", "con1alice"), "record:create", "*")
	if got != policy.OK {
		t.Errorf("create server namespace: want ok, got %s", got)
	}
	// remote requester creating under someone else's namespace: default ng
	got = evaluate(t, p, req("con1alice", "remote.example", "cckv://con1bob/timeline/post", "con1alice"), "record:create", "*")
	if got != policy.NG {
		t.Errorf("remote create in foreign namespace: want ng, got %s", got)
	}
	// reading someone else's record: default ok
	got = evaluate(t, p, req("con1alice", "example.com", "cckv://con1bob/timeline/post", "con1bob"), "record:read", "*")
	if got != policy.OK {
		t.Errorf("read foreign record: want ok, got %s", got)
	}
	// author updating their own record in a foreign namespace
	got = evaluate(t, p, req("con1alice", "example.com", "cckv://con1bob/timeline/post", "con1alice"), "record:update", "*")
	if got != policy.ALLOW {
		t.Errorf("author update: want allow, got %s", got)
	}
	// association delete by the owner of the parent
	got = evaluate(t, p, req("con1parent", "example.com", "cckv://con1parent/assoc/1", "con1other"), "association:delete", "*")
	if got != policy.ALLOW {
		t.Errorf("association delete by parent owner: want allow, got %s", got)
	}
	// association delete by a third party: default ng
	got = evaluate(t, p, req("con1third", "example.com", "cckv://con1parent/assoc/1", "con1other"), "association:delete", "*")
	if got != policy.NG {
		t.Errorf("association delete by third party: want ng, got %s", got)
	}
}

// TestCompiledMatchesConcrntGlobalPolicy verifies that the Rego port of the
// global policy evaluates identically to concrnt's built-in globalPolicyJson
// across a scenario matrix.
func TestCompiledMatchesConcrntGlobalPolicy(t *testing.T) {
	compiled := compileExample(t, "global-policy")

	goldenData, err := jsonVersionBody("../../testdata/golden/global-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var builtin policy.Policy
	if err := json.Unmarshal(goldenData, &builtin); err != nil {
		t.Fatal(err)
	}

	ccids := []string{"con1alice", "con1bob"}
	domains := []string{"example.com", "remote.example"}
	keys := []string{"cckv://con1alice/post", "cckv://con1bob/post", "cckv://example.com/reg"}
	actions := []string{"record:create", "record:read", "record:update", "record:delete", "association:create", "association:read", "association:delete"}

	for _, ccid := range ccids {
		for _, domain := range domains {
			for _, selfKey := range keys {
				for _, author := range ccids {
					req := policy.RequestContext{
						Requester: map[string]any{"ccid": ccid, "domain": domain},
						Self:      map[string]any{"key": selfKey, "author": author, "associate": selfKey},
						Params:    map[string]any{},
						Globals:   map[string]any{"fqdn": "example.com"},
					}
					for _, action := range actions {
						want := evaluate(t, builtin, req, action, "*")
						got := evaluate(t, compiled, req, action, "*")
						if got != want {
							t.Errorf("divergence: ccid=%s domain=%s key=%s author=%s action=%s: builtin=%s compiled=%s",
								ccid, domain, selfKey, author, action, want, got)
						}
					}
				}
			}
		}
	}
}

func jsonVersionBody(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Versions[DefaultVersion], nil
}
