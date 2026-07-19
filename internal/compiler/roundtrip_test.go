package compiler

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/concrnt/concrnt/policy"
)

func compileExample(t *testing.T, name string) policy.Policy {
	t.Helper()
	doc, err := CompileFile("../../examples/" + name + ".rego")
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	body := doc.Versions[DefaultVersion]
	return policy.Policy{Statements: body.Statements, Defaults: body.Defaults}
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

// fakeCaller implements policy.ConcrntCaller for roundtrip tests, recording
// the arguments of the last call and returning a canned result.
type fakeCaller struct {
	result      any
	err         error
	gotResolver string
	gotAPI      string
	gotParams   map[string]string
}

func (f *fakeCaller) ConcrntCall(ctx context.Context, resolver string, api string, params map[string]string) (any, error) {
	f.gotResolver = resolver
	f.gotAPI = api
	f.gotParams = params
	return f.result, f.err
}

// TestRoundtripRestrictAckees runs the compiled restrict-ackees policy through
// concrnt's engine with a fake ConcrntCaller. The statement key is "" so it
// only fires when the policy is evaluated with an empty key.
func TestRoundtripRestrictAckees(t *testing.T) {
	p := compileExample(t, "restrict-ackees")

	req := func(ccid string, caller *fakeCaller) policy.RequestContext {
		return policy.RequestContext{
			Requester: map[string]any{"ccid": ccid},
			Self:      map[string]any{"key": "cckv://con1owner/profile"},
			Params:    map[string]any{},
			Caller:    caller,
		}
	}

	// the owner reads their own record: allowed even when the ack list is empty
	// (note: concrnt's Eval is eager, so the API call happens regardless)
	caller := &fakeCaller{result: []any{}}
	if got := evaluate(t, p, req("con1owner", caller), "record:read", ""); got != policy.OK {
		t.Errorf("owner read: want ok, got %s", got)
	}

	// an ackee of the owner: the API returns a non-empty ack list
	caller = &fakeCaller{result: []any{map[string]any{"document": `{"kind":"ack"}`}}}
	if got := evaluate(t, p, req("con1friend", caller), "record:read", ""); got != policy.OK {
		t.Errorf("ackee read: want ok, got %s", got)
	}
	if caller.gotResolver != "con1owner" || caller.gotAPI != "net.concrnt.core.acknowledges" {
		t.Errorf("unexpected call target: resolver=%q api=%q", caller.gotResolver, caller.gotAPI)
	}
	if caller.gotParams["from"] != "con1owner" || caller.gotParams["to"] != "con1friend" {
		t.Errorf("unexpected call params: %v", caller.gotParams)
	}

	// a stranger: the API returns an empty list -> default ng
	caller = &fakeCaller{result: []any{}}
	if got := evaluate(t, p, req("con1stranger", caller), "record:read", ""); got != policy.NG {
		t.Errorf("stranger read: want ng, got %s", got)
	}

	// the API call fails: fail-closed to default ng
	caller = &fakeCaller{err: errors.New("resolver offline")}
	conclusion, _, err := policy.EvaluatePolicy(context.Background(), p, req("con1friend", caller), "record:read", "")
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if conclusion != policy.NG {
		t.Errorf("caller error: want ng (fail-closed), got %s", conclusion)
	}

	// an anonymous requester (empty ccid) is denied even if the API would
	// return something for to=""
	caller = &fakeCaller{result: []any{map[string]any{"document": "x"}}}
	if got := evaluate(t, p, req("", caller), "record:read", ""); got != policy.NG {
		t.Errorf("anonymous read: want ng, got %s", got)
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
