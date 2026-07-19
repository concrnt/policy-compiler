package compiler

import (
	"fmt"

	"github.com/concrnt/concrnt/policy"
	"github.com/open-policy-agent/opa/v1/ast"
)

// extractDefaults parses the reserved `defaults := {"<action>": "<conclusion>"}`
// rule into the document's defaults map.
func extractDefaults(rules []*ast.Rule, errs *ErrorList) map[string]policy.Conclusion {
	if len(rules) == 0 {
		return nil
	}
	if len(rules) > 1 {
		errs.add(rules[1].Loc(), "duplicate defaults rule", "")
	}
	rule := rules[0]

	if rule.Default {
		errs.add(rule.Loc(), "`default defaults := ...` is not supported",
			`write a plain assignment: defaults := {"record:read": "ok"}`)
		return nil
	}
	if rule.Head.Key != nil || rule.Head.Args != nil || !rule.Head.Assign {
		errs.add(rule.Loc(), "defaults must be a plain := assignment",
			`defaults := {"record:read": "ok"}`)
		return nil
	}
	if !isTrueBody(rule.Body) {
		errs.add(rule.Loc(), "defaults must be unconditional", "remove the `if { ... }` body")
		return nil
	}
	obj, ok := rule.Head.Value.Value.(ast.Object)
	if !ok {
		errs.add(rule.Head.Value.Loc(), "defaults must be an object literal",
			`defaults := {"record:read": "ok"}`)
		return nil
	}

	out := map[string]policy.Conclusion{}
	obj.Foreach(func(k, v *ast.Term) {
		ks, ok := k.Value.(ast.String)
		if !ok {
			errs.add(k.Loc(), "defaults keys must be action strings", `e.g. "record:read"`)
			return
		}
		vs, ok := v.Value.(ast.String)
		if !ok || !isValidConclusion(string(vs)) {
			errs.add(v.Loc(), fmt.Sprintf("invalid default conclusion %v for action %q", v, ks),
				"valid conclusions are: ok, ng, allow, deny")
			return
		}
		out[string(ks)] = policy.ParseConclusion(string(vs))
	})
	return out
}

// isTrueBody reports whether the body is the single literal `true` — which is
// what the parser generates for a bodyless value rule.
func isTrueBody(body ast.Body) bool {
	if len(body) != 1 || body[0].Negated {
		return false
	}
	t, ok := body[0].Terms.(*ast.Term)
	if !ok {
		return false
	}
	b, ok := t.Value.(ast.Boolean)
	return ok && bool(b)
}
