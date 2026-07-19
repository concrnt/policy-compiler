package compiler

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

// compileStatement compiles one definition of an allow/deny/ok/ng rule into a
// concrnt Statement. The emit is the rule name; the action, key pattern, and
// (for `contains reason` heads) the reason binding are extracted from the body
// and the remaining literals become the condition.
func compileStatement(rule *ast.Rule, ec *exprCompiler, errs *ErrorList) *Statement {
	emit := string(rule.Head.Name)

	if rule.Default {
		errs.add(rule.Loc(), "`default` rules are not supported",
			`declare defaults with a top-level rule: defaults := {"record:read": "ok"}`)
		return nil
	}
	if rule.Head.Args != nil {
		errs.add(rule.Loc(), "function definitions are not supported", "")
		return nil
	}
	if rule.Else != nil {
		errs.add(rule.Loc(), "`else` is not supported",
			"write separate statement rules instead")
		return nil
	}

	var reason *string
	reasonVar := ""
	if rule.Head.Key == nil {
		if rule.Head.Value != nil && !rule.Head.Value.Equal(ast.BooleanTerm(true)) {
			errs.add(rule.Loc(), "statement rules cannot have a value",
				fmt.Sprintf("use `%s contains \"reason\" if { ... }` to attach a reason", emit))
			return nil
		}
	} else {
		switch k := rule.Head.Key.Value.(type) {
		case ast.String:
			s := string(k)
			reason = &s
		case ast.Var:
			reasonVar = string(k)
		default:
			errs.add(rule.Head.Key.Loc(), "reason must be a string literal or a variable bound to one",
				fmt.Sprintf("e.g. %s contains \"reason text\" if { ... }", emit))
			return nil
		}
	}

	var action, key string
	rest := ast.Body{}
	for _, lit := range rule.Body {
		op, args, isCall := exprCall(lit)
		switch {
		case isCall && op == "equal" && len(args) == 2 && (isInputMetaRef(args[0], "action") || isInputMetaRef(args[1], "action")):
			if lit.Negated {
				errs.add(lit.Loc(), "the action literal cannot be negated", "")
				continue
			}
			other := args[1]
			if isInputMetaRef(args[1], "action") {
				other = args[0]
			}
			s, isStr := other.Value.(ast.String)
			if !isStr || s == "" {
				errs.add(lit.Loc(), "input.action must be compared to a non-empty string constant",
					`e.g. input.action == "record:read"`)
				continue
			}
			if action != "" {
				errs.add(lit.Loc(), "duplicate action literal in statement", "")
				continue
			}
			action = string(s)
		case isCall && op == keyMatchesFunc:
			if lit.Negated {
				errs.add(lit.Loc(), "key_matches() cannot be negated", "")
				continue
			}
			if len(args) != 1 {
				errs.add(lit.Loc(), fmt.Sprintf("key_matches() takes exactly one string literal, got %d arguments", len(args)), "")
				continue
			}
			s, isStr := args[0].Value.(ast.String)
			if !isStr || s == "" {
				errs.add(lit.Loc(), "key_matches() takes exactly one non-empty string literal",
					`e.g. key_matches("./*")`)
				continue
			}
			if key != "" {
				errs.add(lit.Loc(), "duplicate key_matches() in statement", "")
				continue
			}
			key = string(s)
		case isCall && op == "assign" && reasonVar != "" && len(args) == 2 && isVarNamed(args[0], reasonVar):
			if lit.Negated {
				errs.add(lit.Loc(), "the reason binding cannot be negated", "")
				continue
			}
			s, isStr := args[1].Value.(ast.String)
			if !isStr {
				errs.add(lit.Loc(), fmt.Sprintf("head variable %q must be bound to a string constant", reasonVar), "")
				continue
			}
			if reason != nil {
				errs.add(lit.Loc(), fmt.Sprintf("duplicate binding of head variable %q", reasonVar), "")
				continue
			}
			r := string(s)
			reason = &r
		default:
			rest = append(rest, lit)
		}
	}

	if action == "" {
		errs.add(rule.Loc(), fmt.Sprintf("statement %q does not pin its action", emit),
			`add a literal like: input.action == "record:read"`)
	}
	if key == "" {
		errs.add(rule.Loc(), fmt.Sprintf("statement %q has no key pattern", emit),
			`add key_matches("*") to apply the statement to all keys`)
	}
	if reasonVar != "" && reason == nil {
		errs.add(rule.Head.Key.Loc(), fmt.Sprintf("head variable %q is not bound to a string constant in the body", reasonVar),
			fmt.Sprintf(`bind it: %s := "reason text"`, reasonVar))
	}

	condition := Expr{Op: opConst, Const: true}
	if len(rest) > 0 {
		condition = ec.compileBody(rest)
	}

	return &Statement{
		Action:    action,
		Key:       key,
		Emit:      emit,
		Reason:    reason,
		Condition: condition,
	}
}

// exprCall unpacks a call literal into its operator name and arguments.
func exprCall(lit *ast.Expr) (string, []*ast.Term, bool) {
	terms, ok := lit.Terms.([]*ast.Term)
	if !ok {
		return "", nil, false
	}
	ref, ok := terms[0].Value.(ast.Ref)
	if !ok {
		return "", nil, false
	}
	return ref.String(), terms[1:], true
}

// isInputMetaRef reports whether the term is exactly `input.<field>`.
func isInputMetaRef(t *ast.Term, field string) bool {
	ref, ok := t.Value.(ast.Ref)
	if !ok || len(ref) != 2 {
		return false
	}
	head, ok := ref[0].Value.(ast.Var)
	if !ok || head != ast.Var("input") {
		return false
	}
	s, ok := ref[1].Value.(ast.String)
	return ok && string(s) == field
}

func isVarNamed(t *ast.Term, name string) bool {
	v, ok := t.Value.(ast.Var)
	return ok && string(v) == name
}
