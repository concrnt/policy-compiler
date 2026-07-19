package compiler

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// exprCompiler translates rule bodies into concrnt policy expression trees.
type exprCompiler struct {
	rules    map[string][]*ast.Rule // all rule groups of the module, by name
	memo     map[string]*Expr
	visiting map[string]bool
	errs     *ErrorList
}

func newExprCompiler(rules map[string][]*ast.Rule, errs *ErrorList) *exprCompiler {
	return &exprCompiler{
		rules:    rules,
		memo:     map[string]*Expr{},
		visiting: map[string]bool{},
		errs:     errs,
	}
}

var errExpr = Expr{Op: "<error>"}

// compileRuleGroup compiles all definitions of one rule name.
// Multiple definitions are OR-ed together.
func (c *exprCompiler) compileRuleGroup(rules []*ast.Rule) Expr {
	exprs := make([]Expr, 0, len(rules))
	for _, rule := range rules {
		if !c.checkRuleShape(rule) {
			continue
		}
		exprs = append(exprs, c.compileBody(rule.Body))
	}
	return nAry(opOr, exprs)
}

// checkRuleShape rejects rule forms outside the subset (values, args, else, defaults).
func (c *exprCompiler) checkRuleShape(rule *ast.Rule) bool {
	if rule.Default {
		c.errs.add(rule.Loc(), "`default` rules are not supported",
			`declare defaults with a top-level rule: defaults := {"record:read": "ok"}`)
		return false
	}
	if rule.Head.Args != nil {
		c.errs.add(rule.Loc(), "function definitions are not supported", "")
		return false
	}
	if rule.Head.Value != nil && !rule.Head.Value.Equal(ast.BooleanTerm(true)) {
		c.errs.add(rule.Loc(), "rules with values are not supported",
			"only plain boolean rules (`name if { ... }`) can be compiled")
		return false
	}
	if rule.Head.RuleKind() == ast.MultiValue {
		c.errs.add(rule.Loc(), "helper rules cannot use `contains`",
			"only statement rules (allow/deny/ok/ng) may declare a reason with `contains`")
		return false
	}
	if rule.Else != nil {
		c.errs.add(rule.Loc(), "`else` is not supported",
			"split into separate rules; definitions of the same rule are OR-ed")
		return false
	}
	return true
}

// compileBody AND-s the literals of one rule body.
func (c *exprCompiler) compileBody(body ast.Body) Expr {
	exprs := make([]Expr, 0, len(body))
	for _, e := range body {
		exprs = append(exprs, c.compileExpr(e))
	}
	return nAry(opAnd, exprs)
}

func (c *exprCompiler) compileExpr(e *ast.Expr) Expr {
	var out Expr
	switch terms := e.Terms.(type) {
	case []*ast.Term:
		out = c.compileCall(e.Loc(), terms)
	case *ast.Term:
		out = c.compileTerm(terms)
	default:
		c.errs.addf(e.Loc(), "unsupported statement form (%T)", e.Terms)
		return errExpr
	}
	if e.Negated {
		out = Expr{Op: opNot, Args: []Expr{out}}
	}
	return out
}

func (c *exprCompiler) compileCall(loc *ast.Location, terms []*ast.Term) Expr {
	opRef, ok := terms[0].Value.(ast.Ref)
	if !ok {
		c.errs.addf(loc, "unsupported expression")
		return errExpr
	}
	args := terms[1:]

	switch opRef.String() {
	case "equal": // ==
		return Expr{Op: opEq, Args: []Expr{c.compileTerm(args[0]), c.compileTerm(args[1])}}
	case "neq": // !=
		return Expr{Op: opNot, Args: []Expr{
			{Op: opEq, Args: []Expr{c.compileTerm(args[0]), c.compileTerm(args[1])}},
		}}
	case "internal.member_2": // `x in xs` — concrnt's Contains takes (list, element)
		return Expr{Op: opContains, Args: []Expr{c.compileTerm(args[1]), c.compileTerm(args[0])}}
	case "eq": // unification `=`
		c.errs.add(loc, "unification (`=`) is not supported", "use `==` for comparison")
		return errExpr
	case "assign":
		c.errs.add(loc, "assignment (`:=`) is not supported here",
			"only the head variable of a `contains reason` statement may be bound with := (to a string constant)")
		return errExpr
	case "lt", "lte", "gt", "gte":
		c.errs.add(loc, "numeric comparisons are not supported",
			"the concrnt policy engine only provides equality (`==`) and membership (`in`)")
		return errExpr
	case "plus", "minus", "mul", "div", "rem":
		c.errs.add(loc, "arithmetic is not supported by the concrnt policy engine", "")
		return errExpr
	case keyMatchesFunc:
		c.errs.add(loc, "key_matches() can only appear at the top level of a statement rule body",
			"it selects which keys the statement applies to and cannot be part of a condition")
		return errExpr
	case "ccuri_owner":
		return c.compileCCUriOwner(loc, args)
	default:
		c.errs.add(loc, fmt.Sprintf("built-in function %q is not supported", opRef.String()),
			"supported operations: ==, !=, `in`, `not`, and ccuri_owner()")
		return errExpr
	}
}

func (c *exprCompiler) compileCCUriOwner(loc *ast.Location, args []*ast.Term) Expr {
	if len(args) != 1 {
		c.errs.add(loc, fmt.Sprintf("ccuri_owner() takes exactly 1 argument, got %d", len(args)), "")
		return errExpr
	}
	return Expr{Op: opCCUriOwner, Args: []Expr{c.compileTerm(args[0])}}
}

func (c *exprCompiler) compileTerm(t *ast.Term) Expr {
	switch v := t.Value.(type) {
	case ast.Boolean:
		return Expr{Op: opConst, Const: bool(v)}
	case ast.String:
		return Expr{Op: opConst, Const: string(v)}
	case ast.Number:
		f, ok := v.Float64()
		if !ok {
			c.errs.addf(t.Loc(), "number %v cannot be represented as a float64", v)
			return errExpr
		}
		// float64 matches what concrnt sees after JSON-decoding the context
		return Expr{Op: opConst, Const: f}
	case ast.Null:
		c.errs.add(t.Loc(), "null is not supported", "")
		return errExpr
	case ast.Ref:
		return c.compileRef(t.Loc(), v)
	case ast.Var:
		return c.inlineRule(t.Loc(), string(v))
	case ast.Call:
		return c.compileCall(t.Loc(), []*ast.Term(v))
	case *ast.Array:
		return c.compileArray(v)
	case ast.Set, ast.Object:
		c.errs.add(t.Loc(), "set and object literals are not supported",
			"the concrnt policy engine only handles scalars and arrays")
		return errExpr
	default:
		c.errs.addf(t.Loc(), "unsupported term (%T)", t.Value)
		return errExpr
	}
}

// compileArray turns an array of scalar literals into a Const expression.
func (c *exprCompiler) compileArray(arr *ast.Array) Expr {
	vals := make([]any, 0, arr.Len())
	ok := true
	arr.Foreach(func(el *ast.Term) {
		switch v := el.Value.(type) {
		case ast.Boolean:
			vals = append(vals, bool(v))
		case ast.String:
			vals = append(vals, string(v))
		case ast.Number:
			f, isF := v.Float64()
			if !isF {
				c.errs.addf(el.Loc(), "number %v cannot be represented as a float64", v)
				ok = false
				return
			}
			vals = append(vals, f)
		default:
			c.errs.add(el.Loc(), "array literals may only contain scalar constants", "")
			ok = false
		}
	})
	if !ok {
		return errExpr
	}
	return Expr{Op: opConst, Const: vals}
}

// compileRef turns `input.a.b.c` into a Load expression.
func (c *exprCompiler) compileRef(loc *ast.Location, ref ast.Ref) Expr {
	head, ok := ref[0].Value.(ast.Var)
	if !ok || head != ast.InputRootDocument.Value.(ast.Var) {
		c.errs.add(loc, fmt.Sprintf("reference %v is not supported", ref),
			"only `input.*` references and rule names can be used")
		return errExpr
	}
	if len(ref) < 2 {
		c.errs.add(loc, "bare `input` cannot be used as a value", "")
		return errExpr
	}

	segs := make([]string, 0, len(ref)-1)
	for _, term := range ref[1:] {
		s, ok := term.Value.(ast.String)
		if !ok {
			c.errs.add(loc, fmt.Sprintf("dynamic or non-string index in reference %v", ref),
				"iteration (`xs[_]`) and computed indexing are not supported; use `in` for membership tests")
			return errExpr
		}
		segs = append(segs, string(s))
	}

	switch {
	case segs[0] == "action":
		c.errs.add(loc, "input.action can only be used as a top-level literal `input.action == \"...\"` in a statement rule body", "")
		return errExpr
	case segs[0] == "key":
		c.errs.add(loc, "input.key is not available in conditions",
			`use key_matches("<pattern>") in the statement body to scope the statement`)
		return errExpr
	case !loadRoots[segs[0]]:
		c.errs.add(loc, fmt.Sprintf("unknown context root %q in %v", segs[0], ref),
			"valid roots: requester, requester_domain, parent, self, params, globals")
		return errExpr
	}

	return Expr{Op: opLoad, Const: strings.Join(segs, ".")}
}

// inlineRule expands a reference to another rule of the same module.
func (c *exprCompiler) inlineRule(loc *ast.Location, name string) Expr {
	if strings.HasPrefix(name, "$") {
		c.errs.add(loc, "wildcard or generated variables are not supported", "")
		return errExpr
	}
	if statementNames[name] {
		c.errs.add(loc, "statement rules (allow/deny/ok/ng) cannot be referenced from conditions",
			"move the shared logic into a helper rule and reference that instead")
		return errExpr
	}
	if name == defaultsRuleName {
		c.errs.add(loc, "the defaults rule cannot be referenced from conditions", "")
		return errExpr
	}
	if compiled, ok := c.memo[name]; ok {
		return *compiled
	}
	rules, ok := c.rules[name]
	if !ok {
		c.errs.add(loc, fmt.Sprintf("undefined rule or variable %q", name),
			"local variables are not supported; define a helper rule instead")
		return errExpr
	}
	if c.visiting[name] {
		c.errs.addf(loc, "circular reference through rule %q", name)
		return errExpr
	}
	c.visiting[name] = true
	expr := c.compileRuleGroup(rules)
	delete(c.visiting, name)
	c.memo[name] = &expr
	return expr
}

// nAry wraps exprs in the given operator, unwrapping the trivial 1-element case
// so output matches hand-written policies.
func nAry(op string, exprs []Expr) Expr {
	if len(exprs) == 1 {
		return exprs[0]
	}
	return Expr{Op: op, Args: exprs}
}
