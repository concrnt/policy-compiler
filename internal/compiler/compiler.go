package compiler

import (
	"fmt"
	"os"

	"github.com/concrnt/concrnt/policy"
	"github.com/open-policy-agent/opa/v1/ast"
)

// CompileFile compiles one .rego file into a concrnt policy document.
func CompileFile(path string) (*Document, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Compile(path, string(src))
}

// Compile parses and compiles Rego source into a concrnt policy document.
// The returned error is an *ErrorList (or OPA's ast.Errors for parse errors).
func Compile(filename string, src string) (*Document, error) {
	mod, err := ast.ParseModuleWithOpts(filename, src, ast.ParserOptions{ProcessAnnotation: true})
	if err != nil {
		return nil, err
	}

	errs := &ErrorList{}
	meta := extractDocMeta(mod, errs)

	if len(mod.Imports) > 0 {
		errs.add(mod.Imports[0].Loc(), "imports are not supported",
			"a policy document must be a single self-contained module")
	}

	// classify rules: statements (allow/deny/ok/ng, one definition = one
	// statement), the reserved defaults rule, and helper rules by name
	var stmtRules []*ast.Rule
	var defaultsRules []*ast.Rule
	helpers := map[string][]*ast.Rule{}
	var helperOrder []string
	for _, rule := range mod.Rules {
		if isLegacyStmtRule(rule, errs) {
			continue
		}
		name := string(rule.Head.Name)
		if name == "" {
			errs.add(rule.Loc(), "rules with reference heads (a.b ...) are not supported", "")
			continue
		}
		switch {
		case statementNames[name]:
			stmtRules = append(stmtRules, rule)
		case name == defaultsRuleName:
			defaultsRules = append(defaultsRules, rule)
		case name == keyMatchesFunc:
			errs.add(rule.Loc(), fmt.Sprintf("%q is a reserved name and cannot be defined", keyMatchesFunc), "")
		default:
			if _, seen := helpers[name]; !seen {
				helperOrder = append(helperOrder, name)
			}
			helpers[name] = append(helpers[name], rule)
		}
	}

	ec := newExprCompiler(helpers, errs)

	statements := make([]policy.Statement, 0, len(stmtRules))
	for _, rule := range stmtRules {
		if stmt := compileStatement(rule, ec, errs); stmt != nil {
			statements = append(statements, *stmt)
		}
	}

	defaults := extractDefaults(defaultsRules, errs)

	// helper rules that were never inlined are dead code — likely a
	// misspelled statement rule name, so flag them.
	for _, name := range helperOrder {
		if ec.memo[name] == nil {
			errs.add(helpers[name][0].Loc(), fmt.Sprintf("helper rule %q is never referenced by a statement", name),
				"statements are rules named allow/deny/ok/ng; reference the helper from one, or remove it")
		}
	}

	if len(statements) == 0 && len(defaults) == 0 {
		errs.add(mod.Package.Loc(), "policy has no statements and no defaults", "")
	}

	if !errs.empty() {
		return nil, errs
	}

	return &Document{
		Name:        meta.Name,
		Description: meta.Description,
		Versions: map[string]VersionBody{
			meta.Version: {
				Statements:  statements,
				Defaults:    defaults,
				ParamSchema: meta.ParamSchema,
			},
		},
	}, nil
}
