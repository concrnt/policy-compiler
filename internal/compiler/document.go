package compiler

import (
	"encoding/json"

	"github.com/concrnt/concrnt/policy"
)

// DefaultVersion is the only policy engine version currently supported by concrnt.
const DefaultVersion = "2025-12-23"

// VersionBody is the value of a version entry in a policy document.
// Statements and Defaults are concrnt's own policy types; ParamSchema is not
// part of policy.Policy but real-world policy documents carry one for
// client-side form generation, so it is passed through.
type VersionBody struct {
	Statements  []policy.Statement           `json:"statements"`
	Defaults    map[string]policy.Conclusion `json:"defaults,omitempty"`
	ParamSchema map[string]any               `json:"paramSchema,omitempty"`
}

// Document is a complete concrnt policy document. It mirrors concrnt's
// policy.PolicyDocument, but with typed version bodies (concrnt uses
// map[string]any) and omitempty on Description.
type Document struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Versions    map[string]VersionBody `json:"versions"`
}

// exprJSON mirrors policy.Expr with `omitempty` on Args so that leaf nodes
// serialize in the short form (e.g. {"op":"Load","const":"requester.ccid"}),
// matching the hand-written policies in world-policies. policy.Expr itself
// would emit "args": null there.
type exprJSON struct {
	Op    string     `json:"op"`
	Args  []exprJSON `json:"args,omitempty"`
	Const any        `json:"const,omitempty"`
}

func toExprJSON(e policy.Expr) exprJSON {
	out := exprJSON{Op: e.Operator, Const: e.Const}
	for _, arg := range e.Args {
		out.Args = append(out.Args, toExprJSON(arg))
	}
	return out
}

// statementJSON is the serialization shape of policy.Statement, using exprJSON
// for the condition.
type statementJSON struct {
	Action    string            `json:"action"`
	Key       string            `json:"key,omitempty"`
	Emit      policy.Conclusion `json:"emit"`
	Reason    *string           `json:"reason,omitempty"`
	Condition exprJSON          `json:"condition"`
}

func (b VersionBody) MarshalJSON() ([]byte, error) {
	statements := make([]statementJSON, len(b.Statements))
	for i, stmt := range b.Statements {
		statements[i] = statementJSON{
			Action:    stmt.Action,
			Key:       stmt.Key,
			Emit:      stmt.Emit,
			Reason:    stmt.Reason,
			Condition: toExprJSON(stmt.Condition),
		}
	}
	return json.Marshal(struct {
		Statements  []statementJSON              `json:"statements"`
		Defaults    map[string]policy.Conclusion `json:"defaults,omitempty"`
		ParamSchema map[string]any               `json:"paramSchema,omitempty"`
	}{statements, b.Defaults, b.ParamSchema})
}

// isValidConclusion reports whether s is a conclusion a statement may emit or
// a default may declare.
func isValidConclusion(s string) bool {
	return policy.ParseConclusion(s) != policy.UNSET
}

// Operator names understood by concrnt's policy engine
// (registered in concrnt/policy/operators.go).
const (
	opAnd        = "And"
	opOr         = "Or"
	opNot        = "Not"
	opEq         = "Eq"
	opContains   = "Contains"
	opCCUriOwner = "CCUriOwner"
	opLoad       = "Load"
	opConst      = "Const"
)

// statementNames maps rule names to the conclusion they emit. Only rules with
// these names produce statements; every definition is one statement.
var statementNames = map[string]bool{
	"allow": true,
	"deny":  true,
	"ok":    true,
	"ng":    true,
}

// Reserved rule names of the dialect.
const (
	defaultsRuleName = "defaults"
	keyMatchesFunc   = "key_matches"
)

// loadRoots are the top-level keys of concrnt's policy.RequestContext,
// i.e. the only valid roots for input references.
var loadRoots = map[string]bool{
	"requester":        true,
	"requester_domain": true,
	"parent":           true,
	"self":             true,
	"params":           true,
	"globals":          true,
}
