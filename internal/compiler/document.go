package compiler

// DefaultVersion is the only policy engine version currently supported by concrnt.
const DefaultVersion = "2025-12-23"

// Conclusion values accepted for statement emit and defaults.
var validConclusions = map[string]bool{
	"ok":    true,
	"ng":    true,
	"allow": true,
	"deny":  true,
}

// Expr is the concrnt policy expression tree.
// It mirrors concrnt's policy.Expr but with `omitempty` on Args so that
// leaf nodes serialize in the short form (e.g. {"op":"Load","const":"requester.ccid"}),
// matching the hand-written policies in world-policies.
type Expr struct {
	Op    string `json:"op"`
	Args  []Expr `json:"args,omitempty"`
	Const any    `json:"const,omitempty"`
}

// Statement mirrors concrnt's policy.Statement.
type Statement struct {
	Action    string  `json:"action"`
	Key       string  `json:"key,omitempty"`
	Emit      string  `json:"emit"`
	Reason    *string `json:"reason,omitempty"`
	Condition Expr    `json:"condition"`
}

// VersionBody is the value of a version entry in a policy document.
// concrnt's policy.Policy has no ParamSchema field, but real-world policy
// documents carry one for client-side form generation, so it is passed through.
type VersionBody struct {
	Statements  []Statement       `json:"statements"`
	Defaults    map[string]string `json:"defaults,omitempty"`
	ParamSchema map[string]any    `json:"paramSchema,omitempty"`
}

// Document is a complete concrnt policy document (concrnt's policy.PolicyDocument).
type Document struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Versions    map[string]VersionBody `json:"versions"`
}

// Operator names understood by concrnt's policy engine.
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
