package compiler

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// docMeta is the package-scope METADATA of a policy module.
type docMeta struct {
	Name        string
	Description string
	Version     string
	ParamSchema map[string]any
}

func extractDocMeta(mod *ast.Module, errs *ErrorList) docMeta {
	meta := docMeta{Version: DefaultVersion}

	// fallback name: last segment of the package path, underscores to hyphens
	path := mod.Package.Path.String() // e.g. "data.restrict_readers"
	segs := strings.Split(path, ".")
	meta.Name = strings.ReplaceAll(segs[len(segs)-1], "_", "-")

	var ann *ast.Annotations
	for _, a := range mod.Annotations {
		if a.Scope == "package" || a.Scope == "subpackages" {
			if ann != nil {
				errs.add(a.Loc(), "duplicate package-scope METADATA", "")
				continue
			}
			ann = a
		}
	}
	if ann == nil {
		return meta
	}

	if ann.Title != "" {
		meta.Name = ann.Title
	}
	meta.Description = ann.Description

	for key, val := range ann.Custom {
		switch key {
		case "version":
			s, ok := val.(string)
			if !ok {
				errs.add(ann.Loc(), fmt.Sprintf("custom.version must be a string, got %T", val),
					`quote the value, e.g. version: "2025-12-23"`)
				continue
			}
			if s != DefaultVersion {
				errs.add(ann.Loc(), fmt.Sprintf("unsupported policy version %q", s),
					fmt.Sprintf("only %q is supported by the concrnt policy engine", DefaultVersion))
				continue
			}
			meta.Version = s
		case "defaults":
			errs.add(ann.Loc(), "custom.defaults in package METADATA is no longer supported",
				`declare defaults as a rule instead: defaults := {"record:create": "ng", ...}`)
		case "paramSchema":
			m, ok := val.(map[string]any)
			if !ok {
				errs.add(ann.Loc(), fmt.Sprintf("custom.paramSchema must be a map (JSON Schema), got %T", val), "")
				continue
			}
			meta.ParamSchema = m
		case "action", "key", "emit", "reason":
			errs.add(ann.Loc(), fmt.Sprintf("METADATA statements are no longer supported (found custom.%s)", key),
				`name the rule after its emit (allow/deny/ok/ng), pin the action with input.action == "...", the key with key_matches("..."), and put the reason in the head: deny contains "reason" if { ... }`)
		default:
			errs.add(ann.Loc(), fmt.Sprintf("unknown package METADATA custom key %q", key),
				"supported keys are: version, paramSchema")
		}
	}

	return meta
}

// isLegacyStmtRule reports (and flags as an error) rules still carrying the
// retired METADATA statement annotations, so they get one migration error
// instead of a cascade of dialect errors.
func isLegacyStmtRule(rule *ast.Rule, errs *ErrorList) bool {
	for _, a := range rule.Annotations {
		if a.Custom == nil {
			continue
		}
		for _, k := range []string{"action", "key", "emit", "reason"} {
			if _, ok := a.Custom[k]; ok {
				errs.add(a.Loc(), "rule-scope METADATA statements are no longer supported",
					`name the rule after its emit (allow/deny/ok/ng), pin the action with input.action == "...", the key with key_matches("..."), and put the reason in the head: deny contains "reason" if { ... }`)
				return true
			}
		}
	}
	return false
}
