package compiler

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// CompileError is a single error with source position and an optional hint.
type CompileError struct {
	Path string
	Row  int
	Col  int
	Msg  string
	Hint string
}

func (e *CompileError) Error() string {
	var b strings.Builder
	if e.Path != "" {
		fmt.Fprintf(&b, "%s:%d:%d: ", e.Path, e.Row, e.Col)
	}
	b.WriteString(e.Msg)
	if e.Hint != "" {
		fmt.Fprintf(&b, " (hint: %s)", e.Hint)
	}
	return b.String()
}

// ErrorList collects all errors found in one compilation so they can be
// reported together, like OPA's ast.Errors.
type ErrorList struct {
	errs []*CompileError
}

func (l *ErrorList) add(loc *ast.Location, msg, hint string) {
	e := &CompileError{Msg: msg, Hint: hint}
	if loc != nil {
		e.Path = loc.File
		e.Row = loc.Row
		e.Col = loc.Col
	}
	l.errs = append(l.errs, e)
}

func (l *ErrorList) addf(loc *ast.Location, format string, args ...any) {
	l.add(loc, fmt.Sprintf(format, args...), "")
}

func (l *ErrorList) empty() bool { return len(l.errs) == 0 }

func (l *ErrorList) Error() string {
	msgs := make([]string, len(l.errs))
	for i, e := range l.errs {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "\n")
}
