// Extract the ARTEx code-default prompt constants into editable text files.
// Usage: go run ./scripts/extract_prompts.go <ARTEx-source-root> <output-dir>
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type promptRef struct{ file, name, output string }

var prompts = []promptRef{
	{"agent/goals.go", "goalsDefaultTmpl", "goals/system.md"},
	{"agent/goals.go", "goalsScopeTail", "goals/code-owned-scope-tail.md"},
	{"agent/planner.go", "plannerDefaultTmpl", "planner/system.md"},
	{"agent/mainagent.go", "mainAgentDefaultTmpl", "mainagent/system.md"},
	{"agent/worker.go", "workerDefaultTmpl", "worker/system.md"},
	{"agent/worker.go", "settleWrapUpPrompt", "worker/wrapup.md"},
	{"agent/promptcatalog.go", "autoDefaultTmpl", "auto/system.md"},
	{"agent/promptcatalog.go", "pentestDefaultTmpl", "pentest/system.md"},
	{"agent/promptcatalog.go", "ReporterDefaultPrompt", "reporter/system.md"},
	{"agent/retester.go", "RetesterDefaultPrompt", "retester/system.md"},
	{"agent/wrapup.go", "plannerWrapUpDefault", "planner/wrapup.md"},
	{"agent/wrapup.go", "mainAgentWrapUpDefault", "mainagent/wrapup.md"},
	{"agent/wrapup.go", "genericWrapUpDefault", "generic-wrapup.md"},
	{"agent/wrapup.go", "workerTaskTimeoutDefault", "worker/task-timeout-wrapup.md"},
	{"agent/wrapup.go", "plannerTaskTimeoutDefault", "planner/task-timeout-wrapup.md"},
}

func evalString(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING { return "", false }
		v, err := strconv.Unquote(e.Value)
		return v, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD { return "", false }
		left, lok := evalString(e.X); right, rok := evalString(e.Y)
		return left + right, lok && rok
	case *ast.ParenExpr:
		return evalString(e.X)
	default:
		return "", false
	}
}

func extract(root, relative, name string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(relative))
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil { return "", err }
	for _, decl := range f.Decls {
		g, ok := decl.(*ast.GenDecl); if !ok || g.Tok != token.CONST { continue }
		for _, spec := range g.Specs {
			v := spec.(*ast.ValueSpec)
			for i, id := range v.Names {
				if id.Name == name && i < len(v.Values) {
					if value, ok := evalString(v.Values[i]); ok { return value, nil }
					return "", fmt.Errorf("%s is not a constant string expression", name)
				}
			}
		}
	}
	return "", fmt.Errorf("constant %s not found in %s", name, relative)
}

func main() {
	if len(os.Args) != 3 { fmt.Fprintln(os.Stderr, "usage: go run ./scripts/extract_prompts.go <ARTEx-source-root> <output-dir>"); os.Exit(2) }
	root, out := os.Args[1], os.Args[2]
	for _, p := range prompts {
		body, err := extract(root, p.file, p.name)
		if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
		dst := filepath.Join(out, filepath.FromSlash(p.output))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { panic(err) }
		if err := os.WriteFile(dst, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil { panic(err) }
	}
	fmt.Printf("Extracted %d ARTEx prompt/default constants into %s\n", len(prompts), out)
}
