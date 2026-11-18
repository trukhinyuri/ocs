// Emit the typed statement shape and printed expression tokens of Go functions.
// The independent wire translator accepts a closed set of expression shapes.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type statement struct {
	Kind string      `json:"kind"`
	Expr string      `json:"expr,omitempty"`
	Init string      `json:"init,omitempty"`
	Body []statement `json:"body,omitempty"`
	Else []statement `json:"else,omitempty"`
}

type reader struct{ files *token.FileSet }

func (r reader) tokens(n ast.Node) string {
	if n == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, r.files, n); err != nil {
		panic(err)
	}
	return buf.String()
}

func (r reader) block(body []ast.Stmt) []statement {
	out := make([]statement, 0, len(body))
	for _, s := range body {
		out = append(out, r.stmt(s))
	}
	return out
}

func (r reader) stmt(s ast.Stmt) statement {
	switch n := s.(type) {
	case *ast.IfStmt:
		row := statement{Kind: "if", Expr: r.tokens(n.Cond), Init: r.tokens(n.Init), Body: r.block(n.Body.List)}
		switch alt := n.Else.(type) {
		case nil:
		case *ast.BlockStmt:
			row.Else = r.block(alt.List)
		default:
			row.Else = []statement{r.stmt(alt)}
		}
		return row
	case *ast.SwitchStmt:
		return statement{Kind: "switch", Expr: r.tokens(n.Tag), Init: r.tokens(n.Init), Body: r.block(n.Body.List)}
	case *ast.CaseClause:
		values := make([]string, 0, len(n.List))
		for _, c := range n.List {
			values = append(values, r.tokens(c))
		}
		return statement{Kind: "case", Expr: strings.Join(values, ","), Body: r.block(n.Body)}
	case *ast.RangeStmt:
		return statement{Kind: "range", Expr: r.tokens(n.X), Init: r.tokens(n.Key) + "," + r.tokens(n.Value), Body: r.block(n.Body.List)}
	case *ast.ForStmt:
		return statement{Kind: "for", Expr: r.tokens(n.Cond), Init: r.tokens(n.Init), Body: r.block(n.Body.List)}
	default:
		return statement{Kind: "stmt", Expr: r.tokens(s)}
	}
}

func main() {
	r := reader{files: token.NewFileSet()}
	functions := make(map[string][]statement)
	for _, name := range os.Args[1:] {
		f, err := parser.ParseFile(r.files, name, nil, parser.SkipObjectResolution)
		if err != nil {
			panic(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				key := "#" + filepath.Base(name)
				functions[key] = append(functions[key], statement{Kind: "decl", Expr: r.tokens(decl)})
				continue
			}
			if fn.Body == nil {
				continue
			}
			if _, duplicated := functions[fn.Name.Name]; duplicated {
				panic(fmt.Sprintf("duplicate function %q", fn.Name.Name))
			}
			functions[fn.Name.Name] = r.block(fn.Body.List)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(functions); err != nil {
		panic(err)
	}
}
