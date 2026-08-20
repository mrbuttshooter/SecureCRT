package store_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoUnrebound guards a trap built into store.DB's design.
//
// DB embeds *sql.DB and Tx embeds *sql.Tx, so the promoted ExecContext,
// QueryContext and QueryRowContext methods are reachable from anywhere. Those
// do NOT rewrite ? placeholders into Postgres's $1 form. A query written with
// the promoted method therefore works perfectly on SQLite and fails only on
// PostgreSQL — that is, it passes local development and breaks in production.
//
// This walks the AST of every package outside internal/store and fails if any
// of them calls one of those methods. Callers must use the ctx-first
// Exec/Query/QueryRow wrappers, which rebind.
func TestNoUnrebound(t *testing.T) {
	root := repoRoot(t)

	forbidden := map[string]string{
		"ExecContext":     "Exec",
		"QueryContext":    "Query",
		"QueryRowContext": "QueryRow",
	}

	var findings []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "bin", "dist":
				return filepath.SkipDir
			}
			// internal/store is where rebinding is implemented, so it is the
			// one package legitimately allowed to call these.
			if filepath.Base(path) == "store" && strings.HasSuffix(filepath.Dir(path), "internal") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			replacement, bad := forbidden[sel.Sel.Name]
			if !bad {
				return true
			}

			rel, _ := filepath.Rel(root, path)
			findings = append(findings, "  "+rel+":"+
				itoa(fset.Position(call.Pos()).Line)+
				": uses "+sel.Sel.Name+"; use the rebinding "+replacement+"(ctx, ...) instead")
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}

	if len(findings) > 0 {
		t.Fatalf("these calls bypass placeholder rebinding and will break on PostgreSQL:\n%s",
			strings.Join(findings, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod above the test directory")
		}
		dir = parent
	}
}
