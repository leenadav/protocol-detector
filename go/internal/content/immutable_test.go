package content

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Integration work item #16, the Codex decision on the pin (2026-11-16): a pinned digest is an integrity
// boundary only if the validated content stays immutable after it was checked. A Pack is built once by Parse
// and its tables are exported maps, so the module holds itself to never writing them: no source file outside
// this package that imports it assigns to, increments, deletes from or appends to a Pack table, its release
// or digests, or a field of an Application it looked up. The public facade (go/detector) does not import this
// package at all; this test also fails if that changes, because the boundary would then reach the host.
func TestNoCodeOutsideThePackageWritesAValidatedPack(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks the importing packages from source")
	}
	const self = "github.com/leenadav/protocol-detector/go/internal/content"
	fset := token.NewFileSet()
	dirs := map[string][]*ast.File{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || filepath.Clean(path) == filepath.Clean("../../internal/content") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		dirs[filepath.Dir(path)] = append(dirs[filepath.Dir(path)], file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	checked := 0
	for dir, files := range dirs {
		imports := false
		for _, file := range files {
			for _, spec := range file.Imports {
				if p, _ := strconv.Unquote(spec.Path.Value); p == self {
					imports = true
				}
			}
		}
		if !imports {
			continue
		}
		if strings.Contains(filepath.ToSlash(dir), "/detector") {
			t.Errorf("%s: the public facade imports the content package; the pin's immutability boundary must be reviewed first", dir)
		}
		info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
		if _, err := conf.Check(dir, fset, files, info); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		checked++
		// written reports a write through a field of a Pack or an Application anywhere in expr: the table itself,
		// an element of it, or a field of an Application held by pointer.
		written := func(expr ast.Expr) {
			ast.Inspect(expr, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				selection := info.Selections[sel]
				if selection == nil || selection.Kind() != types.FieldVal {
					return true
				}
				recv := selection.Recv()
				if ptr, ok := recv.(*types.Pointer); ok {
					recv = ptr.Elem()
				}
				if named, ok := recv.(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == self &&
					(named.Obj().Name() == "Pack" || named.Obj().Name() == "Application") {
					t.Errorf("%s: writes %s.%s of a validated pack", fset.Position(sel.Pos()), named.Obj().Name(), sel.Sel.Name)
				}
				return true
			})
		}
		for _, file := range files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range s.Lhs {
						written(lhs)
					}
				case *ast.IncDecStmt:
					written(s.X)
				case *ast.CallExpr:
					if fn, ok := s.Fun.(*ast.Ident); ok && fn.Name == "delete" && len(s.Args) > 0 {
						written(s.Args[0])
					}
				}
				return true
			})
		}
	}
	if checked < 3 {
		t.Fatalf("only %d packages import the content package; the walk root is wrong", checked)
	}
}
