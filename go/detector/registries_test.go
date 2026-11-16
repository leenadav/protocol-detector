package detector

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/protocols/framed"
)

// Integration work item #15: no package of the module exports a map or slice variable. An exported registry
// is shared mutable state: any importer could write to it at run time, and a concurrent map write ends the
// whole process, which no panic boundary recovers. Registries are unexported and read through accessors that
// return copies.
//
// Four tables stay exported, named here. Two because a Python cross-language test (test_migration_parity.py) finds them by
// their names in the Go source and compares them with the reference, and this lane does not edit Python files.
// Each is filled by its declaration and never written; a later rename goes with that test. Two more are in a file
// copied from the engine lane, see below.
var exportedForTheReferenceTest = map[string]bool{
	"contracts.ConfigRanges": true, // go/internal/contracts/contracts.go, read as "var ConfigRanges"
	"engine.DatagramHints":   true, // go/internal/engine/datagram.go, read as "var DatagramHints"
	// go/internal/content/digest.go is a byte-for-byte copy of the engine lane's file (7afc8f6), kept identical so
	// the branches merge cleanly; unexporting these two slices is reported to that lane.
	"content.ApplicationFields": true,
	"content.ComponentNames":    true,
}

func TestNoPackageExportsAMutableRegistry(t *testing.T) {
	listed := map[string]bool{}
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "consumertest" {
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
		files++
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !name.IsExported() {
						continue
					}
					var expr ast.Expr = vs.Type
					if expr == nil && i < len(vs.Values) {
						expr = vs.Values[i]
					}
					if qualified := file.Name.Name + "." + name.Name; mutableContainer(expr) && exportedForTheReferenceTest[qualified] {
						listed[qualified] = true
					} else if mutableContainer(expr) {
						t.Errorf("%s: exported variable %s is a map or slice; unexport it and add an accessor that returns a copy",
							fset.Position(name.Pos()), name.Name)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range exportedForTheReferenceTest {
		if !listed[name] {
			t.Errorf("%s is listed as exported for the reference test but is no longer an exported map or slice; remove it from the list", name)
		}
	}
	if files < 40 {
		t.Fatalf("only %d source files scanned; the walk root is wrong", files)
	}
}

// mutableContainer reports a map or slice type, a composite literal of one, or a make of one.
func mutableContainer(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.MapType:
		return true
	case *ast.ArrayType:
		return e.Len == nil // a slice; a fixed-size array is copied on assignment
	case *ast.CompositeLit:
		return mutableContainer(e.Type)
	case *ast.CallExpr:
		if fn, ok := e.Fun.(*ast.Ident); ok && fn.Name == "make" && len(e.Args) > 0 {
			return mutableContainer(e.Args[0])
		}
	}
	return false
}

// The accessors hand out copies: changing what they return changes nothing in the engine.
func TestRegistryAccessorsReturnCopies(t *testing.T) {
	families := engine.Families()
	if len(families) < 50 || families[0] != "http" {
		t.Fatalf("families: %v", families)
	}
	families[0] = "changed"
	if engine.Families()[0] != "http" {
		t.Error("engine.Families exposes the registry")
	}
	names := engine.PortedNames()
	if len(names) < 50 || !engine.IsPorted("tls") || engine.IsPorted("no-such-family") || engine.IsPorted("tpkt") {
		t.Fatalf("ported: %d names", len(names))
	}
	names[0] = "changed"
	if engine.IsPorted("changed") {
		t.Error("engine.PortedNames exposes the registry")
	}
	validators := framed.DatagramValidatorNames()
	if _, ok := framed.DatagramValidatorFor("syslog"); !ok || len(validators) < 20 {
		t.Fatalf("validators: %v", validators)
	}
	if _, ok := framed.DatagramValidatorFor("no-such-family"); ok {
		t.Error("unknown family has a validator")
	}
	// The facade's own lists were already copies.
	p := ProfileFamilies()
	p[0] = "changed"
	if ProfileFamilies()[0] == "changed" {
		t.Error("ProfileFamilies exposes the list")
	}
}
