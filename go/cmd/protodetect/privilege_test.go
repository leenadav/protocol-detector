package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// privileged matches what would change privileges: a privilege-raising helper run as a command, or a call that sets
// a process's user or group identity or capabilities.
var privileged = regexp.MustCompile(`"(sudo|doas|pkexec|su|setcap|chown|chmod u\+s)"|` +
	`\b(sudo|doas|pkexec) |\bSys(Proc)?Attr\{[^}]*Credential|\bsyscall\.(Setuid|Setgid|Seteuid|Setegid|Setreuid|Setregid|Setresuid|Setresgid|Setgroups)\b|` +
	`\bunix\.(Setuid|Setgid|Seteuid|Setegid|Setreuid|Setregid|Setresuid|Setresgid|Setgroups|Capset)\b|\bos\.Chown\b|\bModeSetuid\b|\bModeSetgid\b|` +
	`\bos\.(setuid|setgid|seteuid|setegid|setreuid|setregid|setgroups|initgroups)\(`)

// scanPrivileges lists the product files under root that match privileged. Tests, vendored code and history are not
// the product.
func scanPrivileges(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if info.IsDir() {
			switch name {
			case "vendor", ".git", "node_modules", "testdata", "history", "research", "lab", "tests":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(name)
		if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "test_") ||
			(ext != ".go" && ext != ".py" && ext != ".js" && ext != ".command" && ext != ".sh") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if privileged.MatchString(line) {
				found = append(found, path+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// SR-60: the product never changes privileges: no sudo, setuid or privileged helper anywhere in the Go engine, the
// command, the presentation service or the launchers.
func TestNoPrivilegeChangesAnywhereInTheProduct(t *testing.T) {
	planted := t.TempDir()
	for name, text := range map[string]string{
		"a.go": "cmd := exec.Command(\"sudo\", \"tcpdump\")", "b.go": "syscall.Setuid(0)", "c.py": "os.setuid(0)",
		"d.go": "attr := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0}}", "e.sh": "sudo tcpdump -i eth0",
	} {
		if err := os.WriteFile(filepath.Join(planted, name), []byte(text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if found := scanPrivileges(t, planted); len(found) != 5 {
		t.Fatalf("the scan found %d of 5 planted privilege changes: %q", len(found), found)
	}

	repository := filepath.Join("..", "..", "..")
	scanned := 0
	for _, part := range []string{"go", "presentation", "main.py", "protodetect.py"} {
		path := filepath.Join(repository, part)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", part, err)
		}
		scanned++
		for _, hit := range scanPrivileges(t, path) {
			t.Errorf("privilege change in the product: %s", hit)
		}
	}
	if scanned != 4 {
		t.Fatalf("scanned %d product roots", scanned)
	}
}
