package main

// Black-box tests that build the real binary and exercise its argument
// validation and no-credential error paths (exit codes + output). These run
// without network — the live GetContact calls themselves are exercised by the
// client package's httptest tests.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary compiles the CLI to a temp file and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gc-lookup")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return string(out), code
}

func TestCLIUnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	out, code := runCLI(t, bin, nil, "bogus-cmd")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; out=%s", code, out)
	}
	if !strings.Contains(out, "unknown command") {
		t.Errorf("out = %q, want 'unknown command'", out)
	}
}

func TestCLISearchBadArgs(t *testing.T) {
	bin := buildBinary(t)
	cfg := []string{"GTC_CONFIG_DIR=" + t.TempDir()}

	out, code := runCLI(t, bin, cfg, "search")
	if code != 2 || !strings.Contains(out, "usage: gc-lookup search") {
		t.Fatalf("search(no args): code=%d out=%q", code, out)
	}

	out, code = runCLI(t, bin, cfg, "search", "--source", "bogus", "628123")
	if code != 2 || !strings.Contains(out, "invalid --source") {
		t.Fatalf("search(bad source): code=%d out=%q", code, out)
	}

	out, code = runCLI(t, bin, cfg, "search", "628123")
	if code != 1 || !strings.Contains(out, "no active credential") {
		t.Fatalf("search(no cred): code=%d out=%q", code, out)
	}
}

func TestCLINoCredentialCommands(t *testing.T) {
	bin := buildBinary(t)
	cfg := []string{"GTC_CONFIG_DIR=" + t.TempDir()}
	for _, args := range [][]string{
		{"subscription"},
		{"refresh-code"},
		{"verify-code", "ABC-123"},
	} {
		out, code := runCLI(t, bin, cfg, args...)
		if code != 1 || !strings.Contains(out, "no active credential") {
			t.Errorf("%v: code=%d out=%q, want exit 1 + no-active-credential", args, code, out)
		}
	}
}

func TestCLIRegisterBadArgs(t *testing.T) {
	bin := buildBinary(t)
	out, code := runCLI(t, bin, nil, "register")
	if code != 2 || !strings.Contains(out, "usage: gc-lookup register") {
		t.Fatalf("register(no args): code=%d out=%q", code, out)
	}
}

func TestCLICredUsage(t *testing.T) {
	bin := buildBinary(t)
	out, code := runCLI(t, bin, nil, "cred")
	if code != 2 || !strings.Contains(out, "cred list") {
		t.Fatalf("cred(no subcommand): code=%d out=%q", code, out)
	}
	out, code = runCLI(t, bin, nil, "cred", "use")
	if code != 2 || !strings.Contains(out, "cred list") {
		t.Fatalf("cred use(no name): code=%d out=%q", code, out)
	}
}
