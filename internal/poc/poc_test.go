package poc

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sampleData() Data {
	return Data{
		Description: "Clickjacking Layer Inspection & Confirmation Kit",
		Author:      "Cr0wtl3r",
		TargetURL:   "https://target.example/login",
		Domain:      "target.example",
		Status:      "POTENTIALLY VULNERABLE - framing not blocked by response headers (not validated in a browser)",
		StatusClass: "potential",
	}
}

func TestRenderGolden(t *testing.T) {
	got, err := Render(sampleData())
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	golden := filepath.Join("testdata", "poc_golden.html")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run go test ./internal/poc -update): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("PoC output differs from golden (run -update to accept):\n--- got ---\n%s", got)
	}
}

func TestRenderEscapesHTMLInjection(t *testing.T) {
	d := sampleData()
	d.TargetURL = `https://x.example/"><script>alert(1)</script><b x="`
	got, err := Render(d)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	if strings.Contains(string(got), "<script>alert(1)") {
		t.Error("raw script tag leaked into PoC HTML")
	}
	if strings.Contains(string(got), `"><script>`) {
		t.Error("attribute breakout leaked into PoC HTML")
	}
}

func TestRenderBlocksJavascriptURLs(t *testing.T) {
	d := sampleData()
	d.TargetURL = "javascript:alert(1)"
	got, err := Render(d)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	if strings.Contains(string(got), `src="javascript:`) {
		t.Error("javascript: URL rendered into iframe src")
	}
}

func TestRenderSelfContained(t *testing.T) {
	got, err := Render(sampleData())
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	for _, marker := range []string{"<link", "<img", `script src=`, "@import", "url(http"} {
		if strings.Contains(string(got), marker) {
			t.Errorf("external resource reference %q found in PoC HTML", marker)
		}
	}
}
