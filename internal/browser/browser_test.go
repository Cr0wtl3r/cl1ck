//go:build browser

package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cl1ck/internal/poc"
	"cl1ck/internal/serve"
)

func runScreenshot(t *testing.T, targetHeaders func(http.Header), rewriteURL func(string) string) Evidence {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if targetHeaders != nil {
			targetHeaders(w.Header())
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>target app</h1></body></html>"))
	}))
	defer target.Close()

	targetURL := target.URL
	if rewriteURL != nil {
		targetURL = rewriteURL(targetURL)
	}

	html, err := poc.Render(poc.Data{
		Description: "test", Author: "Cr0wtl3r",
		TargetURL: targetURL, Domain: "test",
		Status: "TEST", StatusClass: "potential",
	})
	if err != nil {
		t.Fatalf("render PoC: %v", err)
	}
	pocSrv, err := serve.Start(html)
	if err != nil {
		t.Fatalf("serve PoC: %v", err)
	}
	defer pocSrv.Close()

	png := filepath.Join(t.TempDir(), "shot.png")
	ev, err := Screenshot(context.Background(), pocSrv.URL(), png, Options{
		TargetURL: targetURL,
		Timeout:   60 * time.Second,
	})
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("no browser available: %v", err)
		}
		t.Fatalf("Screenshot() error: %v", err)
	}
	if fi, err := os.Stat(png); err != nil || fi.Size() == 0 {
		t.Errorf("screenshot not written or empty: %v", err)
	}
	return ev
}

func TestScreenshotFrameableTarget(t *testing.T) {
	ev := runScreenshot(t, nil, nil)
	if !ev.TargetLoaded {
		t.Error("target response not observed in the frame")
	}
	if ev.FrameRefused {
		t.Errorf("unexpected framing refusal: %s", ev.RefusalMessage)
	}
}

func TestScreenshotBlockedTarget(t *testing.T) {
	ev := runScreenshot(t, func(h http.Header) {
		h.Set("X-Frame-Options", "DENY")
	}, nil)
	if !ev.FrameRefused {
		t.Error("expected browser framing refusal for X-Frame-Options: DENY")
	}
}

func TestScreenshotCrossSiteTarget(t *testing.T) {
	ev := runScreenshot(t, nil, func(u string) string {
		return strings.Replace(u, "127.0.0.1", "localhost", 1)
	})
	if !ev.TargetLoaded {
		t.Error("target response not observed in the cross-site frame")
	}
	if ev.FrameRefused {
		t.Errorf("unexpected framing refusal: %s", ev.RefusalMessage)
	}
}

func TestScreenshotSendsCustomHeaders(t *testing.T) {
	got := make(chan string, 8)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("X-Cl1ck-Test"):
		default:
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>target app</h1></body></html>"))
	}))
	defer target.Close()

	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	html, err := poc.Render(poc.Data{
		Description: "test", Author: "Cr0wtl3r",
		TargetURL: targetURL, Domain: "test",
		Status: "TEST", StatusClass: "potential",
	})
	if err != nil {
		t.Fatalf("render PoC: %v", err)
	}
	pocSrv, err := serve.Start(html)
	if err != nil {
		t.Fatalf("serve PoC: %v", err)
	}
	defer pocSrv.Close()

	png := filepath.Join(t.TempDir(), "shot.png")
	_, err = Screenshot(context.Background(), pocSrv.URL(), png, Options{
		TargetURL: targetURL,
		Headers:   map[string]string{"X-Cl1ck-Test": "present"},
		Timeout:   60 * time.Second,
	})
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("no browser available: %v", err)
		}
		t.Fatalf("Screenshot() error: %v", err)
	}
	select {
	case v := <-got:
		if v != "present" {
			t.Errorf("custom header value sent to target = %q, want %q", v, "present")
		}
	default:
		t.Error("target never received a request")
	}
}
