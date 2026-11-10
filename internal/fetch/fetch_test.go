package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetInvalidURL(t *testing.T) {
	c := New(DefaultTimeout)
	for _, raw := range []string{"example.com", "ftp://example.com", ""} {
		res := c.Get(context.Background(), raw, nil)
		if res.Err == nil {
			t.Errorf("Get(%q): expected error", raw)
		}
	}
}

func TestGetRecordsFinalURLAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := New(DefaultTimeout).Get(context.Background(), srv.URL, nil)
	if res.Err != nil {
		t.Fatalf("Get() error: %v", res.Err)
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d", res.StatusCode)
	}
	if res.Header.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("headers not captured: %v", res.Header)
	}
	if res.FinalURL != srv.URL+"/" && res.FinalURL != srv.URL {
		t.Errorf("FinalURL = %q", res.FinalURL)
	}
}

func TestGetRedirectChain(t *testing.T) {
	var final *httptest.Server
	mid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/landing", 302)
	}))
	defer mid.Close()
	final = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
	}))
	defer final.Close()

	res := New(DefaultTimeout).Get(context.Background(), mid.URL, nil)
	if res.Err != nil {
		t.Fatalf("Get() error: %v", res.Err)
	}
	if len(res.Redirects) != 1 || !strings.HasSuffix(res.Redirects[0], "/landing") {
		t.Errorf("Redirects = %v", res.Redirects)
	}
	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("final document headers not used: %v", res.Header)
	}
}

func TestGetTooManyRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", 302)
	}))
	defer srv.Close()

	res := New(DefaultTimeout).Get(context.Background(), srv.URL, nil)
	if res.Err == nil {
		t.Fatal("expected redirect-loop error")
	}
	if !strings.Contains(res.Err.Error(), "redirect") {
		t.Errorf("error = %v", res.Err)
	}
}

func TestGetTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	res := New(50*time.Millisecond).Get(context.Background(), srv.URL, nil)
	if res.Err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestGetCustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "sess=abc" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := New(DefaultTimeout).Get(context.Background(), srv.URL, map[string]string{"Cookie": "sess=abc"})
	if res.Err != nil || res.StatusCode != 200 {
		t.Fatalf("Get() = status %d, err %v", res.StatusCode, res.Err)
	}
}

func TestGetUntrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := New(DefaultTimeout).Get(context.Background(), srv.URL, nil)
	if res.Err == nil {
		t.Fatal("expected TLS verification error")
	}
}

func TestGetTrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(DefaultTimeout)
	c.HTTP.Transport = srv.Client().Transport
	res := c.Get(context.Background(), srv.URL, nil)
	if res.Err != nil {
		t.Fatalf("Get() error: %v", res.Err)
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d", res.StatusCode)
	}
}
