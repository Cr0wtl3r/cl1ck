package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const frameCommitProbe = `(function () {
	var f = document.querySelector("iframe");
	if (!f) return false;
	try {
		return f.contentDocument === null;
	} catch (e) {
		return true;
	}
})()`

type Options struct {
	BrowserPath string
	Headers     map[string]string
	Width       int
	Height      int
	Timeout     time.Duration
	Delay       time.Duration
	TargetURL   string
	Redirects   []string
}

type Evidence struct {
	ScreenshotPath string
	TargetLoaded   bool
	FrameRefused   bool
	RefusalMessage string
}

func Screenshot(ctx context.Context, pageURL, pngPath string, opts Options) (Evidence, error) {
	if opts.Width == 0 {
		opts.Width = 1600
	}
	if opts.Height == 0 {
		opts.Height = 900
	}
	if opts.Timeout == 0 {
		opts.Timeout = 45 * time.Second
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(opts.Width, opts.Height),
	)
	if path := resolveBrowser(opts.BrowserPath); path != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(path))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	candidates := append([]string{opts.TargetURL}, opts.Redirects...)
	var ev Evidence
	ev.ScreenshotPath = pngPath
	var mu sync.Mutex
	reqURL := map[network.RequestID]string{}
	if err := chromedp.Listen(browserCtx, func(event any) {
		mu.Lock()
		defer mu.Unlock()
		switch e := event.(type) {
		case *network.EventRequestWillBeSent:
			reqURL[e.RequestID] = e.Request.URL
		case *network.EventLoadingFailed:
			if e.Type == network.ResourceTypeDocument && matchesAnyPrefix(reqURL[e.RequestID], candidates) {
				ev.FrameRefused = true
				if ev.RefusalMessage == "" {
					ev.RefusalMessage = "target navigation failed: " + e.ErrorText
				}
			}
		case *page.EventFrameNavigated:
			if e.Frame.ParentID != "" && isCommittableFrameURL(e.Frame.URL) {
				ev.TargetLoaded = true
			}
		case *log.EventEntryAdded:
			noteEntry(&ev, e.Entry.Text)
		case *runtime.EventConsoleAPICalled:
			for _, arg := range e.Args {
				noteEntry(&ev, fmt.Sprint(arg.Value))
			}
		}
	}); err != nil {
		return ev, fmt.Errorf("listen for browser events: %w", err)
	}

	runCtx, cancel := context.WithTimeout(browserCtx, opts.Timeout)
	defer cancel()

	settle := 500*time.Millisecond + opts.Delay
	err := chromedp.Do(runCtx,
		chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			if _, err := cdp.Call(ctx, t, network.Enable, network.EnableParams{}); err != nil {
				return err
			}
			if len(opts.Headers) > 0 {
				h := make(network.Headers, len(opts.Headers))
				for k, v := range opts.Headers {
					h[k] = v
				}
				if _, err := cdp.Call(ctx, t, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: h}); err != nil {
					return err
				}
			}
			_, err := cdp.Call(ctx, t, log.Enable, cdp.Empty{})
			return err
		}),
		chromedp.EmulateViewport(int64(opts.Width), int64(opts.Height)),
		chromedp.Navigate(pageURL),
		chromedp.WaitReady(chromedp.CSS("body")),
		chromedp.Poll[chromedp.Void](`document.readyState === "complete"`, chromedp.WithPollingTimeout(15*time.Second)),
		chromedp.Sleep(settle),
		chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			if res, err := cdp.Call(ctx, t, page.GetFrameTree, cdp.Empty{}); err == nil {
				mu.Lock()
				walkFrameTree(res.FrameTree, &ev)
				mu.Unlock()
			}
			mu.Lock()
			loaded := ev.TargetLoaded
			mu.Unlock()
			if loaded {
				return nil
			}
			if committed, err := chromedp.Evaluate[bool](frameCommitProbe)(ctx, t); err == nil && committed {
				mu.Lock()
				ev.TargetLoaded = true
				mu.Unlock()
			}
			return nil
		}),
	)
	if err != nil {
		return ev, fmt.Errorf("render PoC in browser: %w", err)
	}

	buf, err := chromedp.Run(runCtx, chromedp.CaptureScreenshot())
	if err != nil {
		return ev, fmt.Errorf("browser screenshot: %w", err)
	}
	if err := os.WriteFile(pngPath, buf, 0o644); err != nil {
		return ev, fmt.Errorf("write screenshot: %w", err)
	}
	return ev, nil
}

func matchesAnyPrefix(u string, candidates []string) bool {
	for _, c := range candidates {
		if c != "" && strings.HasPrefix(u, c) {
			return true
		}
	}
	return false
}

func isCommittableFrameURL(u string) bool {
	if u == "" || u == "about:blank" || u == "about:srcdoc" {
		return false
	}
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func walkFrameTree(ft *page.FrameTree, ev *Evidence) {
	if ft == nil {
		return
	}
	if f := ft.Frame; f != nil && f.ParentID != "" && isCommittableFrameURL(f.URL) {
		ev.TargetLoaded = true
	}
	for _, child := range ft.ChildFrames {
		walkFrameTree(child, ev)
	}
}

func noteEntry(ev *Evidence, text string) {
	lower := strings.ToLower(text)
	refused := strings.Contains(lower, "refused to frame") ||
		(strings.Contains(lower, "frame-ancestors") && strings.Contains(lower, "violat")) ||
		(strings.Contains(lower, "x-frame-options") && strings.Contains(lower, "violat"))
	if refused {
		ev.FrameRefused = true
		ev.RefusalMessage = text
	}
}

func resolveBrowser(override string) string {
	if override != "" {
		return override
	}
	if p := os.Getenv("CLICK_BROWSER_PATH"); p != "" {
		return p
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome-stable", "google-chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
