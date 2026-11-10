# Repository Guidelines

## Project Overview

**cl1ck — Clickjacking Layer Inspection & Confirmation Kit** (by Cr0wtl3r): a Go CLI that scans targets for clickjacking exposure, classifies them honestly (`PROTECTED` / `POTENTIALLY_VULNERABLE` / `CONFIRMED_FRAMEABLE` / `INCONCLUSIVE`), generates a self-contained HTML PoC, validates cross-origin framing in a real browser and saves screenshot evidence. All user-facing text is **English**. Small by design: stdlib-first, one external dependency (`chromedp`), no framework.

## Architecture & Data Flow

```
cmd/cl1ck/main.go  →  internal/fetch (net/http GET, redirect chain, headers)
                   →  internal/detect (pure header classification)
                   →  internal/poc (embedded html/template PoC)
                   →  internal/serve (loopback 127.0.0.1 PoC server)
                   →  internal/browser (chromedp screenshot + framing evidence)
                   →  internal/cli (flags, banner, output, JSON report)
```

Per target: fetch → classify → if `POTENTIALLY_VULNERABLE`: render PoC → serve on loopback → screenshot (default on) → promote to `CONFIRMED_FRAMEABLE` only when the browser commits the target in a frame (`page.EventFrameNavigated`); a blocked navigation (`network.EventLoadingFailed`, e.g. `ERR_BLOCKED_BY_RESPONSE`) records a refusal instead. Evidence: `evidencias/{domain}_{timestamp}.png/.html`, findings appended to `url_with_clickjacking.txt` (CWD).

## Key Directories

- `cmd/cl1ck/` — entry point and orchestration.
- `internal/detect/` — pure classification (no I/O); `internal/fetch/` — HTTP; `internal/poc/templates/` — embedded PoC page; `internal/browser/` — chromedp evidence (build-tagged tests); `internal/cli/` — terminal I/O and identity.
- `evidencias/` — runtime output (generated, safe to delete).

## Development Commands

```sh
make build         # go build -o cl1ck ./cmd/cl1ck
make check         # go vet ./... && go test ./...
make test-browser  # go test -tags browser ./internal/browser/  (needs Chromium/Chrome)
make clean
```

Golden update: `go test ./internal/poc -update`. No git repo, no CI — `make check` is the gate.

## Code Conventions & Common Patterns

- Standard Go style (`gofmt`); errors wrapped with `%w`; no interfaces/abstractions without a concrete need.
- Comments are prohibited unless they are extremely important!
- `internal/detect` is pure: headers in, `Result` out. Do not "fix" classification semantics (`frame-ancestors *` is not protection; `ALLOW-FROM` is obsolete; enforced CSP governs over XFO) without an explicit request — they define tool output.
- Honest status labels: absence of headers is never "confirmed exploitation"; only browser-committed framing promotes to `CONFIRMED_FRAMEABLE`.
- Identity is canonical in `internal/cli/banner.go` (palette `#B91C1C`/`#EF4444`/`#E5E7EB`/`#450A0A`, art `brandArt`/`toolArt`): do not redraw the ASCII art casually; colors honor `NO_COLOR`, `TERM=dumb` and TTY detection.
- PoC template (`internal/poc/templates/poc.html`) is self-contained (no external assets) and all interpolation goes through `html/template` — never inject URLs/external data raw (XSS regression test exists).
- Graceful degradation: missing browser skips screenshots with a warning (scan continues).

## Important Files

| File                              | Role                                                                                                   |
| --------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `cmd/cl1ck/main.go`               | Orchestration, evidence flow, `--json` multi-target report                                             |
| `internal/detect/detect.go`       | Classification rules (modern browser semantics)                                                        |
| `internal/browser/browser.go`     | chromedp screenshot + framing evidence (one external dep)                                              |
| `internal/poc/templates/poc.html` | PoC page (Cr0wtl3r identity)                                                                           |
| `internal/cli/banner.go`          | Canonical banner identity (from the user-supplied logo reference)                                      |
| `url_with_clickjacking.txt`       | Append-only findings artifact; contains real engagement data — never delete or "clean up" its contents |

## Runtime & Tooling

- Go (see `go.mod`); `chromedp` is the only module dependency.
- Browser: Chromium/Chrome only for screenshots; `CLICK_BROWSER_PATH` overrides discovery (`/usr/bin/chromium` etc. probed).
- Output contract: `evidencias/`, `url_with_clickjacking.txt` relative to CWD; PNG names are timestamped (no overwrites).

## Testing & QA

- `go test ./...` — unit tests with `httptest` fixtures (header matrix, redirects, timeout, TLS errors, XSS escaping) and a PoC golden file.
- `go test -tags browser ./internal/browser/` — real-browser integration: frameable target must commit in the frame, `X-Frame-Options: DENY` target must record a refusal. Skips cleanly without a browser. Windows/macOS compatibility is not claimed without evidence.
