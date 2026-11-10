package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	DefaultTimeout      = 10 * time.Second
	DefaultMaxRedirects = 10
	maxDrain            = 4096
)

type Result struct {
	RequestedURL string      `json:"requested_url"`
	FinalURL     string      `json:"final_url,omitempty"`
	StatusCode   int         `json:"status_code,omitempty"`
	Header       http.Header `json:"-"`
	Redirects    []string    `json:"redirects,omitempty"`
	Err          error       `json:"-"`
}

type Client struct {
	HTTP         *http.Client
	MaxRedirects int
}

func New(timeout time.Duration) *Client {
	c := &Client{MaxRedirects: DefaultMaxRedirects}
	c.HTTP = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.MaxRedirects {
				return errors.New("stopped after too many redirects")
			}
			return nil
		},
	}
	return c
}

func (c *Client) Get(ctx context.Context, rawURL string, headers map[string]string) Result {
	res := Result{RequestedURL: rawURL}

	u, err := url.Parse(rawURL)
	if err != nil {
		res.Err = errors.New("invalid URL: " + err.Error())
		return res
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		res.Err = errors.New("invalid URL: absolute http(s) URL required")
		return res
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		res.Err = err
		return res
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := *c.HTTP
	baseRedirect := c.HTTP.CheckRedirect
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		res.Redirects = append(res.Redirects, r.URL.String())
		if baseRedirect != nil {
			return baseRedirect(r, via)
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Err = err
		return res
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrain))

	res.FinalURL = resp.Request.URL.String()
	res.StatusCode = resp.StatusCode
	res.Header = resp.Header
	return res
}
