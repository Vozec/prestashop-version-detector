// Package psfp is a fast PrestaShop fingerprinting SDK.
//
// It identifies the core version band, enumerates installed modules (with
// versions), and probes for leaked module source archives - all against a
// fingerprint database built offline from the official PrestaShop git tags.
//
// Basic use:
//
//	c, _ := psfp.New(psfp.Options{})
//	res, _ := c.Scan(context.Background(), "https://shop.example.com", psfp.ScanOpts{Modules: true})
//	fmt.Println(res.Version.Band, res.Modules)
package psfp

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

const defaultUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

// Options configures a Client.
type Options struct {
	Insecure    bool          // skip TLS certificate verification
	Timeout     time.Duration // per-request timeout (default 12s)
	Concurrency int           // max parallel requests (default 24)
	UserAgent   string        // override the default browser UA
	HTTPClient  *http.Client  // bring your own client (overrides Insecure/Timeout)
	MaxProbes   int           // max version hash probes (default 24)
}

// Client is a reusable fingerprinter. Safe for concurrent use.
type Client struct {
	db   *DB
	http *http.Client
	ua   string
	conc int
	max  int
}

// New builds a Client backed by the embedded fingerprint DB.
func New(o Options) (*Client, error) {
	db, err := LoadDB()
	if err != nil {
		return nil, err
	}
	hc := o.HTTPClient
	if hc == nil {
		to := o.Timeout
		if to == 0 {
			to = 12 * time.Second
		}
		tr := &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 32,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure},
		}
		hc = &http.Client{Timeout: to, Transport: tr}
	}
	ua := o.UserAgent
	if ua == "" {
		ua = defaultUA
	}
	conc := o.Concurrency
	if conc == 0 {
		conc = 24
	}
	max := o.MaxProbes
	if max == 0 {
		max = 24
	}
	return &Client{db: db, http: hc, ua: ua, conc: conc, max: max}, nil
}

// DB exposes the loaded fingerprint database.
func (c *Client) DB() *DB { return c.db }

type httpResp struct {
	status int
	header http.Header
	body   []byte
}

// fetch performs a GET, capping the body read to limit bytes (0 = unlimited).
func (c *Client) fetch(ctx context.Context, url string, limit int64) *httpResp {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var r io.Reader = resp.Body
	if limit > 0 {
		r = io.LimitReader(resp.Body, limit)
	}
	b, _ := io.ReadAll(r)
	return &httpResp{status: resp.StatusCode, header: resp.Header, body: b}
}
