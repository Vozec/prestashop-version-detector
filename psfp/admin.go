package psfp

import (
	"context"
	"regexp"
	"strings"
)

var (
	// <span id="shop_version" ...>8.2.3</span>  (back-office header/layout)
	reShopVersion = regexp.MustCompile(`id="shop_version"[^>]*>\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})`)
	// generic ps_version literal in inline JS / data attributes
	rePsVersion = regexp.MustCompile(`(?i)ps_version["'\s:=]+["']?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})`)
	// BO asset cache-buster ?v=8.2.5 - on the back-office this carries the EXACT
	// PrestaShop version (unlike the front office, where ?v= is a global token).
	// Require the dotted X.Y.Z form to avoid the front-office numeric token.
	reAdminAssetVer = regexp.MustCompile(`[?&]v=([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

// AdminVersion fetches the back-office page at /<dir>/ and extracts the EXACT
// PrestaShop version, which the admin layout renders in clear
// (<span id="shop_version">). Returns "" if not found / unreachable.
//
// dir is the (randomised) admin folder name; on your own install you know it.
func (c *Client) AdminVersion(ctx context.Context, base, dir string) (string, string) {
	base = strings.TrimRight(base, "/")
	dir = strings.Trim(dir, "/")
	url := base + "/" + dir + "/"
	r := c.fetch(ctx, url, 2<<20)
	if r == nil || len(r.body) == 0 {
		return "", url
	}
	if m := reShopVersion.FindSubmatch(r.body); m != nil {
		return string(m[1]), url
	}
	if m := rePsVersion.FindSubmatch(r.body); m != nil {
		return string(m[1]), url
	}
	if m := reAdminAssetVer.FindSubmatch(r.body); m != nil {
		return string(m[1]), url
	}
	return "", url
}
