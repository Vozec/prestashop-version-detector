package psfp

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type behavResult struct {
	candidates []string
	notes      []string
	exact      string
}

var (
	reSameSiteLax = regexp.MustCompile(`(?i)PrestaShop-[a-f0-9]{32}=[^;]*;[^\n]*SameSite=Lax`)
	rePoweredBy   = regexp.MustCompile(`(?i)Powered-?by:\s*PrestaShop`)
)

// behavioral applies active route/header/cookie probes that split the version
// space where static hashes cannot (notably 8.x vs 9.x and pre/post 8.0).
// Each probe narrows only on a reliable POSITIVE match; 404s are ignored
// (could be hardening / WAF), keeping false negatives out.
func (c *Client) behavioral(ctx context.Context, base string, cands []string) behavResult {
	res := behavResult{candidates: cands}
	keep := func(pred func([4]int) bool, why string) {
		var next []string
		for _, v := range res.candidates {
			if pred(vtuple(v)) {
				next = append(next, v)
			}
		}
		if len(next) > 0 && len(next) < len(res.candidates) {
			res.candidates = next
			res.notes = append(res.notes, why)
		}
	}
	geq := func(b [4]int) func([4]int) bool { return func(t [4]int) bool { return !vless(t, b) } }
	lt := func(b [4]int) func([4]int) bool { return func(t [4]int) bool { return vless(t, b) } }
	major := func(m int) func([4]int) bool { return func(t [4]int) bool { return t[0] == m } }

	// 9.x: web-root Admin API (no admin folder needed)
	if r := c.fetch(ctx, base+"/admin-api/access_token", 1<<16); r != nil {
		auth := r.header.Get("WWW-Authenticate")
		body := string(r.body)
		if r.status == 400 || r.status == 405 ||
			(r.status == 401 && (strings.Contains(auth, "Bearer") || strings.Contains(body, "Authorization header"))) {
			keep(major(9), "admin-api/access_token -> 9.x")
		}
	}
	if r := c.fetch(ctx, base+"/admin-api/", 1<<16); r != nil &&
		r.status == 401 && strings.Contains(r.header.Get("WWW-Authenticate"), "Bearer") {
		keep(major(9), "admin-api 401 Bearer -> 9.x")
	}

	// webservice /api/ : PSWS-Version leaks the EXACT build, unauthenticated, only <=1.7
	if r := c.fetch(ctx, base+"/api/", 1<<16); r != nil {
		if psws := r.header.Get("PSWS-Version"); psws != "" {
			res.exact = strings.TrimSpace(psws)
			keep(lt([4]int{8, 0, 0, 0}), "PSWS-Version header (unauth) -> <8.0")
		}
		if strings.Contains(r.header.Get("WWW-Authenticate"), "PrestaShop Webservice") {
			res.notes = append(res.notes, "webservice /api/ enabled")
		}
	}

	// front controllers (web-root, no admin folder)
	if c.controllerExists(ctx, base, "registration") {
		keep(geq([4]int{8, 0, 0, 0}), "?controller=registration -> >=8.0")
	}
	if c.controllerExists(ctx, base, "compare") {
		keep(lt([4]int{1, 7, 0, 0}), "?controller=compare -> <=1.6")
	}

	// header / cookie tells from the homepage
	if r := c.fetch(ctx, base+"/", 1<<16); r != nil {
		sc := strings.Join(r.header.Values("Set-Cookie"), " ")
		raw := headerString(r)
		if reSameSiteLax.MatchString(sc) {
			keep(geq([4]int{1, 7, 8, 0}), "cookie SameSite=Lax -> >=1.7.8")
		}
		if rePoweredBy.MatchString(raw) {
			keep(func(t [4]int) bool {
				return !vless(t, [4]int{1, 6, 0, 14}) && !vless([4]int{1, 7, 5, 99}, t)
			}, "Powered-By header -> 1.6.0.14-1.7.5")
		}
	}
	return res
}

// controllerExists reports whether ?controller=<name> renders differently from a
// bogus controller (PrestaShop soft-404s unknown controllers).
func (c *Client) controllerExists(ctx context.Context, base, name string) bool {
	good := c.fetch(ctx, fmt.Sprintf("%s/index.php?controller=%s", base, name), 1<<20)
	bad := c.fetch(ctx, fmt.Sprintf("%s/index.php?controller=zznope_psfp_xyz", base), 1<<20)
	if good == nil || bad == nil {
		return false
	}
	if good.status == 200 && (bad.status == 404 || bad.status == 400) {
		return true
	}
	d := len(good.body) - len(bad.body)
	if d < 0 {
		d = -d
	}
	return good.status == 200 && d > 256
}

func headerString(r *httpResp) string {
	var b strings.Builder
	for k, vs := range r.header {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
