package psfp

import (
	"context"
	"regexp"
	"strings"
)

var (
	reModPath = regexp.MustCompile(`/modules/([a-zA-Z0-9_]+)/`)
	reCfgVer  = regexp.MustCompile(`(?i)<version>\s*(?:<!\[CDATA\[)?\s*([0-9][0-9A-Za-z.\-]*)`)
)

// ScrapeModules collects module NAMES referenced in the homepage DOM.
//
// Only names are taken: the ?v= querystring on asset URLs is a global
// cache-buster token, not the module version - real versions come from
// EnumModules (config.xml).
func (c *Client) ScrapeModules(ctx context.Context, base string) []Module {
	base = strings.TrimRight(base, "/")
	seen := map[string]struct{}{}
	var mods []Module
	for _, p := range []string{"/", "/index.php"} {
		r := c.fetch(ctx, base+p, 4<<20)
		if r == nil || len(r.body) == 0 {
			continue
		}
		for _, m := range reModPath.FindAllSubmatch(r.body, -1) {
			name := string(m[1])
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			mods = append(mods, Module{Name: name, Origin: c.db.Origin(name),
				Source: "dom", Path: "/modules/" + name + "/"})
		}
		break
	}
	return mods
}

// EnumModules actively confirms modules and extracts versions via
// /modules/<name>/config.xml, keying on differential responses (PrestaShop
// serves a themed soft-404 for missing paths, so status code alone is unsafe).
// dom seeds the set with names already seen in the DOM.
func (c *Client) EnumModules(ctx context.Context, base string, names []string, dom []Module) []Module {
	base = strings.TrimRight(base, "/")
	bStatus, bLen := c.baseline404(ctx, base)

	domSet := map[string]struct{}{}
	for _, m := range dom {
		domSet[m.Name] = struct{}{}
	}
	targets := dedup(append(append([]string{}, names...), keysOf(domSet)...))

	type out struct {
		name, ver, src, path string
	}
	found := make([]out, len(targets))
	c.parallel(len(targets), func(i int) {
		name := targets[i]
		cfgURL := base + "/modules/" + name + "/config.xml"
		r := c.fetch(ctx, cfgURL, 1<<20)
		if r == nil {
			return
		}
		isXML := contains(r.body, "<module") || contains(r.body, "<version")
		differs := !(r.status == bStatus && abs(len(r.body)-bLen) < 64)
		if isXML {
			ver := "?"
			if m := reCfgVer.FindSubmatch(r.body); m != nil {
				ver = string(m[1])
			}
			found[i] = out{name, ver, "config.xml", cfgURL}
			return
		}
		if (r.status == 200 || r.status == 403) && differs && !contains(r.body, "page-not-found") {
			logoURL := base + "/modules/" + name + "/logo.png"
			lr := c.fetch(ctx, logoURL, 1<<16)
			if lr != nil && lr.status == 200 && len(lr.body) >= 4 && string(lr.body[:4]) == "\x89PNG" {
				found[i] = out{name, "", "logo.png", logoURL}
			}
		}
	})

	result := map[string]Module{}
	for _, m := range dom {
		result[m.Name] = m
	}
	for _, f := range found {
		if f.name == "" {
			continue
		}
		ex, ok := result[f.name]
		if !ok || ex.Version == "" {
			result[f.name] = Module{Name: f.name, Version: f.ver, Origin: c.db.Origin(f.name),
				Source: f.src, Path: f.path}
		}
	}
	return sortModules(result)
}

func (c *Client) baseline404(ctx context.Context, base string) (int, int) {
	r := c.fetch(ctx, base+"/modules/zz_nope_psfp_9xq/config.xml", 1<<16)
	if r == nil {
		return 0, 0
	}
	return r.status, len(r.body)
}

// --- helpers ---

func contains(b []byte, s string) bool { return strings.Contains(string(b), s) }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortModules(m map[string]Module) []Module {
	names := keysOf2(m)
	sortStrings(names)
	out := make([]Module, 0, len(names))
	for _, n := range names {
		out = append(out, m[n])
	}
	return out
}

func keysOf2(m map[string]Module) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
