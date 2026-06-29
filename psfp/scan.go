package psfp

import (
	"context"
	"strings"
)

// Scan runs a full fingerprint of base according to opts and returns a Result.
// Version detection always runs; module enumeration and archive fuzzing are
// opt-in via opts.
func (c *Client) Scan(ctx context.Context, base string, opts ScanOpts) (*Result, error) {
	base = strings.TrimRight(base, "/")
	res := &Result{Target: base}

	res.Detection = c.Detect(ctx, base)
	res.Version = c.DetectVersion(ctx, base)
	res.UpgradeFeed = c.FetchUpgradeFeed(ctx, base)
	res.Gitignore = c.FetchGitignore(ctx, base)

	// Exact version from the back-office page. Use an explicit --admin dir, or
	// fall back to an admin folder auto-discovered from a leaked .gitignore.
	adminDir := opts.AdminDir
	if adminDir == "" && res.Gitignore != nil && len(res.Gitignore.AdminDirs) > 0 {
		adminDir = res.Gitignore.AdminDirs[0]
	}
	if adminDir != "" {
		if ver, url := c.AdminVersion(ctx, base, adminDir); ver != "" {
			res.Version.Exact = ver
			res.Version.Band = ver
			res.Version.Candidates = []string{ver}
			res.Version.Identified = true
			res.Version.Evidence = append(res.Version.Evidence,
				Evidence{adminDir + "/", url, "admin-page", "", "exact " + ver})
		}
	}

	dom := c.ScrapeModules(ctx, base)
	// Fold in project modules disclosed by .gitignore (often custom = high value).
	if res.Gitignore != nil {
		for _, m := range res.Gitignore.Modules {
			dom = append(dom, Module{Name: m, Origin: c.db.Origin(m),
				Source: "gitignore", Path: "/modules/" + m + "/"})
		}
	}
	if opts.Modules {
		res.Modules = c.EnumModules(ctx, base, c.db.Wordlist, dom)
	} else {
		res.Modules = dedupModules(dom)
	}

	if opts.Archives || opts.ArchivesWordlist {
		names := moduleNames(res.Modules)
		if opts.ArchivesWordlist {
			names = dedup(append(names, c.db.Wordlist...))
		}
		res.Leaks = c.FuzzArchives(ctx, base, names)
	}
	return res, nil
}

func moduleNames(mods []Module) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.Name)
	}
	return out
}

// dedupModules collapses duplicate module names, preferring the entry that
// carries a version.
func dedupModules(mods []Module) []Module {
	by := map[string]Module{}
	for _, m := range mods {
		if ex, ok := by[m.Name]; !ok || (ex.Version == "" && m.Version != "") {
			by[m.Name] = m
		}
	}
	return sortModules(by)
}
