package psfp

import (
	"context"
	"regexp"
	"strings"
)

// defaultIgnored are the paths PrestaShop ships in its stock .gitignore - used
// to filter them out so only project-specific entries surface.
var defaultIgnored = map[string]bool{
	"autoload.php": true, "bin": true, "cache": true, "classes": true,
	"controllers": true, "docs": true, "download": true, "images.inc.php": true,
	"index.php": true, "init.php": true, "js": true, "localization": true,
	"pdf": true, "src": true, "tools": true, "webservice": true, "translations": true,
	"upload": true, "var": true, "vendor": true, ".htaccess": true, "install.txt": true,
	"licenses": true, "makefile": true, "app": true, "composer.lock": true,
	"config": true, "img": true, "phpstan.neon.dist": true, "robots.txt": true,
	"templates": true, "log": true, "logs": true, "mails": true, "override": true,
	"themes": true,
}

var (
	reGiAdmin  = regexp.MustCompile(`^admin[A-Za-z0-9_\-]+$`)
	reGiModule = regexp.MustCompile(`^modules/([A-Za-z0-9_]+)/`)
)

// FetchGitignore retrieves /.gitignore and extracts the admin folder(s),
// project modules and other non-default paths. Returns nil if absent.
func (c *Client) FetchGitignore(ctx context.Context, base string) *GitignoreLeak {
	base = strings.TrimRight(base, "/")
	url := base + "/.gitignore"
	r := c.fetch(ctx, url, 1<<16)
	if r == nil || r.status != 200 || len(r.body) == 0 {
		return nil
	}
	body := string(r.body)
	// Sanity: must look like a gitignore (not an HTML soft-404).
	if strings.Contains(body, "<html") || !strings.Contains(body, "/") {
		return nil
	}
	gi := &GitignoreLeak{URL: url}
	seenMod, seenOther := map[string]bool{}, map[string]bool{}
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		clean := strings.Trim(line, "/")
		first := clean
		if i := strings.IndexByte(clean, '/'); i >= 0 {
			first = clean[:i]
		}
		switch {
		case reGiAdmin.MatchString(first):
			gi.AdminDirs = appendUniq(gi.AdminDirs, first)
		case reGiModule.MatchString(clean):
			m := reGiModule.FindStringSubmatch(clean)[1]
			if m != "*" && !seenMod[m] {
				seenMod[m] = true
				gi.Modules = append(gi.Modules, m)
			}
		default:
			lc := strings.ToLower(first)
			if !defaultIgnored[lc] && !strings.Contains(clean, "*") &&
				!strings.Contains(first, ".") && first != "" && !seenOther[first] {
				seenOther[first] = true
				gi.OtherPaths = append(gi.OtherPaths, clean)
			}
		}
	}
	return gi
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
