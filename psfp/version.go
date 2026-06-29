package psfp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

// reInstallMajor matches the version major stated in clear in INSTALL.txt,
// e.g. "--- ===== Installation instructions for PrestaShop 8 ===== ---".
var reInstallMajor = regexp.MustCompile(`(?i)PrestaShop\s+(\d+)\b`)

// DetectVersion resolves the core-version band of base by hashing static assets
// and intersecting the candidate sets, then applying behavioural probes.
func (c *Client) DetectVersion(ctx context.Context, base string) VersionResult {
	base = strings.TrimRight(base, "/")
	candidates := toSet(c.db.Versions)
	var evidence []Evidence
	var mu sync.Mutex

	// --- stage 1: static content-hash intersection ---
	order := c.db.ProbeOrder
	if len(order) > c.max {
		order = order[:c.max]
	}
	type hit struct {
		path string
		sha  string
	}
	results := make([]hit, len(order))
	c.parallel(len(order), func(i int) {
		r := c.fetch(ctx, base+"/"+order[i], 4<<20)
		if r == nil || r.status != 200 || len(r.body) == 0 {
			return
		}
		sum := sha256.Sum256(r.body)
		results[i] = hit{order[i], hex.EncodeToString(sum[:])}
	})
	for _, h := range results {
		if h.path == "" {
			continue
		}
		url := base + "/" + h.path
		table := c.db.Hashes[h.path]
		if vs, ok := table[h.sha]; ok {
			next := intersect(candidates, vs)
			if len(next) > 0 {
				candidates = next
				mu.Lock()
				evidence = append(evidence, Evidence{h.path, url, "hash", h.sha, Band(vs)})
				mu.Unlock()
			}
		} else {
			mu.Lock()
			evidence = append(evidence, Evidence{h.path, url, "unknown-hash", h.sha, ""})
			mu.Unlock()
		}
	}

	// --- stage 2: positive-only presence narrowing ---
	var presPaths []string
	for p := range c.db.Presence {
		if _, isHash := c.db.Hashes[p]; !isHash {
			presPaths = append(presPaths, p)
		}
	}
	sortStrings(presPaths) // deterministic order
	if len(presPaths) > 12 {
		presPaths = presPaths[:12]
	}
	present := make([]bool, len(presPaths))
	c.parallel(len(presPaths), func(i int) {
		r := c.fetch(ctx, base+"/"+presPaths[i], 1<<16)
		present[i] = r != nil && r.status == 200 && len(r.body) > 64
	})
	for i, ok := range present {
		if !ok {
			continue
		}
		next := intersect(candidates, c.db.Presence[presPaths[i]])
		if len(next) > 0 && len(next) < len(candidates) {
			candidates = next
			evidence = append(evidence, Evidence{presPaths[i], base + "/" + presPaths[i],
				"presence", "", Band(c.db.Presence[presPaths[i]])})
		}
	}

	// --- stage 2b: INSTALL.txt states the major in clear ("...for PrestaShop 8") ---
	if r := c.fetch(ctx, base+"/INSTALL.txt", 1<<16); r != nil && r.status == 200 {
		if m := reInstallMajor.FindSubmatch(r.body); m != nil {
			major := string(m[1])
			kept := make(map[string]struct{})
			for v := range candidates {
				if strings.HasPrefix(v, major+".") {
					kept[v] = struct{}{}
				}
			}
			if len(kept) > 0 {
				candidates = kept
			}
			evidence = append(evidence, Evidence{"INSTALL.txt", base + "/INSTALL.txt",
				"install-txt", "", "states PrestaShop " + major})
		}
	}

	cands := setSlice(candidates)
	// --- stage 3: behavioural probes (8↔9, pre/post-8.0, exact build) ---
	bres := c.behavioral(ctx, base, cands)
	if len(bres.candidates) > 0 {
		cands = bres.candidates
	}

	vr := VersionResult{
		Band:       Band(cands),
		Exact:      bres.exact,
		Candidates: SortVersions(cands),
		Evidence:   evidence,
		Behavioral: bres.notes,
		Identified: len(cands) > 0 && len(cands) < len(c.db.Versions),
	}
	if bres.exact != "" {
		vr.Band = bres.exact
	}
	return vr
}

// --- small set helpers ---

func toSet(vs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(vs))
	for _, v := range vs {
		m[v] = struct{}{}
	}
	return m
}

func intersect(set map[string]struct{}, vs []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, v := range vs {
		if _, ok := set[v]; ok {
			out[v] = struct{}{}
		}
	}
	return out
}

func setSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	return out
}
