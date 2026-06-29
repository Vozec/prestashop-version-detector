package psfp

import (
	"context"
	"strconv"
	"strings"
)

// archiveMagic maps a file's leading bytes to an archive type.
var archiveMagic = []struct {
	magic []byte
	kind  string
}{
	{[]byte("PK\x03\x04"), "zip"},
	{[]byte("PK\x05\x06"), "zip(empty)"},
	{[]byte("\x1f\x8b"), "gzip/tgz"},
	{[]byte("7z\xbc\xaf\x27\x1c"), "7z"},
	{[]byte("Rar!\x1a\x07"), "rar"},
	{[]byte("BZh"), "bzip2"},
	{[]byte("\xfd7zXZ"), "xz"},
}

// archiveExts are the suffixes probed for leaked module source.
var archiveExts = []string{"zip", "tar", "tar.gz", "tgz", "tar.bz2", "7z", "rar", "bak", "old", "zip.bak"}

// FuzzArchives probes /modules/<name>.<ext> and /modules/<name>/<name>.<ext>
// for downloadable source archives, confirming hits by magic-byte sniff (not
// status code - a soft-404 HTML page can return 200). It is common for shops
// to leave a module's source zip next to its folder.
func (c *Client) FuzzArchives(ctx context.Context, base string, names []string) []ArchiveLeak {
	base = strings.TrimRight(base, "/")
	names = dedup(names)

	type job struct {
		name, url string
	}
	var jobs []job
	for _, n := range names {
		for _, ext := range archiveExts {
			jobs = append(jobs, job{n, base + "/modules/" + n + "." + ext})
			jobs = append(jobs, job{n, base + "/modules/" + n + "/" + n + "." + ext})
		}
	}

	hits := make([]*ArchiveLeak, len(jobs))
	c.parallel(len(jobs), func(i int) {
		j := jobs[i]
		r := c.fetch(ctx, j.url, 16) // only need the magic bytes
		if r == nil || r.status != 200 || len(r.body) < 2 {
			return
		}
		for _, m := range archiveMagic {
			if len(r.body) >= len(m.magic) && string(r.body[:len(m.magic)]) == string(m.magic) {
				size := r.header.Get("Content-Length")
				if size == "" {
					size = "?"
				} else if _, err := strconv.Atoi(size); err != nil {
					size = "?"
				}
				hits[i] = &ArchiveLeak{Module: j.name, URL: j.url, Type: m.kind, Size: size}
				return
			}
		}
	})

	var out []ArchiveLeak
	for _, h := range hits {
		if h != nil {
			out = append(out, *h)
		}
	}
	return out
}
