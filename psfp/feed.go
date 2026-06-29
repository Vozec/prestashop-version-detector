package psfp

import (
	"context"
	"encoding/xml"
	"strings"
)

// feedPaths are locations where the autoupgrade module caches the version feed.
var feedPaths = []string{
	"/XMLFeed.cache",
	"/admin/autoupgrade/XMLFeed.cache",
	"/modules/autoupgrade/XMLFeed.cache",
}

// xml schema of /XMLFeed.cache
type feedXML struct {
	Channel struct {
		Name     string `xml:"name,attr"`
		Branches []struct {
			Name     string `xml:"name,attr"`
			Latest   string `xml:"name"` // <name>8.1.7</name> inside branch
			Num      string `xml:"num"`
			Download struct {
				Link string `xml:"link"`
			} `xml:"download"`
		} `xml:"branch"`
	} `xml:"channel"`
}

// FetchUpgradeFeed probes for the autoupgrade version-feed cache and parses it.
// Returns nil if no feed is reachable. One cheap GET per candidate path.
func (c *Client) FetchUpgradeFeed(ctx context.Context, base string) *UpgradeFeed {
	base = strings.TrimRight(base, "/")
	for _, p := range feedPaths {
		r := c.fetch(ctx, base+p, 1<<16)
		if r == nil || r.status != 200 || !contains(r.body, "<prestashop") {
			continue
		}
		var f feedXML
		if err := xml.Unmarshal(r.body, &f); err != nil {
			continue
		}
		uf := &UpgradeFeed{URL: base + p, Channel: f.Channel.Name}
		for _, b := range f.Channel.Branches {
			latest := b.Num
			if latest == "" {
				latest = b.Latest
			}
			uf.Branches = append(uf.Branches, FeedBranch{
				Branch:   b.Name,
				Latest:   latest,
				Download: b.Download.Link,
			})
		}
		return uf
	}
	return nil
}
