// Command psdetect is a fast PrestaShop fingerprinter CLI built on the psfp SDK.
//
//	psdetect https://shop.example.com                 # version + DOM module scrape
//	psdetect --modules https://shop.example.com       # + config.xml module enum (+versions)
//	psdetect --archives https://shop.example.com      # + leaked source-archive fuzz
//	psdetect --all -json out.json https://shop...      # everything, JSON report
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Vozec/prestashop-version-detector/psfp"
)

const (
	cReset  = "\033[0m"
	cDim    = "\033[2m"
	cBold   = "\033[1m"
	cGreen  = "\033[32m"
	cYel    = "\033[33m"
	cRed    = "\033[31m"
	cCyan   = "\033[36m"
	cOrange = "\033[38;5;208m"
)

func main() {
	var (
		modules   = flag.Bool("modules", false, "active config.xml module enumeration (with versions)")
		archives  = flag.Bool("archives", false, "fuzz discovered modules for leaked source archives")
		archesWL  = flag.Bool("archives-wordlist", false, "fuzz the FULL wordlist for archives (noisy)")
		all       = flag.Bool("all", false, "version + modules + archives")
		adminDir  = flag.String("admin", "", "known admin folder - parse EXACT version from the BO page")
		insecure  = flag.Bool("k", false, "skip TLS certificate verification")
		jsonOut   = flag.String("json", "", "write JSON report to file (\"-\" for stdout)")
		timeout   = flag.Duration("timeout", 12*time.Second, "per-request timeout")
		conc      = flag.Int("c", 24, "max concurrent requests")
		maxProbes = flag.Int("max-probes", 24, "max version hash probes")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: psdetect [flags] <url>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if *all {
		*modules, *archives = true, true
	}

	client, err := psfp.New(psfp.Options{
		Insecure:    *insecure,
		Timeout:     *timeout,
		Concurrency: *conc,
		MaxProbes:   *maxProbes,
	})
	if err != nil {
		fatal(err)
	}

	target := flag.Arg(0)
	res, err := client.Scan(context.Background(), target, psfp.ScanOpts{
		Modules:          *modules,
		Archives:         *archives,
		ArchivesWordlist: *archesWL,
		AdminDir:         *adminDir,
	})
	if err != nil {
		fatal(err)
	}

	if *jsonOut != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		if *jsonOut == "-" {
			fmt.Println(string(b))
		} else {
			if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
				fatal(err)
			}
		}
		if *jsonOut != "-" {
			print(target, res, *modules || *all, *archives || *archesWL || *all)
			fmt.Printf("%s  -> %s%s\n\n", cDim, *jsonOut, cReset)
		}
		return
	}
	print(target, res, *modules || *all, *archives || *archesWL || *all)
}

func print(target string, res *psfp.Result, didModules, didArchives bool) {
	tty := isTTY()
	c := func(s, color string) string {
		if !tty {
			return s
		}
		return color + s + cReset
	}

	fmt.Printf("\n  %s\n", c("psdetect -> "+target, cBold))

	if res.Detection.Confirmed {
		fmt.Printf("  %s  %s  %s\n", c("prestashop", cCyan), c("CONFIRMED", cGreen),
			c("("+strings.Join(res.Detection.Signals, ", ")+")", cDim))
	} else {
		fmt.Printf("  %s  %s\n", c("prestashop", cCyan), c("not confirmed (no strong signal)", cYel))
	}

	v := res.Version
	exactSrc := "EXACT - leaked via PSWS-Version"
	for _, e := range v.Evidence {
		if e.Via == "admin-page" {
			exactSrc = "EXACT - back-office page"
		}
	}
	switch {
	case v.Exact != "":
		fmt.Printf("  %s  %s  %s\n", c("version", cCyan), c(v.Exact, cGreen),
			c("("+exactSrc+")", cRed))
	case v.Identified:
		fmt.Printf("  %s  %s  %s\n", c("version", cCyan), c(v.Band, cGreen),
			c(fmt.Sprintf("(%d candidate release(s))", len(v.Candidates)), cDim))
	default:
		fmt.Printf("  %s  %s\n", c("version", cCyan), c("not identified", cYel))
	}
	n := 0
	for _, e := range v.Evidence {
		switch e.Via {
		case "hash":
			if n >= 6 {
				continue
			}
			sha := e.SHA256
			if len(sha) > 12 {
				sha = sha[:12]
			}
			fmt.Println(c(fmt.Sprintf("     ├─ %-26s sha256:%s -> %s", e.Path, sha, e.Band), cDim))
			n++
		case "install-txt", "presence":
			fmt.Println(c(fmt.Sprintf("     ├─ %-26s %s", e.Path, e.Band), cDim))
		case "admin-page":
			fmt.Println(c(fmt.Sprintf("     ├─ %-26s %s", e.Path, e.Band), cGreen))
		}
	}
	for _, b := range v.Behavioral {
		fmt.Println(c("     ├─ behavioral  "+b, cDim))
	}

	if res.UpgradeFeed != nil {
		uf := res.UpgradeFeed
		fmt.Printf("\n  %s  channel=%s  %s\n", c("upgrade-feed", cCyan),
			c(uf.Channel, cYel), c("("+uf.URL+" - autoupgrade module)", cDim))
		for _, b := range uf.Branches {
			fmt.Printf("     ├─ branch %-5s latest %s %s\n",
				b.Branch, c(b.Latest, cGreen), c(b.Download, cDim))
		}
	}

	if gi := res.Gitignore; gi != nil && (len(gi.AdminDirs) > 0 || len(gi.Modules) > 0 || len(gi.OtherPaths) > 0) {
		fmt.Printf("\n  %s  %s\n", c(".gitignore", cCyan), c("("+gi.URL+" exposed)", cDim))
		if len(gi.AdminDirs) > 0 {
			fmt.Printf("     ├─ %s %s\n", c("admin dir ->", cRed), c(strings.Join(gi.AdminDirs, ", "), cOrange))
		}
		if len(gi.Modules) > 0 {
			fmt.Printf("     ├─ project modules -> %s\n", c(strings.Join(gi.Modules, ", "), cOrange))
		}
		if len(gi.OtherPaths) > 0 {
			fmt.Printf("     ├─ other paths -> %s\n", c(strings.Join(gi.OtherPaths, ", "), cDim))
		}
	}

	if len(res.Modules) > 0 {
		off, cust := 0, 0
		for _, m := range res.Modules {
			if m.Origin == "official" {
				off++
			} else {
				cust++
			}
		}
		fmt.Printf("\n  %s  %s found  %s\n", c("modules", cCyan),
			c(fmt.Sprintf("%d", len(res.Modules)), cGreen),
			c(fmt.Sprintf("(%d official, %d custom)", off, cust), cDim))
		for _, m := range res.Modules {
			ver := "v?"
			if m.Version != "" && m.Version != "?" {
				ver = "v" + m.Version
			}
			// official -> green, custom -> orange
			color, origin := cGreen, "official"
			if m.Origin != "official" {
				color, origin = cOrange, "CUSTOM"
			}
			fmt.Printf("     • %s %s %s %s\n",
				c(fmt.Sprintf("%-30s", m.Name), color),
				c(fmt.Sprintf("%-8s", ver), cYel),
				c(fmt.Sprintf("%-8s", origin), color),
				c(m.Path+" ["+m.Source+"]", cDim))
		}
	} else if didModules {
		fmt.Printf("\n  %s  none found\n", c("modules", cCyan))
	}

	if len(res.Leaks) > 0 {
		fmt.Printf("\n  %s  %s archive(s)!\n", c("LEAKED SOURCE", cRed), c(fmt.Sprintf("%d", len(res.Leaks)), cRed))
		for _, l := range res.Leaks {
			fmt.Println(c(fmt.Sprintf("     ⚠ %s  [%s, %s bytes]", l.URL, l.Type, l.Size), cRed))
		}
	} else if didArchives {
		fmt.Printf("\n  %s  no leaked source archives found\n", c("archives", cCyan))
	}
	fmt.Println()
}

func isTTY() bool {
	fi, _ := os.Stdout.Stat()
	return fi != nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
