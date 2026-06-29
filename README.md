<div align="center">

# 🛍️ prestashop-version-detector

**Fast PrestaShop fingerprinter - version, modules & leaked source in seconds.**

Pinpoints the exact PrestaShop version, enumerates installed modules (official vs custom),
hunts leaked module source archives, and auto-chains recon from an exposed `.gitignore` -
all driven by a fingerprint database built from the **149 official PrestaShop git tags
(1.5.0.0 -> 9.1.4)**.

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PrestaShop](https://img.shields.io/badge/PrestaShop-1.5->9.1-blueviolet)](https://github.com/PrestaShop/PrestaShop)

</div>

---

```text
  psdetect -> https://shop.example.com
  prestashop    CONFIRMED  (error500.html)
  version       8.1.7  (EXACT - back-office page)
     |- js/admin.js                sha256:564800085fe4 -> 8.1.5 - 8.1.7
     |- js/tools.js                sha256:4c85fbb2829d -> 8.1.3 - 8.2.7
     |- INSTALL.txt                states PrestaShop 8
     |- adminA1B2C3/               exact 8.1.7
     |- behavioral  webservice /api/ enabled
  upgrade-feed  channel=stable  (/XMLFeed.cache - autoupgrade module)
     |- branch 8.1   latest 8.1.7   https://assets.prestashop3.com/.../8.1.7.zip
  .gitignore    (/.gitignore exposed)
     |- admin dir -> adminA1B2C3
     |- project modules -> acme_customblock
  modules       26 found  (18 official, 8 custom)
     - blockwishlist        v?   official  /modules/blockwishlist/logo.png
     - acme_import          v?   CUSTOM    /modules/acme_import/logo.png
  LEAKED SOURCE  1 archive(s)!
     ! https://shop.example.com/modules/acme_import.zip  [zip, 477140 bytes]
```

## ✨ Features

- **Near one-shot detection** - primary signal is the default static `error500.html`
  (present on every release, survives custom themes / headless front-ends / hardened `.htaccess`).
- **Exact version fingerprinting** - `sha256` of theme-independent core assets (`/js/*.js`)
  **intersected** against a UNION database built across all git tags. Behavioural probes split
  what hashes can't; an exposed admin folder yields the **exact** patch release.
- **Module enumeration** - names from the DOM, versions from `config.xml`, presence via
  `logo.png`, classified **official vs custom** (the custom ones are your real targets).
- **Leaked source hunting** - fuzzes `/modules/<name>.{zip,tar,tar.gz,7z,…}` and confirms by
  **magic bytes**, catching developers' source archives left on disk.
- **`.gitignore` auto-recon** - discovers the randomised admin folder, project modules and
  other paths, then **chains** the admin folder into exact-version detection - zero flags.
- **Upgrade-feed disclosure** - parses `/XMLFeed.cache` (autoupgrade) for channel & branches.
- **Fast & concurrent** - version-only resolves in ~5 s; full scan in seconds.
- **Library + CLI** - embeddable Go SDK (`psfp`) and a colorized CLI with JSON output.

## 📦 Install

```bash
go install github.com/Vozec/prestashop-version-detector/cmd/psdetect@latest
```

Or build from source:

```bash
git clone https://github.com/Vozec/prestashop-version-detector
cd prestashop-version-detector
make build      # -> ./psdetect   (DB is embedded, the binary is self-contained)
```

## 🚀 Usage

```bash
psdetect https://shop.example.com                  # detect + version + DOM module scrape
psdetect --modules https://shop.example.com        # + config.xml enum (with versions)
psdetect --archives https://shop.example.com       # + leaked-source archive fuzz
psdetect --admin admin123xyz https://shop...        # exact version from the back-office page
psdetect --all -json out.json https://shop...       # everything + JSON report
psdetect -k -c 32 --timeout 8s https://shop...      # skip TLS, 32 workers, 8s timeout
```

| Flag | Description |
|------|-------------|
| `--modules` | Active `config.xml` module enumeration (with versions) |
| `--archives` | Fuzz discovered modules for leaked source archives |
| `--archives-wordlist` | Fuzz the **full** wordlist for archives (noisy) |
| `--admin <dir>` | Known admin folder - parse the **exact** version from the BO page |
| `--all` | version + modules + archives |
| `-json <file\|->` | Write a JSON report (`-` for stdout) |
| `-k` | Skip TLS certificate verification |
| `-c <n>` | Max concurrent requests (default 24) |
| `--timeout <dur>` | Per-request timeout (default 12s) |
| `--max-probes <n>` | Max version hash probes (default 24) |

## 🧠 How it works

**Version = UNION of static-asset hashes.** `tooling/build_db.py` walks every git tag, hashes
all `/js/*.js` files (deduped by blob OID), and emits `path -> sha256 -> [versions]`. At scan
time `psdetect` fetches the most-discriminating files and **intersects** the candidate sets -
each hash narrows the band. PrestaShop patch releases that touch no static asset are
irreducible passively (e.g. `8.2.x`), which the tool reports honestly.

**Behavioural probes** split what hashes can't:

| Probe | Signal | Verdict |
|-------|--------|---------|
| `/admin-api/access_token` | `400/405` / `401 Bearer` | **9.x** |
| `/api/` `PSWS-Version` header | present (unauth) | **< 8.0** + exact build |
| `?controller=registration` | exists | **>= 8.0** |
| cookie `SameSite=Lax` | present | **>= 1.7.8** |
| `INSTALL.txt` | `"…for PrestaShop 8"` | major in clear |

**Exact version** comes from the back-office login page assets - the BO `?v=8.1.7`
cache-buster carries the real version (unlike the front office, where it's a global token).
The admin folder is supplied with `--admin`, or **auto-discovered from `/.gitignore`**.

**Detection** mirrors the bundled nuclei template: `error500.html`'s
`<meta>` literally reads *"This store is powered by PrestaShop"* on every version -
one GET, survives reskins.

## 📚 SDK

```go
import "github.com/Vozec/prestashop-version-detector/psfp"

c, _ := psfp.New(psfp.Options{Insecure: true})
res, _ := c.Scan(context.Background(), "https://shop.example.com",
    psfp.ScanOpts{Modules: true, Archives: true})

fmt.Println(res.Detection.Confirmed)              // true
fmt.Println(res.Version.Band, res.Version.Exact)  // "8.1.5 - 8.1.7"  "8.1.7"
for _, m := range res.Modules {
    fmt.Printf("%s %s [%s]\n", m.Name, m.Version, m.Origin)
}
for _, l := range res.Leaks {
    fmt.Println("LEAK:", l.URL)
}
```

Granular calls are exported too: `Detect`, `DetectVersion`, `AdminVersion`, `ScrapeModules`,
`EnumModules`, `FuzzArchives`, `FetchUpgradeFeed`, `FetchGitignore`.

## 🗂️ Project layout

```
.
├── cmd/psdetect/        # CLI
├── psfp/                # SDK package
│   ├── detect.go        # error500 + fallback detection
│   ├── version.go       # static-hash intersection
│   ├── behavioral.go    # route/header/cookie probes
│   ├── admin.go         # exact version from the BO page
│   ├── modules.go       # config.xml / logo.png enumeration
│   ├── archives.go      # leaked-source magic-byte fuzz
│   ├── gitignore.go     # .gitignore recon + auto-chaining
│   ├── feed.go          # /XMLFeed.cache parsing
│   └── data/            # embedded fingerprint DB (go:embed)
├── nuclei-templates/    # companion detection templates
└── tooling/build_db.py  # offline DB generator (from a PrestaShop git clone)
```

### Regenerating the database

```bash
make db     # python3 tooling/build_db.py - rewrites the DB and syncs the embed dir
```

## 🛡️ Nuclei templates

Companion detection templates ship in `nuclei-templates/`:

- `prestashop-fast.yaml` - near one-shot detection (`error500.html`)
- `prestashop-detect.yaml` - robust, headless-aware multi-signal
- `prestashop-version.yaml` - version fingerprint by `/js/tools.js` hash

```bash
nuclei -t nuclei-templates/prestashop-fast.yaml -l scope.txt -silent
```

## ⚖️ Legal

For **authorised security testing only** - bug-bounty programs, pentest engagements, your own
infrastructure. The archive-leak probe downloads bytes from the target. You are responsible for
having permission. WAF/Cloudflare-protected hosts may rate-limit; run from authorised infra.

## License

MIT © [Vozec](https://github.com/Vozec)
