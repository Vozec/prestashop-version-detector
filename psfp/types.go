package psfp

// ScanOpts selects which stages run during a Scan.
type ScanOpts struct {
	Modules          bool   // active /modules/<m>/config.xml enumeration
	Archives         bool   // fuzz discovered modules for leaked source archives
	ArchivesWordlist bool   // fuzz the full wordlist for archives (noisy)
	AdminDir         string // known admin folder - parse exact version from the BO page
}

// Result is the full fingerprint report.
type Result struct {
	Target      string         `json:"target"`
	Detection   Detection      `json:"detection"`
	Version     VersionResult  `json:"version"`
	UpgradeFeed *UpgradeFeed   `json:"upgrade_feed,omitempty"`
	Gitignore   *GitignoreLeak `json:"gitignore,omitempty"`
	Modules     []Module       `json:"modules,omitempty"`
	Leaks       []ArchiveLeak  `json:"archive_leaks,omitempty"`
}

// Detection is the "is this PrestaShop?" verdict and the signals that fired.
type Detection struct {
	Confirmed bool     `json:"confirmed"`
	Signals   []string `json:"signals"` // e.g. ["error500.html", "webservice /api/ realm"]
}

// GitignoreLeak holds recon extracted from an exposed /.gitignore - frequently
// discloses the (randomised) admin folder, project-specific modules and other
// non-default paths.
type GitignoreLeak struct {
	URL        string   `json:"url"`
	AdminDirs  []string `json:"admin_dirs,omitempty"`  // e.g. ["admin_xp2025"]
	Modules    []string `json:"modules,omitempty"`     // custom modules referenced
	OtherPaths []string `json:"other_paths,omitempty"` // non-default paths of interest
}

// UpgradeFeed is the cached PrestaShop version channel left by the autoupgrade
// module at /XMLFeed.cache - confirms PrestaShop + autoupgrade and discloses the
// release channel and available upgrade branches.
type UpgradeFeed struct {
	URL      string       `json:"url"`
	Channel  string       `json:"channel"` // "stable" | "rc" | "beta" ...
	Branches []FeedBranch `json:"branches"`
}

// FeedBranch is one upgrade branch entry from the feed.
type FeedBranch struct {
	Branch   string `json:"branch"`   // "8.1"
	Latest   string `json:"latest"`   // "8.1.7"
	Download string `json:"download"` // zip link
}

// VersionResult holds the resolved core-version band and the evidence behind it.
type VersionResult struct {
	Band       string     `json:"band"`            // "8.1.5 - 8.1.7"
	Exact      string     `json:"exact,omitempty"` // set when a build leaks (PSWS-Version)
	Candidates []string   `json:"candidates"`      // remaining release tags
	Evidence   []Evidence `json:"evidence"`        // static-hash / presence hits
	Behavioral []string   `json:"behavioral"`      // behavioural narrowings applied
	Identified bool       `json:"identified"`      // false when nothing matched
}

// Evidence is a single fingerprint observation.
type Evidence struct {
	Path   string `json:"path"`           // static asset path probed, e.g. "js/admin.js"
	URL    string `json:"url"`            // full URL fetched
	Via    string `json:"via"`            // "hash" | "presence" | "unknown-hash"
	SHA256 string `json:"sha256"`         // sha256 of the fetched body
	Band   string `json:"band,omitempty"` // version band this hash maps to (when known)
}

// Module is a detected PrestaShop module.
type Module struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"` // from config.xml when available
	Origin  string `json:"origin"`            // "official" (native PS) | "custom" (third-party)
	Source  string `json:"source"`            // "dom" | "config.xml" | "logo.png"
	Path    string `json:"path"`              // path/URL that confirmed it
}

// ArchiveLeak is a downloadable module source archive found on the target.
type ArchiveLeak struct {
	Module string `json:"module"`
	URL    string `json:"url"`
	Type   string `json:"type"` // zip | gzip/tgz | 7z | rar | ...
	Size   string `json:"size"`
}
