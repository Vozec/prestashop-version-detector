package psfp

import (
	"embed"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

//go:embed data/hashes.json data/presence.json data/probe_order.json data/meta.json data/modules_wordlist.txt data/native_modules.json
var dataFS embed.FS

// DB is the fingerprint database built offline from the PrestaShop git tags.
type DB struct {
	// Hashes maps a static path -> sha256 hex -> the versions carrying that content.
	Hashes map[string]map[string][]string
	// Presence maps a static path -> versions in which the file exists (when it
	// does not exist in every version).
	Presence map[string][]string
	// ProbeOrder lists fingerprint paths most-discriminating first.
	ProbeOrder []string
	// Versions is the full sorted list of known release tags.
	Versions []string
	// Wordlist is the bundled module-name wordlist for active enumeration.
	Wordlist []string
	// Native is the set of module names that ship with PrestaShop (official).
	// A name absent from this set is third-party / custom.
	Native map[string]bool
}

// IsOfficial reports whether name is an official PrestaShop module: either in
// the native/authored set, or carrying the PrestaShop-reserved "ps_" prefix.
func (db *DB) IsOfficial(name string) bool {
	return db.Native[name] || strings.HasPrefix(name, "ps_")
}

// Origin classifies a module name as "official" or "custom".
func (db *DB) Origin(name string) string {
	if db.IsOfficial(name) {
		return "official"
	}
	return "custom"
}

var loaded *DB

// LoadDB returns the embedded fingerprint database (parsed once, cached).
func LoadDB() (*DB, error) {
	if loaded != nil {
		return loaded, nil
	}
	db := &DB{}
	if err := readJSON("data/hashes.json", &db.Hashes); err != nil {
		return nil, err
	}
	if err := readJSON("data/presence.json", &db.Presence); err != nil {
		return nil, err
	}
	if err := readJSON("data/probe_order.json", &db.ProbeOrder); err != nil {
		return nil, err
	}
	var meta struct {
		Versions []string `json:"versions"`
	}
	if err := readJSON("data/meta.json", &meta); err != nil {
		return nil, err
	}
	db.Versions = meta.Versions
	var native []string
	if err := readJSON("data/native_modules.json", &native); err != nil {
		return nil, err
	}
	db.Native = make(map[string]bool, len(native))
	for _, n := range native {
		db.Native[n] = true
	}
	if b, err := dataFS.ReadFile("data/modules_wordlist.txt"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				db.Wordlist = append(db.Wordlist, l)
			}
		}
	}
	loaded = db
	return db, nil
}

func readJSON(name string, v any) error {
	b, err := dataFS.ReadFile(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// vtuple parses a dotted version into a 4-int comparable tuple (zero-padded).
func vtuple(v string) [4]int {
	var t [4]int
	for i, p := range strings.SplitN(v, ".", 4) {
		if i > 3 {
			break
		}
		n, _ := strconv.Atoi(p)
		t[i] = n
	}
	return t
}

func vless(a, b [4]int) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// SortVersions returns versions in ascending semantic order.
func SortVersions(vs []string) []string {
	out := append([]string(nil), vs...)
	sort.Slice(out, func(i, j int) bool { return vless(vtuple(out[i]), vtuple(out[j])) })
	return out
}

// Band renders a candidate set as a compact "min - max" band.
func Band(vs []string) string {
	if len(vs) == 0 {
		return "unknown"
	}
	s := SortVersions(vs)
	if len(s) == 1 {
		return s[0]
	}
	return s[0] + " - " + s[len(s)-1]
}
