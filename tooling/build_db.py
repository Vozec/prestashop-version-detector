#!/usr/bin/env python3
"""
Build the PrestaShop fingerprint DB from the local git clone.

Produces (under ../db):
  hashes.json    : { path: { sha256: [versions...] } }   (only discriminating files)
  presence.json  : { path: [versions where file exists] } (only files whose presence varies)
  probe_order.json: ordered list of paths, most-discriminating first (greedy set cover)
  meta.json      : { versions: [...], generated_from: "<describe>" }

Set PS_REPO to a PrestaShop git clone (with full tag history):
    PS_REPO=/path/to/PrestaShop python3 tooling/build_db.py
The DB is written into this repo's db/ and synced into psfp/data (embedded).
No network. Deterministic.
"""
import subprocess, hashlib, json, os, sys
from collections import defaultdict

# This tool's repo root (where db/ and psfp/ live).
TOOL_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The PrestaShop git clone to fingerprint (override with PS_REPO).
REPO = os.environ.get("PS_REPO") or os.path.expanduser("~/Desktop/r&d/prestashop")
if not os.path.isdir(os.path.join(REPO, ".git")):
    sys.exit(f"[!] PS_REPO is not a git clone: {REPO}\n"
             f"    Set PS_REPO=/path/to/PrestaShop (with full tag history).")
OUT  = os.path.join(TOOL_REPO, "db")

# Static path prefixes that are reachable on a default install without auth and
# are theme-independent. js/ is served verbatim by the default .htaccess.
INCLUDE_PREFIXES = ("js/",)
# Extra individual root-level static files worth fingerprinting.
EXTRA_FILES = ("INSTALL.txt", "Install_PrestaShop.html", "docs/CHANGELOG.txt")

def git(*args):
    return subprocess.run(["git", "-C", REPO, *args],
                          capture_output=True, text=False).stdout

def git_text(*args):
    return subprocess.run(["git", "-C", REPO, *args],
                          capture_output=True, text=True).stdout

def version_tags():
    import re
    tags = git_text("tag").split()
    clean = [t for t in tags if re.fullmatch(r"\d+\.\d+\.\d+(\.\d+)?", t)]
    def key(v): return tuple(int(x) for x in v.split("."))
    return sorted(clean, key=key)

def tree_blobs(tag):
    """Return {path: oid} for fingerprintable static files at <tag>."""
    # Limit to the paths we fingerprint via pathspec — listing the full repo
    # tree for every tag is 100x slower.
    out = git_text("ls-tree", "-r", tag, "--", "js", *EXTRA_FILES)
    res = {}
    for line in out.splitlines():
        # <mode> blob <oid>\t<path>
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) < 3 or parts[1] != "blob":
            continue
        oid = parts[2]
        # .php files execute server-side (return HTML, not the file bytes) — useless
        # as static fingerprints. Keep only genuinely static-served extensions.
        if path.endswith(".php"):
            continue
        if path.startswith(INCLUDE_PREFIXES) or path in EXTRA_FILES:
            res[path] = oid
    return res

def sha256_of_oids(oids):
    """Batch-hash blob OIDs -> {oid: sha256} via a single git cat-file --batch."""
    import threading
    proc = subprocess.Popen(["git", "-C", REPO, "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    payload = ("\n".join(oids) + "\n").encode()
    # Feed stdin from a thread to avoid a pipe deadlock when payload + git's
    # stdout both exceed the OS pipe buffer.
    def feed():
        proc.stdin.write(payload); proc.stdin.close()
    threading.Thread(target=feed, daemon=True).start()
    out = proc.stdout
    result = {}
    while True:
        header = out.readline()
        if not header:
            break
        h = header.decode().strip().split()
        if len(h) != 3:  # "<oid> missing" etc.
            continue
        oid, _typ, size = h[0], h[1], int(h[2])
        data = out.read(size)
        out.read(1)  # trailing newline
        result[oid] = hashlib.sha256(data).hexdigest()
    proc.wait()
    return result

def native_modules(tags):
    """Union of module names that ship NATIVELY with PrestaShop across all tags.
    1.5-1.7 keep modules in modules/<name>/; 8.x/9.x are composer-managed so the
    list lives in composer.json. A module NOT in this set is third-party/custom."""
    import json as _json
    native = set()
    for t in tags:
        # dir-based (1.5 .. 1.7)
        for line in git_text("ls-tree", "--name-only", f"{t}:modules").splitlines():
            n = line.strip().strip("/")
            if n and n not in ("index.php", ".htaccess"):
                native.add(n)
        # composer-based (8.x / 9.x)
        raw = git_text("show", f"{t}:composer.json")
        if raw.strip():
            try:
                cj = _json.loads(raw)
                for sect in ("require", "require-dev"):
                    for k in cj.get(sect, {}):
                        name = k.split("/")[-1]
                        if k.lower().startswith("prestashop/") or \
                           name.startswith(("ps_", "block", "stats", "dash", "gs")):
                            native.add(name)
            except ValueError:
                pass
    # PrestaShop-authored modules distributed via the marketplace rather than
    # bundled in core (so they never appear in modules/ or composer.json) — but
    # they ARE official. Curated from known PrestaShop SA author modules.
    PRESTASHOP_AUTHORED = {
        "gamification", "welcome", "psgdpr", "pscleaner", "productcomments",
        "ps_accounts", "ps_checkout", "ps_eventbus", "ps_mbo", "ps_metrics",
        "ps_facebook", "ps_googleanalytics", "ps_buybuttonlite", "ps_themecusto",
        "ps_livetranslation", "ps_faviconnotificationbo", "ps_distributionapiclient",
        "ps_apiresources", "ps_emailalerts", "ps_emailsubscription", "ps_shoppingcart",
    }
    native |= PRESTASHOP_AUTHORED
    return sorted(native)

def main():
    tags = version_tags()
    print(f"[*] {len(tags)} version tags: {tags[0]} .. {tags[-1]}", file=sys.stderr)

    per_tag = {}           # tag -> {path: oid}
    all_oids = set()
    for t in tags:
        blobs = tree_blobs(t)
        per_tag[t] = blobs
        all_oids.update(blobs.values())
    print(f"[*] {len(all_oids)} unique blobs to hash", file=sys.stderr)

    oid_sha = sha256_of_oids(list(all_oids))
    print(f"[*] hashed {len(oid_sha)} blobs", file=sys.stderr)

    # path -> sha256 -> set(versions)
    path_hash_versions = defaultdict(lambda: defaultdict(set))
    # path -> set(versions present)
    path_present = defaultdict(set)
    for t in tags:
        for path, oid in per_tag[t].items():
            sha = oid_sha.get(oid)
            if not sha:
                continue
            path_hash_versions[path][sha].add(t)
            path_present[path].add(t)

    # Keep only DISCRIMINATING content files: >1 distinct hash across the
    # versions in which the file exists (otherwise content tells us nothing).
    hashes = {}
    for path, hv in path_hash_versions.items():
        if len(hv) > 1:
            hashes[path] = {sha: sorted(vs, key=lambda v: tuple(int(x) for x in v.split(".")))
                            for sha, vs in hv.items()}

    # Presence is informative only when a file does NOT exist in every version.
    presence = {}
    nversions = len(tags)
    for path, vs in path_present.items():
        if len(vs) < nversions:
            presence[path] = sorted(vs, key=lambda v: tuple(int(x) for x in v.split(".")))

    # Greedy probe ordering: pick content-hash files that split the version
    # space the most. Score = number of distinct (hash) buckets weighted by
    # how evenly they partition. Simpler proxy: distinct-hash count desc.
    scored = sorted(hashes.keys(),
                    key=lambda p: (len(hashes[p]), sum(len(v) for v in hashes[p].values())),
                    reverse=True)
    probe_order = scored

    native = native_modules(tags)
    print(f"[*] {len(native)} native module names", file=sys.stderr)

    os.makedirs(OUT, exist_ok=True)
    json.dump(native, open(os.path.join(OUT, "native_modules.json"), "w"))
    json.dump(hashes,   open(os.path.join(OUT, "hashes.json"), "w"))
    json.dump(presence, open(os.path.join(OUT, "presence.json"), "w"))
    json.dump(probe_order, open(os.path.join(OUT, "probe_order.json"), "w"), indent=0)
    json.dump({"versions": tags,
               "generated_from": "PrestaShop git tags",
               "n_discriminating_files": len(hashes),
               "n_presence_files": len(presence)},
              open(os.path.join(OUT, "meta.json"), "w"), indent=2)

    # Keep the embedded copy used by the Go SDK in sync.
    embed_dir = os.path.join(TOOL_REPO, "psfp", "data")
    if os.path.isdir(embed_dir):
        import shutil
        for fn in ("hashes.json", "presence.json", "probe_order.json", "meta.json",
                   "modules_wordlist.txt", "native_modules.json"):
            src = os.path.join(OUT, fn)
            if os.path.exists(src):
                shutil.copy(src, os.path.join(embed_dir, fn))
        print(f"[+] synced DB into {embed_dir}", file=sys.stderr)

    print(f"[+] hashes.json: {len(hashes)} discriminating files", file=sys.stderr)
    print(f"[+] presence.json: {len(presence)} presence-variable files", file=sys.stderr)
    print(f"[+] top discriminating files:", file=sys.stderr)
    for p in probe_order[:15]:
        print(f"      {len(hashes[p]):3d} hashes  {p}", file=sys.stderr)

if __name__ == "__main__":
    main()
