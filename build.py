#!/usr/bin/env python3
"""Builds Bastion's threat-definitions bundle.

Runs nightly in GitHub Actions (and locally for testing). Standard library only, plus the
`yara` command-line tool for checking rules.

  1. Downloads macOS malware hashes from MalwareBazaar (needs ABUSECH_KEY).
  2. Downloads the YARA Forge "core" rule package and keeps only macOS rules from
     permissively licensed sources.
  3. Drops any rule that doesn't compile with Bastion's YARA modules, or that matches a known-clean
     file (Apple's own apps and tools) — a false alarm on a clean Mac is worse than a missed rule.
  4. Writes dist/: signatures.txt, rules-yaraforge.yar, NOTICE.txt and manifest.json.
     Signing manifest.json is a separate step (sign.sh) so the private key never touches this script.
"""
import hashlib, io, json, os, re, subprocess, sys, tempfile, time, urllib.request, zipfile
from datetime import datetime, timezone

DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")
FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
MB_API = "https://mb-api.abuse.ch/api/v1/"
MB_FILE_TYPES = ["macho", "dmg", "pkg", "app"]
MB_TAGS = ["macOS", "AMOS", "AtomicStealer", "Poseidon", "Banshee", "Cuckoo", "MacSync", "Odyssey", "RustBucket"]

# Folders that are clean on every Mac. A rule matching anything here is a false alarm.
CLEAN_CORPUS = ["/System/Applications", "/System/Library/CoreServices", "/usr/bin", "/usr/sbin", "/bin",
                "/sbin", "/usr/libexec", "/Applications"]

# libyara modules Bastion compiles in (Package.swift). Rules needing others would break loading.
SUPPORTED_MODULES = {"pe", "elf", "math", "time", "console", "string", "hash", "macho"}

MACOS_HINT = re.compile(r"macos|mac_os|\bosx\b|_osx_|darwin|mach-?o|macho\.|amos\b|atomic.?stealer|poseidon|banshee|"
                        r"cuckoo.?stealer|xcsset|shlayer|adload|pirrit|bundlore|silver.?sparrow|rustbucket|"
                        r"lazarus.*mac|applejeus|metamorfo.*mac|\.dylib|launchagents|osascript", re.I)

# Licenses that allow use in a commercial product (with attribution).
OK_LICENSE = re.compile(r"\bMIT\b|Apache|BSD|Detection Rule License|DRL|CC0|CC[- ]BY(?![- ]NC)|Creative Commons Attribution(?! ?-? ?Non)|"
                        r"Elastic License 2", re.I)
BAD_LICENSE = re.compile(r"non.?commercial|\bNC\b|GPL|NO LICENSE|N/A", re.I)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def http(url, data=None, headers=None, timeout=90):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    req.add_header("User-Agent", "bastion-definitions-builder")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---------------------------------------------------------------- MalwareBazaar

def fetch_hashes(key):
    hashes = {}
    queries = [("file_type=" + t, f"query=get_file_type&file_type={t}") for t in MB_FILE_TYPES]
    queries += [("tag=" + t, f"query=get_taginfo&tag={t}") for t in MB_TAGS]
    for label, body in queries:
        line = f"{label}: failed"
        for limit in (1000, 500, 200):  # big families time out server-side at 1000
            try:
                raw = http(MB_API, f"{body}&limit={limit}".encode(), {"Auth-Key": key})
                resp = json.loads(raw)
            except Exception as e:  # noqa: BLE001 — retry smaller
                line = f"{label}: {e.__class__.__name__}"
                continue
            data = resp.get("data") if isinstance(resp.get("data"), list) else []
            for s in data:
                h = (s.get("sha256_hash") or "").lower()
                if re.fullmatch(r"[0-9a-f]{64}", h):
                    hashes[h] = re.sub(r"[^\w.\- ]", "", s.get("signature") or label)[:60] or label
            line = f"{label}: {resp.get('query_status')}, {len(data)} samples"
            break
        log("  " + line)
        time.sleep(1)  # be polite to abuse.ch
    return hashes


# ---------------------------------------------------------------- YARA Forge

def split_forge(text):
    """Yields (ruleset_header, rule_text) for every rule; header holds the source repo + license."""
    header = ""
    for block in re.split(r"(?m)^(?=/\*\n \* YARA Rule Set|rule \w)", text):
        if block.startswith("/*\n * YARA Rule Set"):
            end = block.find("*/")
            header = block[: end + 2]
            block = block[end + 2:].lstrip()
        if block.startswith("rule "):
            yield header, block.rstrip() + "\n"


def header_field(header, name):
    m = re.search(rf"\* {name}: (.+)", header)
    return m.group(1).strip() if m else ""


def header_license(header):
    m = re.search(r"\* LICENSE\n \* \n(.*?) \*/", header, re.S)
    if not m:
        return ""
    return " ".join(l.strip(" *") for l in m.group(1).splitlines()).strip()


def rule_name(rule):
    return re.match(r"rule (\w+)", rule).group(1)


def modules_used(rule):
    return set(re.findall(r"\b(pe|elf|math|time|console|string|hash|macho|dotnet|cuckoo|magic)\.", rule))


def fetch_forge_rules():
    zf = zipfile.ZipFile(io.BytesIO(http(FORGE_URL, timeout=180)))
    text = zf.read(next(n for n in zf.namelist() if n.endswith(".yar"))).decode("utf-8", "replace")
    kept, sources, stats = [], {}, {"total": 0, "not_macos": 0, "license": 0, "module": 0}
    for header, rule in split_forge(text):
        stats["total"] += 1
        if not MACOS_HINT.search(rule):
            stats["not_macos"] += 1
            continue
        lic = header_license(header)
        if not OK_LICENSE.search(lic) or (BAD_LICENSE.search(lic) and not OK_LICENSE.search(lic)):
            stats["license"] += 1
            continue
        if not modules_used(rule) <= SUPPORTED_MODULES:
            stats["module"] += 1
            continue
        repo = header_field(header, "Repository")
        sources.setdefault(repo, {"name": header_field(header, "Repository Name"), "license": lic[:300]})
        kept.append(rule)
    log(f"  YARA Forge: {stats['total']} rules → {len(kept)} macOS rules with a usable license "
        f"(skipped {stats['not_macos']} non-macOS, {stats['license']} license, {stats['module']} unsupported module)")
    return kept, sources


def imports_for(rules):
    used = set().union(*(modules_used(r) for r in rules)) if rules else set()
    return "".join(f'import "{m}"\n' for m in sorted(used & SUPPORTED_MODULES))


def compiles(rules):
    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as f:
        f.write(imports_for(rules) + "\n".join(rules))
    out = subprocess.run(["yarac", f.name, f.name + ".bin"], capture_output=True, text=True)
    os.unlink(f.name)
    if os.path.exists(f.name + ".bin"):
        os.unlink(f.name + ".bin")
    return out.returncode == 0


def vet_rules(rules):
    """Keep rules that compile on their own and never fire on the clean corpus."""
    good = [r for r in rules if compiles([r])]
    log(f"  compile check: {len(rules) - len(good)} dropped")
    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as f:
        f.write(imports_for(good) + "\n".join(good))
    noisy = set()
    for folder in CLEAN_CORPUS:
        if not os.path.isdir(folder):
            continue
        out = subprocess.run(["yara", "-r", "-N", "-p", "8", "-w", f.name, folder],
                             capture_output=True, text=True)
        for line in out.stdout.splitlines():
            name = line.split(" ", 1)[0]
            if name not in noisy:
                log(f"  false alarm: {name} on {line.split(' ', 1)[1] if ' ' in line else '?'}")
            noisy.add(name)
    os.unlink(f.name)
    kept = [r for r in good if rule_name(r) not in noisy]
    log(f"  false-alarm check: {len(good) - len(kept)} dropped")
    return kept


# ---------------------------------------------------------------- Output

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.makedirs(DIST, exist_ok=True)
    for f in os.listdir(DIST):
        os.unlink(os.path.join(DIST, f))

    key = os.environ.get("ABUSECH_KEY", "").strip()
    if not key and os.path.exists(os.path.expanduser("~/Library/Application Support/Bastion/abusech.key")):
        key = open(os.path.expanduser("~/Library/Application Support/Bastion/abusech.key")).read().strip()
    log("MalwareBazaar:")
    hashes = fetch_hashes(key) if key else {}
    if not hashes:
        sys.exit("no hashes downloaded — refusing to publish an empty bundle")

    log("YARA Forge:")
    rules, sources = fetch_forge_rules()
    rules = vet_rules(rules)

    created = datetime.now(timezone.utc)
    version = int(created.strftime("%Y%m%d%H%M"))

    with open(os.path.join(DIST, "signatures.txt"), "w") as f:
        f.write(f"# Bastion threat definitions {version} — MalwareBazaar (abuse.ch), CC0\n")
        for h in sorted(hashes):
            f.write(f"{h},{hashes[h]}\n")
    with open(os.path.join(DIST, "rules-yaraforge.yar"), "w") as f:
        f.write(f"// Bastion threat definitions {version} — macOS rules from YARA Forge (see NOTICE.txt)\n")
        f.write(imports_for(rules) + "\n" + "\n".join(rules))
    with open(os.path.join(DIST, "NOTICE.txt"), "w") as f:
        f.write("Bastion threat definitions include data from:\n\n")
        f.write("MalwareBazaar by abuse.ch — https://bazaar.abuse.ch — CC0\n")
        f.write("YARA Forge — https://github.com/YARAHQ/yara-forge — rule sets and licenses:\n\n")
        for repo, s in sorted(sources.items()):
            f.write(f"- {s['name']} ({repo})\n  {s['license']}\n")

    files = {}
    for name in sorted(os.listdir(DIST)):
        p = os.path.join(DIST, name)
        files[name] = {"sha256": sha256(p), "size": os.path.getsize(p)}
    manifest = {
        "format": 1,
        "version": version,
        "created": created.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "counts": {"hashes": len(hashes), "rules": len(rules)},
        "files": files,
    }
    with open(os.path.join(DIST, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    log(f"Built definitions {version}: {len(hashes)} hashes, {len(rules)} YARA rules")


if __name__ == "__main__":
    main()
