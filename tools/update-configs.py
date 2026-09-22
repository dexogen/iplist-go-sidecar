#!/usr/bin/env python3
"""Collect and publish validated, compressed configuration snapshots."""
from __future__ import annotations
import argparse
import concurrent.futures
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

FIELDS = ("domains", "ip4", "ip6", "cidr4", "cidr6")
PUBLIC = {"beta": "https://beta.iplist.opencck.org", "russia": "https://russia.iplist.opencck.org"}
MASTER = "https://github.com/rekryt/iplist/archive/refs/heads/master.zip"
DEFAULT_URL = "https://github.com/dexogen/iplist-go-sidecar/releases/download/data/manifest.json"
MAX_BYTES = 512 * 1024 * 1024
EPOCH = "1970-01-01T00:00:00Z"


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fetch(url, attempts=3, limit=MAX_BYTES):
    error = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip", "User-Agent": "iplist-go-sidecar"})
            with urllib.request.urlopen(req, timeout=45) as response:
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise ValueError("response exceeds size limit")
                if response.headers.get("Content-Encoding") == "gzip":
                    with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                        body = stream.read(limit + 1)
                    if len(body) > limit:
                        raise ValueError("expanded response exceeds limit")
                return body
        except (OSError, ValueError, EOFError, urllib.error.URLError) as exc:
            error = exc
            if attempt + 1 < attempts:
                delay = 2 ** attempt
                if isinstance(exc, urllib.error.HTTPError):
                    retry = exc.headers.get("Retry-After", "")
                    if retry.isdigit():
                        delay = min(60, max(delay, int(retry)))
                time.sleep(delay)
    raise RuntimeError(f"{url}: {error}") from error


def fetch_json(url):
    for attempt in range(3):
        try:
            return json.loads(fetch(url))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            if attempt == 2:
                raise RuntimeError(f"{url}: invalid JSON") from exc
            time.sleep(1 + attempt)


def identifier(value):
    if not isinstance(value, str) or not value or value in (".", "..") or any(c.isspace() or ord(c) < 32 or c in "/\\" for c in value):
        raise ValueError(f"invalid identifier: {value!r}")
    return value


def strings(value):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
        raise ValueError("expected array of nonempty strings")
    return list(dict.fromkeys(x.strip() for x in value))


def normalize(field, value):
    result = set()
    for item in strings(value):
        if field == "domains":
            domain = item.lower().rstrip(".")
            host = domain.removeprefix("*.").removeprefix(".").encode("idna").decode()
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", part) for part in host.split(".")):
                raise ValueError(f"invalid domain: {item!r}")
            result.add(domain)
        else:
            parsed = ipaddress.ip_network(item, strict=False) if field.startswith("cidr") else ipaddress.ip_address(item)
            if parsed.version != int(field[-1]):
                raise ValueError(f"wrong IP family for {field}: {item}")
            result.add(str(parsed))
    return sorted(result)


def validate_site(value, name, group):
    if not isinstance(value, dict):
        raise ValueError("site must be an object")
    site = {"name": identifier(name), "group": identifier(group)}
    for f in FIELDS:
        if f != "domains":
            site[f] = normalize(f, value.get(f))
            continue
        valid, rejected = [], []
        for domain in strings(value.get(f)):
            try:
                valid.extend(normalize(f, [domain]))
            except ValueError:
                rejected.append(domain)
        if rejected and (not valid or len(rejected) > 20 or len(rejected) > len(valid) * .1):
            raise ValueError("too many invalid domains")
        site[f] = sorted(set(valid))
        site["rejected_domains"] = rejected
    site["dns"] = strings(value.get("dns", []))
    timeout = value.get("timeout", 0)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 0:
        raise ValueError("invalid timeout")
    site["timeout"] = timeout
    external = value.get("external", {})
    if not isinstance(external, dict):
        raise ValueError("invalid external sources")
    site["external"] = {f: strings(external.get(f, [])) for f in FIELDS}
    for urls in site["external"].values():
        if any(urllib.parse.urlparse(u).scheme not in ("http", "https") for u in urls):
            raise ValueError("external URL must use HTTP(S)")
    replace = value.get("replace", {})
    if not isinstance(replace, dict):
        raise ValueError("invalid replacements")
    site["replace"] = {}
    for f in ("cidr4", "cidr6"):
        mapping = replace.get(f, {})
        if not isinstance(mapping, dict):
            raise ValueError("invalid replacement map")
        site["replace"][f] = {normalize(f, [k])[0]: normalize(f, v) for k, v in mapping.items()}
    site["as"] = strings(value.get("as", []))
    for asn in site["as"]:
        if not re.fullmatch(r"(?:AS)?[1-9][0-9]*", asn.upper()):
            raise ValueError(f"invalid ASN {asn}")
    return site


def check_drop(old, new, allow=False):
    if allow:
        return
    for f in FIELDS:
        before, after = len(old.get(f, [])), len(new[f])
        if before and (after == 0 or after < before * .65):
            raise ValueError(f"suspicious {f} decrease {before} -> {after}")


def api(base, **params):
    return base + "/?" + urllib.parse.urlencode({"format": "json", **params})


def discover(base):
    errors = []
    for field in ("group", "domains"):
        try:
            data = fetch_json(api(base, data=field))
            if not isinstance(data, dict) or not data:
                raise ValueError("empty catalog")
            if field == "group":
                return {identifier(k): identifier(v) for k, v in data.items()}
            for values in data.values():
                normalize("domains", values)
            return {identifier(k): None for k in data}
        except (RuntimeError, ValueError) as exc:
            errors.append(str(exc))
    raise RuntimeError("catalog discovery failed: " + "; ".join(errors))


def text_values(url, field):
    lines = fetch(url).decode("utf-8").splitlines()
    if any("error" in line.lower() for line in lines if line.lstrip().startswith("#")):
        raise ValueError("text response reports an error")
    return normalize(field, [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")])


def fetch_field(base, name, field):
    try:
        data = fetch_json(api(base, site=name, data=field))
        if not isinstance(data, dict) or name not in data:
            raise ValueError("site missing from response")
        return normalize(field, data[name])
    except (RuntimeError, ValueError):
        url = base + "/?" + urllib.parse.urlencode({"format": "text", "site": name, "data": field})
        return text_values(url, field)


def collect_public(name, previous, allow=False, workers=2):
    base = PUBLIC[name]
    groups = discover(base)
    old_sites = previous.get("sites", {})
    warnings, sites = [], {}
    def collect(item):
        site_name, group = item
        old = old_sites.get(site_name, {})
        group = group or old.get("group", name)
        retained_metadata = False
        try:
            try:
                data = fetch_json(api(base, site=site_name))
                if not isinstance(data, dict) or not isinstance(data.get(site_name), dict):
                    raise ValueError("site missing from response")
                if not {"dns", "external", "replace"} <= data[site_name].keys():
                    raise ValueError("incomplete site metadata")
                site = validate_site(data[site_name], site_name, group)
            except (RuntimeError, ValueError):
                fields = {f: fetch_field(base, site_name, f) for f in FIELDS}
                if not old:
                    raise ValueError("new site metadata unavailable")
                site = validate_site({**old, **fields}, site_name, group)
                retained_metadata = True
            check_drop(old, site, allow)
            if not any(site[f] for f in FIELDS) and not old:
                raise ValueError("empty new site")
            return site_name, site, f"{site_name}: fields recovered; previous metadata retained" if retained_metadata else None
        except (RuntimeError, ValueError) as exc:
            return site_name, old or None, f"{site_name}: {exc}"
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for site_name, site, error in pool.map(collect, sorted(groups.items())):
            if error:
                warnings.append(error)
            if site:
                sites[site_name] = site
    if not allow:
        for missing in sorted(old_sites.keys() - groups.keys()):
            sites[missing] = old_sites[missing]
            warnings.append(f"{missing}: missing from catalog; previous site retained")
    if not sites:
        raise ValueError("no valid sites")
    return {"sites": sites, "last_success_at": previous.get("last_success_at", EPOCH) if warnings else now(), "warnings": warnings}


def collect_master(previous, allow=False):
    sites = {}
    with zipfile.ZipFile(io.BytesIO(fetch(MASTER))) as archive:
        total = 0
        for entry in archive.infolist():
            parts = Path(entry.filename).parts
            if len(parts) != 4 or parts[1] != "config" or not parts[3].endswith(".json"):
                continue
            total += entry.file_size
            if total > MAX_BYTES:
                raise ValueError("master archive exceeds limit")
            name = parts[3][:-5]
            if name in sites:
                raise ValueError(f"duplicate site {name}")
            sites[name] = validate_site(json.loads(archive.read(entry)), name, parts[2])
    if not sites:
        raise ValueError("master archive has no valid sites")
    warnings = []
    for name, old in previous.get("sites", {}).items():
        try:
            if name not in sites:
                if allow:
                    continue
                raise ValueError("missing site")
            check_drop(old, sites[name], allow)
        except ValueError as exc:
            sites[name] = old
            warnings.append(f"{name}: {exc}; previous site retained")
    return {"sites": sites, "last_success_at": previous.get("last_success_at", EPOCH) if warnings else now(), "warnings": warnings}


def enrich(site, cache, warnings, allow=False):
    site = json.loads(json.dumps(site))
    for field, urls in site.get("external", {}).items():
        for url in urls:
            key = field + ":" + url
            previous = cache.get(key)
            try:
                values = text_values(url, field)
                if not values:
                    raise ValueError("empty external resource")
                if previous and not allow and len(values) < .65 * len(previous["values"]):
                    raise ValueError("suspicious external decrease")
                cache[key] = {"values": values, "last_success_at": now()}
            except (OSError, RuntimeError, ValueError) as exc:
                warnings.append(f"{key}: {exc}; previous resource retained")
                if previous is None:
                    raise ValueError(f"resource has no previous valid value: {key}") from exc
            site[field] = sorted(set(site[field]) | set(cache[key]["values"]))
    for raw_asn in site.get("as", []):
        asn = "AS" + raw_asn.upper().removeprefix("AS")
        url = "https://stat.ripe.net/data/announced-prefixes/data.json?" + urllib.parse.urlencode({"resource": asn, "min_peers_seeing": "0"})
        key = "asn:" + asn
        previous = cache.get(key)
        try:
            response = fetch_json(url)
            if response.get("status") != "ok" or str(response.get("data", {}).get("resource")) != asn[2:] or not isinstance(response.get("data", {}).get("prefixes"), list):
                raise ValueError("invalid RIPE response")
            values = sorted({str(ipaddress.ip_network(e["prefix"], strict=False)) for e in response["data"]["prefixes"]})
            if previous and not allow and len(values) < .65 * len(previous["values"]):
                raise ValueError("suspicious ASN decrease")
            cache[key] = {"values": values, "last_success_at": now()}
        except (RuntimeError, ValueError, KeyError, TypeError) as exc:
            warnings.append(f"{asn}: {exc}; previous prefixes retained")
            if previous is None:
                raise ValueError(f"no valid prefixes for {asn}") from exc
        for value in cache[key]["values"]:
            site["cidr" + str(ipaddress.ip_network(value).version)].append(value)
        site["cidr4"] = sorted(set(site["cidr4"]))
        site["cidr6"] = sorted(set(site["cidr6"]))
    return site


def custom_sites(root):
    for path in sorted(root.rglob("*.json")):
        parts = path.relative_to(root).parts
        if len(parts) != 3:
            raise ValueError(f"invalid custom config path {path}")
        key = "main" if parts[0] == "master" else identifier(parts[0])
        yield key, identifier(parts[1]), identifier(path.stem), json.loads(path.read_text())


def merge_custom(base, custom, name, group):
    merged = {**base, **custom}
    for f in (*FIELDS, "as"):
        merged[f] = sorted(set(base.get(f, [])) | set(custom.get(f, [])))
    merged["external"] = {f: sorted(set(base.get("external", {}).get(f, [])) | set(custom.get("external", {}).get(f, []))) for f in FIELDS}
    merged["replace"] = {f: {**base.get("replace", {}).get(f, {}), **custom.get("replace", {}).get(f, {})} for f in ("cidr4", "cidr6")}
    return validate_site(merged, name, group)


def write_object(root, value):
    raw = encode(value)
    body = gzip.compress(raw, compresslevel=6, mtime=0)
    digest = hashlib.sha256(body).hexdigest()
    path = "objects/" + digest + ".json.gz"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    return {"path": path, "sha256": digest, "bytes": len(body), "unpacked_bytes": len(raw)}


def object_url(manifest_url, descriptor):
    path = descriptor["path"]
    if not re.fullmatch(r"objects/[a-f0-9]{64}\.json\.gz", path):
        raise ValueError("invalid object path")
    if "/releases/download/" in manifest_url:
        path = path.split("/")[-1]
    return urllib.parse.urljoin(manifest_url, path)


def read_object(manifest_url, descriptor):
    body = fetch(object_url(manifest_url, descriptor))
    if len(body) != descriptor["bytes"] or hashlib.sha256(body).hexdigest() != descriptor["sha256"]:
        raise ValueError("snapshot checksum/size mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or len(raw) != descriptor["unpacked_bytes"]:
        raise ValueError("snapshot expanded size mismatch")
    return json.loads(raw)


def seed(root):
    sources = {}
    for name in ("master", "beta", "russia"):
        sites = {}
        for path in sorted((root / name).glob("*/*.json")):
            if path.stem in sites:
                raise ValueError(f"duplicate seed site {path.stem}")
            sites[path.stem] = validate_site(json.loads(path.read_text()), path.stem, path.parent.name)
        if sites:
            sources[name] = {"sites": sites, "last_success_at": EPOCH, "warnings": ["unverified seed"]}
    return {"schema_version": 1, "sources": sources, "resources": {}}


def build(args):
    previous_manifest = None
    try:
        previous_manifest = fetch_json(args.previous_url)
        if previous_manifest.get("schema_version") != 1:
            raise ValueError("unsupported manifest schema")
        state = read_object(args.previous_url, previous_manifest["state"])
    except (RuntimeError, ValueError, KeyError) as exc:
        if not args.seed_dir:
            raise RuntimeError(f"previous snapshot unavailable and no seed: {exc}") from exc
        print(f"bootstrap from seed: {exc}", file=sys.stderr)
        previous_manifest = None
        state = seed(Path(args.seed_dir))
    state.setdefault("resources", {})
    state.setdefault("sources", {})
    for name in ("master", "beta", "russia"):
        old = state["sources"].get(name, {})
        try:
            print(f"collecting {name}", flush=True)
            source = collect_master(old, args.allow_removals) if name == "master" else collect_public(name, old, args.allow_removals, args.workers)
        except Exception as exc:
            if not old.get("sites"):
                raise RuntimeError(f"{name}: no valid fallback") from exc
            source = {**old, "warnings": [f"collection failed; previous source retained: {exc}"]}
        state["sources"][name] = source
    sets, metadata = {}, {}
    for name, source in state["sources"].items():
        key = "main" if name == "master" else name
        sets[key] = dict(source["sites"])
        metadata[key] = {"last_success_at": source["last_success_at"], "warnings": list(source["warnings"])}
    for key, group, name, custom in custom_sites(Path(args.custom_dir)):
        sets.setdefault(key, {})[name] = merge_custom(sets.get(key, {}).get(name, {}), custom, name, group)
        metadata.setdefault(key, {"last_success_at": now(), "warnings": []})
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "published_at": now(), "revision": os.environ.get("GITHUB_SHA", "local"), "sets": {}}
    for key in sorted(sets):
        info = metadata[key]
        warnings = info["warnings"]
        before = len(warnings)
        try:
            sites = [enrich(site, state["resources"], warnings, args.allow_removals) for _, site in sorted(sets[key].items())]
        except ValueError as exc:
            if not previous_manifest or key not in previous_manifest["sets"]:
                raise
            sites = read_object(args.previous_url, previous_manifest["sets"][key])["sites"]
            warnings.append(f"enrichment failed; previous set retained: {exc}")
        if len(warnings) > before:
            info["last_success_at"] = previous_manifest["sets"].get(key, {}).get("last_success_at", EPOCH) if previous_manifest else EPOCH
        descriptor = write_object(output, {"schema_version": 1, "config_set": key, "sites": sites})
        descriptor.update(last_success_at=info["last_success_at"], checked_at=now(), status="degraded" if warnings else "ok", warnings=warnings, sites=len(sites), counts={f: sum(len(s[f]) for s in sites) for f in FIELDS}, rejected_domains={s["name"]: s["rejected_domains"] for s in sites if s.get("rejected_domains")})
        manifest["sets"][key] = descriptor
        print(f"{key}: {len(sites)} sites, {len(warnings)} warnings, {descriptor['bytes']} compressed bytes", flush=True)
    manifest["state"] = write_object(output, state)
    if previous_manifest:
        for descriptor in [*previous_manifest["sets"].values(), previous_manifest["state"]]:
            target = output / descriptor["path"]
            if not target.exists():
                # Copy exact bytes: compression can differ between runtime versions.
                body = fetch(object_url(args.previous_url, descriptor))
                if hashlib.sha256(body).hexdigest() != descriptor["sha256"]:
                    raise ValueError("previous object checksum mismatch")
                target.write_bytes(body)
    (output / "manifest.json").write_bytes(encode(manifest) + b"\n")
    (output / "collection-summary.json").write_bytes(encode({k: {f: v[f] for f in ("status", "sites", "counts", "last_success_at", "warnings")} for k, v in manifest["sets"].items()}) + b"\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-url", default=DEFAULT_URL)
    parser.add_argument("--seed-dir", default=None)
    parser.add_argument("--custom-dir", default="custom")
    parser.add_argument("--output", default="dist")
    parser.add_argument("--workers", type=int, default=2, choices=range(1, 9))
    parser.add_argument("--allow-removals", action="store_true", help="accept intentional catalog removals and large decreases")
    manifest = build(parser.parse_args())
    if any(v["status"] != "ok" for v in manifest["sets"].values()):
        print("::warning::Some sources retained previous data; see collection-summary.json")


if __name__ == "__main__":
    main()
