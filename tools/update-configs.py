#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG_ROOT = ROOT / "config"
MASTER_ARCHIVE_URL = "https://github.com/rekryt/iplist/archive/refs/heads/master.zip"
PUBLIC_SETS = {
    "beta": "https://beta.iplist.opencck.org",
    "russia": "https://russia.iplist.opencck.org",
}
DATA_TYPES = ("domains", "ip4", "ip6", "cidr4", "cidr6")
DEFAULT_DNS = ["127.0.0.11:53", "77.88.8.88:53", "8.8.8.8:53", "1.1.1.1:53"]
DEFAULT_EXTERNAL = {name: [] for name in DATA_TYPES}
DEFAULT_REPLACE = {"cidr4": {}, "cidr6": {}}


def fetch_bytes(url: str, timeout: float = 120.0, retries: int = 2) -> bytes:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "iplist-go-sidecar"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(1 + attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_error}") from last_error


def fetch_json(url: str, timeout: float = 60.0, retries: int = 2) -> Any:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "iplist-go-sidecar"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return json.loads(response.read().decode(charset))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(1 + attempt)
    raise RuntimeError(f"failed to fetch JSON from {url}: {last_error}") from last_error


def fetch_text_lines(url: str, timeout: float = 60.0, retries: int = 2) -> list[str]:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "iplist-go-sidecar"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                text = response.read().decode(charset)
            return sorted({line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")})
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(1 + attempt)
    raise RuntimeError(f"failed to fetch text from {url}: {last_error}") from last_error


def api_url(base_url: str, params: dict[str, str]) -> str:
    return f"{base_url.rstrip('/')}/?{urllib.parse.urlencode(params)}"


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()})


def as_string_map(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key, values in value.items():
        if isinstance(key, str):
            result[key] = as_string_list(values)
    return dict(sorted(result.items()))


def normalize_replace(value: Any) -> dict[str, dict[str, list[str]]]:
    if not isinstance(value, dict):
        return {"cidr4": {}, "cidr6": {}}
    return {
        "cidr4": as_string_map(value.get("cidr4")),
        "cidr6": as_string_map(value.get("cidr6")),
    }


def path_part(value: str) -> str:
    return value.replace("/", "_").replace("\\", "_")


def replace_dir(path: Path, source: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, path)


def collect_master() -> None:
    print("collecting master from rekryt/iplist", file=sys.stderr)
    archive = fetch_bytes(MASTER_ARCHIVE_URL)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "master.zip"
        zip_path.write_bytes(archive)
        with zipfile.ZipFile(zip_path) as package:
            package.extractall(tmp_path)
        extracted = tmp_path / "iplist-master" / "config"
        if not extracted.is_dir():
            raise RuntimeError("master archive does not contain config/")
        replace_dir(CONFIG_ROOT / "master", extracted)


def discover_groups(base_url: str, fallback_group: str) -> dict[str, str]:
    data = fetch_json(api_url(base_url, {"format": "json", "data": "group"}))
    if isinstance(data, dict) and data:
        groups = {
            str(site): str(group)
            for site, group in data.items()
            if isinstance(site, str) and isinstance(group, str) and site
        }
        if groups:
            return dict(sorted(groups.items()))

    domains = fetch_json(api_url(base_url, {"format": "json", "data": "domains"}))
    if isinstance(domains, dict) and domains:
        return {str(site): fallback_group for site in sorted(domains) if isinstance(site, str) and site}

    raise RuntimeError(f"could not discover sites from {base_url}")


def fetch_site_metadata(base_url: str, site: str) -> dict[str, Any]:
    try:
        data = fetch_json(api_url(base_url, {"format": "json", "site": site}))
    except RuntimeError as error:
        print(f"metadata fallback for {site}: {error}", file=sys.stderr)
        return {}
    if isinstance(data, dict) and isinstance(data.get(site), dict):
        return data[site]
    return {}


def fetch_site_field(base_url: str, site: str, field: str) -> list[str]:
    json_url = api_url(base_url, {"format": "json", "data": field, "site": site})
    try:
        data = fetch_json(json_url)
        if isinstance(data, dict):
            return as_string_list(data.get(site))
    except RuntimeError as error:
        print(f"text fallback for {site}/{field}: {error}", file=sys.stderr)

    text_url = api_url(base_url, {"format": "text", "data": field, "site": site})
    try:
        return fetch_text_lines(text_url)
    except RuntimeError as error:
        print(f"empty fallback for {site}/{field}: {error}", file=sys.stderr)
        return []


def build_site_config(base_url: str, site: str) -> dict[str, Any]:
    metadata = fetch_site_metadata(base_url, site)
    values: dict[str, Any] = {}

    for field in DATA_TYPES:
        raw = metadata.get(field)
        values[field] = as_string_list(raw) if isinstance(raw, list) else fetch_site_field(base_url, site, field)

    dns = metadata.get("dns")
    external = metadata.get("external")

    return {
        "domains": values["domains"],
        "dns": as_string_list(dns) if isinstance(dns, list) else DEFAULT_DNS,
        "timeout": 0,
        "ip4": values["ip4"],
        "ip6": values["ip6"],
        "cidr4": values["cidr4"],
        "cidr6": values["cidr6"],
        "external": {field: as_string_list(external.get(field)) for field in DATA_TYPES}
        if isinstance(external, dict)
        else DEFAULT_EXTERNAL.copy(),
        "replace": normalize_replace(metadata.get("replace", DEFAULT_REPLACE)),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")


def collect_public_set(name: str, base_url: str) -> None:
    print(f"collecting {name} from {base_url}", file=sys.stderr)
    target = CONFIG_ROOT / name
    if target.exists():
        shutil.rmtree(target)

    groups = discover_groups(base_url, name)
    for index, (site, group) in enumerate(groups.items(), start=1):
        print(f"[{name} {index}/{len(groups)}] {site}", file=sys.stderr)
        config = build_site_config(base_url, site)
        write_json(target / path_part(group) / f"{path_part(site)}.json", config)


def normalize_config_modes() -> None:
    for path in CONFIG_ROOT.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)


def main() -> int:
    collect_master()
    for name, base_url in PUBLIC_SETS.items():
        collect_public_set(name, base_url)
    normalize_config_modes()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
