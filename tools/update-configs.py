#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
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
DEFAULT_MAX_DROP_RATIO = 0.35


@dataclass
class FetchedJSON:
    data: Any
    damaged_paths: set[tuple[str, ...]]
    repaired: bool


def skip_ws(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    return index


def parse_partial_array(text: str, index: int, path: tuple[str, ...]) -> tuple[list[Any], set[tuple[str, ...]], int, bool]:
    decoder = json.JSONDecoder()
    damaged = set()
    result: list[Any] = []
    index = skip_ws(text, index)
    if index >= len(text) or text[index] != "[":
        damaged.add(path)
        return result, damaged, index, False
    index += 1
    while True:
        index = skip_ws(text, index)
        if index >= len(text):
            damaged.add(path)
            return result, damaged, index, False
        if text[index] == "]":
            return result, damaged, index + 1, True
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            damaged.add(path)
            return result, damaged, index, False
        result.append(value)
        index = skip_ws(text, index)
        if index >= len(text):
            damaged.add(path)
            return result, damaged, index, False
        if text[index] == ",":
            index += 1
            continue
        if text[index] == "]":
            return result, damaged, index + 1, True
        damaged.add(path)
        return result, damaged, index, False


def parse_partial_object(text: str, index: int, path: tuple[str, ...] = ()) -> tuple[dict[str, Any], set[tuple[str, ...]], int, bool]:
    decoder = json.JSONDecoder()
    damaged = set()
    result: dict[str, Any] = {}
    index = skip_ws(text, index)
    if index >= len(text) or text[index] != "{":
        damaged.add(path)
        return result, damaged, index, False
    index += 1
    while True:
        index = skip_ws(text, index)
        if index >= len(text):
            damaged.add(path)
            return result, damaged, index, False
        if text[index] == "}":
            return result, damaged, index + 1, True
        try:
            key, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            damaged.add(path)
            return result, damaged, index, False
        if not isinstance(key, str):
            damaged.add(path)
            return result, damaged, index, False
        index = skip_ws(text, index)
        if index >= len(text) or text[index] != ":":
            damaged.add(path + (key,))
            return result, damaged, index, False
        index = skip_ws(text, index + 1)
        try:
            value, next_index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            if index < len(text) and text[index] == "{":
                value, nested_damaged, next_index, complete = parse_partial_object(text, index, path + (key,))
                result[key] = value
                damaged |= nested_damaged
                if not complete:
                    return result, damaged, next_index, False
                index = next_index
            elif index < len(text) and text[index] == "[":
                value, nested_damaged, next_index, complete = parse_partial_array(text, index, path + (key,))
                result[key] = value
                damaged |= nested_damaged
                if not complete:
                    return result, damaged, next_index, False
                index = next_index
            else:
                damaged.add(path + (key,))
                return result, damaged, index, False
        else:
            result[key] = value
            index = next_index
        index = skip_ws(text, index)
        if index >= len(text):
            damaged.add(path)
            return result, damaged, index, False
        if text[index] == ",":
            index += 1
            continue
        if text[index] == "}":
            return result, damaged, index + 1, True
        damaged.add(path)
        return result, damaged, index, False


def decode_json(text: str, url: str, allow_repair: bool = False) -> FetchedJSON:
    try:
        return FetchedJSON(json.loads(text), set(), False)
    except json.JSONDecodeError as error:
        if not allow_repair:
            raise
        repaired, damaged_paths, _, _ = parse_partial_object(text, 0)
        if not repaired:
            raise
        print(
            f"repaired partial JSON from {url!r}: {error}; "
            f"damaged paths: {', '.join('/'.join(path) or '<root>' for path in sorted(damaged_paths))}",
            file=sys.stderr,
        )
        return FetchedJSON(repaired, damaged_paths, True)


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


def fetch_json_result(url: str, timeout: float = 60.0, retries: int = 2, allow_repair: bool = False) -> FetchedJSON:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "iplist-go-sidecar"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                text = response.read().decode(charset)
                try:
                    return decode_json(text, url)
                except json.JSONDecodeError:
                    if allow_repair and attempt == retries:
                        return decode_json(text, url, allow_repair=True)
                    raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(1 + attempt)
    raise RuntimeError(f"failed to fetch JSON from {url!r}; {last_error}") from last_error


def fetch_json(url: str, timeout: float = 60.0, retries: int = 2) -> Any:
    return fetch_json_result(url, timeout=timeout, retries=retries).data


def fetch_json_repaired(url: str, timeout: float = 60.0, retries: int = 2) -> FetchedJSON:
    return fetch_json_result(url, timeout=timeout, retries=retries, allow_repair=True)


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


def load_existing_site_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ignoring existing config {path}: {error}", file=sys.stderr)
        return {}
    return data if isinstance(data, dict) else {}


def count_entries(path: Path) -> dict[str, int]:
    counts = {field: 0 for field in DATA_TYPES}
    if not path.exists():
        return counts
    for config_path in path.rglob("*.json"):
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"skip entry count for {config_path}: {error}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            continue
        for field in DATA_TYPES:
            value = data.get(field)
            if isinstance(value, list):
                counts[field] += len(value)
    return counts


def assert_no_large_drop(name: str, previous: Path, collected: Path) -> None:
    if os.getenv("IPLIST_REFRESH_ALLOW_LARGE_DROP", "").lower() in {"1", "true", "yes"}:
        return
    old_counts = count_entries(previous)
    new_counts = count_entries(collected)
    max_drop_ratio = float(os.getenv("IPLIST_REFRESH_MAX_DROP_RATIO", DEFAULT_MAX_DROP_RATIO))
    failures: list[str] = []
    for field in DATA_TYPES:
        old = old_counts[field]
        new = new_counts[field]
        if old < 100:
            continue
        dropped = old - new
        if dropped <= 0:
            continue
        ratio = dropped / old
        if ratio > max_drop_ratio:
            failures.append(f"{field}: {old} -> {new} (-{dropped}, -{ratio:.1%})")
    if failures:
        details = "; ".join(failures)
        raise RuntimeError(
            f"{name}: suspicious entry drop detected: {details}. "
            "Set IPLIST_REFRESH_ALLOW_LARGE_DROP=true to accept it."
        )


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


def fetch_site_metadata(base_url: str, site: str) -> tuple[dict[str, Any], set[str]]:
    try:
        result = fetch_json_repaired(api_url(base_url, {"format": "json", "site": site}))
    except RuntimeError as error:
        print(f"metadata fallback for {site}: {error}", file=sys.stderr)
        return {}, set()
    data = result.data
    if isinstance(data, dict) and isinstance(data.get(site), dict):
        damaged_fields = {
            path[1]
            for path in result.damaged_paths
            if len(path) > 1 and path[0] == site and path[1] in DATA_TYPES
        }
        return data[site], damaged_fields
    return {}, set()


def fetch_site_field(base_url: str, site: str, field: str, previous: dict[str, Any]) -> list[str]:
    json_url = api_url(base_url, {"format": "json", "data": field, "site": site})
    try:
        result = fetch_json_repaired(json_url)
        data = result.data
        if isinstance(data, dict):
            if (site,) in result.damaged_paths:
                raise RuntimeError(f"partial JSON for {site}/{field} is unreliable")
            return as_string_list(data.get(site))
    except RuntimeError as error:
        print(f"text fallback for {site}/{field}: {error}", file=sys.stderr)

    text_url = api_url(base_url, {"format": "text", "data": field, "site": site})
    try:
        return fetch_text_lines(text_url)
    except RuntimeError as error:
        old_values = as_string_list(previous.get(field))
        if old_values:
            print(f"existing fallback for {site}/{field}: {error}", file=sys.stderr)
            return old_values
        print(f"empty fallback for {site}/{field}: {error}", file=sys.stderr)
        return []


def build_site_config(base_url: str, site: str, previous: dict[str, Any]) -> dict[str, Any]:
    metadata, damaged_fields = fetch_site_metadata(base_url, site)
    values: dict[str, Any] = {}

    for field in DATA_TYPES:
        raw = metadata.get(field)
        values[field] = as_string_list(raw) if isinstance(raw, list) and field not in damaged_fields else fetch_site_field(base_url, site, field, previous)

    dns = metadata.get("dns", previous.get("dns"))
    external = metadata.get("external", previous.get("external"))

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
        "replace": normalize_replace(metadata.get("replace", previous.get("replace", DEFAULT_REPLACE))),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")


def collect_public_set(name: str, base_url: str) -> None:
    print(f"collecting {name} from {base_url}", file=sys.stderr)
    target = CONFIG_ROOT / name

    groups = discover_groups(base_url, name)
    with tempfile.TemporaryDirectory() as tmp:
        collected = Path(tmp) / name
        for index, (site, group) in enumerate(groups.items(), start=1):
            print(f"[{name} {index}/{len(groups)}] {site}", file=sys.stderr)
            relative_path = Path(path_part(group)) / f"{path_part(site)}.json"
            previous = load_existing_site_config(target / relative_path)
            config = build_site_config(base_url, site, previous)
            write_json(collected / relative_path, config)
        assert_no_large_drop(name, target, collected)
        replace_dir(target, collected)


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
