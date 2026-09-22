#!/usr/bin/env python3
"""Publish objects first, then replace the small release manifest."""
import datetime as dt
import json
from pathlib import Path
import subprocess


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def main():
    root = Path("dist")
    manifest = json.loads((root / "manifest.json").read_text())
    try:
        release = json.loads(gh("release", "view", "data", "--json", "assets"))
    except subprocess.CalledProcessError:
        gh("release", "create", "data", "--target", "main", "--title", "Configuration snapshots", "--notes", "Validated configuration snapshots. See manifest.json for source freshness and checksums.")
        release = {"assets": []}
    assets = {a["name"]: a for a in release["assets"]}
    files = sorted((root / "objects").glob("*.json.gz"))
    for path in files:
        if path.name not in assets:
            gh("release", "upload", "data", str(path))
    gh("release", "upload", "data", str(root / "collection-summary.json"), "--clobber")
    gh("release", "upload", "data", str(root / "manifest.json"), "--clobber")
    retained = {p.name for p in files} | {"manifest.json", "collection-summary.json"}
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)
    for name, asset in assets.items():
        created = dt.datetime.fromisoformat(asset["createdAt"].replace("Z", "+00:00"))
        if name.endswith(".json.gz") and name not in retained and created < cutoff:
            gh("release", "delete-asset", "data", name, "--yes")
    print(json.dumps({k: {"status": v["status"], "sites": v["sites"], "last_success_at": v["last_success_at"]} for k, v in manifest["sets"].items()}, indent=2))


if __name__ == "__main__":
    main()
