"""Live PyPI package registry fetcher for WheelGate X (FR-03).

Fetches genuine distribution wheels directly from PyPI API:
- Queries https://pypi.org/pypi/{package}/json
- Resolves exact release artifacts matching the requested version
- Verifies PyPI expected SHA-256 digest during bounded streaming download
- Enforces strict decompression and size caps (MAX_WHEEL_BYTES)
- Caches wheels locally in .wheel_cache to avoid redundant network transfers
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from wheelgate.inspector import MAX_WHEEL_BYTES

CACHE_DIR = Path(__file__).resolve().parents[1] / ".wheel_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
_USER_AGENT = "WheelGateX-LiveFetcher/2.5 (+https://github.com/wheelgate-x)"


def get_pypi_package_info(package_name: str) -> dict[str, Any]:
    """Retrieve package metadata from PyPI JSON API."""
    norm_name = re.sub(r"[-_.]+", "-", package_name).lower()
    url = f"https://pypi.org/pypi/{norm_name}/json"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to query PyPI for '{package_name}': {exc}")


def resolve_wheel_url(package_info: dict[str, Any], version: str) -> dict[str, Any]:
    """Select appropriate wheel artifact for the given version."""
    releases = package_info.get("releases", {})
    if version not in releases:
        avail = sorted(releases.keys(), reverse=True)[:5]
        raise ValueError(f"Version '{version}' not found on PyPI. Recent releases: {avail}")

    artifacts = releases[version]
    wheel_artifacts = [a for a in artifacts if a.get("filename", "").endswith(".whl")]
    if not wheel_artifacts:
        raise ValueError(f"Version '{version}' has no wheel (.whl) distributions on PyPI (sdist only).")

    # Prefer universal / pure Python wheels
    universal = [w for w in wheel_artifacts if "py3-none-any" in w["filename"] or "py2.py3-none-any" in w["filename"]]
    if universal:
        return universal[0]
    return wheel_artifacts[0]


def fetch_pypi_wheel(package_name: str, version: str) -> tuple[Path, str, dict[str, Any]]:
    """Download and cache genuine wheel from PyPI.

    Returns:
        (cached_file_path, computed_sha256, artifact_metadata)
    """
    info = get_pypi_package_info(package_name)
    artifact = resolve_wheel_url(info, version)
    filename = artifact["filename"]
    download_url = artifact["url"]
    expected_sha256 = artifact.get("digests", {}).get("sha256", "").lower()

    dest_path = CACHE_DIR / filename
    if dest_path.is_file():
        # Verify cached file integrity
        h = hashlib.sha256()
        with dest_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        cached_sha = h.hexdigest()
        if not expected_sha256 or cached_sha == expected_sha256:
            return dest_path, cached_sha, artifact

    # Stream download with size cap
    req = urllib.request.Request(download_url, headers={"User-Agent": _USER_AGENT})
    h = hashlib.sha256()
    total_bytes = 0

    with urllib.request.urlopen(req, timeout=15) as stream, dest_path.open("wb") as out_file:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_WHEEL_BYTES:
                dest_path.unlink(missing_ok=True)
                raise ValueError(f"Wheel exceeds size limit of {MAX_WHEEL_BYTES} bytes")
            h.update(chunk)
            out_file.write(chunk)

    computed_sha256 = h.hexdigest()
    if expected_sha256 and computed_sha256 != expected_sha256:
        dest_path.unlink(missing_ok=True)
        raise ValueError(
            f"PyPI digest mismatch: expected {expected_sha256}, got {computed_sha256}"
        )

    return dest_path, computed_sha256, artifact
