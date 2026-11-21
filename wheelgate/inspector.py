"""WheelGate X: deterministic, non-executing wheel startup-hook gate.

Scope: compares executable .pth files against an approved, digest-pinned
baseline; validates wheel identity metadata (FR-07) and RECORD (FR-19);
reports PASS / HOLD / BLOCK. Does NOT install or import wheel code.
"""
from __future__ import annotations

import base64
import csv
import email
import hashlib
import io
import json
import re
import stat
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Mapping

MAX_WHEEL_BYTES = 40 * 1024 * 1024
MAX_ENTRIES = 3000
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_SINGLE_ENTRY_BYTES = 10 * 1024 * 1024
MAX_PTH_BYTES = 256 * 1024
MAX_COMPRESSION_RATIO = 250
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class StartupFile:
    path: str                # normalized installation path within site-packages
    sha256: str
    executable: bool
    line_numbers: tuple[int, ...] = ()
    kind: str = "pth"

    def public_dict(self) -> dict:
        return asdict(self)


@dataclass
class WheelEvidence:
    filename: str
    sha256: str = ""
    package: str = ""
    version: str = ""
    pth_files: dict[str, StartupFile] = field(default_factory=dict)
    other_startup_files: dict[str, StartupFile] = field(default_factory=dict)
    metadata_package: str = ""
    metadata_version: str = ""
    metadata_summary: str = ""
    wheel_metadata_valid: bool = False
    record_valid: bool = False
    record_entries_count: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    def public_dict(self) -> dict:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "package": self.package,
            "version": self.version,
            "metadata_package": self.metadata_package,
            "metadata_version": self.metadata_version,
            "metadata_summary": self.metadata_summary,
            "wheel_metadata_valid": self.wheel_metadata_valid,
            "record_valid": self.record_valid,
            "record_entries_count": self.record_entries_count,
            "pth_files": [f.public_dict() for f in sorted(self.pth_files.values(), key=lambda x: x.path)],
            "other_startup_files": [f.public_dict() for f in sorted(self.other_startup_files.values(), key=lambda x: x.path)],
            "warnings": self.warnings,
            "errors": self.errors,
        }


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_filename(name: str) -> tuple[str, str]:
    if not name.endswith(".whl"):
        raise ValueError("Wheel filename must end in .whl")
    parts = name[:-4].split("-")
    if len(parts) not in (5, 6):
        raise ValueError("Wheel filename must contain distribution, version and wheel tags")
    package, version = parts[0], parts[1]
    if not re.fullmatch(r"[A-Za-z0-9_.]+", package) or not re.fullmatch(r"[A-Za-z0-9_.!+]+", version):
        raise ValueError("Invalid distribution or version in wheel filename")
    return re.sub(r"[-_.]+", "-", package).lower(), version


def _safe_member_path(name: str) -> str:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValueError("Absolute, empty, or non-POSIX archive member path")
    if any(ord(ch) < 32 for ch in name):
        raise ValueError("Control character in archive member path")
    if re.match(r"^[a-zA-Z]:", name):
        raise ValueError("Windows drive in archive path")
    segments = name.rstrip("/").split("/")
    if any(s in ("", ".", "..") for s in segments):
        raise ValueError("Unsafe or noncanonical archive path")
    return name.rstrip("/")


def _installed_site_path(member: str) -> str | None:
    """Map wheel root and .data/(purelib|platlib) into site-packages."""
    parts = PurePosixPath(member).parts
    if len(parts) == 1:
        return member
    if len(parts) == 3 and parts[0].endswith(".data") and parts[1] in ("purelib", "platlib"):
        return parts[2]
    # Nested files are not interpreted as startup hooks by Python site.py.
    return None


def _classify_pth(data: bytes) -> tuple[tuple[int, ...], str | None]:
    """Python site.py executable lines start exactly with `import ` or `import\\t`."""
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return (), "Cannot decode .pth as UTF-8; manual review required"
    lines = tuple(
        index for index, line in enumerate(content.splitlines(), start=1)
        if line.startswith(("import ", "import\t"))
    )
    return lines, None


def _verify_record(
    z: zipfile.ZipFile,
    record_member: str,
    raw_member_hashes: dict[str, tuple[str, int]],
    ev: WheelEvidence,
) -> bool:
    """Verify wheel RECORD (FR-19). Returns True if valid, False if errors."""
    try:
        record_bytes = z.read(record_member)
        record_text = record_bytes.decode("utf-8")
        reader = csv.reader(io.StringIO(record_text))
        record_entries: dict[str, tuple[str, str]] = {}
        for row in reader:
            if not row:
                continue
            path = row[0].strip()
            hash_spec = row[1].strip() if len(row) > 1 else ""
            size_spec = row[2].strip() if len(row) > 2 else ""
            record_entries[path] = (hash_spec, size_spec)

        ev.record_entries_count = len(record_entries)

        # Check every member in archive against RECORD
        for member, (actual_sha, actual_size) in raw_member_hashes.items():
            if member == record_member:
                continue
            if member not in record_entries:
                ev.warnings.append(f"Archive member not in RECORD: {member}")
                return False

            hash_spec, size_spec = record_entries[member]
            if hash_spec:
                algo, _, digest = hash_spec.partition("=")
                if algo == "sha256":
                    # RECORD stores urlsafe base64 without padding
                    expected_b64 = digest.rstrip("=")
                    actual_b64 = base64.urlsafe_b64encode(bytes.fromhex(actual_sha)).rstrip(b"=").decode()
                    if actual_b64 != expected_b64:
                        ev.errors.append(f"RECORD digest mismatch for {member}")
                        return False
            if size_spec:
                try:
                    if int(size_spec) != actual_size:
                        ev.errors.append(f"RECORD size mismatch for {member}")
                        return False
                except ValueError:
                    ev.errors.append(f"Invalid RECORD size format for {member}")
                    return False

        return True
    except Exception as exc:
        ev.errors.append(f"Failed to verify RECORD: {exc}")
        return False


def _verify_dist_info(
    z: zipfile.ZipFile,
    seen_members: set[str],
    raw_member_hashes: dict[str, tuple[str, int]],
    ev: WheelEvidence,
) -> None:
    """Verify minimum wheel identity metadata (FR-07, FR-19)."""
    dist_info_dirs = {
        m.split("/")[0] for m in seen_members
        if "/" in m and m.split("/")[0].endswith(".dist-info")
    }

    if not dist_info_dirs:
        # Absence of dist-info is recorded as warning so evaluate() will HOLD
        ev.warnings.append("Missing .dist-info directory in wheel archive")
        return

    if len(dist_info_dirs) > 1:
        ev.errors.append(f"Multiple .dist-info directories in wheel: {sorted(dist_info_dirs)}")
        return

    dist_info = list(dist_info_dirs)[0]
    wheel_file = f"{dist_info}/WHEEL"
    metadata_file = f"{dist_info}/METADATA"
    record_file = f"{dist_info}/RECORD"

    if wheel_file not in seen_members:
        ev.warnings.append(f"Missing WHEEL metadata in {dist_info}")
        return
    if metadata_file not in seen_members:
        ev.warnings.append(f"Missing METADATA in {dist_info}")
        return
    if record_file not in seen_members:
        ev.warnings.append(f"Missing RECORD in {dist_info}")
        return

    # 1. Parse WHEEL
    try:
        wheel_bytes = z.read(wheel_file)
        wheel_msg = email.message_from_bytes(wheel_bytes)
        if not wheel_msg.get("Wheel-Version"):
            ev.errors.append(f"{wheel_file} missing Wheel-Version header")
            return
    except Exception as exc:
        ev.errors.append(f"Failed to parse WHEEL metadata: {exc}")
        return

    # 2. Parse METADATA
    try:
        meta_bytes = z.read(metadata_file)
        meta_msg = email.message_from_bytes(meta_bytes)
        meta_name = meta_msg.get("Name", "").strip()
        meta_ver = meta_msg.get("Version", "").strip()
        if not meta_name or not meta_ver:
            ev.errors.append(f"{metadata_file} missing Name or Version header")
            return

        norm_meta_name = re.sub(r"[-_.]+", "-", meta_name).lower()
        if norm_meta_name != ev.package or meta_ver != ev.version:
            ev.errors.append(
                f"METADATA identity mismatch: {norm_meta_name}=={meta_ver} vs filename {ev.package}=={ev.version}"
            )
            return

        ev.metadata_package = norm_meta_name
        ev.metadata_version = meta_ver
        summary = meta_msg.get("Summary", "").strip()
        # Truncate summary to avoid huge prompt payloads
        ev.metadata_summary = summary[:300]
        ev.wheel_metadata_valid = True
    except Exception as exc:
        ev.errors.append(f"Failed to parse METADATA: {exc}")
        return

    # 3. Parse & Verify RECORD (FR-19)
    ev.record_valid = _verify_record(z, record_file, raw_member_hashes, ev)


def scan_wheel(path: str | Path) -> WheelEvidence:
    p = Path(path)
    ev = WheelEvidence(filename=p.name)
    try:
        ev.package, ev.version = _parse_filename(p.name)
        if not p.is_file():
            raise ValueError("Wheel file does not exist")
        if p.stat().st_size > MAX_WHEEL_BYTES:
            raise ValueError("Wheel exceeds maximum compressed size")
        ev.sha256 = _file_sha256(p)
        with zipfile.ZipFile(p, "r") as z:
            infos = z.infolist()
            if not infos or len(infos) > MAX_ENTRIES:
                raise ValueError("Wheel empty or too many archive entries")
            if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Wheel exceeds maximum expanded size")
            seen_members: set[str] = set()
            seen_install_paths: set[str] = set()
            raw_member_hashes: dict[str, tuple[str, int]] = {}

            for info in infos:
                member = _safe_member_path(info.filename)
                if member in seen_members:
                    raise ValueError(f"Duplicate archive entry: {member}")
                seen_members.add(member)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(f"Symlink forbidden: {member}")
                if info.file_size > MAX_SINGLE_ENTRY_BYTES:
                    raise ValueError(f"Archive member exceeds size limit: {member}")
                if info.file_size > 128 * 1024 and info.file_size / max(1, info.compress_size) > MAX_COMPRESSION_RATIO:
                    raise ValueError(f"Extreme compression ratio: {member}")
                if info.is_dir():
                    continue

                data = z.read(info)
                sha = hashlib.sha256(data).hexdigest()
                raw_member_hashes[member] = (sha, len(data))

                installed = _installed_site_path(member)
                if installed is None:
                    continue
                suffix = PurePosixPath(installed).suffix.lower()
                name = PurePosixPath(installed).name.lower()
                if suffix not in (".pth", ".start") and name not in ("sitecustomize.py", "usercustomize.py"):
                    continue
                if installed in seen_install_paths:
                    raise ValueError(f"Collision at site-packages destination: {installed}")
                seen_install_paths.add(installed)
                if info.file_size > MAX_PTH_BYTES:
                    raise ValueError(f"Startup file too large to inspect safely: {member}")

                if suffix == ".pth":
                    lines, warning = _classify_pth(data)
                    if warning:
                        ev.warnings.append(f"{member}: {warning}")
                    ev.pth_files[installed] = StartupFile(installed, sha, bool(lines), lines, "pth")
                else:
                    ev.other_startup_files[installed] = StartupFile(installed, sha, True, (), "start" if suffix == ".start" else "startup_module")

            # Verify wheel metadata and RECORD (FR-07, FR-19)
            _verify_dist_info(z, seen_members, raw_member_hashes, ev)

    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        ev.errors.append(f"Wheel inspection incomplete: {exc}")
    return ev


def evaluate(
    candidate_path: str | Path,
    baseline_path: str | Path | None = None,
    *,
    expected_sha256: str | None = None,
    baseline_sha256: str | None = None,
    allowlist: Mapping[str, str] | None = None,
) -> dict:
    """Fail-closed evaluation, no network, no subprocesses, no imports from wheel.

    An allowlist is a trusted, independent path->exact SHA256 mapping, NEVER
    parsed from the candidate wheel or agent-produced text.
    """
    candidate = scan_wheel(candidate_path)
    baseline = scan_wheel(baseline_path) if baseline_path is not None else None
    codes: list[str] = []
    block = False
    hold = False

    if not candidate.valid:
        hold = True
        codes.append("CANDIDATE_INSPECTION_INCOMPLETE")
    if candidate.warnings:
        hold = True
        if any("Cannot decode" in w for w in candidate.warnings):
            codes.append("CANDIDATE_UNKNOWN_STARTUP_ENCODING")
        if any("dist-info" in w or "WHEEL" in w or "METADATA" in w for w in candidate.warnings):
            codes.append("IDENTITY_OR_METADATA_UNVERIFIED")
        if any("RECORD" in w for w in candidate.warnings):
            codes.append("RECORD_INCOMPLETE")

    if not candidate.wheel_metadata_valid:
        hold = True
        codes.append("IDENTITY_OR_METADATA_UNVERIFIED")
    if not candidate.record_valid:
        hold = True
        codes.append("RECORD_INCOMPLETE")

    if any("RECORD digest mismatch" in err for err in candidate.errors):
        hold = True
        codes.append("RECORD_DIGEST_MISMATCH")

    if not expected_sha256 or not _SHA256_RE.fullmatch(expected_sha256.lower()):
        hold = True
        codes.append("MISSING_EXPECTED_CANDIDATE_DIGEST")
    elif candidate.sha256 and candidate.sha256 != expected_sha256.lower():
        block = True
        codes.append("CANDIDATE_DIGEST_MISMATCH")

    if baseline is None:
        hold = True
        codes.append("NO_APPROVED_BASELINE")
    else:
        if not baseline.valid or baseline.warnings:
            hold = True
            codes.append("BASELINE_INSPECTION_INCOMPLETE")
        if not baseline.wheel_metadata_valid or not baseline.record_valid:
            hold = True
            codes.append("BASELINE_INSPECTION_INCOMPLETE")
        if not baseline_sha256 or not _SHA256_RE.fullmatch(baseline_sha256.lower()):
            hold = True
            codes.append("MISSING_APPROVED_BASELINE_DIGEST")
        elif baseline.sha256 and baseline.sha256 != baseline_sha256.lower():
            hold = True
            codes.append("BASELINE_DIGEST_MISMATCH")
        if candidate.package and baseline.package and candidate.package != baseline.package:
            hold = True
            codes.append("PACKAGE_IDENTITY_MISMATCH")

    allowed = {}
    for name, digest in (allowlist or {}).items():
        if not isinstance(name, str) or not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest.lower()):
            hold = True
            codes.append("INVALID_ALLOWLIST_ENTRY")
            continue
        allowed[name] = digest.lower()

    # Never classify a *change* against an absent/unverified baseline or a
    # partially parsed candidate. Such cases are HOLD, rather than a spurious
    # BLOCK caused by comparing an unknown baseline to an arbitrary file.
    trusted_candidate = (
        candidate.valid and not candidate.warnings and candidate.wheel_metadata_valid
        and bool(expected_sha256) and candidate.sha256 == expected_sha256.lower()
    )
    trusted_baseline = (
        baseline is not None and baseline.valid and not baseline.warnings and baseline.wheel_metadata_valid
        and bool(baseline_sha256) and baseline.sha256 == baseline_sha256.lower()
        and baseline.package == candidate.package
    )
    changed_hooks = []
    if trusted_candidate and trusted_baseline:
        for name, hook in sorted(candidate.pth_files.items()):
            before = baseline.pth_files.get(name)
            if hook.executable and (before is None or before.sha256 != hook.sha256):
                allowlisted = allowed.get(name) == hook.sha256
                changed_hooks.append({
                    "path": name, "sha256": hook.sha256,
                    "change": "NEW" if before is None else "MODIFIED",
                    "allowlisted": allowlisted,
                })
                if not allowlisted:
                    block = True
                    codes.append("UNAPPROVED_EXECUTABLE_PTH_CHANGE")

        for name, hook in sorted(candidate.other_startup_files.items()):
            before = baseline.other_startup_files.get(name)
            if before is None or before.sha256 != hook.sha256:
                hold = True
                codes.append("UNREVIEWED_OTHER_STARTUP_MECHANISM")

    result = "BLOCK" if block else "HOLD" if hold else "PASS"
    if result == "PASS":
        codes.append("STARTUP_POLICY_SATISFIED")

    return {
        "verdict": result,
        "reason_codes": sorted(set(codes)),
        "changed_executable_hooks": changed_hooks,
        "candidate": candidate.public_dict(),
        "baseline": baseline.public_dict() if baseline is not None else None,
        "limits": "Only installed top-level .pth and startup files; static inspection does not prove absence of malware.",
    }
