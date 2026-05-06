"""
Low-level helpers to download and install pre-built d8 binaries from GCS.
Adapted from autopoc/tools/ensure_version.py — no LLM tool decorator.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

from google.cloud import storage

BUCKET = "v8-asan"

VARIANTS: dict[str, tuple[str, str]] = {
    "debug":        ("linux-debug",   "d8-linux-debug-v8-component"),
    "debug-asan":   ("linux-debug",   "d8-asan-linux-debug-v8-component"),
    "release":      ("linux-release", "d8-linux-release-v8-component"),
    "release-asan": ("linux-release", "d8-asan-linux-release-v8-component"),
}

_EXTRACT_PATTERNS = ("d8", "icudtl.dat", "*.so", "*.bin")


def hash_to_commit_position(commit_hash: str, v8_dir: str = "/v8") -> int:
    result = subprocess.run(
        ["git", "log", "-1", "--format=%B", commit_hash],
        cwd=v8_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    match = re.search(r"Cr-Commit-Position: refs/heads/\S+@\{#(\d+)\}", result.stdout)
    if not match:
        raise ValueError(
            f"No Cr-Commit-Position trailer found in commit {commit_hash!r}.\n"
            f"Commit message:\n{result.stdout.strip()}"
        )
    return int(match.group(1))


def extract_d8(zip_path: str, dest_dir: str = ".") -> list[str]:
    os.makedirs(dest_dir, exist_ok=True)
    extracted = []

    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.infolist():
            name = os.path.basename(entry.filename)
            if not name:
                continue
            if not any(fnmatch.fnmatch(name, pat) for pat in _EXTRACT_PATTERNS):
                continue

            dest_path = os.path.join(dest_dir, name)
            with zf.open(entry) as src, open(dest_path, "wb") as dst:
                dst.write(src.read())

            unix_mode = (entry.external_attr >> 16) & 0o777
            if unix_mode:
                os.chmod(dest_path, unix_mode)

            extracted.append(dest_path)
            print(f"  extracted: {name}")

    return extracted


def _make_client() -> storage.Client:
    return storage.Client.create_anonymous_client()


def find_blob(
    client: storage.Client,
    commit_position: int,
    variant: str = "debug",
) -> storage.Blob:
    folder, prefix = VARIANTS[variant]
    object_prefix = f"{folder}/{prefix}-{commit_position}"
    bucket = client.bucket(BUCKET)
    blobs = list(bucket.list_blobs(prefix=object_prefix))
    if not blobs:
        raise FileNotFoundError(
            f"No object found for commit position {commit_position} "
            f"(variant={variant!r}).  Searched prefix: {object_prefix!r}"
        )
    return blobs[0]


class _ProgressFile:
    def __init__(self, f, total: int) -> None:
        self._f = f
        self._total = total
        self._written = 0

    def write(self, data: bytes) -> int:
        n = self._f.write(data)
        self._written += n
        self._render()
        return n

    def _render(self) -> None:
        if self._total:
            pct = self._written / self._total * 100
            mb_done = self._written / 1_048_576
            mb_total = self._total / 1_048_576
            bar_len = 30
            filled = int(bar_len * self._written / self._total)
            bar = "#" * filled + "-" * (bar_len - filled)
            print(
                f"\r  [{bar}] {pct:5.1f}%  {mb_done:.1f}/{mb_total:.1f} MB",
                end="",
                flush=True,
            )
        else:
            print(
                f"\r  {self._written / 1_048_576:.1f} MB downloaded",
                end="",
                flush=True,
            )


def download_d8(
    commit_position: int,
    dest_dir: str = ".",
    variant: str = "debug",
) -> str:
    client = _make_client()

    print(f"Looking up commit position {commit_position} (variant={variant!r}) ...")
    blob = find_blob(client, commit_position, variant)

    size_mb = (blob.size or 0) / 1_048_576
    metadata = blob.metadata or {}

    print(f"  Object  : {blob.name}")
    print(f"  Size    : {size_mb:.1f} MB")
    print(f"  Updated : {blob.updated}")
    if "cr-commit-position" in metadata:
        print(f"  Position: {metadata['cr-commit-position']}")
    if "cr-git-commit" in metadata:
        print(f"  Commit  : {metadata['cr-git-commit']}")

    filename = os.path.basename(blob.name)
    dest_path = os.path.join(dest_dir, filename)

    if os.path.exists(dest_path):
        local_size = os.path.getsize(dest_path)
        if local_size == blob.size:
            print(f"Already downloaded: {dest_path}")
            return dest_path
        print(
            f"Incomplete download detected "
            f"({local_size} vs {blob.size} bytes), re-downloading."
        )

    os.makedirs(dest_dir, exist_ok=True)
    print(f"Downloading to {dest_path} ...")
    with open(dest_path, "wb") as f:
        blob.download_to_file(_ProgressFile(f, blob.size or 0))
    print()
    print(f"Done: {dest_path}")
    return dest_path


def install_d8(commit: str, dest_dir: str, variant: str, v8_dir: str = "/v8") -> str:
    """
    Download and install d8 into dest_dir for the given commit and variant.

    Returns the path to the d8 binary.
    Raises FileNotFoundError if no pre-built binary exists for this commit/variant.
    """
    commit_position = hash_to_commit_position(commit, v8_dir)
    tmp_dir = tempfile.mkdtemp(prefix="v8gym_dl_")
    try:
        zip_path = download_d8(commit_position, dest_dir=tmp_dir, variant=variant)
        extract_d8(zip_path, dest_dir=dest_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    d8_path = os.path.join(dest_dir, "d8")
    if not os.path.exists(d8_path):
        raise RuntimeError(f"d8 not found in {dest_dir} after extraction")
    return d8_path
