#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
CHUNK_NAMES = [f"part-{i:02d}" for i in range(7)]
ALLOWED_EXACT = {
    PurePosixPath("README.md"),
    PurePosixPath("SECURITY.md"),
    PurePosixPath(".gitignore"),
    PurePosixPath("bundle/README.md"),
    PurePosixPath("bundle/manifest.json"),
    PurePosixPath("tools/public_ci_bundle.py"),
    PurePosixPath("tools/test_public_ci_bundle.py"),
    PurePosixPath("tools/validate_public_repo.py"),
    PurePosixPath(".github/workflows/bootstrap.yml"),
    PurePosixPath(".github/workflows/deploy-cloudflare.yml"),
    *(PurePosixPath(f"bundle/chunks/{name}") for name in CHUNK_NAMES),
}
BUNDLE_FIELDS = {
    "format",
    "algorithm",
    "source_ref",
    "file_count",
    "plaintext_sha256",
    "nonce_b64",
    "ciphertext_b64",
}
MANIFEST_FIELDS = {
    "format",
    "algorithm",
    "parts",
    "bundle_bytes",
    "bundle_sha256",
    "source_ref",
    "plaintext_sha256",
}


def _hex_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _bundle_bytes() -> bytes:
    chunk_dir = ROOT / "bundle" / "chunks"
    names = sorted(p.name for p in chunk_dir.glob("part-*") if p.is_file())
    if names != CHUNK_NAMES:
        raise SystemExit(f"Encrypted bundle chunk set mismatch: {names}")
    return b"".join((chunk_dir / name).read_bytes() for name in CHUNK_NAMES)


def main() -> None:
    files: list[PurePosixPath] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = PurePosixPath(path.relative_to(ROOT).as_posix())
        if ".git" in rel.parts:
            continue
        files.append(rel)

    unexpected = sorted(str(path) for path in files if path not in ALLOWED_EXACT)
    if unexpected:
        raise SystemExit("Unexpected public-repository files rejected: " + ", ".join(unexpected))

    manifest_path = ROOT / "bundle" / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit("Bundle manifest is invalid JSON.") from exc
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        raise SystemExit("Bundle manifest schema mismatch.")
    if manifest["format"] != "PFARMA_CI_BUNDLE_V2" or manifest["algorithm"] != "AES-256-GCM":
        raise SystemExit("Bundle manifest uses an unapproved format.")
    if manifest["parts"] != len(CHUNK_NAMES):
        raise SystemExit("Bundle manifest part count mismatch.")
    if not _hex_digest(manifest["bundle_sha256"]) or not _hex_digest(manifest["plaintext_sha256"]):
        raise SystemExit("Bundle manifest digest format mismatch.")

    raw = _bundle_bytes()
    if len(raw) != manifest["bundle_bytes"]:
        raise SystemExit("Reconstructed encrypted bundle byte count mismatch.")
    if hashlib.sha256(raw).hexdigest() != manifest["bundle_sha256"]:
        raise SystemExit("Reconstructed encrypted bundle SHA-256 mismatch.")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit("Reconstructed encrypted bundle is invalid JSON.") from exc
    if not isinstance(payload, dict) or set(payload) != BUNDLE_FIELDS:
        raise SystemExit("Encrypted bundle schema mismatch.")
    if payload["format"] != "PFARMA_CI_BUNDLE_V2" or payload["algorithm"] != "AES-256-GCM":
        raise SystemExit("Encrypted bundle policy mismatch.")
    if payload["source_ref"] != manifest["source_ref"] or payload["plaintext_sha256"] != manifest["plaintext_sha256"]:
        raise SystemExit("Encrypted bundle authenticated metadata mismatch.")
    if type(payload["file_count"]) is not int or payload["file_count"] <= 0:
        raise SystemExit("Encrypted bundle file count is invalid.")
    try:
        nonce = base64.b64decode(payload["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext_b64"], validate=True)
    except Exception as exc:
        raise SystemExit("Encrypted bundle contains invalid base64.") from exc
    if len(nonce) != 12 or not ciphertext:
        raise SystemExit("Encrypted bundle nonce/ciphertext policy mismatch.")

    print(
        f"PASS: public boundary contains {len(files)} allowlisted files; "
        f"encrypted bundle reconstructed and SHA-256 verified ({len(raw)} bytes)."
    )


if __name__ == "__main__":
    main()
