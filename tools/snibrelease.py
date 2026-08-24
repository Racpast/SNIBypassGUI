#!/usr/bin/env python3
"""SNIBypassGUI release tool — keygen / pack / verify.
Copyright © 2026 Racpast. All Rights Reserved.

This file is part of SNIBypassGUI, a proprietary software project.

NOTICE: All information contained herein is, and remains the property of
Racpast. The intellectual and technical concepts contained herein are
proprietary to Racpast and are protected by copyright law and international
treaties. Dissemination of this information or reproduction of this material
is strictly forbidden unless prior written permission is obtained from Racpast.

Unauthorized copying, modification, distribution, or use of this file,
via any medium, is strictly prohibited.

For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com

See the LICENSE file in the project root for full terms and conditions.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
except ImportError:  # pragma: no cover
    sys.stderr.write("This tool requires 'cryptography'.  pip install cryptography\n")
    raise

MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.json.sig"
BLOB_DIR = "blobs"
HOST_FILE_LIMIT = 25 * 1024 * 1024          # hard host constraint
DEFAULT_CHUNK_SIZE = 20 * 1024 * 1024       # 20 MB, 5 MB of headroom
CURVE = ec.SECP256R1()

# Single source of truth for the compared version: APP_VERSION_NUM in
# src/app/version.h (strict dotted-numeric). The manifest's "version" is this exact
# string, and the client compares it (CompareVersions) to the APP_VERSION_NUM
# baked into the running exe, so the release version can never disagree with what
# the build shipped. The human APP_VERSION_STR is display-only and never packed.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_VERSION_H = _REPO_ROOT / "src" / "app" / "version.h"
# Canonical extract-and-run payload tree (paths.ini, data/, WinDivert dll+sys).
# Both the ZIP and the signed update tree are built from this exact directory.
_DEFAULT_PAYLOAD = _REPO_ROOT / "resources" / "payload"


def read_app_version() -> str:
    """Extract the numeric APP_VERSION_NUM literal from src/app/version.h."""
    import re
    text = _VERSION_H.read_text(encoding="utf-8")
    m = re.search(r'#define\s+APP_VERSION_NUM\s+L"([^"]*)"', text)
    if not m:
        raise SystemExit(f"could not find APP_VERSION_NUM in {_VERSION_H}")
    return m.group(1)


# --------------------------------------------------------------------------- #
# Hashing / chunking helpers
# --------------------------------------------------------------------------- #
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def chunk_file(path: Path, chunk_size: int, out_root: Path) -> tuple[list[dict], str, int]:
    """Split `path` into content-addressed chunks under out_root/blobs/.
    Returns (chunk records, whole-file sha256, total size)."""
    file_hash = hashlib.sha256()
    chunks: list[dict] = []
    total = 0
    with path.open("rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            total += len(block)
            file_hash.update(block)
            digest = sha256_bytes(block)
            rel = f"{BLOB_DIR}/{digest[:2]}/{digest}.chunk"
            dest = out_root / rel
            if not dest.exists():  # content-addressed => dedup for free
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(block)
            chunks.append({"name": rel, "size": len(block), "sha256": digest})
    if total == 0:  # empty file: emit a single empty chunk so the client has something to fetch
        digest = sha256_bytes(b"")
        rel = f"{BLOB_DIR}/{digest[:2]}/{digest}.chunk"
        dest = out_root / rel
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"")
        chunks.append({"name": rel, "size": 0, "sha256": digest})
    return chunks, file_hash.hexdigest(), total


def is_safe_rel_path(p: str) -> bool:
    """Mirror of the client's IsSafeAssetRelPath: plain relative path, no
    drive/UNC/absolute, no '..' component."""
    if not p:
        return False
    if ":" in p:
        return False
    if p[0] in ("\\", "/"):
        return False
    parts = p.replace("\\", "/").split("/")
    return ".." not in parts and "" not in parts


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Deterministic serialisation that is signed AND written verbatim, so the
    client verifies over exactly the bytes on disk."""
    return json.dumps(
        manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Signing / key handling
# --------------------------------------------------------------------------- #
def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SystemExit(f"{path} is not an EC private key")
    return key


def pubkey_xy(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed point X‖Y (32+32 big-endian) — the form CNG imports."""
    nums = pub.public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def sign_raw(priv: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ECDSA-P256/SHA256 signature as raw r‖s (64 bytes) — CNG-compatible."""
    der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(xy: bytes, sig_raw: bytes, data: bytes) -> bool:
    if len(sig_raw) != 64 or len(xy) != 64:
        return False
    x = int.from_bytes(xy[:32], "big")
    y = int.from_bytes(xy[32:], "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()
    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    der = asym_utils.encode_dss_signature(r, s)
    try:
        pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def emit_pubkey_header(xy: bytes, path: Path) -> None:
    lines = ", ".join(f"0x{b:02x}" for b in xy)
    body = (
        "// Copyright © 2026 Racpast. All Rights Reserved.\n"
        "//\n"
        "// This file is part of SNIBypassGUI, a proprietary software project.\n"
        "//\n"
        "// NOTICE: All information contained herein is, and remains the property of\n"
        "// Racpast. The intellectual and technical concepts contained herein are\n"
        "// proprietary to Racpast and are protected by copyright law and international\n"
        "// treaties. Dissemination of this information or reproduction of this material\n"
        "// is strictly forbidden unless prior written permission is obtained from Racpast.\n"
        "//\n"
        "// Unauthorized copying, modification, distribution, or use of this file,\n"
        "// via any medium, is strictly prohibited.\n"
        "//\n"
        "// For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com\n"
        "//\n"
        "// See the LICENSE file in the project root for full terms and conditions.\n"
        "\n"
        "// Auto-generated by tools/snibrelease.py — do not edit.\n"
        "// ECDSA P-256 public key (uncompressed point X||Y, 64 bytes) used to\n"
        "// verify update manifests. The matching private key never leaves the\n"
        "// release machine / CI secret store.\n"
        "#pragma once\n"
        "static const unsigned char kUpdatePublicKey[64] = {\n"
        f"    {lines}\n"
        "};\n"
    )
    path.write_bytes(body.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_keygen(args) -> int:
    key_path = Path(args.out_key)
    if key_path.exists() and not args.force:
        raise SystemExit(f"{key_path} exists; refuse to overwrite (use --force)")
    for p in (key_path, Path(args.out_header)):
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
    priv = ec.generate_private_key(CURVE)
    key_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    xy = pubkey_xy(priv.public_key())
    emit_pubkey_header(xy, Path(args.out_header))
    print(f"Wrote private key : {key_path}  (KEEP SECRET -- never commit)")
    print(f"Wrote public header: {args.out_header}")
    print(f"Public key X||Y   : {xy.hex()}")
    return 0


def collect_files(exe: Path, payload: Path) -> list[tuple[str, str, Path]]:
    """Return (install_path, role, source) for the exe and every payload file."""
    items: list[tuple[str, str, Path]] = []
    if exe:
        items.append(("SNIBypassGUI.exe", "exe", exe))
    if payload:
        for src in sorted(payload.rglob("*")):
            if src.is_file():
                rel = src.relative_to(payload).as_posix()
                if not is_safe_rel_path(rel):
                    raise SystemExit(f"unsafe payload path: {rel}")
                items.append((rel, "asset", src))
    return items


def _load_release_notes(path: Path) -> dict:
    """Return the per-language notes for THIS publish from a cumulative changelog.

    The file is a YAML list, newest entry first; only that first entry is read,
    because notes describe a single publish, not a version — data-only refreshes
    keep the same version yet still deserve their own note (e.g. "updated a
    site's IP"), which the client surfaces on its update check. A missing file or
    empty list yields {} (a publish with no notes is allowed, e.g. a data refresh
    the author chose not to annotate)."""
    if not path.is_file():
        raise SystemExit(f"notes file not found: {path}")
    try:
        import yaml  # lazy: only `pack --notes-file` needs it
    except ImportError:  # pragma: no cover
        raise SystemExit("--notes-file needs PyYAML.  pip install pyyaml")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(doc, list) or not doc:
        return {}
    top = doc[0] or {}
    notes = {}
    for key in ("en", "zh-CN"):
        val = top.get(key)
        if val and str(val).strip():
            notes[key] = str(val).strip()
    return notes


def cmd_pack(args) -> int:
    # Version defaults to the single source of truth (src/app/version.h); an explicit
    # --version only overrides it (and is warned about) to keep them from drifting.
    version = args.version if args.version else read_app_version()
    if args.version and args.version != read_app_version():
        print(f"  !! --version {args.version!r} overrides version.h "
              f"{read_app_version()!r}", file=sys.stderr)
    exe = Path(args.exe) if args.exe else None
    # Payload defaults to the repo's canonical tree (resources/payload) so the
    # published update tree can't drift from what ships in the ZIP; --payload
    # overrides it only for one-off packs.
    payload = Path(args.payload) if args.payload else _DEFAULT_PAYLOAD
    out = Path(args.out)
    chunk_size = int(args.chunk_size)
    if chunk_size > HOST_FILE_LIMIT:
        raise SystemExit(f"chunk_size {chunk_size} exceeds host limit {HOST_FILE_LIMIT}")
    if exe and not exe.is_file():
        raise SystemExit(f"exe not found: {exe}")
    if payload and not payload.is_dir():
        raise SystemExit(f"payload dir not found: {payload}")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    files_meta = []
    for install_path, role, src in collect_files(exe, payload):
        chunks, digest, size = chunk_file(src, chunk_size, out)
        files_meta.append(
            {"path": install_path, "role": role, "size": size,
             "sha256": digest, "chunks": chunks}
        )
        print(f"  packed {install_path:32s} {size:>10d}B  {len(chunks)} chunk(s)")

    # Notes come from the newest changelog entry (--notes-file); the explicit
    # --notes-en/--notes-zh remain as per-language overrides for one-off packs.
    notes = _load_release_notes(Path(args.notes_file)) if args.notes_file else {}
    if args.notes_en:
        notes["en"] = args.notes_en
    if args.notes_zh:
        notes["zh-CN"] = args.notes_zh
    if notes:
        for lang, text in notes.items():
            first = text.splitlines()[0] if text else ""
            print(f"  notes[{lang}]: {first}")
    else:
        print("  notes: (none)")

    manifest = {
        "schema": 2,
        "version": version,
        "released": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "chunk_size": chunk_size,
        "notes": notes,
        "files": files_meta,
    }
    if args.min_from:
        manifest["min_upgradable_from"] = args.min_from

    data = canonical_manifest_bytes(manifest)
    (out / MANIFEST_NAME).write_bytes(data)

    priv = load_private_key(Path(args.key))
    sig = sign_raw(priv, data)
    (out / SIG_NAME).write_bytes(base64.b64encode(sig))

    # Self-check: verify what we just wrote.
    xy = pubkey_xy(priv.public_key())
    if not verify_raw(xy, sig, (out / MANIFEST_NAME).read_bytes()):
        raise SystemExit("internal error: signature self-check failed")

    total_blobs = sum(1 for _ in (out / BLOB_DIR).rglob("*.chunk")) if (out / BLOB_DIR).exists() else 0
    print(f"\nRelease {version}: {len(files_meta)} file(s), {total_blobs} unique chunk(s)")
    print(f"  {out / MANIFEST_NAME}  ({len(data)} B)")
    print(f"  {out / SIG_NAME}")
    _warn_oversize(out)
    return 0


def _warn_oversize(root: Path) -> None:
    bad = [p for p in root.rglob("*") if p.is_file() and p.stat().st_size > HOST_FILE_LIMIT]
    for p in bad:
        print(f"  !! {p} is {p.stat().st_size} B > {HOST_FILE_LIMIT} host limit", file=sys.stderr)
    if bad:
        raise SystemExit("one or more output files exceed the 25 MB host limit")


def cmd_verify(args) -> int:
    dist = Path(args.dist)
    manifest_path = dist / MANIFEST_NAME
    sig_path = dist / SIG_NAME
    raw = manifest_path.read_bytes()

    # Public key: from the C++ header (source of truth compiled into the app).
    xy = _read_pubkey_header(Path(args.header))
    sig = base64.b64decode(sig_path.read_text().strip())
    if not verify_raw(xy, sig, raw):
        print("SIGNATURE INVALID", file=sys.stderr)
        return 1
    print("signature OK")

    manifest = json.loads(raw)
    if manifest.get("schema") != 2:
        raise SystemExit(f"unexpected schema {manifest.get('schema')}")
    if manifest["chunk_size"] > HOST_FILE_LIMIT:
        raise SystemExit("chunk_size exceeds host limit")

    problems = 0
    for f in manifest["files"]:
        if not is_safe_rel_path(f["path"]):
            print(f"  UNSAFE PATH: {f['path']}", file=sys.stderr)
            problems += 1
            continue
        h = hashlib.sha256()
        total = 0
        for c in f["chunks"]:
            blob = dist / c["name"]
            data = blob.read_bytes()
            if len(data) != c["size"] or sha256_bytes(data) != c["sha256"]:
                print(f"  CHUNK MISMATCH: {c['name']}", file=sys.stderr)
                problems += 1
            h.update(data)
            total += len(data)
        if total != f["size"] or h.hexdigest() != f["sha256"]:
            print(f"  FILE MISMATCH: {f['path']}", file=sys.stderr)
            problems += 1
        else:
            print(f"  ok {f['path']} ({len(f['chunks'])} chunk(s))")
    if problems:
        print(f"{problems} problem(s)", file=sys.stderr)
        return 1
    print("all files verified")
    return 0


def _read_pubkey_header(path: Path) -> bytes:
    txt = path.read_text(encoding="utf-8")
    start = txt.index("{", txt.index("kUpdatePublicKey"))
    end = txt.index("}", start)
    body = txt[start + 1:end]
    vals = [int(tok.strip(), 0) for tok in body.split(",") if tok.strip()]
    if len(vals) != 64:
        raise SystemExit(f"expected 64 pubkey bytes, got {len(vals)}")
    return bytes(vals)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SNIBypassGUI release tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate signing key + C++ public-key header")
    kg.add_argument("--out-key", default="signing_key.pem")
    kg.add_argument("--out-header", default="src/update/public_key.h")
    kg.add_argument("--force", action="store_true")
    kg.set_defaults(func=cmd_keygen)

    pk = sub.add_parser("pack", help="build a signed, chunked dist/ tree")
    pk.add_argument("--exe", help="path to the built SNIBypassGUI.exe")
    pk.add_argument("--payload", default=None,
                    help="payload dir; defaults to resources/payload in the repo")
    pk.add_argument("--version", default=None,
                    help="override the version; defaults to APP_VERSION_NUM in src/app/version.h")
    pk.add_argument("--notes-file", default=None,
                    help="cumulative changelog YAML; its newest entry supplies "
                         "the manifest notes (en / zh-CN)")
    pk.add_argument("--notes-en", default="")
    pk.add_argument("--notes-zh", default="")
    pk.add_argument("--min-from", default="")
    pk.add_argument("--key", required=True, help="signing_key.pem")
    pk.add_argument("--out", default="dist")
    pk.add_argument("--chunk-size", default=DEFAULT_CHUNK_SIZE)
    pk.set_defaults(func=cmd_pack)

    vf = sub.add_parser("verify", help="verify a dist/ tree like the client would")
    vf.add_argument("--dist", default="dist")
    vf.add_argument("--header", default="src/update/public_key.h")
    vf.set_defaults(func=cmd_verify)

    # Release notes carry non-ASCII (zh-CN). On a CI runner the console encoding
    # is often cp1252/GBK, where printing them raises UnicodeEncodeError and kills
    # the pack step. Force UTF-8 on our own streams (replace, never crash) so a
    # note's text can never abort a release. Guarded: reconfigure() is 3.7+ and a
    # redirected/closed stream may lack it.
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf:
            try:
                reconf(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
