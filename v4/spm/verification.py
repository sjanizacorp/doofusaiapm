"""Detached-signature verification for model promotion and audit export."""
import base64
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from math import prod
import os
from pathlib import Path
import re
import sqlite3
import stat
from struct import iter_unpack, unpack
import subprocess
import tempfile
import zipfile
import zlib

import gguf
import model_threat
import onnx_policy
from controls import Problem, parse_time


def signed_command(args, data):
    try:
        return subprocess.run(["openssl", "dgst", "-sha256", *args], input=data,
                              check=True, capture_output=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        raise Problem(400, "OpenSSL signature operation failed.") from None


def verify_signature(data, signature, public_key):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "signature.bin"
        path.write_bytes(signature)
        signed_command(["-verify", str(public_key.resolve()), "-signature", str(path)], data)


@contextmanager
def regular_input(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise Problem(400, "Verification input must be a regular file.")
        yield file


def read_limited(path, limit):
    with regular_input(path) as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise Problem(400, f"{path.name} exceeds the allowed input size.")
    return data


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = item
        return result

    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        raise Problem(400, "Invalid signed JSON document.") from None


TENSOR_WIDTHS = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
    "I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8, "F64": 8,
}
MAX_TENSOR_HEADER = 16 * 1024 * 1024
FLOAT_ENCODINGS = {
    "F16": ("<H", 0x7C00), "BF16": ("<H", 0x7F80),
    "F32": ("<I", 0x7F800000), "F64": ("<Q", 0x7FF0000000000000),
    "F8_E5M2": ("<B", 0x7C),
}


def check_numeric_values(file, header_end, ranges):
    inspected = 0
    for begin, end, dtype in ranges:
        encoding = FLOAT_ENCODINGS.get(dtype)
        if not encoding and dtype not in ("BOOL", "F8_E4M3"):
            continue
        file.seek(header_end + begin)
        remaining = end - begin
        while remaining:
            size = min(remaining, 1024 * 1024)
            data = file.read(size)
            if len(data) != size:
                raise Problem(400, "Tensor bytes changed during numeric verification.")
            if encoding:
                spec, exponent = encoding
                invalid = any(word & exponent == exponent for (word,) in iter_unpack(spec, data))
            elif dtype == "F8_E4M3":
                # This encoding has NaN but no infinity encoding.
                invalid = 127 in data or 255 in data
            else:
                invalid = any(value > 1 for value in data)
            if invalid:
                raise Problem(400, "Safetensors numeric policy found non-finite floats or invalid Boolean bytes.")
            remaining -= size
            inspected += size
    return inspected


def safetensors_structure(file, size, *, numeric=False):
    """Validate metadata and tensor ranges without loading tensor contents."""
    file.seek(0)
    prefix = file.read(8)
    length = int.from_bytes(prefix, "little")
    if len(prefix) != 8 or not 2 <= length <= min(MAX_TENSOR_HEADER, size - 8):
        raise Problem(400, "Invalid or oversized Safetensors header.")
    raw = file.read(length)
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Problem(400, "Safetensors header must be UTF-8.") from None
    if len(raw) != length or not text.startswith("{"):
        raise Problem(400, "Invalid Safetensors header.")
    header = parse_json(text)
    if not isinstance(header, dict):
        raise Problem(400, "Safetensors header must be an object.")
    metadata = header.pop("__metadata__", {})
    if not isinstance(metadata, dict) or any(not isinstance(value, str) for value in metadata.values()):
        raise Problem(400, "Safetensors metadata must contain string values.")
    ranges = []
    data_size = size - 8 - length
    for tensor in header.values():
        if not isinstance(tensor, dict) or tensor.keys() != {"dtype", "shape", "data_offsets"}:
            raise Problem(400, "Invalid Safetensors tensor entry.")
        dtype, shape, offsets = tensor["dtype"], tensor["shape"], tensor["data_offsets"]
        if not isinstance(dtype, str) or dtype not in TENSOR_WIDTHS:
            raise Problem(400, "Unsupported Safetensors data type.")
        if (not isinstance(shape, list) or len(shape) > 64
                or any(type(dimension) is not int or not 0 <= dimension < 2**63 for dimension in shape)):
            raise Problem(400, "Invalid Safetensors tensor shape.")
        if (not isinstance(offsets, list) or len(offsets) != 2
                or any(type(offset) is not int for offset in offsets)):
            raise Problem(400, "Invalid Safetensors tensor offsets.")
        begin, end = offsets
        if not 0 <= begin <= end <= data_size or end - begin != prod(shape) * TENSOR_WIDTHS[dtype]:
            raise Problem(400, "Safetensors dimensions do not match the declared byte range.")
        ranges.append((begin, end, dtype))
    position = 0
    for begin, end, _ in sorted(ranges):
        if begin != position:
            raise Problem(400, "Safetensors contains overlapping or unreferenced data.")
        position = end
    if position != data_size:
        raise Problem(400, "Safetensors contains trailing unreferenced data.")
    result = {"format": "safetensors", "tensors": len(ranges), "data_bytes": data_size}
    if numeric:
        result["numeric_policy"] = "finite"
        result["numeric_bytes_checked"] = check_numeric_values(file, 8 + length, ranges)
    return result


def safe_model_package(file, size, *, numeric=False):
    """Strict model-package allowlist, inspected as bytes without extraction or execution."""
    if size < 22 or size > 512 * 1024 * 1024:
        raise Problem(400, "Model package exceeds the supported 512 MiB archive scope.")
    file.seek(0)
    if file.read(4) != b"PK\x03\x04":
        raise Problem(400, "Model package must be a plain ZIP archive.")
    file.seek(-22, os.SEEK_END)
    footer_bytes = file.read(22)
    if len(footer_bytes) != 22:
        raise Problem(400, "Model package footer was truncated.")
    footer, disk, directory_disk, local_count, count, length, position, comment = unpack("<4s4H2LH", footer_bytes)
    if (footer != b"PK\x05\x06" or disk or directory_disk or comment or local_count != count
            or not 1 <= count <= 2048 or length > 2 * 1024 * 1024 or position + length != size - 22):
        raise Problem(400, "Model package has an unsupported or oversized ZIP directory.")
    names = set()
    expanded = 0
    weight_files = 0
    try:
        with zipfile.ZipFile(file) as archive:
            entries = archive.infolist()
            if len(entries) != count:
                raise Problem(400, "Model package directory entry count is inconsistent.")
            for item in entries:
                name = item.orig_filename
                clean = name.rstrip("/")
                if (len(name) > 240 or not all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", part)
                                                 for part in clean.split("/"))
                        or clean.casefold() in names or item.flag_bits & 1):
                    raise Problem(400, "Model package contains an unsafe, encrypted or duplicate entry.")
                names.add(clean.casefold())
                mode = stat.S_IFMT(item.external_attr >> 16)
                expected = stat.S_IFDIR if item.is_dir() else stat.S_IFREG
                if mode not in (0, expected):
                    raise Problem(400, "Model package contains a link or special file.")
                if item.is_dir():
                    if item.file_size:
                        raise Problem(400, "Model package directory contains unexpected data.")
                    continue
                suffix = Path(clean).suffix.lower()
                if suffix not in (".safetensors", ".json", ".txt", ".md"):
                    raise Problem(400, "Model package contains a disallowed file type.")
                if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise Problem(400, "Model package uses an unsupported compression method.")
                expanded += item.file_size
                if (expanded > 2 * 1024 * 1024 * 1024
                        or item.file_size > max(item.compress_size, 1) * 200):
                    raise Problem(400, "Model package exceeds expansion limits.")
                with archive.open(item) as stream:
                    if suffix == ".safetensors":
                        with tempfile.TemporaryFile() as tensor:
                            remaining = item.file_size
                            while remaining:
                                data = stream.read(min(remaining, 1024 * 1024))
                                if not data:
                                    raise Problem(400, "Model package entry was truncated.")
                                tensor.write(data)
                                remaining -= len(data)
                            if stream.read(1):
                                raise Problem(400, "Model package entry exceeds its declared size.")
                            safetensors_structure(tensor, item.file_size, numeric=numeric)
                        weight_files += 1
                    else:
                        if item.file_size > 2 * 1024 * 1024:
                            raise Problem(400, "Model package metadata exceeds the size limit.")
                        data = stream.read()
                        if len(data) != item.file_size:
                            raise Problem(400, "Model package metadata size is inconsistent.")
                        if suffix == ".json":
                            parse_json(data.decode("utf-8"))
                        else:
                            data.decode("utf-8")
    except (zipfile.BadZipFile, NotImplementedError, UnicodeError, ValueError, zlib.error) as error:
        raise Problem(400, "Model package archive or metadata is invalid.") from error
    if weight_files == 0:
        raise Problem(400, "Model package contains no Safetensors weights.")
    return {"format": "safe-model-package", "entries": count, "weight_files": weight_files,
            "expanded_bytes": expanded, "numeric_policy": "finite" if numeric else None}


def verify_artifact(artifact, manifest, signature, public_key, artifact_id, policy=None, numeric=False):
    payload = read_limited(manifest, 8192)
    verify_signature(payload, read_limited(signature, 8192), public_key)
    document = parse_json(payload)
    if (not isinstance(document, dict) or document.keys() != {"schema", "artifact_id", "sha256", "size"}
            or type(document["schema"]) is not int or document["schema"] != 1
            or document["artifact_id"] != artifact_id or not isinstance(document["sha256"], str)
            or re.fullmatch("[0-9a-f]{64}", document["sha256"]) is None
            or type(document["size"]) is not int or document["size"] < 1):
        raise Problem(400, "Signed manifest is malformed or belongs to another artifact.")
    with regular_input(artifact) as file:
        initial = os.fstat(file.fileno())
        sha = hashlib.sha256()
        remaining = document["size"]
        while remaining:
            data = file.read(min(remaining, 1024 * 1024))
            if not data:
                break
            sha.update(data)
            remaining -= len(data)
        if remaining or file.read(1) or sha.hexdigest() != document["sha256"]:
            raise Problem(400, "Artifact bytes do not match the signed manifest.")
        if policy == "onnx-inline":
            if numeric:
                raise Problem(400, "ONNX policy does not support numeric verification.")
            document["structure"] = onnx_policy.inspect(file, document["size"])
        elif policy == "checkpoint-data":
            if numeric:
                raise Problem(400, "Checkpoint archive policy does not support numeric verification.")
            document["structure"] = model_threat.inspect_checkpoint(file, document["size"])
        elif policy == "pickle-data":
            if numeric:
                raise Problem(400, "Raw Pickle policy does not support numeric verification.")
            document["structure"] = model_threat.inspect(file, document["size"])
        elif policy == "gguf":
            if numeric:
                raise Problem(400, "GGUF format policy does not support finite-value verification.")
            document["structure"] = gguf.structure(file, document["size"])
        elif policy == "safe-model-package":
            document["structure"] = safe_model_package(file, document["size"], numeric=numeric)
        elif policy == "safetensors" or numeric:
            document["structure"] = safetensors_structure(file, document["size"], numeric=numeric)
        final = os.fstat(file.fileno())
        current = artifact.stat(follow_symlinks=False)
        if ((initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)
                != (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                or (final.st_dev, final.st_ino) != (current.st_dev, current.st_ino)):
            raise Problem(400, "Artifact changed during verification.")
    return document


def verify_threat_report(artifact, report, signature, public_key, scanner, max_age_hours):
    """Enforce a verdict from an independent, trusted scanner for these exact bytes."""
    raw = read_limited(report, 8192)
    verify_signature(raw, read_limited(signature, 8192), public_key)
    document = parse_json(raw)
    required = {"schema", "artifact_id", "sha256", "scanner", "scanned_at", "verdict"}
    if (not isinstance(document, dict) or document.keys() != required
            or document["schema"] != "doofusai.threat-verdict.v1"
            or document["artifact_id"] != artifact["artifact_id"]
            or document["sha256"] != artifact["sha256"] or document["scanner"] != scanner):
        raise Problem(400, "Threat verdict does not match the trusted scanner or verified artifact.")
    observed = parse_time(document["scanned_at"])
    now = datetime.now(timezone.utc)
    if observed < now - timedelta(hours=max_age_hours) or observed > now + timedelta(minutes=5):
        raise Problem(400, "Threat verdict has expired or is dated in the future.")
    if document["verdict"] != "allow":
        raise Problem(400, "Threat scanner did not authorize promotion.")
    return {"scanner": scanner, "scanned_at": document["scanned_at"], "verdict": "allow"}


def write_signed_export(destination, document, private_key):
    payload = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    signature = signed_command(["-sign", str(private_key.resolve())], payload)
    envelope = json.dumps({"payload": base64.b64encode(payload).decode("ascii"),
                           "signature": base64.b64encode(signature).decode("ascii")})
    with destination.open("x", encoding="ascii") as file:
        file.write(envelope + "\n")


def verify_signed_export(path, public_key):
    envelope = parse_json(read_limited(path, 4 * 1024 * 1024))
    try:
        if not isinstance(envelope, dict) or envelope.keys() != {"payload", "signature"}:
            raise ValueError()
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, TypeError):
        raise Problem(400, "Invalid signed export envelope.") from None
    verify_signature(payload, signature, public_key)
    document = parse_json(payload)
    if not isinstance(document, dict) or document.get("schema") != "doofusai.audit.v1":
        raise Problem(400, "Unsupported signed document type.")
    return document


def verify_backup(path, expected_version):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn, conn:
        conn.execute("BEGIN")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != expected_version:
            raise Problem(400, "Backup schema differs from the current release.")
        if (conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or conn.execute("PRAGMA foreign_key_check").fetchone() is not None):
            raise Problem(400, "Backup integrity verification failed.")
        counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("assets", "scans", "issues", "audit")}
        return {"schema_version": version, "counts": counts}
