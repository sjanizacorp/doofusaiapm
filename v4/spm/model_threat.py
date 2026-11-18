"""Non-executing detection of object loading and executable constructs in raw Pickle."""
import pickletools

from controls import Problem

MAX_BYTES = 8 * 1024 * 1024
DATA_OPS = frozenset("""
    INT BININT BININT1 BININT2 LONG LONG1 LONG4 FLOAT BINFLOAT
    STRING BINSTRING SHORT_BINSTRING BINBYTES SHORT_BINBYTES BINBYTES8 BYTEARRAY8
    NONE NEWTRUE NEWFALSE UNICODE SHORT_BINUNICODE BINUNICODE BINUNICODE8
    EMPTY_LIST APPEND APPENDS LIST EMPTY_TUPLE TUPLE TUPLE1 TUPLE2 TUPLE3
    EMPTY_DICT DICT SETITEM SETITEMS EMPTY_SET ADDITEMS FROZENSET
    POP DUP MARK POP_MARK GET BINGET LONG_BINGET PUT BINPUT LONG_BINPUT MEMOIZE
    PROTO FRAME STOP
""".split())


def inspect(file, size):
    if not 1 <= size <= MAX_BYTES:
        raise Problem(400, "Raw Pickle inspection supports artifacts up to 8 MiB.")
    file.seek(0)
    data = file.read(size)
    findings = set()
    try:
        for count, (opcode, argument, offset) in enumerate(pickletools.genops(data), 1):
            if count > 250_000:
                raise ValueError("excessive operation count")
            if opcode.name not in DATA_OPS:
                findings.add(opcode.name)
            if opcode.name == "FRAME" and argument > size - offset - 9:
                raise ValueError("truncated frame")
            if opcode.name == "STOP" and offset + 1 != size:
                raise ValueError("unexpected trailing content")
    except (ValueError, OverflowError, UnicodeError) as exc:
        raise Problem(400, "Malformed or unsupported raw Pickle artifact.") from exc
    if findings:
        raise Problem(400, "Raw Pickle contains disallowed operations: " + ", ".join(sorted(findings)))
    return {"format": "raw-pickle", "opcodes_checked": count}


def inspect_checkpoint(file, size):
    """Screen a narrow data-only checkpoint ZIP profile without extracting members."""
    import re
    import stat
    from zipfile import BadZipFile, ZIP_STORED, ZipFile

    if not 22 <= size <= 64 * 1024 * 1024:
        raise Problem(400, "Checkpoint archive inspection supports files up to 64 MiB.")
    file.seek(0)
    if file.read(4) != b"PK\x03\x04":
        raise Problem(400, "Require a plain checkpoint ZIP archive.")
    try:
        with ZipFile(file) as archive:
            entries = archive.infolist()
            if not 2 <= len(entries) <= 1024 or archive.comment:
                raise Problem(400, "Checkpoint archive has unsupported entry count or comment.")
            root = None
            members = {}
            for item in entries:
                directory, sep, member = item.orig_filename.partition("/")
                if (not sep or not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", directory)
                        or (root is not None and directory != root) or member in members
                        or item.flag_bits & 1 or item.compress_type != ZIP_STORED
                        or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                        or not re.fullmatch(r"data[.]pkl|version|byteorder|data/[0-9]{1,12}|"
                                            r"[.]data/(?:serialization_id|version)|[.]format_version|"
                                            r"[.]storage_alignment", member)):
                    raise Problem(400, "Checkpoint archive includes an unsupported or duplicate member.")
                root = directory
                members[member] = item
            if "data.pkl" not in members or "version" not in members:
                raise Problem(400, "Checkpoint archive is missing data.pkl or version.")
            for name, item in members.items():
                if name == "data.pkl":
                    if item.file_size > MAX_BYTES:
                        raise Problem(400, "Checkpoint Pickle exceeds the supported size.")
                    from io import BytesIO
                    result = inspect(BytesIO(archive.read(item)), item.file_size)
                else:
                    with archive.open(item) as stream:
                        while stream.read(1024 * 1024):
                            pass
            return {"format": "checkpoint-data-zip", "entries": len(members),
                    "opcodes_checked": result["opcodes_checked"]}
    except (BadZipFile, RuntimeError, NotImplementedError, UnicodeError) as error:
        raise Problem(400, "Checkpoint archive could not be verified.") from error
