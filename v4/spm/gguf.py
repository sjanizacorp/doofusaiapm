"""Bounded structural validation for signed, little-endian GGUF v3 artifacts."""
from math import prod
import re
from struct import calcsize, unpack

from controls import Problem

MAX_HEADER = 64 * 1024 * 1024
TYPES = {
    0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24),
    8: (32, 34), 10: (256, 84), 11: (256, 110), 12: (256, 144), 13: (256, 176),
    14: (256, 210), 24: (1, 1), 25: (1, 2), 26: (1, 4), 27: (1, 8), 28: (1, 8), 30: (1, 2),
}
SCALARS = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f",
           7: "B", 10: "Q", 11: "q", 12: "d"}


class Header:
    def __init__(self, file, size):
        self.file = file
        self.limit = min(size, MAX_HEADER)

    def read(self, count):
        if count > self.limit - self.file.tell():
            raise Problem(400, "GGUF header is truncated or exceeds the size limit.")
        data = self.file.read(count)
        if len(data) != count:
            raise Problem(400, "GGUF header is truncated.")
        return data

    def number(self, code):
        return unpack("<" + code, self.read(calcsize("<" + code)))[0]

    def string(self, max_bytes):
        length = self.number("Q")
        if length > max_bytes:
            raise Problem(400, "GGUF header string exceeds the field limit.")
        try:
            value = self.read(length).decode("utf-8")
        except UnicodeError:
            raise Problem(400, "GGUF header string contains invalid UTF-8.") from None
        if "\0" in value:
            raise Problem(400, "GGUF header string contains a null character.")
        return value

    def value(self, kind):
        if kind == 8:
            return self.string(4 * 1024 * 1024)
        if kind in SCALARS:
            result = self.number(SCALARS[kind])
            if kind == 7 and result > 1:
                raise Problem(400, "GGUF contains an invalid Boolean.")
            return result
        if kind != 9:
            raise Problem(400, "GGUF contains an unsupported metadata type.")
        element, count = self.number("I"), self.number("Q")
        if count > 1_000_000 or (element not in SCALARS and element != 8):
            raise Problem(400, "GGUF metadata array exceeds limits or uses an unsupported type.")
        if element in SCALARS:
            data = self.read(count * calcsize("<" + SCALARS[element]))
            if element == 7 and any(byte > 1 for byte in data):
                raise Problem(400, "GGUF contains an invalid Boolean array.")
        else:
            for _ in range(count):
                self.string(4 * 1024 * 1024)
        return None


def structure(file, size):
    file.seek(0)
    header = Header(file, size)
    if header.read(4) != b"GGUF" or header.number("I") != 3:
        raise Problem(400, "Require a little-endian GGUF v3 file.")
    tensors, entries = header.number("Q"), header.number("Q")
    if not 1 <= tensors <= 100_000 or entries > 100_000:
        raise Problem(400, "GGUF tensor or metadata count is outside supported limits.")
    keys, alignment = set(), 32
    for _ in range(entries):
        key, kind = header.string(65535), header.number("I")
        if not re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*", key) or key in keys:
            raise Problem(400, "GGUF metadata key is invalid or duplicated.")
        keys.add(key)
        if key == "general.alignment" and kind != 4:
            raise Problem(400, "GGUF alignment must be a uint32.")
        value = header.value(kind)
        if key == "general.alignment":
            alignment = value
    if not 8 <= alignment <= 4096 or alignment & (alignment - 1):
        raise Problem(400, "GGUF alignment is outside the supported range.")

    def aligned(end):
        return (end + alignment - 1) // alignment * alignment

    names, ranges = set(), []
    for _ in range(tensors):
        name, dimensions = header.string(64), header.number("I")
        if not name or not name.isprintable() or name in names or not 1 <= dimensions <= 4:
            raise Problem(400, "GGUF tensor name or dimension count is invalid.")
        names.add(name)
        shape = [header.number("Q") for _ in range(dimensions)]
        kind, offset = header.number("I"), header.number("Q")
        if kind not in TYPES:
            raise Problem(400, "GGUF tensor uses an unsupported encoding.")
        block, width = TYPES[kind]
        if not all(0 < axis <= 2**31 for axis in shape) or shape[0] % block or offset % alignment:
            raise Problem(400, "GGUF tensor shape or alignment is invalid.")
        ranges.append((offset, offset + prod(shape) // block * width))

    position = file.tell()
    start = aligned(position)
    if any(header.read(start - position)):
        raise Problem(400, "GGUF header padding must be zero.")
    expected = end = 0
    for begin, end in sorted(ranges):
        if begin != expected or end > size - start:
            raise Problem(400, "GGUF tensor ranges overlap, leave a gap or exceed the artifact.")
        expected = aligned(end)
    if size - start not in (end, expected):
        raise Problem(400, "GGUF file has unexpected trailing data.")
    for _, tensor_end in ranges:
        padding = min(aligned(tensor_end), size - start) - tensor_end
        if padding:
            file.seek(start + tensor_end)
            data = file.read(padding)
            if len(data) != padding or any(data):
                raise Problem(400, "GGUF tensor padding must be zero.")
    return {"format": "gguf-v3-le", "tensors": tensors, "metadata_entries": entries,
            "alignment": alignment, "data_bytes": size - start}
