"""Bounded, persistent Python worker for native Galeikan executables."""

import contextlib
import hashlib
import importlib.util
import os
import sys


MAX_MESSAGE = 1024 * 1024
MAX_MODULES = 64
MAX_MODULE_BYTES = 64 * 1024 * 1024
modules = {}
module_bytes = 0
executable = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else None


SCALARS = b"iubsx"
LISTS = b"IUBSX"


def decode_scalar(kind, raw):
    if kind in (b"i", b"u"):
        if len(raw) != 8:
            raise ValueError("invalid native integer")
        return int.from_bytes(raw, "little", signed=kind == b"i")
    if kind == b"b":
        if raw not in (b"\x00", b"\x01"):
            raise ValueError("invalid native boolean")
        return raw == b"\x01"
    if kind == b"s":
        return raw.decode("utf-8")
    return raw


def decode_sequence(kind, raw):
    if len(raw) < 4:
        raise ValueError("invalid native list")
    count = int.from_bytes(raw[:4], "little")
    if count > 100_000:
        raise ValueError("native list exceeds 100000 items")
    scalar = bytes([kind[0] + 32])
    offset = 4
    values = []
    for _ in range(count):
        if scalar in (b"i", b"u"):
            size = 8
        elif scalar == b"b":
            size = 1
        else:
            if offset + 4 > len(raw):
                raise ValueError("invalid native list item")
            size = int.from_bytes(raw[offset:offset + 4], "little")
            offset += 4
        if size > 500_000 or offset + size > len(raw):
            raise ValueError("invalid native list item")
        values.append(decode_scalar(scalar, raw[offset:offset + size]))
        offset += size
    if offset != len(raw):
        raise ValueError("invalid native list trailing bytes")
    return values


def decode_argument(field):
    kind, separator, encoded = field.partition(b":")
    if not separator or len(kind) != 1 or kind[0] not in SCALARS + LISTS:
        raise ValueError("invalid native argument")
    raw = bytes.fromhex(encoded.decode("ascii"))
    if len(raw) > 500_000:
        raise ValueError("Python argument exceeds 500000 bytes")
    if kind[0] in LISTS:
        return decode_sequence(kind, raw)
    return decode_scalar(kind, raw)


def encode_scalar(value, expected):
    if expected == b"b" and type(value) is bool:
        return bytes([value])
    if expected == b"i" and type(value) is int and -(2**63) <= value < 2**63:
        return value.to_bytes(8, "little", signed=True)
    if expected == b"u" and type(value) is int and 0 <= value < 2**64:
        return value.to_bytes(8, "little")
    if expected == b"s" and type(value) is str:
        return value.encode("utf-8")
    if expected == b"x" and type(value) is bytes:
        return value
    raise TypeError("Python result does not match the declared Galeikan type")


def encode_result(value, expected):
    if len(expected) != 1 or expected[0] not in SCALARS + LISTS:
        raise ValueError("invalid native result type")
    if expected[0] in LISTS:
        if type(value) is not list or len(value) > 100_000:
            raise TypeError("Python result does not match the declared Galeikan list type")
        scalar = bytes([expected[0] + 32])
        encoded = bytearray(len(value).to_bytes(4, "little"))
        for item in value:
            raw = encode_scalar(item, scalar)
            if scalar in (b"s", b"x"):
                encoded.extend(len(raw).to_bytes(4, "little"))
            encoded.extend(raw)
            if len(encoded) > 500_000:
                raise ValueError("Python list result exceeds 500000 bytes")
        return expected, bytes(encoded)
    encoded = encode_scalar(value, expected)
    if len(encoded) > 500_000:
        raise ValueError("Python result exceeds 500000 bytes")
    return expected, encoded


def load_module(path, expected_sha256):
    global module_bytes
    cached = modules.get(path)
    if cached is not None:
        if cached[0] != expected_sha256:
            raise ValueError("Python module changed after load")
        return cached[1]
    if len(modules) >= MAX_MODULES:
        raise ValueError("Python module cache exceeds 64 modules")
    with open(path, "rb") as handle:
        source = handle.read(8 * 1024 * 1024 + 1)
    if len(source) > 8 * 1024 * 1024 or module_bytes + len(source) > MAX_MODULE_BYTES:
        raise ValueError("Python module exceeds worker limits")
    digest = hashlib.sha256(source).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Python module changed after compilation")
    spec = importlib.util.spec_from_file_location("galeikan_user_module", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load Python module")
    module = importlib.util.module_from_spec(spec)
    directory = os.path.dirname(path)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    with contextlib.redirect_stdout(sys.stderr):
        exec(compile(source, path, "exec"), module.__dict__)
    modules[path] = (digest, module)
    module_bytes += len(source)
    return module


def call(parts):
    if len(parts) < 6 or parts[0] not in (b"C", b"G"):
        raise ValueError("invalid native request")
    expected = parts[4]
    argc = int(parts[5])
    if argc < 0 or argc > 64 or len(parts) != 6 + argc:
        raise ValueError("invalid native argument count")
    if parts[0] == b"G" and argc != 0:
        raise ValueError("Python value read cannot take arguments")
    path = bytes.fromhex(parts[1].decode("ascii")).decode("utf-8")
    if path.startswith("galeikan-exe:"):
        if executable is None:
            raise ValueError("native executable path is unavailable")
        relative = path[len("galeikan-exe:"):]
        if not relative or os.path.isabs(relative) or os.path.splitdrive(relative)[0]:
            raise ValueError("invalid executable-relative Python module path")
        path = os.path.normpath(os.path.join(os.path.dirname(executable), relative))
    digest = parts[2].decode("ascii")
    function = bytes.fromhex(parts[3].decode("ascii")).decode("utf-8")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("invalid Python module hash")
    module = load_module(path, digest)
    with contextlib.redirect_stdout(sys.stderr):
        target = getattr(module, function)
        if parts[0] == b"G":
            return encode_result(target, expected)
        if not callable(target):
            raise TypeError("Python target is not callable")
        args = [decode_argument(field) for field in parts[6:]]
        return encode_result(target(*args), expected)


while True:
    line = sys.stdin.buffer.readline(MAX_MESSAGE + 2)
    if not line:
        break
    if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
        break
    try:
        kind, value = call(line[:-1].split(b"\t"))
        response = b"O\t" + kind + b"\t" + value.hex().encode("ascii") + b"\n"
    except Exception as error:
        message = f"{type(error).__name__}: {error}".encode("utf-8")[:4096]
        response = b"E\t" + message.hex().encode("ascii") + b"\n"
    if len(response) > MAX_MESSAGE:
        response = b"E\t" + b"Python output exceeds 1 MiB".hex().encode("ascii") + b"\n"
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
