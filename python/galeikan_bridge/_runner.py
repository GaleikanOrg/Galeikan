"""Internal bounded JSON-line bridge. Invoked with Python's isolated mode."""

import contextlib
import hashlib
import importlib.util
import json
import os
import sys


MAX_MESSAGE = 1024 * 1024
MAX_MODULES = 64
MAX_MODULE_BYTES = 64 * 1024 * 1024
modules = {}
module_bytes = 0


class U64(int):
    pass


def decode_scalar(value):
    if isinstance(value, dict):
        if set(value) == {"$galeikan", "value"} and value["$galeikan"] == "u64":
            number = value["value"]
            if type(number) is not str or not number.isascii() or not number.isdecimal() or len(number) > 20:
                raise TypeError("invalid u64 argument")
            parsed = int(number)
            if parsed >= 2**64:
                raise OverflowError("u64 argument is out of range")
            return U64(parsed)
        if set(value) != {"$galeikan", "hex"} or value["$galeikan"] != "bytes":
            raise TypeError("invalid tagged Galeikan argument")
        hex_data = value["hex"]
        if not isinstance(hex_data, str) or len(hex_data) > 1_000_000:
            raise TypeError("invalid bytes argument")
        return bytes.fromhex(hex_data)
    if type(value) not in (int, bool, str):
        raise TypeError("Python bridge accepts only i64, u64, bool, str, bytes, or homogeneous lists")
    if type(value) is int and not (-(2**63) <= value < 2**63):
        raise OverflowError("Python integer is outside i64 range")
    return value


def decode_arg(value):
    if type(value) is list:
        if len(value) > 100_000:
            raise ValueError("Python bridge list exceeds 100000 items")
        values = [decode_scalar(item) for item in value]
        if values and any(type(item) is not type(values[0]) for item in values):
            raise TypeError("Python bridge list must be homogeneous")
        return values
    return decode_scalar(value)


def encode_scalar(value):
    if type(value) is U64:
        return {"$galeikan": "u64", "value": str(value)}
    if type(value) is dict:
        if set(value) == {"$galeikan", "value"} and value["$galeikan"] == "u64":
            return {"$galeikan": "u64", "value": str(decode_scalar(value))}
        raise TypeError("invalid tagged Python result")
    if type(value) not in (int, bool, str, bytes):
        raise TypeError("Python function must return i64, u64, bool, str, bytes, or a homogeneous list")
    if type(value) is int:
        if value < -(2**63) or value >= 2**64:
            raise OverflowError("Python integer is outside i64/u64 range")
        if value >= 2**63:
            return {"$galeikan": "u64", "value": str(value)}
    if type(value) is bytes:
        if len(value) > 500_000:
            raise ValueError("Python bytes result exceeds 500000 bytes")
        return {"$galeikan": "bytes", "hex": value.hex()}
    return value


def encode_result(value):
    if type(value) is list:
        if len(value) > 100_000:
            raise ValueError("Python list exceeds 100000 items")
        if value and any(type(item) is not type(value[0]) for item in value):
            raise TypeError("Python list must be homogeneous")
        return [encode_scalar(item) for item in value]
    return encode_scalar(value)


def load_module(path, expected_sha256):
    global module_bytes
    cached = modules.get(path)
    if cached is not None and expected_sha256 is None:
        return cached[1]
    with open(path, "rb") as handle:
        source = handle.read(8 * 1024 * 1024 + 1)
    if len(source) > 8 * 1024 * 1024:
        raise ValueError("Python module exceeds 8 MiB")
    digest = hashlib.sha256(source).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("Python module changed after case snapshot")
    if cached is not None:
        if cached[0] != digest:
            raise ValueError("Python module changed after load")
        return cached[1]
    if len(modules) >= MAX_MODULES or module_bytes + len(source) > MAX_MODULE_BYTES:
        raise ValueError("Python module cache exceeds 64 modules or 64 MiB")
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


def main(request):
    path = request["path"]
    function = request["function"]
    operation = request.get("operation", "call")
    expected_sha256 = request.get("expected_sha256")
    args = request["args"]
    if (
        not isinstance(path, str)
        or not isinstance(function, str)
        or not isinstance(args, list)
        or operation not in ("call", "get")
        or (expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_sha256)
        ))
    ):
        raise TypeError("invalid bridge request")
    module = load_module(path, expected_sha256)
    with contextlib.redirect_stdout(sys.stderr):
        callback = getattr(module, function)
        if operation == "call":
            if not callable(callback):
                raise TypeError("Python target is not callable")
            result = callback(*(decode_arg(value) for value in args))
        else:
            if args:
                raise TypeError("Python value lookup takes no arguments")
            result = callback
    return encode_result(result)


while True:
    line = sys.stdin.buffer.readline(MAX_MESSAGE + 2)
    if not line:
        break
    if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
        break
    try:
        request = json.loads(line)
        response = {"ok": True, "value": main(request)}
    except Exception as error:
        response = {"ok": False, "error": f"{type(error).__name__}: {error}"}
    encoded = json.dumps(response, ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_MESSAGE:
        encoded = b'{"ok":false,"error":"Python output exceeds 1 MiB"}'
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()
