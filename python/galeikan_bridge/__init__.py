"""Small Python client for running Galeikan scripts from automation code."""

from __future__ import annotations

import subprocess
import json
import os
import queue
import signal
import shutil
import threading
import time
from os import PathLike
from pathlib import Path
from typing import Sequence


def _kill_process_tree(process: subprocess.Popen) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=3, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _run_bounded(
    command: Sequence[str], *, input: str | bytes | None = None,
    text: bool = False, timeout: float = 30.0, check: bool = True,
) -> subprocess.CompletedProcess:
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=text, encoding="utf-8" if text else None,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_tree(process)
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            process.wait(timeout=1)
        raise
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


Scalar = int | bool | str | bytes
Value = Scalar | list[Scalar]


class U64(int):
    def __new__(cls, value: int) -> U64:
        if type(value) is not int or not 0 <= value < 2**64:
            raise OverflowError("u64 value is outside 0..2^64-1")
        return int.__new__(cls, value)


class Galeikan:
    def __init__(self, binary: str | PathLike[str] = "galeikan") -> None:
        selected = str(binary)
        if selected == "galeikan" and os.name == "nt" and shutil.which(selected) is None:
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                installed = Path(local_app_data) / "Programs" / "Galeikan" / "galeikan.exe"
                if installed.is_file():
                    selected = str(installed)
        self.binary = selected

    def run(
        self,
        script: str | PathLike[str],
        *,
        allow_read: Sequence[str | PathLike[str]] = (),
        allow_connect: Sequence[str] = (),
        allow_process: Sequence[int] = (),
        allow_python: str | PathLike[str] | None = None,
        case_path: str | PathLike[str] | None = None,
        args: Sequence[str] = (),
        timeout: float = 30.0,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._execute(
            "run", script, allow_read=allow_read, allow_connect=allow_connect,
            allow_process=allow_process,
            allow_python=allow_python, case_path=case_path,
            args=args, timeout=timeout, check=check,
        )

    def exec(
        self,
        bundle: str | PathLike[str],
        *,
        allow_read: Sequence[str | PathLike[str]] = (),
        allow_connect: Sequence[str] = (),
        allow_process: Sequence[int] = (),
        allow_python: str | PathLike[str] | None = None,
        case_path: str | PathLike[str] | None = None,
        args: Sequence[str] = (),
        timeout: float = 30.0,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._execute(
            "exec", bundle, allow_read=allow_read, allow_connect=allow_connect,
            allow_process=allow_process,
            allow_python=allow_python, case_path=case_path,
            args=args, timeout=timeout, check=check,
        )

    def call(
        self,
        script: str | PathLike[str],
        function: str,
        *values: Value,
        engine: str | None = None,
        allow_read: Sequence[str | PathLike[str]] = (),
        allow_connect: Sequence[str] = (),
        allow_process: Sequence[int] = (),
        allow_python: str | PathLike[str] | None = None,
        args: Sequence[str] = (),
        timeout: float = 30.0,
    ) -> object:
        """Call one Galeikan function in source, bundle, or native form."""
        is_native = engine == "native" or Path(script).suffix.lower() in (".exe", ".native")
        if is_native:
            if engine not in (None, "native"):
                raise ValueError("native executable calls require the native engine")
            return self._call_native(
                script, function, values, allow_read=allow_read,
                allow_connect=allow_connect, allow_process=allow_process,
                allow_python=allow_python, args=args, timeout=timeout,
            )
        is_bundle = Path(script).suffix.lower() == ".gakb"
        selected_engine = engine or ("vm" if is_bundle else "ast")
        if selected_engine not in ("ast", "vm"):
            raise ValueError("engine must be 'ast' or 'vm'")
        if is_bundle and selected_engine != "vm":
            raise ValueError(".gakb calls require the VM engine")
        request = {"version": 1, "args": [self._encode_value(value) for value in values]}
        payload = json.dumps(request, ensure_ascii=False, separators=(",", ":"))
        if len(payload.encode("utf-8")) > 1024 * 1024:
            raise ValueError("call request exceeds 1 MiB")
        command = [self.binary, "call", str(script), function, "--engine", selected_engine]
        for directory in allow_read:
            command.extend(("--allow-read", str(directory)))
        for endpoint in allow_connect:
            command.extend(("--allow-connect", endpoint))
        for pid in allow_process:
            command.extend(("--allow-process", str(pid)))
        if allow_python is not None:
            command.extend(("--allow-python", str(allow_python)))
        if args:
            command.append("--")
            command.extend(args)
        result = _run_bounded(command, input=payload, text=True, timeout=timeout, check=True)
        response = json.loads(result.stdout)
        if not isinstance(response, dict) or response.get("version") != 1 or "value" not in response:
            raise ValueError("invalid Galeikan call response")
        return self._decode_value(response["value"])

    @staticmethod
    def _native_call_argument(value: Value) -> tuple[int, bytes]:
        if type(value) is list:
            return Galeikan._native_list_argument(value)
        if type(value) is U64:
            return 2, int(value).to_bytes(8, "little")
        if type(value) is bool:
            return 3, bytes((int(value),))
        if type(value) is int:
            if 0 <= value < 2**64 and value >= 2**63:
                return 2, value.to_bytes(8, "little")
            if not -(2**63) <= value < 2**63:
                raise OverflowError("call integer is outside i64/u64 range")
            return 1, value.to_bytes(8, "little", signed=True)
        if type(value) is str:
            encoded = value.encode("utf-8")
            if len(encoded) > 500_000:
                raise ValueError("native call string argument exceeds 500000 bytes")
            return 4, encoded
        if type(value) is bytes:
            if len(value) > 500_000:
                raise ValueError("native call bytes argument exceeds 500000 bytes")
            return 5, value
        raise TypeError("native call accepts i64, u64, bool, str, bytes, or homogeneous lists")

    @staticmethod
    def _native_list_argument(value: list[Scalar]) -> tuple[int, bytes]:
        if len(value) > 100_000:
            raise ValueError("native call list exceeds 100000 items")
        payload = bytearray(len(value).to_bytes(4, "little"))
        if not value:
            return 11, bytes(payload)
        item_type = type(value[0])
        if any(type(item) is not item_type for item in value):
            raise TypeError("native call list must be homogeneous")
        if item_type is U64:
            tag = 7
            for item in value:
                payload.extend(int(item).to_bytes(8, "little"))
        elif item_type is int:
            if any(not -(2**63) <= item < 2**64 for item in value):
                raise OverflowError("native call list integer is outside i64/u64 range")
            unsigned = any(item >= 2**63 for item in value)
            if unsigned and any(item < 0 for item in value):
                raise OverflowError("native call list cannot mix negative i64 and large u64")
            tag = 7 if unsigned else 6
            for item in value:
                payload.extend(item.to_bytes(8, "little", signed=not unsigned))
        elif item_type is bool:
            tag = 8
            payload.extend(int(item) for item in value)
        elif item_type is str or item_type is bytes:
            tag = 9 if item_type is str else 10
            for item in value:
                encoded = item.encode("utf-8") if item_type is str else item
                payload.extend(len(encoded).to_bytes(4, "little"))
                payload.extend(encoded)
                if len(payload) > 500_000:
                    raise ValueError("native call list argument exceeds 500000 bytes")
        else:
            raise TypeError("native call list accepts i64, u64, bool, str, or bytes items")
        if len(payload) > 500_000:
            raise ValueError("native call list argument exceeds 500000 bytes")
        return tag, bytes(payload)

    @staticmethod
    def _decode_native_list(tag: int, payload: bytes) -> list[Scalar]:
        if len(payload) < 4:
            raise ValueError("invalid native Galeikan list result")
        count = int.from_bytes(payload[:4], "little")
        if count > 100_000:
            raise ValueError("native Galeikan list result exceeds 100000 items")
        if tag in (6, 7) and len(payload) != 4 + 8 * count:
            raise ValueError("invalid native Galeikan integer list result")
        if tag == 8 and len(payload) != 4 + count:
            raise ValueError("invalid native Galeikan boolean list result")
        if tag in (9, 10) and count > (len(payload) - 4) // 4:
            raise ValueError("invalid native Galeikan boxed list result")
        items: list[Scalar] = []
        offset = 4
        for _ in range(count):
            if tag in (6, 7):
                number = int.from_bytes(payload[offset:offset + 8], "little", signed=tag == 6)
                items.append(number if tag == 6 else U64(number))
                offset += 8
            elif tag == 8:
                value = payload[offset]
                if value > 1:
                    raise ValueError("invalid native Galeikan boolean list result")
                items.append(bool(value))
                offset += 1
            else:
                length = int.from_bytes(payload[offset:offset + 4], "little")
                offset += 4
                if length > len(payload) - offset:
                    raise ValueError("invalid native Galeikan boxed list result")
                value = payload[offset:offset + length]
                items.append(value.decode("utf-8") if tag == 9 else value)
                offset += length
        if offset != len(payload):
            raise ValueError("trailing native Galeikan list result data")
        return items

    def _call_native(
        self,
        executable: str | PathLike[str],
        function: str,
        values: tuple[Value, ...],
        *,
        allow_read: Sequence[str | PathLike[str]],
        allow_connect: Sequence[str],
        allow_process: Sequence[int],
        allow_python: str | PathLike[str] | None,
        args: Sequence[str],
        timeout: float,
    ) -> object:
        request = self._native_request(function, values)
        command = [str(executable), "--galeikan-call"]
        for directory in allow_read:
            command.extend(("--allow-read", str(directory)))
        for endpoint in allow_connect:
            command.extend(("--allow-connect", endpoint))
        for pid in allow_process:
            command.extend(("--allow-process", str(pid)))
        if allow_python is not None:
            command.extend(("--allow-python", str(allow_python)))
        if args:
            command.append("--")
            command.extend(args)
        result = _run_bounded(command, input=request, timeout=timeout)
        return self._native_response(result.stdout)

    @classmethod
    def _native_request(cls, function: str, values: tuple[Value, ...]) -> bytes:
        if not isinstance(function, str) or not function or "\x00" in function:
            raise ValueError("Galeikan function name must be nonempty")
        name = function.encode("utf-8")
        if len(name) > 255:
            raise ValueError("Galeikan function name exceeds 255 bytes")
        if len(values) > 64:
            raise ValueError("native call exceeds 64 arguments")
        request = bytearray(b"GAKCALL1")
        request.extend(len(name).to_bytes(2, "little"))
        request.extend(name)
        request.append(len(values))
        for value in values:
            tag, payload = cls._native_call_argument(value)
            request.append(tag)
            request.extend(len(payload).to_bytes(4, "little"))
            request.extend(payload)
        if len(request) > 1024 * 1024:
            raise ValueError("native call request exceeds 1 MiB")
        return bytes(request)

    @classmethod
    def _native_response(cls, response: bytes) -> object:
        if len(response) < 13 or response[:8] != b"GAKRESP1":
            raise ValueError("invalid native Galeikan call response")
        tag = response[8]
        length = int.from_bytes(response[9:13], "little")
        if length > 500_000 or len(response) != 13 + length:
            raise ValueError("invalid native Galeikan call response")
        payload = response[13:]
        if tag == 0:
            raise RuntimeError(payload.decode("utf-8"))
        if tag == 1 and length == 8:
            return int.from_bytes(payload, "little", signed=True)
        if tag == 2 and length == 8:
            return U64(int.from_bytes(payload, "little"))
        if tag == 3 and length == 1 and payload in (b"\x00", b"\x01"):
            return payload == b"\x01"
        if tag == 4:
            return payload.decode("utf-8")
        if tag == 5:
            return payload
        if tag in (6, 7, 8, 9, 10):
            return cls._decode_native_list(tag, payload)
        if tag in (12, 13):
            result = json.loads(payload)
            expected = "Source" if tag == 12 else "Observation"
            lineage_key = "lineage" if tag == 12 else "source_lineage"
            if (not isinstance(result, dict) or result.get("$galeikan") != expected
                    or not isinstance(result.get("sha256"), str)
                    or not isinstance(result.get("origin"), str)
                    or not isinstance(result.get(lineage_key), list)
                    or len(result[lineage_key]) > 65):
                raise ValueError("invalid native Galeikan research result")
            return result
        raise ValueError("invalid native Galeikan call result type")

    def module(
        self,
        script: str | PathLike[str],
        *,
        engine: str | None = None,
        allow_read: Sequence[str | PathLike[str]] = (),
        allow_connect: Sequence[str] = (),
        allow_process: Sequence[int] = (),
        allow_python: str | PathLike[str] | None = None,
        args: Sequence[str] = (),
        timeout: float = 30.0,
    ) -> GaleikanModule:
        """Bind one Galeikan script or bundle for Python-style function calls."""
        return GaleikanModule(
            self, script,
            engine=engine,
            allow_read=tuple(allow_read),
            allow_connect=tuple(allow_connect),
            allow_process=tuple(allow_process),
            allow_python=allow_python,
            args=tuple(args),
            timeout=timeout,
        )

    def session(
        self,
        script: str | PathLike[str],
        *,
        engine: str | None = None,
        allow_read: Sequence[str | PathLike[str]] = (),
        allow_connect: Sequence[str] = (),
        allow_process: Sequence[int] = (),
        allow_python: str | PathLike[str] | None = None,
        args: Sequence[str] = (),
        timeout: float = 30.0,
    ) -> GaleikanSession:
        """Open a persistent, explicitly closed Galeikan function session."""
        return GaleikanSession(
            self, script, engine=engine, allow_read=allow_read,
            allow_connect=allow_connect, allow_process=allow_process,
            allow_python=allow_python, args=args, timeout=timeout,
        )

    @staticmethod
    def _encode_value(value: Value) -> object:
        if type(value) is list:
            if len(value) > 100_000:
                raise ValueError("call list exceeds 100000 items")
            if value and any(type(item) is not type(value[0]) for item in value):
                raise TypeError("call list must be homogeneous")
            return [Galeikan._encode_scalar(item) for item in value]
        return Galeikan._encode_scalar(value)

    @staticmethod
    def _encode_scalar(value: Scalar) -> object:
        if type(value) is U64:
            return {"$galeikan": "u64", "value": str(value)}
        if type(value) is bytes:
            if len(value) > 500_000:
                raise ValueError("call bytes argument exceeds 500000 bytes")
            return {"$galeikan": "bytes", "hex": value.hex()}
        if type(value) is int:
            if value >= 2**63 and value < 2**64:
                return {"$galeikan": "u64", "value": str(value)}
            if not (-(2**63) <= value < 2**63):
                raise OverflowError("call integer is outside i64/u64 range")
            return value
        if type(value) in (bool, str):
            return value
        raise TypeError("call accepts i64, u64, bool, str, bytes, or a homogeneous list")

    @staticmethod
    def _decode_value(value: object) -> object:
        if isinstance(value, list):
            return [Galeikan._decode_value(item) for item in value]
        if isinstance(value, dict) and value.get("$galeikan") == "bytes":
            if set(value) != {"$galeikan", "hex"} or not isinstance(value["hex"], str):
                raise ValueError("invalid Galeikan bytes result")
            return bytes.fromhex(value["hex"])
        if isinstance(value, dict) and value.get("$galeikan") == "u64":
            if set(value) != {"$galeikan", "value"} or type(value["value"]) is not str:
                raise ValueError("invalid Galeikan u64 result")
            return U64(int(value["value"]))
        if isinstance(value, dict) and value.get("$galeikan") == "Result":
            if value.get("ok") is True:
                return {"ok": True, "value": Galeikan._decode_value(value["value"])}
            if value.get("ok") is False:
                return {"ok": False, "error": value["error"]}
            raise ValueError("invalid Galeikan Result")
        return value

    def build(self, script: str | PathLike[str], *, timeout: float = 30.0) -> Path:
        return self._path_command("build", script, timeout)

    def compile(self, script: str | PathLike[str], *, timeout: float = 30.0) -> Path:
        return self._path_command("compile", script, timeout)

    def lock(self, project_dir: str | PathLike[str], *, timeout: float = 30.0) -> Path:
        return self._path_command("lock", project_dir, timeout)

    def _path_command(self, mode: str, target: str | PathLike[str], timeout: float) -> Path:
        result = _run_bounded([self.binary, mode, str(target)], text=True, timeout=timeout)
        path = result.stdout.strip()
        if not path:
            raise RuntimeError(f"Galeikan {mode} returned no path")
        return Path(path)

    def _execute(
        self,
        mode: str,
        target: str | PathLike[str],
        *,
        allow_read: Sequence[str | PathLike[str]],
        allow_connect: Sequence[str],
        allow_process: Sequence[int],
        allow_python: str | PathLike[str] | None,
        case_path: str | PathLike[str] | None,
        args: Sequence[str],
        timeout: float,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.binary, mode, str(target)]
        if case_path is not None:
            command.extend(("--case", str(case_path)))
        for directory in allow_read:
            command.extend(("--allow-read", str(directory)))
        for endpoint in allow_connect:
            command.extend(("--allow-connect", endpoint))
        for pid in allow_process:
            command.extend(("--allow-process", str(pid)))
        if allow_python is not None:
            command.extend(("--allow-python", str(allow_python)))
        if args:
            command.append("--")
            command.extend(args)
        result = _run_bounded(command, text=True, timeout=timeout, check=False)
        if check:
            result.check_returncode()
        return result


class GaleikanModule:
    """Lazy Python view of functions in one Galeikan script or bundle."""

    def __init__(self, client: Galeikan, script: str | PathLike[str], **options: object) -> None:
        self._client = client
        self._script = script
        self._options = options

    def __getitem__(self, function: str):
        if not isinstance(function, str) or not function.isidentifier():
            raise ValueError("Galeikan function name must be an identifier")

        def invoke(*values: Value) -> object:
            return self._client.call(self._script, function, *values, **self._options)

        return invoke

    def __getattr__(self, function: str):
        if function.startswith("_"):
            raise AttributeError(function)
        return self[function]


class GaleikanSession:
    """Context-managed Python view backed by one Galeikan runtime process."""

    _MAX_MESSAGE = 1024 * 1024

    def __init__(
        self, client: Galeikan, script: str | PathLike[str], *,
        engine: str | None, allow_read: Sequence[str | PathLike[str]],
        allow_connect: Sequence[str], allow_process: Sequence[int],
        allow_python: str | PathLike[str] | None, args: Sequence[str], timeout: float,
    ) -> None:
        is_bundle = Path(script).suffix.lower() == ".gakb"
        self._native = engine == "native" or Path(script).suffix.lower() in (".exe", ".native")
        selected_engine = engine or ("native" if self._native else "vm" if is_bundle else "ast")
        if self._native and selected_engine != "native":
            raise ValueError("native executable sessions require the native engine")
        if not self._native and selected_engine not in ("ast", "vm"):
            raise ValueError("engine must be 'ast' or 'vm'")
        if is_bundle and selected_engine != "vm":
            raise ValueError(".gakb calls require the VM engine")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        command = ([str(script), "--galeikan-serve"] if self._native else
                   [client.binary, "serve", str(script), "--engine", selected_engine])
        for directory in allow_read:
            command.extend(("--allow-read", str(directory)))
        for endpoint in allow_connect:
            command.extend(("--allow-connect", endpoint))
        for pid in allow_process:
            command.extend(("--allow-process", str(pid)))
        if allow_python is not None:
            command.extend(("--allow-python", str(allow_python)))
        if args:
            command.append("--")
            command.extend(args)
        self._client = client
        self._command = command
        self._timeout = timeout
        self._lock = threading.RLock()
        self._responses: queue.Queue[bytes | None] = queue.Queue()
        self._stderr = bytearray()
        self._stderr_lock = threading.Lock()
        self._process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()
        try:
            ready = self._responses.get(timeout=timeout)
        except queue.Empty as error:
            self._kill_tree()
            self.close()
            raise subprocess.TimeoutExpired(command, timeout) from error
        expected_ready = b"GAKRDY01" if self._native else b'{"version":1,"ready":true}\n'
        if ready != expected_ready:
            self.close()
            with self._stderr_lock:
                detail = self._stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Galeikan session could not start: {detail}")

    def _read_stdout(self) -> None:
        assert self._process.stdout is not None
        if self._native:
            self._read_native_stdout()
            return
        while True:
            line = self._process.stdout.readline(self._MAX_MESSAGE + 2)
            self._responses.put(line or None)
            if not line or len(line) > self._MAX_MESSAGE or not line.endswith(b"\n"):
                return

    def _read_native_stdout(self) -> None:
        assert self._process.stdout is not None

        def exact(length: int) -> bytes | None:
            chunks = bytearray()
            while len(chunks) < length:
                data = self._process.stdout.read(length - len(chunks))
                if not data:
                    return None
                chunks.extend(data)
            return bytes(chunks)

        ready = exact(8)
        self._responses.put(ready)
        if ready != b"GAKRDY01":
            return
        while True:
            header = exact(13)
            if header is None:
                self._responses.put(None)
                return
            length = int.from_bytes(header[9:13], "little")
            if header[:8] != b"GAKRESP1" or length > 500_000:
                self._responses.put(header)
                return
            payload = exact(length)
            self._responses.put(header + payload if payload is not None else None)
            if payload is None:
                return

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        while chunk := self._process.stderr.read(8192):
            with self._stderr_lock:
                room = self._MAX_MESSAGE - len(self._stderr)
                self._stderr.extend(chunk[:room])

    def call(self, function: str, *values: Value, timeout: float | None = None) -> object:
        if not isinstance(function, str) or not function.isidentifier():
            raise ValueError("Galeikan function name must be an identifier")
        selected_timeout = self._timeout if timeout is None else timeout
        if selected_timeout <= 0:
            raise ValueError("timeout must be positive")
        if self._native:
            native_request = self._client._native_request(function, values)
            payload = len(native_request).to_bytes(4, "little") + native_request
        else:
            payload = json.dumps(
                {"version": 1, "function": function,
                 "args": [self._client._encode_value(value) for value in values]},
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        if len(payload) > self._MAX_MESSAGE:
            raise ValueError("call request exceeds 1 MiB")
        with self._lock:
            if self._process.poll() is not None:
                raise RuntimeError("Galeikan session is closed")
            assert self._process.stdin is not None
            written: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)

            def send() -> None:
                try:
                    remaining = memoryview(payload)
                    while remaining:
                        count = self._process.stdin.write(remaining)
                        if count is None or count <= 0:
                            raise OSError("Galeikan session write made no progress")
                        remaining = remaining[count:]
                    self._process.stdin.flush()
                    written.put(None)
                except (BrokenPipeError, OSError, ValueError) as error:
                    written.put(error)

            deadline = time.monotonic() + selected_timeout
            threading.Thread(target=send, daemon=True).start()
            try:
                write_error = written.get(timeout=selected_timeout)
                if write_error is not None:
                    raise write_error
                line = self._responses.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty as error:
                self._kill_tree()
                self.close()
                raise subprocess.TimeoutExpired(self._command, selected_timeout) from error
            except (BrokenPipeError, OSError, ValueError) as error:
                self.close()
                raise RuntimeError(f"Galeikan session write failed: {error}") from error
            if line is None:
                self.close()
                with self._stderr_lock:
                    detail = self._stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"Galeikan session ended: {detail}")
            if self._native:
                try:
                    return self._client._native_response(line)
                except (ValueError, UnicodeError):
                    self.close()
                    raise
            if len(line) > self._MAX_MESSAGE or not line.endswith(b"\n"):
                self.close()
                raise ValueError("invalid Galeikan serve response")
            try:
                response = json.loads(line)
            except (UnicodeError, json.JSONDecodeError) as error:
                self.close()
                raise ValueError("invalid Galeikan serve response") from error
            if not isinstance(response, dict) or response.get("version") != 1:
                self.close()
                raise ValueError("invalid Galeikan serve response")
            if response.get("ok") is True and "value" in response:
                return self._client._decode_value(response["value"])
            if response.get("ok") is False and isinstance(response.get("error"), str):
                raise RuntimeError(response["error"])
            self.close()
            raise ValueError("invalid Galeikan serve response")

    def __getitem__(self, function: str):
        if not isinstance(function, str) or not function.isidentifier():
            raise ValueError("Galeikan function name must be an identifier")

        def invoke(*values: Value) -> object:
            return self.call(function, *values)

        return invoke

    def __getattr__(self, function: str):
        if function.startswith("_"):
            raise AttributeError(function)
        return self[function]

    def __enter__(self) -> GaleikanSession:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _kill_tree(self) -> None:
        _kill_process_tree(self._process)

    def close(self) -> None:
        with self._lock:
            if self._process.stdin is not None and not self._process.stdin.closed:
                self._process.stdin.close()
            try:
                self._process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._kill_tree()
                self._process.wait()
            self._stdout_thread.join(timeout=0.2)
            self._stderr_thread.join(timeout=0.2)
            for stream in (self._process.stdout, self._process.stderr):
                if stream is not None:
                    stream.close()
