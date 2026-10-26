import os
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from galeikan_bridge import Galeikan, U64


@contextmanager
def _temporary_test_directory():
    temporary = tempfile.TemporaryDirectory()
    try:
        yield temporary.name
    finally:
        for retry in range(10):
            try:
                temporary.cleanup()
                break
            except PermissionError:
                if os.name != "nt" or retry == 9:
                    raise
                time.sleep(0.1 * (retry + 1))


def _worker_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel.OpenProcess(0x00100000, 0, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 0x102
        finally:
            kernel.CloseHandle(handle)
    status = Path(f"/proc/{pid}/stat")
    return status.is_file() and status.read_text().split(") ", 1)[1][0] != "Z"


class GaleikanClientTests(unittest.TestCase):
    def test_u64_round_trip_from_python_to_galeikan(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "unsigned.gak"
            script.write_text("fn identity(value: u64) -> u64 = value\n", encoding="utf-8")
            client = Galeikan(binary)
            for value in (U64(5), U64(2**64 - 1)):
                result = client.call(script, "identity", value)
                self.assertIs(type(result), U64)
                self.assertEqual(result, value)
            self.assertEqual(client.call(script, "identity", 2**63), 2**63)
            (Path(directory) / "helper.py").write_text(
                "def identity(value):\n    return value\n", encoding="utf-8"
            )
            script.write_text(
                "requires { python.exec }\nimport py.helper\n"
                "fn identity(value: u64) -> u64 = helper.identity(value)\n",
                encoding="utf-8",
            )
            for value in (U64(5), U64(2**64 - 1)):
                result = client.call(script, "identity", value, allow_python=sys.executable)
                self.assertIs(type(result), U64)
                self.assertEqual(result, value)

    def test_session_timeout_stops_galeikan_and_python_worker(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            pid_file = root / "worker.pid"
            (root / "sleeper.py").write_text(
                "import os\nimport time\nfrom pathlib import Path\n"
                "def ready():\n    return 1\n"
                "def stall():\n"
                "    Path(__file__).with_name('worker.pid').write_text(str(os.getpid()))\n"
                "    time.sleep(60)\n    return 2\n",
                encoding="utf-8",
            )
            script = root / "sleep.gak"
            script.write_text(
                "requires { python.exec }\nimport py.sleeper\n"
                "fn ready() -> i64 = sleeper.ready()\n"
                "fn stall() -> i64 = sleeper.stall()\n",
                encoding="utf-8",
            )
            with Galeikan(binary).session(script, allow_python=sys.executable) as module:
                self.assertEqual(module.ready(), 1)
                with self.assertRaises(subprocess.TimeoutExpired):
                    module.call("stall", timeout=0.5)
                self.assertIsNotNone(module._process.poll())
            self.assertTrue(pid_file.is_file())
            worker_pid = int(pid_file.read_text(encoding="utf-8"))

            for _ in range(20):
                if not _worker_alive(worker_pid):
                    break
                time.sleep(0.1)
            self.assertFalse(_worker_alive(worker_pid), f"Python worker {worker_pid} survived timeout")

    def test_one_shot_timeout_stops_python_worker_from_source_and_native(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            pid_file = root / "worker.pid"
            (root / "sleeper.py").write_text(
                "import os\nimport time\nfrom pathlib import Path\n"
                "def stall():\n"
                "    Path(__file__).with_name('worker.pid').write_text(str(os.getpid()))\n"
                "    time.sleep(60)\n    return 1\n",
                encoding="utf-8",
            )
            script = root / "sleep.gak"
            script.write_text(
                "requires { python.exec }\nimport py.sleeper\n"
                "fn stall() -> i64 = sleeper.stall()\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            for target in (script, compiled):
                with self.subTest(target=target.suffix):
                    pid_file.unlink(missing_ok=True)
                    with self.assertRaises(subprocess.TimeoutExpired):
                        client.call(target, "stall", allow_python=sys.executable, timeout=2.0)
                    self.assertTrue(pid_file.is_file(), "Python worker did not start")
                    worker_pid = int(pid_file.read_text(encoding="utf-8"))
                    for _ in range(20):
                        if not _worker_alive(worker_pid):
                            break
                        time.sleep(0.1)
                    self.assertFalse(_worker_alive(worker_pid), f"Python worker {worker_pid} survived timeout")

    def test_persistent_session_reuses_runtime_and_recovers_from_call_errors(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            (root / "state.py").write_text(
                "counter = 0\n"
                "def bump():\n    global counter\n    counter += 1\n    return counter\n"
                "def fail():\n    raise ValueError('boom')\n",
                encoding="utf-8",
            )
            script = root / "session.gak"
            script.write_text(
                "requires { python.exec }\n"
                "import py.state\n"
                "import std.binary\n"
                "fn bump() -> i64 = state.bump()\n"
                "fn fail() -> i64 = state.fail()\n"
                "fn size(data: bytes) -> i64 = binary.size(data)\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            bundle = client.build(script)
            for target, engine in ((script, "ast"), (script, "vm"), (bundle, "vm")):
                with client.session(target, engine=engine, allow_python=sys.executable) as module:
                    self.assertEqual(module.bump(), 1)
                    self.assertEqual(module["bump"](), 2)
                    with self.assertRaisesRegex(RuntimeError, "ValueError: boom"):
                        module.fail()
                    self.assertEqual(module.bump(), 3)
                    self.assertEqual(module.size(b"G" * 100_000), 100_000)
                with self.assertRaises(RuntimeError):
                    module.bump()
            with client.session(script, allow_python=sys.executable) as fresh:
                self.assertEqual(fresh.bump(), 1)
            with self.assertRaisesRegex(RuntimeError, "cannot read script"):
                client.session(root / "missing.gak")

    def test_python_client_receives_http_response_metadata(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(10)
            endpoint = f"127.0.0.1:{listener.getsockname()[1]}"
            requests = []

            def serve():
                for _ in range(2):
                    with listener.accept()[0] as connection:
                        connection.settimeout(5)
                        data = b""
                        while b"\r\n\r\n" not in data:
                            data += connection.recv(1024)
                        requests.append(data)
                        connection.sendall(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 3\r\n"
                            b"X-Tag: Galeikan\r\nConnection: close\r\n\r\nMZ!"
                        )

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            with _temporary_test_directory() as directory:
                script = Path(directory) / "http.gak"
                script.write_text(
                    "requires { net.connect }\n"
                    "from std.net import request\n"
                    "fn probe(url: str) -> HttpResponse = request(\"GET\", url, [], \"\", 3, 2000)\n",
                    encoding="utf-8",
                )
                client = Galeikan(binary)
                url = f"http://{endpoint}/probe"
                source = client.call(script, "probe", url, allow_connect=[endpoint])
                bundle = client.build(script)
                compiled = client.call(bundle, "probe", url, allow_connect=[endpoint])
                self.assertEqual(source, compiled)
                self.assertEqual(source["$galeikan"], "HttpResponse")
                self.assertEqual(source["status"], 202)
                self.assertEqual(source["body"]["size"], 3)
                self.assertEqual(source["request"]["size"], 0)
                self.assertIn(["x-tag", "Galeikan"], source["headers"])
            server.join(timeout=10)
            self.assertFalse(server.is_alive())
            self.assertEqual(len(requests), 2)

    def test_python_client_receives_explicit_result_values(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "result.gak"
            script.write_text(
                "from std.result import ok, fail\n"
                "fn gate(value: i64) -> Result<i64> = if value < 2 { fail(\"too small\") } else { ok(value) }\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            self.assertEqual(client.call(script, "gate", 3), {"ok": True, "value": 3})
            self.assertEqual(client.call(script, "gate", 1), {"ok": False, "error": "too small"})
            bundle = client.build(script)
            self.assertEqual(client.call(bundle, "gate", 3), {"ok": True, "value": 3})
            self.assertEqual(client.call(bundle, "gate", 1), {"ok": False, "error": "too small"})

    def test_python_client_receives_binary_overlay_source(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        data = bytearray(0x21c)
        data[0:2] = b"MZ"
        data[0x3c:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\0\0"
        data[0x86:0x88] = (1).to_bytes(2, "little")
        data[0x94:0x96] = (0xf0).to_bytes(2, "little")
        data[0x98:0x9a] = (0x20b).to_bytes(2, "little")
        data[0x98 + 60:0x98 + 64] = (0x200).to_bytes(4, "little")
        data[0x98 + 108:0x98 + 112] = (5).to_bytes(4, "little")
        data[0x98 + 144:0x98 + 148] = (0x208).to_bytes(4, "little")
        data[0x98 + 148:0x98 + 152] = (16).to_bytes(4, "little")
        section = 0x80 + 4 + 20 + 0xf0
        data[section + 16:section + 20] = (4).to_bytes(4, "little")
        data[section + 20:section + 24] = (0x200).to_bytes(4, "little")
        data[0x208:0x20c] = (11).to_bytes(4, "little")
        data[0x20c:0x20e] = (0x200).to_bytes(2, "little")
        data[0x20e:0x210] = (2).to_bytes(2, "little")
        data[0x210:0x213] = b"GAK"
        data[0x218:] = b"TAIL"
        with _temporary_test_directory() as directory:
            script = Path(directory) / "overlay.gak"
            script.write_text(
                "from std.binary import snapshot, extract\n"
                "from std.formats import probe, overlay, certificate_data, certificate_count, certificate_size\n"
                "fn tail(data: bytes) -> Source = overlay(probe(snapshot(data)))\n"
                "fn certificate(data: bytes) -> Source = certificate_data(probe(snapshot(data)), 0)\n"
                "fn count(data: bytes) -> i64 = certificate_count(probe(snapshot(data)))\n"
                "fn certificate_bytes(data: bytes) -> bytes = extract(certificate(data), 0, certificate_size(probe(snapshot(data)), 0))\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            source = client.call(script, "tail", bytes(data))
            bundle = client.build(script)
            self.assertEqual(source, client.call(bundle, "tail", bytes(data)))
            self.assertEqual(source["$galeikan"], "Source")
            self.assertEqual(source["size"], 24)
            self.assertEqual(source["lineage"][1]["operation"], "view")
            self.assertEqual(source["lineage"][1]["start"], 0x204)
            self.assertEqual(client.call(script, "count", bytes(data)), 1)
            certificate = client.call(script, "certificate", bytes(data))
            self.assertEqual(certificate, client.call(bundle, "certificate", bytes(data)))
            self.assertEqual(certificate["size"], 3)
            self.assertEqual(certificate["lineage"][1]["start"], 0x210)
            self.assertEqual(client.call(script, "certificate_bytes", bytes(data)), b"GAK")
            self.assertEqual(client.call(bundle, "certificate_bytes", bytes(data)), b"GAK")

    def test_python_client_receives_mutation_provenance(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "mutate.gak"
            script.write_text(
                "import std.binary\n"
                "from std.lab import mutate\n"
                "fn variants(data: bytes) -> List<Source> = mutate(binary.snapshot(data), \"bitflip\", 2)\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            source = client.call(script, "variants", b"G")
            bundle = client.build(script)
            self.assertEqual(source, client.call(bundle, "variants", b"G"))
            self.assertEqual(len(source), 2)
            self.assertEqual(source[0]["$galeikan"], "Source")
            self.assertEqual(source[0]["lineage"][0]["operation"], "capture")
            self.assertEqual(source[0]["lineage"][1]["operation"], "patch")
            self.assertNotEqual(source[0]["sha256"], source[1]["sha256"])

    def test_lists_round_trip_through_client_and_bundle(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "lists.gak"
            script.write_text(
                "from std.list import append, count\n"
                "fn extended(values: List<i64>) -> List<i64> = append(values, count(values))\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            self.assertEqual(client.module(script).extended([4, 5]), [4, 5, 2])
            bundle = client.build(script)
            self.assertEqual(client.module(bundle).extended([4, 5]), [4, 5, 2])
            with self.assertRaises(TypeError):
                client.call(script, "extended", [1, "two"])

    def test_default_client_finds_per_user_windows_install(self):
        if os.name != "nt":
            self.skipTest("Windows installer discovery")
        with _temporary_test_directory() as directory:
            binary = Path(directory) / "Programs" / "Galeikan" / "galeikan.exe"
            binary.parent.mkdir(parents=True)
            binary.touch()
            with patch.dict(os.environ, {"LOCALAPPDATA": directory}), patch(
                "galeikan_bridge.shutil.which", return_value=None
            ):
                self.assertEqual(Galeikan().binary, str(binary))

    def test_builds_command_and_returns_output(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.stdout = "ok\n"
            run.return_value.check_returncode.return_value = None
            result = Galeikan("galeikan-bin").run(
                "probe.gak",
                allow_read=["samples"],
                allow_connect=["127.0.0.1:8080"],
                allow_process=[1234],
                allow_python="python3",
                args=["a.bin"],
            )
            self.assertEqual(result.stdout, "ok\n")
            args, kwargs = run.call_args
            self.assertEqual(
                args[0],
                [
                    "galeikan-bin", "run", "probe.gak",
                    "--allow-read", "samples",
                    "--allow-connect", "127.0.0.1:8080",
                    "--allow-process", "1234",
                    "--allow-python", "python3",
                    "--", "a.bin",
                ],
            )
            self.assertEqual(kwargs["timeout"], 30.0)

    def test_case_path_is_forwarded_for_run_and_exec(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.check_returncode.return_value = None
            client = Galeikan("galeikan-bin")
            client.run("probe.gak", case_path="case.json")
            self.assertEqual(
                run.call_args.args[0],
                ["galeikan-bin", "run", "probe.gak", "--case", "case.json"],
            )
            client.exec("probe.gakb", case_path="bundle-case.json")
            self.assertEqual(
                run.call_args.args[0],
                ["galeikan-bin", "exec", "probe.gakb", "--case", "bundle-case.json"],
            )

    def test_python_client_exports_same_case_from_script_and_bundle(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            script = root / "case.gak"
            script.write_text(
                "requires { case.write }\n"
                "import std.binary\n"
                "fn derived() -> Source = binary.view(binary.snapshot(binary.from_hex(\"00 11 22\")), 1, 2)\n"
                "impact binary.deep(binary.snapshot(binary.from_hex(\"47 41\")), 0, \"u16le\")\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            source_case = root / "source.json"
            bundle_case = root / "bundle.json"
            client.run(script, case_path=source_case)
            bundle = client.build(script)
            client.exec(bundle, case_path=bundle_case)
            source = json.loads(source_case.read_text(encoding="utf-8"))
            compiled = json.loads(bundle_case.read_text(encoding="utf-8"))
            self.assertEqual(source["program_sha256"], compiled["program_sha256"])
            self.assertEqual(source["events"], compiled["events"])
            derived = client.call(script, "derived")
            self.assertEqual(derived["$galeikan"], "Source")
            self.assertEqual(derived["lineage"][0]["operation"], "capture")
            self.assertEqual(derived["lineage"][1]["operation"], "view")
            self.assertEqual(derived["lineage"][1]["start"], 1)

    def test_python_client_receives_pattern_finding(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "scan.gak"
            script.write_text(
                "import std.binary\n"
                "import std.audit\n"
                "fn scan(data: bytes) -> Finding = audit.hunt(binary.snapshot(data), "
                "\"hex:4d 5a\", \"pe.marker\")\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            source = client.call(script, "scan", b"MZ..MZ")
            bundle = client.build(script)
            compiled = client.call(bundle, "scan", b"MZ..MZ")
            self.assertEqual(source, compiled)
            self.assertEqual(source["$galeikan"], "Finding")
            self.assertEqual(source["kind"], "pattern")
            self.assertEqual(source["offsets"], [0, 4])
            self.assertEqual(source["source_lineage"][0]["operation"], "capture")

    def test_runs_actual_interpreter_when_binary_is_available(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "hello.gak"
            script.write_text(
                "import std.bytes\n"
                "fn twice(value: i64) -> i64 = value * 2\n"
                "fn echo(data: bytes) -> bytes = data\n"
                "fn unmask(data: bytes) -> bytes = bytes.xor(data, bytes.from_hex(\"20\"))\n"
                "fn pack_u32(value: i64) -> bytes = bytes.pack(value, \"u32le\")\n"
                "print 21 * 2\n", encoding="utf-8",
            )
            client = Galeikan(binary)
            result = client.run(script)
            self.assertEqual(result.stdout, "42\n")
            self.assertEqual(client.call(script, "twice", 21), 42)
            self.assertEqual(client.call(script, "echo", b"\x00\xff", engine="vm"), b"\x00\xff")
            self.assertEqual(client.call(script, "unmask", b"mz"), b"MZ")
            self.assertEqual(client.call(script, "pack_u32", 305419896), b"\x78\x56\x34\x12")
            module = client.module(script)
            self.assertEqual(module.twice(21), 42)
            self.assertEqual(module.echo(b"\x00\xff"), b"\x00\xff")
            bundle = client.build(script)
            self.assertTrue(bundle.exists())
            script.unlink()
            self.assertEqual(client.exec(bundle).stdout, "42\n")
            self.assertEqual(client.call(bundle, "twice", 21), 42)
            self.assertEqual(client.call(bundle, "echo", b"MZ"), b"MZ")
            self.assertEqual(client.call(bundle, "unmask", b"mz"), b"MZ")
            self.assertEqual(client.call(bundle, "pack_u32", 305419896), b"\x78\x56\x34\x12")
            self.assertEqual(client.module(bundle).twice(21), 42)
            with self.assertRaises(ValueError):
                client.call(bundle, "twice", 21, engine="ast")

    def test_python_can_call_compiled_scalar_functions_without_top_level_output(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "native_calls.gaks"
            script.write_text(
                "from std.text import length, slice\n"
                "fn signed(value: i64) -> i64 = value\n"
                "fn unsigned(value: u64) -> u64 = value\n"
                "fn flag(value: bool) -> bool = value\n"
                "fn text(value: str) -> str = value\n"
                "fn append(value: str) -> str = value + \"λ\"\n"
                "fn text_length(value: str) -> i64 = length(value)\n"
                "fn text_slice(value: str) -> str = slice(value, 1, 2)\n"
                "fn blob(value: bytes) -> bytes = value\n"
                "print \"top-level output\"\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            self.assertTrue(compiled.is_file())
            self.assertEqual(
                subprocess.run(
                    [compiled], capture_output=True, text=True, encoding="utf-8",
                    timeout=5, check=True,
                ).stdout,
                "top-level output\n",
            )
            script.unlink()
            self.assertEqual(client.call(compiled, "signed", -(2**63)), -(2**63))
            unsigned = client.call(compiled, "unsigned", U64(2**64 - 1))
            self.assertIs(type(unsigned), U64)
            self.assertEqual(unsigned, 2**64 - 1)
            self.assertIs(client.call(compiled, "flag", True), True)
            self.assertEqual(client.call(compiled, "text", "Galeikan λ\x00"), "Galeikan λ\x00")
            self.assertEqual(client.call(compiled, "append", "GAK\x00"), "GAK\x00λ")
            self.assertEqual(client.call(compiled, "text_length", "Aλ😀Z"), 4)
            self.assertEqual(client.call(compiled, "text_slice", "Aλ😀Z"), "λ😀")
            self.assertEqual(client.call(compiled, "blob", b"\x00\xffGAK"), b"\x00\xffGAK")
            module = client.module(compiled)
            self.assertEqual(module.signed(42), 42)
            self.assertEqual(module["blob"](b"\x00\xff"), b"\x00\xff")

    def test_compiled_research_results_match_vm_from_python(self):
        self.maxDiff = None
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "research.gak"
            (Path(directory) / "input.bin").write_bytes(b"\x00\x01\x02\x03")
            script.write_text(
                "requires { file.read }\n"
                "from std.binary import analyze, snapshot, view, patch, splice, deep, from_hex\n"
                "from std.formats import probe, rva, va\n"
                "fn captured(data: bytes) -> Source = snapshot(data)\n"
                "fn observed(data: bytes) -> Observation = deep(view(snapshot(data), 1, 2), 0, \"u16le\")\n"
                "fn patched(data: bytes) -> Source = patch(snapshot(data), 1, from_hex(\"aa\"))\n"
                "fn spliced(data: bytes) -> Source = splice(snapshot(data), 1, 1, from_hex(\"ff00\"))\n"
                "fn read_file() -> Source = analyze(\"input.bin\", 1024)\n"
                "fn read_field() -> Observation = deep(analyze(\"input.bin\", 1024), 1, \"u16le\")\n"
                "fn mapped_pe(data: bytes) -> Source = rva(probe(snapshot(data)), 0x1000, 8)\n"
                "fn mapped_elf(data: bytes) -> Source = va(probe(snapshot(data)), 0x1000, 8)\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            sample = b"\x00\x01\x02\x03"
            pe = bytearray(0x120)
            pe[:2] = b"MZ"
            pe[0x3c:0x40] = (0x40).to_bytes(4, "little")
            pe[0x40:0x44] = b"PE\0\0"
            pe[0x44:0x46] = (0x014c).to_bytes(2, "little")
            pe[0x46:0x48] = (1).to_bytes(2, "little")
            pe[0x54:0x56] = (0x60).to_bytes(2, "little")
            pe[0x58:0x5a] = (0x10b).to_bytes(2, "little")
            pe[0x68:0x6c] = (0x1000).to_bytes(4, "little")
            pe[0x94:0x98] = (0x100).to_bytes(4, "little")
            pe[0xc0:0xc4] = (0x20).to_bytes(4, "little")
            pe[0xc4:0xc8] = (0x1000).to_bytes(4, "little")
            pe[0xc8:0xcc] = (0x10).to_bytes(4, "little")
            pe[0xcc:0xd0] = (0x100).to_bytes(4, "little")
            pe[0x100:0x110] = b"0123456789abcdef"
            elf = bytearray(0x120)
            elf[:4] = b"\x7fELF"
            elf[4:7] = b"\x01\x01\x01"
            elf[16:18] = (2).to_bytes(2, "little")
            elf[18:20] = (3).to_bytes(2, "little")
            elf[20:24] = (1).to_bytes(4, "little")
            elf[24:28] = (0x1000).to_bytes(4, "little")
            elf[28:32] = (52).to_bytes(4, "little")
            elf[40:42] = (52).to_bytes(2, "little")
            elf[42:44] = (32).to_bytes(2, "little")
            elf[44:46] = (1).to_bytes(2, "little")
            elf[52:56] = (1).to_bytes(4, "little")
            elf[56:60] = (0x100).to_bytes(4, "little")
            elf[60:64] = (0x1000).to_bytes(4, "little")
            elf[68:72] = (0x10).to_bytes(4, "little")
            elf[72:76] = (0x20).to_bytes(4, "little")
            elf[76:80] = (5).to_bytes(4, "little")
            elf[0x100:0x110] = b"0123456789abcdef"
            expected = {
                name: client.call(script, name, sample, engine="vm")
                for name in ("captured", "observed", "patched", "spliced")
            }
            expected_files = {
                name: client.call(script, name, engine="vm", allow_read=[directory])
                for name in ("read_file", "read_field")
            }
            mapped = {
                name: client.call(script, name, bytes(data), engine="vm")
                for name, data in (("mapped_pe", pe), ("mapped_elf", elf))
            }
            try:
                compiled = client.compile(script)
            except subprocess.CalledProcessError as error:
                self.fail(str(error.stderr))
            script.unlink()
            for name, result in expected.items():
                with self.subTest(name=name):
                    self.assertEqual(client.call(compiled, name, sample), result)
            for name, result in expected_files.items():
                with self.subTest(name=name):
                    self.assertEqual(client.call(compiled, name, allow_read=[directory]), result)
            for name, result in mapped.items():
                data = pe if name == "mapped_pe" else elf
                with self.subTest(name=name):
                    self.assertEqual(client.call(compiled, name, bytes(data)), result)
            with client.session(compiled) as module:
                self.assertEqual(module.observed(sample), expected["observed"])
                self.assertEqual(module.spliced(sample), expected["spliced"])
                self.assertEqual(module.mapped_pe(bytes(pe)), mapped["mapped_pe"])

    def test_compiled_session_reuses_native_process_and_python_module(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            (root / "helper.py").write_text(
                "count = 0\n"
                "def increment(value):\n"
                "    global count\n"
                "    count += 1\n"
                "    return value + count\n"
                "def fail():\n"
                "    raise ValueError('boom')\n",
                encoding="utf-8",
            )
            script = root / "session.gak"
            script.write_text(
                "requires { python.exec }\n"
                "import py.helper\n"
                "fn increment(value: i64) -> i64 = helper.increment(value)\n"
                "fn fail() -> i64 = helper.fail()\n"
                "fn divide(value: i64) -> i64 = 10 / value\n"
                "fn echo(values: List<i64>) -> List<i64> = values\n"
                "print \"top-level output\"\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            script.unlink()
            with client.session(compiled, allow_python=sys.executable) as module:
                pid = module._process.pid
                self.assertEqual(module.increment(40), 41)
                self.assertEqual(module.increment(40), 42)
                self.assertEqual(module.echo([1, 2]), [1, 2])
                self.assertEqual(module.call("increment", 40), 43)
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    module.fail()
                self.assertEqual(module.increment(40), 44)
                with self.assertRaises(RuntimeError):
                    module.divide(0)
                self.assertEqual(module.divide(2), 5)
                with self.assertRaisesRegex(RuntimeError, "unknown or unsupported"):
                    module.call("missing")
                self.assertEqual(module.increment(40), 45)
                with self.assertRaisesRegex(RuntimeError, "argument count mismatch"):
                    module.increment()
                with self.assertRaisesRegex(RuntimeError, "argument type mismatch"):
                    module.increment("wrong")
                self.assertEqual(module.increment(40), 46)
                self.assertEqual(module._process.pid, pid)
                self.assertIsNone(module._process.poll())
            self.assertIsNotNone(module._process.poll())

    def test_compiled_session_timeout_stops_python_worker(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            pid_file = root / "worker.pid"
            (root / "sleeper.py").write_text(
                "import os\nimport time\nfrom pathlib import Path\n"
                "def stall():\n"
                "    Path(__file__).with_name('worker.pid').write_text(str(os.getpid()))\n"
                "    time.sleep(60)\n    return 1\n",
                encoding="utf-8",
            )
            script = root / "sleep.gak"
            script.write_text(
                "requires { python.exec }\nimport py.sleeper\n"
                "fn stall() -> i64 = sleeper.stall()\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            with client.session(compiled, allow_python=sys.executable) as module:
                with self.assertRaises(subprocess.TimeoutExpired):
                    module.call("stall", timeout=2.0)
                self.assertTrue(pid_file.is_file(), "Python worker did not start")
                worker_pid = int(pid_file.read_text(encoding="utf-8"))
            for _ in range(20):
                if not _worker_alive(worker_pid):
                    break
                time.sleep(0.1)
            self.assertFalse(_worker_alive(worker_pid), f"Python worker {worker_pid} survived timeout")

    def test_compiled_session_rejects_invalid_frames(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "session.gak"
            script.write_text("fn identity(value: i64) -> i64 = value\n", encoding="utf-8")
            compiled = Galeikan(binary).compile(script)
            for frame in (
                (1024 * 1024 + 1).to_bytes(4, "little"),
                (12).to_bytes(4, "little") + b"short",
                (11).to_bytes(4, "little") + b"not a call!",
            ):
                with self.subTest(frame=frame[:4]):
                    result = subprocess.run(
                        [compiled, "--galeikan-serve"], input=frame,
                        capture_output=True, timeout=5, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"GAKRDY01")
                    self.assertTrue(result.stderr)

    def test_compiled_session_caps_decoded_argument_memory(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "memory.gak"
            script.write_text("fn scalar(value: i64) -> i64 = value\n", encoding="utf-8")
            compiled = Galeikan(binary).compile(script)
            values = [False] * 100_000
            exhausted = False
            with Galeikan(binary).session(compiled) as module:
                for _ in range(100):
                    try:
                        module.scalar(values)
                    except RuntimeError as error:
                        if "transport memory exceeds 64 MiB" in str(error):
                            exhausted = True
                            break
                        self.assertIn("argument type mismatch", str(error))
            self.assertTrue(exhausted, "decoded arguments grew beyond the session memory cap")

    def test_python_can_call_compiled_homogeneous_lists(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "native_lists.gak"
            script.write_text(
                "from std.list import append, concat\n"
                "from std.iter import range\n"
                "from std.bytes import from_hex, repeat\n"
                "fn ints(values: List<i64>) -> List<i64> = values\n"
                "fn uints(values: List<u64>) -> List<u64> = values\n"
                "fn flags(values: List<bool>) -> List<bool> = values\n"
                "fn texts(values: List<str>) -> List<str> = values\n"
                "fn blobs(values: List<bytes>) -> List<bytes> = values\n"
                "fn first(values: List<i64>) -> i64 = values[0]\n"
                "fn added(values: List<i64>) -> List<i64> = append(values, 7)\n"
                "fn empty() -> List<bytes> = []\n"
                "fn huge() -> List<i64> {\n"
                "    var values: List<i64> = [0]\n"
                "    for index in range(16) {\n"
                "        values = concat(values, values)\n"
                "    }\n"
                "    return values\n"
                "}\n"
                "fn huge_bytes() -> bytes = repeat(from_hex(\"aa\"), 500001)\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            script.unlink()
            self.assertEqual(client.call(compiled, "ints", [-2, 0, 42]), [-2, 0, 42])
            unsigned = client.call(compiled, "uints", [U64(0), U64(2**64 - 1)])
            self.assertEqual(unsigned, [U64(0), U64(2**64 - 1)])
            self.assertTrue(all(type(item) is U64 for item in unsigned))
            self.assertEqual(client.call(compiled, "flags", [True, False]), [True, False])
            self.assertEqual(client.call(compiled, "texts", ["", "Galeikan λ\x00"]), ["", "Galeikan λ\x00"])
            self.assertEqual(client.call(compiled, "blobs", [b"", b"\x00\xffGAK"]), [b"", b"\x00\xffGAK"])
            for function in ("ints", "uints", "flags", "texts", "blobs"):
                self.assertEqual(client.call(compiled, function, []), [])
            self.assertEqual(client.module(compiled).first([9, 10]), 9)
            self.assertEqual(client.call(compiled, "added", [1, 2]), [1, 2, 7])
            self.assertEqual(client.call(compiled, "empty"), [])
            with self.assertRaisesRegex(TypeError, "homogeneous"):
                client.call(compiled, "ints", [1, True])
            with self.assertRaisesRegex(OverflowError, "mix negative"):
                client.call(compiled, "ints", [-1, 2**63])
            with self.assertRaisesRegex(ValueError, "500000"):
                client.call(compiled, "ints", [0] * 62_500)
            with self.assertRaises(subprocess.CalledProcessError) as too_large:
                client.call(compiled, "huge")
            self.assertEqual(too_large.exception.stdout, b"")
            self.assertIn(b"500000", too_large.exception.stderr)
            with self.assertRaises(subprocess.CalledProcessError):
                client.call(compiled, "huge_bytes")
            with client.session(compiled) as module:
                with self.assertRaisesRegex(RuntimeError, "500000"):
                    module.huge()
                with self.assertRaisesRegex(RuntimeError, "500000"):
                    module.huge_bytes()
                self.assertEqual(module.first([9, 10]), 9)

    def test_compiled_call_rejects_unknown_untyped_and_wrongly_typed_functions(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "invalid_calls.gak"
            script.write_text(
                "fn typed(value: i64) -> i64 = value\n"
                "fn loose(value) = value\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            for function, values in (
                ("missing", ()),
                ("loose", (1,)),
                ("typed", ("wrong type",)),
                ("typed", ()),
            ):
                with self.subTest(function=function, values=values):
                    with self.assertRaises(subprocess.CalledProcessError) as failure:
                        client.call(compiled, function, *values)
                    self.assertEqual(failure.exception.stdout, b"")
                    self.assertTrue(failure.exception.stderr)

    def test_compiled_call_rejects_malformed_and_oversized_input(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            script = Path(directory) / "protocol.gak"
            script.write_text("fn identity(value: i64) -> i64 = value\n", encoding="utf-8")
            compiled = Galeikan(binary).compile(script)
            long_argument = b"\x05" + (400_000).to_bytes(4, "little") + b"A" * 400_000
            for payload in (
                b"not a Galeikan call",
                b"GAKCALL1\x08\x00identity\x01",
                b"GAKCALL1\x08\x00identity\x01\x06\x04\x00\x00\x00\x01\x00\x00\x00",
                b"GAKCALL1\x08\x00identity\x01\x08\x05\x00\x00\x00\x01\x00\x00\x00\x02",
                b"GAKCALL1\x08\x00identity\x03" + long_argument * 3,
            ):
                with self.subTest(size=len(payload)):
                    result = subprocess.run(
                        [compiled, "--galeikan-call"], input=payload,
                        capture_output=True, timeout=5, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertTrue(result.stderr)

    def test_compiled_call_uses_explicit_file_read_grant(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            (root / "payload.bin").write_bytes(b"GAK\x00")
            script = root / "read.gak"
            script.write_text(
                "requires { file.read }\n"
                "from std.binary import analyze, size\n"
                "fn measure() -> i64 = size(analyze(\"payload.bin\", 4))\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            with self.assertRaises(subprocess.CalledProcessError) as denied:
                client.call(compiled, "measure")
            self.assertIn(b"file access not allowed", denied.exception.stderr)
            self.assertEqual(client.call(compiled, "measure", allow_read=[root]), 4)

    def test_compiled_callable_can_use_python_module_with_explicit_grant(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        if shutil.which("gcc") is None:
            self.skipTest("native compiler requires gcc")
        with _temporary_test_directory() as directory:
            root = Path(directory)
            (root / "helper.py").write_text(
                "def increment(value):\n    return value + 1\n"
                "def decorate(value):\n    return '<' + value + '>'\n"
                "def reverse(value):\n    return value[::-1]\n",
                encoding="utf-8",
            )
            script = root / "python_forward.gak"
            script.write_text(
                "requires { python.exec }\n"
                "import py.helper\n"
                "fn increment(value: i64) -> i64 = helper.increment(value)\n"
                "fn decorate(value: str) -> str = helper.decorate(value)\n"
                "fn reverse(value: bytes) -> bytes = helper.reverse(value)\n"
                "fn reverse_list(values: List<i64>) -> List<i64> = helper.reverse(values)\n",
                encoding="utf-8",
            )
            client = Galeikan(binary)
            compiled = client.compile(script)
            script.unlink()
            with self.assertRaises(subprocess.CalledProcessError) as denied:
                client.call(compiled, "increment", 41)
            self.assertIn(b"--allow-python", denied.exception.stderr)
            module = client.module(compiled, allow_python=sys.executable)
            self.assertEqual(module.increment(41), 42)
            self.assertEqual(module.decorate("Galeikan"), "<Galeikan>")
            self.assertEqual(module.reverse(b"\x00\xffGAK"), b"KAG\xff\x00")
            self.assertEqual(module.reverse_list([1, 2, 3]), [3, 2, 1])

    def test_python_can_call_galeikan_udp_function(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(5)
            port = server.getsockname()[1]
            script = Path(directory) / "probe.gak"
            script.write_text(
                "requires { net.connect }\n"
                "from std.net import datagram\n"
                "fn probe(host: str, port: i64, data: bytes) -> Source = datagram(host, port, data, 4, 2000)\n",
                encoding="utf-8",
            )
            def reply():
                request, peer = server.recvfrom(16)
                self.assertEqual(request, b"PING")
                server.sendto(b"GAK\0", peer)
            worker = threading.Thread(target=reply)
            worker.start()
            try:
                response = Galeikan(binary).call(
                    script, "probe", "127.0.0.1", port, b"PING",
                    allow_connect=[f"127.0.0.1:{port}"],
                )
            finally:
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual(response["$galeikan"], "Source")
            self.assertEqual(response["label"], f"udp://127.0.0.1:{port}")
            self.assertEqual(response["size"], 4)

    def test_python_can_call_galeikan_http_fetch(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        with _temporary_test_directory() as directory, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(5)
            port = server.getsockname()[1]
            script = Path(directory) / "fetch.gak"
            script.write_text(
                "requires { net.connect }\n"
                "from std.net import fetch\n"
                "fn body(url: str) -> Source = fetch(url, 4, 2000)\n",
                encoding="utf-8",
            )
            def reply():
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        chunk = connection.recv(1024)
                        if not chunk:
                            raise AssertionError("HTTP client closed before request headers")
                        request.extend(chunk)
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nGAK\0"
                    )
            worker = threading.Thread(target=reply)
            worker.start()
            try:
                url = f"http://127.0.0.1:{port}/sample"
                response = Galeikan(binary).call(
                    script, "body", url, allow_connect=[f"127.0.0.1:{port}"
                ])
            finally:
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual(response["$galeikan"], "Source")
            self.assertEqual(response["size"], 4)
            self.assertIn("HTTP 200", response["origin"])

    def test_python_can_call_galeikan_process_snapshot(self):
        binary = Path(os.environ["GALEIKAN_TEST_BINARY"]) if "GALEIKAN_TEST_BINARY" in os.environ else (
            Path(__file__).resolve().parents[2] / "target" / "debug" /
            ("galeikan.exe" if os.name == "nt" else "galeikan")
        )
        if not binary.exists():
            self.skipTest("build the Galeikan interpreter first")
        helper_source = r"""import ctypes, sys
data = ctypes.create_string_buffer(b'GAK\x00')
if sys.platform.startswith('linux'):
    libc = ctypes.CDLL(None)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    assert libc.prctl(0x59616d61, ctypes.c_ulong(-1).value, 0, 0, 0) == 0
print(ctypes.addressof(data), flush=True)
sys.stdin.read(1)
"""
        with _temporary_test_directory() as directory:
            script = Path(directory) / "capture.gak"
            script.write_text(
                "requires { process.inspect }\n"
                "import std.process\n"
                "from std.process import snapshot\n"
                "fn capture(pid: i64, address: i64) -> Source = snapshot(pid, address, 4)\n"
                "fn map(pid: i64) -> Regions = process.regions(pid)\n"
                "fn threads(pid: i64) -> List<i64> = process.thread_ids(pid)\n"
                "fn children(pid: i64) -> List<i64> = process.children(pid)\n"
                "fn executable(pid: i64) -> str = process.executable(pid)\n"
                "fn parent(pid: i64) -> i64 = process.parent_pid(pid)\n"
                "fn first(pid: i64) -> Region = process.at(process.regions(pid), 0)\n"
                "fn image_maps(pid: i64) -> Regions = process.images(pid)\n"
                "fn first_image(pid: i64) -> Region = process.at(process.images(pid), 0)\n",
                encoding="utf-8",
            )
            helper = subprocess.Popen(
                [sys.executable, "-u", "-c", helper_source],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            )
            try:
                address = int(helper.stdout.readline().strip())
                response = Galeikan(binary).call(
                    script, "capture", helper.pid, address,
                    allow_process=[helper.pid],
                )
                self.assertEqual(response["$galeikan"], "Source")
                self.assertEqual(response["size"], 4)
                self.assertIn(f"process {helper.pid} @", response["origin"])
                regions = Galeikan(binary).call(
                    script, "map", helper.pid, allow_process=[helper.pid]
                )
                self.assertEqual(regions["$galeikan"], "Regions")
                self.assertGreater(regions["count"], 0)
                first = Galeikan(binary).call(
                    script, "first", helper.pid, allow_process=[helper.pid]
                )
                self.assertEqual(first["$galeikan"], "Region")
                self.assertEqual(first["pid"], helper.pid)
                images = Galeikan(binary).call(
                    script, "image_maps", helper.pid, allow_process=[helper.pid]
                )
                self.assertEqual(images["$galeikan"], "Regions")
                self.assertGreater(images["count"], 0)
                image = Galeikan(binary).call(
                    script, "first_image", helper.pid, allow_process=[helper.pid]
                )
                self.assertEqual(image["image_backed"], True)
                self.assertTrue(image["access"].endswith("x"))
                client = Galeikan(binary)
                source_ids = client.call(script, "threads", helper.pid, allow_process=[helper.pid])
                compiled = client.compile(script)
                native_ids = client.call(compiled, "threads", helper.pid, allow_process=[helper.pid])
                self.assertEqual(native_ids, source_ids)
                self.assertGreater(len(native_ids), 0)
                self.assertEqual(native_ids, sorted(set(native_ids)))
                for target, engine in ((script, "ast"), (script, "vm"), (compiled, None)):
                    options = {"engine": engine} if engine else {}
                    child_ids = client.call(
                        target, "children", os.getpid(), allow_process=[os.getpid()], **options
                    )
                    self.assertIn(helper.pid, child_ids)
                    self.assertEqual(child_ids, sorted(set(child_ids)))
                    self.assertEqual(
                        client.call(target, "children", helper.pid, allow_process=[helper.pid], **options),
                        [],
                    )
                source_executable = client.call(
                    script, "executable", helper.pid, allow_process=[helper.pid]
                )
                vm_executable = client.call(
                    script, "executable", helper.pid, engine="vm", allow_process=[helper.pid]
                )
                native_executable = client.call(
                    compiled, "executable", helper.pid, allow_process=[helper.pid]
                )
                self.assertEqual(source_executable, vm_executable)
                self.assertEqual(source_executable, native_executable)
                self.assertTrue(Path(source_executable).is_file())
                for target, engine in ((script, "ast"), (script, "vm"), (compiled, None)):
                    options = {"engine": engine} if engine else {}
                    self.assertEqual(
                        client.call(target, "parent", helper.pid, allow_process=[helper.pid], **options),
                        os.getpid(),
                    )
                with self.assertRaises(subprocess.CalledProcessError):
                    client.call(compiled, "threads", helper.pid)
                with self.assertRaises(subprocess.CalledProcessError):
                    client.call(compiled, "executable", helper.pid)
                with self.assertRaises(subprocess.CalledProcessError):
                    client.call(compiled, "parent", helper.pid)
                with self.assertRaises(subprocess.CalledProcessError):
                    client.call(compiled, "children", helper.pid)
            finally:
                if helper.poll() is None:
                    helper.kill()
                helper.wait(timeout=5)
                helper.stdin.close()
                helper.stdout.close()

    def test_exec_uses_same_permission_arguments(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.check_returncode.return_value = None
            Galeikan("galeikan-bin").exec(
                "probe.gakb", allow_read=["samples"], allow_python="python3", args=["x"],
            )
            self.assertEqual(
                run.call_args.args[0],
                ["galeikan-bin", "exec", "probe.gakb", "--allow-read", "samples", "--allow-python", "python3", "--", "x"],
            )

    def test_call_uses_json_protocol_and_permissions(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.stdout = '{"version":1,"value":{"$galeikan":"bytes","hex":"00ff"}}\n'
            result = Galeikan("galeikan-bin").call(
                "module.gak", "echo", b"\x00\xff", engine="vm",
                allow_read=["samples"], allow_python="python3", args=["sample.bin"],
            )
            self.assertEqual(result, b"\x00\xff")
            self.assertEqual(
                run.call_args.args[0],
                ["galeikan-bin", "call", "module.gak", "echo", "--engine", "vm",
                 "--allow-read", "samples", "--allow-python", "python3", "--", "sample.bin"],
            )
            self.assertEqual(json.loads(run.call_args.kwargs["input"]), {
                "version": 1, "args": [{"$galeikan": "bytes", "hex": "00ff"}],
            })
            self.assertTrue(run.call_args.kwargs["check"])

    def test_module_view_reuses_permissions_and_supports_named_functions(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.stdout = '{"version":1,"value":42}\n'
            client = Galeikan("galeikan-bin")
            module = client.module(
                "math.gak", engine="vm", allow_read=["samples"],
                allow_python="python3", timeout=5.0,
            )
            self.assertEqual(module.twice(21), 42)
            self.assertEqual(module["call"](21), 42)
            self.assertEqual(
                run.call_args.args[0],
                ["galeikan-bin", "call", "math.gak", "call", "--engine", "vm",
                 "--allow-read", "samples", "--allow-python", "python3"],
            )
            self.assertEqual(run.call_args.kwargs["timeout"], 5.0)
            with self.assertRaises(ValueError):
                module["not a function"]

    def test_call_rejects_unrepresentable_arguments(self):
        client = Galeikan("galeikan-bin")
        with self.assertRaises(OverflowError):
            client.call("module.gak", "f", 2**64)
        with self.assertRaises(TypeError):
            client.call("module.gak", "f", [1, "two"])

    def test_lock_returns_lockfile_path(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.stdout = "project/galeikan.lock\n"
            result = Galeikan("galeikan-bin").lock("project")
            self.assertEqual(result, Path("project/galeikan.lock"))
            self.assertEqual(run.call_args.args[0], ["galeikan-bin", "lock", "project"])

    def test_compile_returns_native_executable_path(self):
        with patch("galeikan_bridge._run_bounded") as run:
            run.return_value.stdout = "project/main.gak.native\n"
            result = Galeikan("galeikan-bin").compile("project/main.gak")
            self.assertEqual(result, Path("project/main.gak.native"))
            self.assertEqual(run.call_args.args[0], ["galeikan-bin", "compile", "project/main.gak"])


if __name__ == "__main__":
    unittest.main()
