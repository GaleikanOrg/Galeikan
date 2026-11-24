# Getting started with Galeikan

Galeikan accepts both `.gak` and `.gaks` as source files. They have identical language semantics. Use `.gaks` to signal a script and `.gak` to signal a program; either file can use `run`, `build`, or `compile`. On Windows, the installer adds Galeikan to your user PATH. Open a new terminal after installation before running these commands. The Debian package installs the CLI at `/usr/bin/galeikan`.

```sh
galeikan check examples/hello.gak
galeikan run examples/inspect_script.gaks
galeikan run examples/inspect_script.gaks --engine vm
galeikan build examples/inspect_script.gaks
galeikan exec examples/inspect_script.gakb
galeikan compile examples/native_scalar.gak
```

`check` parses and checks code without running its effects. `run` executes source in the AST interpreter by default. `--engine vm` uses the bytecode VM. `build` creates a `.gakb` bundle, and `exec` runs it without the Galeikan source files. `compile` produces a native x86-64 executable for the currently supported subset and requires a host C toolchain with GCC.

Local modules can be imported with `import helper` or `from helper import name`. Standard modules use `std.*`. Local Python modules use `py.*` and require both `requires { python.exec }` in the source and `--allow-python <python-executable>` on the command line. The Python bridge executes Python code with the Python process's normal operating-system permissions.

Compiled programs can call local Python modules too. For example, compile `examples/interop/main.gak`, then run `examples/interop/main.gak.exe --allow-python python` on Windows or `examples/interop/main.gak.native --allow-python python3` on Linux. The executable does not need the Galeikan source file, but it does need a compatible Python installation and the imported `.py` file in the same relative location beside the executable. You can move the executable and Python files together while preserving their directory layout. Galeikan checks each imported module's content hash before calling it. Native calls currently exchange typed `i64`, `u64`, `bool`, `str`, `bytes`, and homogeneous lists of those values; the Python function's result type must be declared at the Galeikan call site. Python can also call functions in a compiled executable through `galeikan_bridge`: `Galeikan().module("program.gak.native").function(42)` on Linux, or the corresponding `.exe` path on Windows. `Galeikan().session(...)` keeps the native process alive across calls. This is a bounded process bridge, not an importable CPython extension module or a general Python object bridge.

The Python bridge accepts `allow_write=["output-directory"]` for `run`, `exec`, `call`, `module`, and `session` when Galeikan code uses `std.file.write`.

Effectful operations require declarations in the source and matching command-line grants. For example, a script that reads a file declares `requires { file.read }` and runs with `--allow-read <directory>`. To save a patched `Source` as a new binary, import `std.file`, declare `file.write`, and call `file.write("patched.bin", source)` with `--allow-write <directory>`. The output directory must exist and an existing file is never replaced. Process and network operations use their own explicit grants. Run `galeikan --help` for the current command syntax.

The preview is designed for bounded, reproducible research. It does not yet implement every planned language feature or a general sandbox for untrusted code. The native backend supports a smaller subset than the interpreter and VM.

Integer bit operations include `&`, `|`, `^`, `~`, `<<`, arithmetic `>>`, and logical `>>>`. Shift counts must be between 0 and 63. Hexadecimal literals may describe any 64-bit pattern; patterns with the high bit set are interpreted as signed `i64` values.

String literals support `\n`, `\t`, `\r`, `\0`, `\"`, `\\`, `\xNN` (exactly two hexadecimal digits), and `\u{N}` (one to six hexadecimal digits forming a valid Unicode scalar value). `\xNN` inserts the corresponding Unicode character, so values above `0x7f` are encoded as UTF-8 when used as text. Use `bytes.from_hex(...)` when exact raw byte values matter.

## A practical binary workflow

The following program creates a `Source` from bytes, changes one byte without mutating the original, and writes the new data to a separate file. Put it in `patch.gaks` and choose a path inside an existing output directory:

```galeikan
requires { file.write }
import std.binary
import std.file

let original = binary.snapshot(binary.from_hex("47 41 4b 00"))
let patched = binary.patch(original, 3, binary.from_hex("01"))
print binary.diff_count(original, patched)
file.write("output/patched.bin", patched)
```

```sh
galeikan check patch.gaks
galeikan run patch.gaks --allow-write output
```

`file.write` creates a new file and rejects an existing destination. Derived `Source` values retain lineage to their input. For PE or ELF files, use `binary.analyze(path, max_bytes)` with a declared `file.read` effect and `--allow-read` grant, then `formats.probe` to inspect format metadata. Parsing a format does not execute it.

## Inspect a candidate instruction sequence

`asm.ret_gadget_starts` scans a bounded visible `Source` for straight-line x86 instruction sequences ending in a near `ret`. The result contains candidate offsets, not a claim that those bytes are reachable or executable. Decode a selected offset with `asm.linear_source` and inspect each instruction before drawing a conclusion. See [ret_gadget_starts.gak](../examples/ret_gadget_starts.gak) for a runnable example. The third argument of `linear_source` is the address assigned to the first decoded instruction; derive it from a trusted file-to-virtual-address mapping if it should represent a real address.

## Work across execution modes

Run a script with both `--engine ast` and `--engine vm` when reproducibility matters. Compile it separately when the native subset supports every construct it uses. A successful `check` does not guarantee native compilation. The `.gak` and `.gaks` suffixes communicate intended use; neither changes language semantics. `galeikan build` produces a `.gakb` bytecode bundle, while `galeikan compile` produces a host-native executable. All three modes should be tested on the target OS with the same inputs and grants.
