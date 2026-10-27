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

Effectful operations require declarations in the source and matching command-line grants. For example, a script that reads a file declares `requires { file.read }` and runs with `--allow-read <directory>`. Process and network operations use their own explicit grants. Run `galeikan --help` for the current command syntax.

The preview is designed for bounded, reproducible research. It does not yet implement every planned language feature or a general sandbox for untrusted code. The native backend supports a smaller subset than the interpreter and VM.

Integer bit operations include `&`, `|`, `^`, `~`, `<<`, arithmetic `>>`, and logical `>>>`. Shift counts must be between 0 and 63. Hexadecimal literals may describe any 64-bit pattern; patterns with the high bit set are interpreted as signed `i64` values.

String literals support `\n`, `\t`, `\r`, `\0`, `\"`, `\\`, `\xNN` (exactly two hexadecimal digits), and `\u{N}` (one to six hexadecimal digits forming a valid Unicode scalar value). `\xNN` inserts the corresponding Unicode character, so values above `0x7f` are encoded as UTF-8 when used as text. Use `bytes.from_hex(...)` when exact raw byte values matter.
