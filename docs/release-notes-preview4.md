# Galeikan 0.1.0 Preview 4

Preview 4 brings the current security-research language and tools to Windows x64 and Debian 13 amd64. `.gak` and `.gaks` remain the same language: run source in the AST interpreter or bytecode VM, build a `.gakb` bundle, or compile supported programs to a native executable.

## Highlights

- Save a modified `Source` or byte buffer to a **new** binary with `std.file.write`, a declared `file.write` effect, and an explicit output-directory grant. Existing files are never overwritten.
- Explore PE and ELF binaries with expanded import, dependency, symbol, relocation, and selected debug metadata. Compare files with import and dependency fingerprints, byte differences, bit distance, histograms, entropy windows, and bounded text scans.
- Inspect x86 instructions, control-flow graphs, function-local reachable paths, dominators, natural loops, and bounded `ret`-ending instruction-sequence candidates. `asm.linear_source` decodes any selected `Source` offset for manual inspection.
- Inspect permitted process mappings, heap-like regions, pointers, and bounded memory ranges. Region references tie addresses to their observed mapping; they are not durable across remapping.
- Use project-local Galeikan modules and the explicit Python process bridge from supported script and native programs. The VS Code language extension and optional Eclipse theme are separate packages.
- Strengthen source-range checks, bundle and case-file validation, native frame checks, and cross-engine parity. The CLI, editor packages, website documentation, and release assets use English public-facing text.

## Documentation

The [quickstart](quickstart.md) covers execution modes, grants, Python, binary patching, and instruction-sequence inspection. The [technical reference](technical.md) catalogs commands, types, modules, functions, effects, limits, and native coverage. The [FAQ](faq.md) explains maturity and security boundaries.

## Limits

The native compiler still supports a subset of the interpreter and VM. `check` is a parse/type preflight, not proof that native compilation will succeed. Static instruction-sequence candidates may be data or unreachable bytes. Effect grants and bounded APIs do not sandbox Python, native executables, raw syscalls, or untrusted malware. Windows builds are unsigned; use the published SHA-256 sums to verify downloads.

## Validation

The complete Windows Rust test suite, Windows installer smoke test, Debian package smoke test, and the new cross-engine `asm.linear_source` test on Windows and Linux passed. The full Linux suite still has ten network tests failing in this WSL environment because UDP exchanges time out after WSL falls back from NAT to VirtioProxy networking. Those failures have not been attributed to the language implementation.
