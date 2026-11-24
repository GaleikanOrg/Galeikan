# Galeikan FAQ

This FAQ describes the current source tree. The downloadable Preview 3 packages may contain fewer functions. See the [quickstart](quickstart.md) for commands and the [technical reference](technical.md) for current signatures and limits.

## Language and distribution

### What is Galeikan?

Galeikan is a research-oriented programming language for bounded binary inspection, process-memory work, and automation. A program can run through an AST interpreter or bytecode VM; supported programs can also compile to a native x86-64 executable. The language is still a preview, and its API is not yet stable.

### Are GaleikanScript and GaleikanLang separate languages?

No. They are names for discussing script and compiled usage. `.gak` and `.gaks` contain the same language and can both be interpreted, bundled, or compiled. Installers and distribution packages use the name **Galeikan**.

### Which systems does the current toolchain target?

The current native backend targets host x86-64 Windows and Linux. The CLI, examples, and integrations should be tested on the intended host before delivery. Native compilation requires GCC or a compatible host C toolchain. Other CPU architectures and a general GPU backend are not implemented yet.

### How do modules and packages work?

Use `import std.binary`, `import helper`, `import helper as h`, or `from helper import name`. Local modules are resolved within the project boundary. Offline `pkg.*` imports use project-local package and lock data; there is no hosted package registry in the current preview.

### Can a compiled program use Python?

Yes, for the supported bridge types. A Galeikan program can call a local `py.*` module after declaring `requires { python.exec }` and receiving `--allow-python <executable>`. The compiled executable needs a compatible Python installation and the imported `.py` files at their expected relative paths. The bridge checks imported module content hashes and exchanges typed integers, Booleans, strings, bytes, and homogeneous lists. It is a process bridge, not an embedded CPython runtime or general Python-object interop. Python also has a `galeikan_bridge` client for calling Galeikan functions.

### Do all programs behave identically in the interpreter, VM, and native compiler?

The intended semantics are shared, but the native backend currently supports a smaller language subset. `galeikan check` validates source syntax and types without executing effects; it does not prove that native compilation will succeed. Compile and run a program on each intended engine before distributing it.

## Research workflows

### Which binary formats are understood?

`std.formats` currently parses PE and ELF structures and exposes bounded views of sections, addresses, dependencies, symbols, relocations, and selected format-specific metadata. PE support includes imports, delayed imports, exports, certificates, debug entries, TLS callbacks, and selected CLR metadata. Parsing a file does not execute it or prove that its declarations match runtime behavior.

### What does `formats.import_fingerprint` measure?

It returns a Galeikan-specific SHA-256 key for a PE file's regular and delayed imports. The records are sorted and ASCII-case-normalized; duplicates remain significant. This key ignores code and IAT addresses. It is not the conventional PE imphash, a file hash, or a malware verdict.

### Can Galeikan save a patched binary?

Yes. `binary.patch`, `binary.splice`, and the bit-patching functions produce a new `Source` without changing the original. `file.write(path, source)` writes that result to a **new** file after `requires { file.write }` and an `--allow-write` grant. It does not overwrite an existing file or provide atomic replacement.

### Does Galeikan include disassembly and control-flow analysis?

`std.asm` decodes x86 instructions and provides reachable walks, function-local approximations, basic blocks, references, paths, dominators, and natural-loop queries. Static analysis cannot resolve every indirect branch or prove a complete function boundary. `function_reachable` avoids descending into direct calls, but a jump or tail call can still leave the function.

### Can scripts inspect process memory and heaps?

With `requires { process.inspect }`, an explicit `--allow-process <pid|self>` grant, and sufficient OS permissions, `std.process` can enumerate mappings, capture bounded memory ranges, search readable regions, and follow bounded pointer paths. `heap_candidates` identifies mappings that look heap-like; it does not enumerate allocator objects. A mapping can change after enumeration, so a region list is not a frozen process snapshot.

### Can addresses have readable references?

Yes. `process.reference(region, address)` returns a checked text reference containing a region label, PID, mapping start, and offset. `process.resolve` and `process.advance_ref` validate it against a region. The reference is convenient within a research session; it is not a durable pointer across restarts or remapping. See the [runnable example](../examples/process-reference.gak).

### Are raw system calls available?

`std.syscall.call` currently exposes raw Linux x86-64 system calls when the source declares `syscall.raw` and execution receives `--allow-syscall`. Raw calls bypass the guarantees of ordinary checked library functions. There is no corresponding portable named-syscall layer yet.

## Security and maturity

### Does “secure” mean that Galeikan is a sandbox for untrusted malware?

No. Built-in file, network, process, Python, and raw-syscall effects require declarations and runtime grants, and many operations enforce byte or time limits. These checks do not replace operating-system isolation. Python workers and native executables run with the user's normal OS authority; raw syscalls are especially powerful. Use an isolated research environment for untrusted samples.

### Are native Galeikan binaries impossible to reverse engineer?

No. The native build applies available platform hardening checks, but no compiled program is inherently opaque. Obfuscation or anti-analysis measures are not a substitute for memory safety, least privilege, or sound cryptography. The current preview should not be described as providing complete anti-debugging or virtualization-based protection.

### Are ROP, BROP, symbolic execution, SMT solving, and kernel debugging built in?

Not as complete native subsystems today. Galeikan already provides lower-level building blocks such as bounded binary parsing, disassembly, control-flow queries, and process-memory inspection. Full gadget search, exploit-chain construction, symbolic execution, solver integration, and kernel debugging remain larger research milestones. The [technical reference](technical.md) lists the functions that exist now.

### Where should I start?

Run the [quickstart](quickstart.md), inspect the [examples](../examples/), and use `galeikan check` before executing a new script. For binary work, start with `std.binary`, `std.formats`, and `std.asm`; for live memory, read the `std.process` limits and grants in the [technical reference](technical.md).
