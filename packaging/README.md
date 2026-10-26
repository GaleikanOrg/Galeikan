# Galeikan 0.1.0 Preview

Galeikan is a research-oriented language for reproducible binary inspection and security workflows. The same source language uses `.gak` and `.gaks` files; either extension can run in the interpreter or be compiled where the native backend supports the program.

The preview includes an AST interpreter, a bytecode VM, versioned `.gakb` bundles, local modules, explicit effects and permissions, a bounded binary research library, and optional Python interoperability. Native compilation currently supports a smaller x86-64 subset. Galeikan does not yet provide a full operating-system sandbox for untrusted programs.

See [Getting started](docs/quickstart.md) for commands, permissions, and current limits. The full language documentation is still being revised for the public release.
