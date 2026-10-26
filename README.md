# Galeikan

![Galeikan symbol](gak_logo.jpg)

Galeikan is a hybrid programming language for security research, binary inspection, and repeatable automation. The same syntax runs in a reference interpreter, a bytecode VM, or, within the currently supported subset, as a native x86-64 executable. **.gak** and **.gaks** are interchangeable source extensions; GaleikanScript and GaleikanLang are ecosystem names for the script and native modes.

**Status: 0.1.0 development preview.** Native feature coverage is narrower than interpreter coverage. The packages are unsigned, and effect declarations do not provide an operating-system sandbox.

## Get started

Download the Windows x64 installer, Debian 13 amd64 package, or Visual Studio Code syntax extension from [Releases](https://github.com/GaleikanOrg/Galeikan/releases). The Windows and Debian packages use the public product name **Galeikan**. Both include the command-line tool and English quickstart material.

~~~sh
galeikan check examples/hello.gak
galeikan run examples/hello.gak
galeikan run examples/hello.gak --engine vm
galeikan build examples/hello.gak
galeikan exec examples/hello.gakb
galeikan compile examples/native_scalar.gak
~~~

Native compilation requires a suitable host x86-64 GCC toolchain. See [the quickstart](docs/quickstart.md) for commands, permissions, and Python interop.

## A small example

~~~galeikan
requires { file.read }
from std.binary import analyze, size
from std.formats import probe, kind, arch

let source: Source = analyze("sample.bin", 1048576)
let report: Format = probe(source)
print kind(report)
print arch(report)
print size(source)
~~~

Run it with **galeikan run inspect.gak --allow-read DIRECTORY**. File reading requires both a source declaration and a command-line grant.

## What is implemented

| Area | Preview capability |
| --- | --- |
| Execution | Reference interpreter, bytecode VM with .gakb bundles, native x86-64 subset |
| Modules | Project-local imports and selective imports; offline local packages with manifest and lockfile |
| Binary research | Bounded Source snapshots, views, hashes, transformations, observations, and structured findings |
| Formats | PE and ELF metadata, sections, dependencies, imports and exports, relocations, and selected debug metadata |
| Disassembly | Bounded x86 decoding and control-flow oriented views |
| System access | Explicitly granted file, network, and process-inspection operations |
| Python | Explicit process bridge in both directions, including supported native programs |
| Editor | .gak/.gaks highlighting and the Galeikan Eclipse theme for Visual Studio Code |

The case format can record source lineage and be verified without rerunning the program. Binary metadata and signals are observations, not malware verdicts or proofs of runtime protection.

## Python interoperability

Galeikan can import a project-local Python module with **import py.helper** when the source declares **python.exec** and the invocation grants **--allow-python**. Supported native executables can use the same bridge; Python and module files remain external dependencies. The optional **python/galeikan_bridge** package calls Galeikan functions from Python and supports persistent sessions. The process bridge exchanges bounded typed values, not arbitrary Python objects.

## Build from source

The main implementation is in Rust with C runtime components and an x86-64 assembly stage-0. Build with **cargo build --release** on a supported host. Windows packaging is in **scripts/build-windows-installer.ps1**; Debian packaging is in **scripts/build-deb.sh**. See **galeikan --help** for current CLI options.

## Security boundaries

Galeikan is designed to make effects explicit and binary observations traceable. In this preview, path grants and declared effects are not a complete sandbox; Python modules run with their normal OS permissions. Do not run untrusted source without separate system isolation. Stable semantics, broader native parity, target-platform testing, and security review remain release criteria.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Technical overview](docs/technical.md)
- [Language examples](examples/)
- [Visual Studio Code extension](editors/vscode/galeikan/)

The public release documentation is in English. The project is under active development.
