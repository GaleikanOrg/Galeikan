# Technical overview

## Execution model

Galeikan has one parser and one source language for .gak and .gaks. The reference interpreter executes the syntax tree; the bytecode VM executes .gakb bundles; the native compiler emits x86-64 PE or ELF code for its supported subset. Script and native semantics are intended to converge, but the preview does not yet claim full parity. A small assembly stage-0 is retained for bootstrap learning; the larger implementation is currently Rust with C runtime components.

## Modules and effects

Project-local modules use Python-like **import helper as h** and **from helper import name**. Local packages are resolved from galeikan.json with a lockfile; there is no hosted registry in this preview. Standard modules use std.*, while project-local Python modules use py.*. Effectful operations must be declared with **requires { ... }** and granted at launch. Supported effects include file.read, net.connect, process.inspect, python.exec, and case.write. These checks are intended to make access visible and bounded; they are not OS-level isolation.

## Research data model

**Source** records captured bytes, their hash, and lineage through views and transformations. **Observation** records a decoded value and its source span. **Finding** records a rule result. A versioned case export can include the script, imported modules, relevant blobs, source lineage, and findings. The **verify-case** command checks hashes and transformations without executing the original program. Hashes are integrity checks, not proof of authorship.

Built-in modules provide bounded binary reads, byte transformations, PE/ELF parsing, x86 disassembly, process memory snapshots, TCP/UDP/HTTP network operations, and audit helpers. PE and ELF accessors report declared file metadata. They do not simulate a loader or prove that a defense is active at runtime.

## Python bridge

Galeikan calls project-local Python through a subprocess protocol. Calls require an explicit python.exec declaration and runtime permission. A compiled Galeikan program can call those modules if compatible Python and the modules are available beside the executable in the expected layout. The optional Python package can call Galeikan functions; sessions can keep a process alive for repeated calls. The bridge exchanges bounded i64, u64, bool, str, bytes, and homogeneous lists. It is not an embedded CPython runtime or an arbitrary object bridge.

## Preview limits

The native backend supports fewer constructs than the interpreter and VM. A complete static type system, complete HTTP streaming, GPU support, comprehensive sandboxing, and stable 1.0 semantics remain future work. Build and package checks are performed on Windows x64 and Linux amd64; the Debian package targets Debian 13. The preview binaries are unsigned.
