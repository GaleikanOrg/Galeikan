# Galeikan technical reference

This is the function and command reference for the **current source tree**. It is a living development document, not a stable API contract. The packaged `v0.1.0-preview3` release is described separately in the [Preview 3 technical review](technical-review-preview3.md). Source changes after that tag may not be available in the downloadable packages yet.

Use this page to find current functions by module, learn what each group returns, and identify permission requirements. Each function group below gives its present purpose; a name in this reference does not imply that every execution engine supports every argument form. Test the exact source on the intended engine and platform.

**Navigate:** [Commands](#command-line-reference) · [Language and types](#language-and-data-types) · [Bytes and text](#stdbytes) · [Binary data](#stdbinary) · [Formats and CLR](#stdformats) · [Disassembly](#stdasm) · [Processes](#stdprocess) · [Network](#stdnet) · [Utilities](#stdaudit-stdlab-stditer-stdlist-stdresult-stdcli-stdsyscall) · [Effects](#effects-and-grants-reference).

## Availability and conventions

The Preview 3 downloads do not yet include `binary.histogram`, `process.heap_candidates`, `process.pointer_refs_u64`, or `process.read_pointer_u64`; these are implemented in the current source tree. `check` validates source without running it. The AST interpreter and VM cover more language constructs than the native compiler, so compile and test a program before relying on native delivery. All byte counts and offsets are bounded; invalid ranges return errors. Functions that access files, processes, networks, Python, or raw syscalls require the corresponding declared effect and runtime grant.

Functions are written below without the `std.` prefix for readability: `binary.deep` means `std.binary.deep` after importing `std.binary`. A vertical bar in a table groups related calls; it does not indicate that they all take the same arguments or return the same type.

## Command-line reference

| Command | Purpose |
| --- | --- |
| `galeikan check <source>` | Parse and check a `.gak` or `.gaks` file without executing its effects. |
| `galeikan run <source> [--engine ast\|vm]` | Execute source in the AST interpreter (default) or bytecode VM. |
| `galeikan build <source>` | Write a versioned `.gakb` bytecode bundle. |
| `galeikan inspect <bundle.gakb>` | Validate and describe a bytecode bundle without executing it. |
| `galeikan exec <bundle.gakb>` | Run a bundle with the bytecode VM. |
| `galeikan compile <source>` | Build a host x86-64 native program for supported language constructs. |
| `galeikan call <source\|bundle> <function>` | Call an exported function through a JSON request on standard input. |
| `galeikan serve <source\|bundle>` | Keep a JSON-lines function-call session alive for clients such as the Python bridge. |
| `galeikan lock <project-dir>` | Resolve project-local packages and write their lock data. |
| `galeikan verify-case <case.json>` | Check a recorded case's hashes and lineage without rerunning its source. |
| `galeikan --help`, `--version` | Show command usage or the core package version. |

`run`, `exec`, `call`, and `serve` accept applicable permission flags. `run` and `exec` can write a case with `--case <output.json>`. Arguments after `--` are passed to the Galeikan program and read with `std.cli`. The compiler's generated file uses `.exe` on Windows and `.native` on Linux. The CLI package version is currently `0.1.0`. Distribution builds have their own preview label.

## Language and data types

```galeikan
requires { file.read }
import std.binary
from std.result import is_error

fn header_byte(source: Source) -> Result<Observation> = binary.deep(source, 0, "u8")

let sample: Source = binary.analyze("sample.bin", 4096)
let first = header_byte(sample)
if is_error(first) {
    print "No first byte"
} else {
    print first
}
```

`.gak` and `.gaks` are interchangeable source extensions. `let` is immutable, `var` is mutable, `fn` declares a function, typed parameters/returns are supported, and `requires` declares intended effects. The preview has conditionals, `while`/`for`, matching, records and classes, methods, `return`, `break`, and `continue`. Imports can name a standard module, a local source module, an offline `pkg.*` package, or a project-local `py.*` Python module. `import helper as h` and `from helper import name` are supported. File-scoped modules live beside the importing source under the project boundary.

| Type or value | Meaning |
| --- | --- |
| `i64`, `u64`, `bool`, `str`, `bytes` | Signed and unsigned 64-bit integers, Boolean, UTF-8 text, and raw bytes. Checked integer arithmetic reports overflow; bitwise and shift operators are available. |
| `List<T>`, `Offsets` | Homogeneous lists and bounded offset sequences. Indexing and iteration are supported in the appropriate execution paths. |
| `Result<T>` | Success or an error message; `std.result` constructs, tests, and recovers values. |
| `Source` | Bounded byte snapshot or derived view with origin and lineage. |
| `Observation`, `Diff`, `Finding` | Source-linked decoded value, byte comparison, and audit result. |
| `Format`, `Section` | Parsed PE/ELF report and a selected section. |
| `Instruction`, `Disassembly` | Decoded x86 instruction and bounded instruction collection. |
| `Regions`, `Region` | Process mapping collection and one mapping. |
| `HttpResponse` | Bounded HTTP result with status, body, and headers. |
| records and classes | User-defined structured values and associated methods. |

Built-ins include `print` for output, `len` for supported collections/text/bytes, `assert` for runtime checks, and `i64`/`u64` for checked integer conversion. String escapes include newline/tab/carriage return, NUL, quote, backslash, two-digit `\xNN`, and Unicode scalar `\u{N}`. `\xNN` creates text; use `bytes.from_hex` for exact raw byte values. An `Observation` is always tied to a range in a `Source`; errors and `Result` values should be checked before relying on decoded content.

## Standard-library reference

### `std.bytes`

| Function | Current purpose |
| --- | --- |
| `from_hex`, `to_hex` | Decode hex text into bytes; encode bytes as hex text. |
| `pack` | Pack a checked integer or field into bytes using the requested representation. |
| `concat`, `repeat`, `xor` | Concatenate, repeat, or XOR byte buffers with size checks. |
| `at`, `find`, `contains` | Read a byte by index, locate a byte sequence, or test membership. |

### `std.text`

| Function | Current purpose |
| --- | --- |
| `length`, `byte_length` | Count Unicode characters or UTF-8 bytes. |
| `find`, `contains` | Find a substring or test whether it occurs. |
| `starts_with`, `ends_with` | Test a text prefix or suffix. |
| `slice` | Take a checked character-indexed substring. |

### `std.binary`

| Function family | Current purpose |
| --- | --- |
| `analyze`, `from_hex`, `snapshot` | Read an authorized file into a bounded `Source`, decode hex bytes, or capture in-memory bytes as a `Source`. |
| `view`, `extract`, `patch`, `splice` | Create bounded source views, extract bytes, replace a span immutably, or insert/remove bytes while keeping lineage. |
| `deep`, `value`, `signed_value`, `value_u64`, `offset`, `width` | Decode a typed integer observation and read its value, signed value, unsigned value, byte offset, or width. `deep` accepts `u8`, signed/unsigned 16/32/64-bit little/big-endian fields, and canonical `uleb128`/`sleb128`. |
| `bits`, `signed_bits`, `patch_bits`, `patch_signed_bits` | Read or immutably change 1–64 bits with explicit `lsb0`/`msb0` ordering and signedness checks. |
| `read_text`, `read_cstring`, `read_utf8`, `read_wstring` | Decode bounded fixed-length or terminated ASCII/UTF-8/UTF-16 text. |
| `size`, `sha256`, `crc32`, `entropy`, `entropy_windows`, `histogram` | Get size, SHA-256, CRC32 (including an optional previous CRC for chunking), global entropy, source-span-aware window entropy, or a 256-count byte-frequency list. `histogram` accepts bytes or a `Source`. |
| `find`, `contains`, `hunt`, `strings` | Search bounded source bytes, match a byte pattern, or enumerate candidate strings. |
| `hexdump`, `diff`, `diff_offsets`, `diff_count` | Produce a bounded hex view; compare sources and inspect changed offsets/count. |

`crc32` is a conventional checksum; use SHA-256 when cryptographic collision resistance matters. Entropy and pattern hits are evidence for investigation, not automatic classification. Source size, string count, mutation count, and entropy-window count have implementation limits that return errors rather than silently truncating results.

### `std.formats`

`probe(source)` produces a `Format` for supported PE or ELF data. Format accessors inspect file structures; they do not execute the file. The following is the current public accessor catalog, grouped by the object returned.

| Functions | Current purpose |
| --- | --- |
| `probe`, `kind`, `bits`, `endian`, `arch`, `build_id` | Parse a source and report recognized format, word size, byte order, architecture, or ELF build ID. |
| `signal`, `field`, `image_base` | Read a selected hardening/declaration signal, named observed field, or PE image base. Signals are file metadata, not runtime proof. |
| `count`, `section`, `section_at_offset`, `section_at_address` | Count sections and select one by index, file offset, or virtual address. |
| `name`, `data`, `offset`, `size`, `virtual_size`, `address`, `address_u64`, `flags`, `flags_u64`, `writable`, `executable` | Inspect a selected section's name, bytes, location, extent, flags, and write/execute attributes. |
| `overlay`, `entry_view` | Return bytes beyond mapped content or a bounded view around the declared entry point. |
| `rva`, `pe_va`, `pe_va_at`, `va`, `va_u64`, `elf_va_at` | Map PE RVA/VA or ELF VA ranges into source views; the `_at` forms allow an explicit address context. |
| `rva_offset`, `pe_va_offset`, `pe_va_offset_at`, `va_offset`, `va_offset_u64`, `elf_va_offset_at` | Convert a declared virtual address into a file offset, with checked mapping. |
| `offset_rva`, `offset_pe_va`, `offset_pe_va_at`, `offset_va`, `offset_va_u64`, `offset_elf_va_at` | Convert a file offset into a format virtual address, with checked mapping. |
| `import_count`, `delay_import_count`, `export_count`, `import_iat_rva`, `delay_import_iat_rva` | Count PE imports, delayed imports, or exports and inspect import-address-table locations. |
| `export_name`, `export_target`, `export_kind`, `export_summary`, `export_ordinal`, `export_address`, `export_view` | Inspect an export's name, target/forwarder, kind, ordinal, address, summary, or backing source view. |
| `dependency_count`, `delay_dependency_count`, `needed_count`, `dependency_name`, `delay_dependency_name`, `needed_name` | Count and name PE normal/delayed dependencies or ELF `DT_NEEDED` libraries. |
| `certificate_count`, `certificate_data` | Count PE certificate entries and return bounded certificate bytes; no trust-chain validation is performed. |
| `debug_count`, `debug_kind`, `debug_type`, `debug_size`, `debug_timestamp`, `debug_data` | Count and inspect PE debug directory entries and their data. |
| `debug_pdb_path`, `debug_pdb_guid`, `debug_pdb_age` | Read CodeView RSDS PDB identity fields when present. |
| `tls_callback_count`, `tls_callback_address_u64` | Count PE TLS callbacks and report their declared addresses. |
| `symbol_count`, `static_symbol_count`, `coff_symbol_count` | Count dynamic, static, or PE COFF symbols. COFF auxiliary rows are excluded from the logical count. |
| `coff_symbol_name`, `coff_symbol_field` | Read a PE COFF symbol name or numeric field. |
| `symbol_defined`, `static_symbol_defined`, `symbol_at_address`, `static_symbol_at_address`, `symbol_at_address_at`, `static_symbol_at_address_at` | Test definition status or find dynamic/static symbols at a mapped address. |
| `symbol_view`, `static_symbol_view`, `symbol_address_u64`, `static_symbol_address_u64` | Return the backing source view or address for dynamic/static symbols. |
| `relocation_count`, `relocation_location`, `relocation_address`, `relocation_address_u64`, `relocation_kind`, `relocation_summary` | Count relocation entries and read their location, address, type, or summary. |

#### CLR metadata within `std.formats`

These accessors operate on the parsed CLR metadata of a PE file and fail cleanly if the required directory/table is missing or malformed. Table indices and blob lengths are bounded.

| Functions | Current purpose |
| --- | --- |
| `clr_metadata_version`, `clr_stream_count`, `clr_stream_name`, `clr_stream_rva`, `clr_stream_size`, `clr_stream_data` | Describe the metadata root and its named streams; return a bounded stream view. |
| `clr_string`, `clr_blob`, `clr_guid` | Read a value from the `#Strings`, `#Blob`, or `#GUID` heap. |
| `clr_module_name`, `clr_module_mvid` | Read the Module table's name and module version ID. |
| `clr_table_present` | Test whether a supported metadata table is present. |
| `clr_type_name`, `clr_type_namespace`, `clr_type_ref_name`, `clr_type_ref_namespace`, `clr_type_ref_full_name` | Resolve TypeDef or TypeRef names, namespaces, and nested reference names. |
| `clr_method_name`, `clr_method_owner`, `clr_method_rva`, `clr_method_signature`, `clr_method_signature_text` | Identify a MethodDef's name/declaring type, RVA, raw signature, or decoded signature text. |
| `clr_method_impl_flags`, `clr_method_flags`, `clr_method_max_stack`, `clr_method_local_sig_token` | Inspect declared method attributes, implementation flags, IL stack limit, and local-signature token. |
| `clr_method_il`, `clr_method_eh_count`, `clr_method_eh_field` | Read a bounded IL body and exception-handler clauses; these do not execute or verify managed code. |

### `std.asm`

| Functions | Current purpose |
| --- | --- |
| `entry`, `linear`, `reachable_entry`, `decode`, `decode_u64`, `reachable` | Decode the declared executable entry, a bounded linear range, or reachable x86 instructions. |
| `count`, `at`, `next`, `size`, `offset`, `address`, `address_u64`, `target`, `target_u64`, `data_target_u64` | Navigate a `Disassembly` or `Instruction` and inspect positions, size, branch target, or data reference. |
| `text`, `mnemonic`, `flow`, `source`, `bytes` | Read formatted instruction text, mnemonic, control-flow class, origin source, or instruction bytes. |
| `register_usage_complete`, `register_reads`, `register_writes`, `flags_read`, `flags_modified` | Inspect register/flag use including implicit and conditional access where available. |
| `successors`, `call_targets`, `data_refs`, `xrefs`, `data_xrefs`, `overlap_count`, `overlap_at` | Inspect resolved branch successors, call/data references, cross-references, or overlapping decode starts. |
| `block_count`, `block_instruction`, `block_start`, `block_end`, `block_instruction_count`, `block_successors`, `block_unresolved` | Traverse bounded basic blocks and their outgoing edges. |

The decoder provides static instruction observations. Indirect control flow can remain unresolved; a reachable walk is not complete program execution.

### `std.process`

| Functions | Current purpose |
| --- | --- |
| `self_pid`, `parent_pid`, `children`, `thread_ids`, `executable`, `modules` | Identify the current/target process, its parent/children/threads, executable, and loaded module paths where the OS exposes them. |
| `regions`, `images`, `readable_regions`, `writable_regions`, `executable_regions`, `wx_regions` | Enumerate mappings or select by image backing and memory permissions. |
| `heap_candidates` | Select readable and writable, non-image-backed mappings classified as heap, anonymous, or private. These are **candidate regions**, not confirmed allocator objects or a heap dump. |
| `count`, `at`, `locate`, `locate_u64` | Count regions, index one, or locate a mapping containing an address. |
| `pid`, `start`, `start_u64`, `end`, `end_u64`, `size`, `access`, `label`, `kind`, `image_backed` | Inspect a region's owner, address interval, extent, access flags, mapped label/type, or image status. |
| `offset`, `offset_u64`, `address`, `address_u64` | Translate between a region-relative offset and address. |
| `reference`, `resolve`, `advance_ref` | Create, resolve, or move a checked process-region reference. |
| `snapshot`, `snapshot_u64`, `snapshot_region`, `snapshot_ref`, `snapshot_at`, `snapshot_at_u64` | Capture a bounded process-memory range as a `Source`, by PID/address, region, or reference. |
| `hunt_region` | Search an accessible region for a bounded byte pattern. |
| `pointer_refs_u64` | Search a readable region for the little-endian bytes of a `u64` pointer value and return matching region-relative offsets, including unaligned matches. It does not dereference or validate those values. |
| `read_pointer_u64` | Read eight bytes at a region-relative offset as a little-endian `u64`. The region must be readable, the range must fit, and OS process permissions still apply. This reads a value; it does not follow the pointer. |

Mapping enumeration is not a snapshot of an entire process; regions can change between lookup and read, and permission grants do not override OS access controls.

### `std.net`

| Functions | Current purpose |
| --- | --- |
| `exchange`, `datagram` | Send and receive bounded TCP or UDP data with timeout and destination grant checks. |
| `fetch`, `request` | Perform bounded HTTP retrieval or a request with explicit method/body/headers. |
| `status`, `body`, `headers` | Read an `HttpResponse` status, bounded response body, or headers. |

### `std.audit`, `std.lab`, `std.iter`, `std.list`, `std.result`, `std.cli`, `std.syscall`

| Module and functions | Current purpose |
| --- | --- |
| `audit.bound`, `audit.expect` | Create a `Finding` from a bounded or expected numeric observation. |
| `audit.hunt`, `audit.signal` | Produce a finding from a byte-pattern match or a file-format signal. |
| `audit.passed`, `audit.failed` | Test the outcome of a `Finding`. |
| `lab.mutate` | Generate a bounded list of immutable `Source` variants using bit flips, byte/integer boundaries, truncation, insertion, or deletion. |
| `iter.range` | Produce a bounded integer-offset range for iteration. |
| `list.count`, `list.append`, `list.concat` | Count, immutably append to, or concatenate homogeneous flat lists. |
| `result.ok`, `result.fail` | Construct a successful or failed `Result`. |
| `result.is_ok`, `result.is_error`, `result.message`, `result.recover` | Test a `Result`, read its failure message, or use a fallback value. |
| `cli.count`, `cli.arg`, `cli.int` | Count and read program arguments, including checked `i64` parsing. |
| `syscall.call` | Invoke a Linux x86-64 system call after `--allow-syscall`; this bypasses the safety expectations of ordinary built-ins and is for controlled local experiments only. |

## Effects and grants reference

| Source effect | CLI grant | Scope and limit |
| --- | --- | --- |
| `file.read` | `--allow-read <directory>` | Authorizes built-in file reads rooted at the granted directory. |
| `net.connect` | `--allow-connect <host:port>` | Authorizes the matching network destination for bounded TCP/UDP/HTTP operations. |
| `process.inspect` | `--allow-process <pid\|self>` | Authorizes supported inspection of the specified process; OS permissions still apply. |
| `python.exec` | `--allow-python <executable>` | Starts a compatible external Python worker with that user's normal OS authority. |
| `case.write` | `--case <output.json>` | Records a case from an execution path that supports case output. |
| `syscall.raw` | `--allow-syscall` | Permits unrestricted Linux x86-64 system calls; use only for controlled experiments. |

For a research workflow, document the exact grants beside the script, set finite byte/time limits, preserve the source hashes, and test all intended engines. `check` is a parser/type preflight, not an execution or sandbox proof.
