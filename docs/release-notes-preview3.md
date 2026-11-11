# Galeikan 0.1.0 Preview 3

Preview 3 packages the latest Galeikan research language for Windows x64 and Debian 13 amd64. `.gak` and `.gaks` remain one language: run them in the AST interpreter or bytecode VM, build `.gakb` bundles, or compile the supported x86-64 native subset.

## Highlights

- Expanded bounded binary inspection: signed and cross-byte bitfields, UTF readers, LEB128, incremental CRC32, and span-aware entropy windows.
- Deeper PE and ELF inspection, including COFF symbols and selected CLR metadata, MethodDef signatures and IL bodies, and exception-handler clauses.
- Readable, writable, executable, and writable-executable process-region filters for permitted process-inspection workflows.
- More native parity coverage for research values, format accessors, process observations, and project-local Python imports.
- A [full technical review and function reference](https://github.com/GaleikanOrg/Galeikan/blob/v0.1.0-preview3/docs/technical-review-preview3.md) with current APIs, security boundaries, and known limits.

## Downloads

- `Galeikan-0.1.0-preview3-windows-x64-setup.exe`: Windows installer with user PATH registration.
- `galeikan_0.1.0.preview3_amd64.deb`: Debian 13 amd64 package with `/usr/bin/galeikan` (Debian package version `0.1.0~preview3`).
- `galeikan-language-0.1.3.vsix`: VS Code syntax and color theme, versioned separately from the language release.
- `SHA256SUMS.txt`: SHA-256 digests for the three binary artifacts.

## Validation

The full Windows `cargo test --locked` suite passed. Windows release builds passed AST and VM smoke runs; the NSIS archive integrity check and embedded CLI, branding JPEG, and VSIX payload hash comparisons passed. The Debian package build and `scripts/smoke-deb.sh` passed, including installed CLI, AST/VM/bundle/native examples, format and process workflows, editor assets, Python bridge, case verification, MIME registrations, and package metadata. Artifact checksums were generated after the builds and checked against the website copies.

An isolated Windows installer installation was not run because a Galeikan installation was already registered on the validation machine; the smoke script intentionally refuses to overwrite it. The packages are unsigned. The native compiler remains a subset, and effect grants are not an OS-level sandbox. See the [technical review](https://github.com/GaleikanOrg/Galeikan/blob/v0.1.0-preview3/docs/technical-review-preview3.md) before using the preview with untrusted material.
