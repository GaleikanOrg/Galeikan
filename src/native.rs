use crate::syntax::{
    self, BlockStmt, BlockStmtKind, Expr, ExprKind, FunctionBody, MatchPattern, Op, Param, Stmt,
    StmtKind,
};
use crate::{project, runtime};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_SOURCE: u64 = 8 * 1024 * 1024;
const MAX_SLOTS: usize = 4096;
const MAX_NATIVE_CODE: usize = 16 * 1024 * 1024;
const MAX_RANGE_ITEMS: i64 = 100_000;
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const SHA256_RUNTIME: &str = r#"gak_sha256:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    sub rsp, 424
    mov rbx, rax
    mov r12, rdx
    cmp r12, 536870912
    ja gak_source_backing_limit
    lea r14, [r12+72]
    shr r14, 6
    xor r13d, r13d
    mov rax, r12
    shl rax, 3
    bswap rax
    mov QWORD PTR [rsp+384], rax
    lea r10, [rip+gak_sha_iv]
    xor ecx, ecx
gak_sha_init:
    mov eax, DWORD PTR [r10+rcx*4]
    mov DWORD PTR [rsp+352+rcx*4], eax
    inc ecx
    cmp ecx, 8
    jb gak_sha_init
gak_sha_block:
    cmp r13, r14
    jae gak_sha_output
    xor ecx, ecx
gak_sha_block_byte:
    mov r8, r13
    shl r8, 6
    add r8, rcx
    xor eax, eax
    cmp r8, r12
    jb gak_sha_data_byte
    je gak_sha_pad_byte
    mov r9, r14
    shl r9, 6
    sub r9, 8
    cmp r8, r9
    jb gak_sha_store_byte
    sub r8, r9
    mov al, BYTE PTR [rsp+r8+384]
    jmp gak_sha_store_byte
gak_sha_data_byte:
    mov al, BYTE PTR [rbx+r8]
    jmp gak_sha_store_byte
gak_sha_pad_byte:
    mov al, 128
gak_sha_store_byte:
    mov BYTE PTR [rsp+rcx+32], al
    inc ecx
    cmp ecx, 64
    jb gak_sha_block_byte
    xor ecx, ecx
gak_sha_first_words:
    mov eax, DWORD PTR [rsp+rcx*4+32]
    bswap eax
    mov DWORD PTR [rsp+rcx*4+96], eax
    inc ecx
    cmp ecx, 16
    jb gak_sha_first_words
gak_sha_expand:
    mov eax, DWORD PTR [rsp+rcx*4+36]
    mov r8d, eax
    ror r8d, 7
    mov r9d, eax
    ror r9d, 18
    xor r8d, r9d
    shr eax, 3
    xor r8d, eax
    mov eax, DWORD PTR [rsp+rcx*4+88]
    mov r9d, eax
    ror r9d, 17
    mov r10d, eax
    ror r10d, 19
    xor r9d, r10d
    shr eax, 10
    xor r9d, eax
    mov eax, DWORD PTR [rsp+rcx*4+32]
    add eax, r8d
    add eax, DWORD PTR [rsp+rcx*4+68]
    add eax, r9d
    mov DWORD PTR [rsp+rcx*4+96], eax
    inc ecx
    cmp ecx, 64
    jb gak_sha_expand
    xor ecx, ecx
gak_sha_work_init:
    mov eax, DWORD PTR [rsp+352+rcx*4]
    mov DWORD PTR [rsp+392+rcx*4], eax
    inc ecx
    cmp ecx, 8
    jb gak_sha_work_init
    xor ecx, ecx
gak_sha_round:
    mov r8d, DWORD PTR [rsp+420]
    mov eax, DWORD PTR [rsp+408]
    mov r9d, eax
    ror r9d, 6
    mov r10d, eax
    ror r10d, 11
    xor r9d, r10d
    mov r10d, eax
    ror r10d, 25
    xor r9d, r10d
    add r8d, r9d
    mov r9d, eax
    and r9d, DWORD PTR [rsp+412]
    not eax
    and eax, DWORD PTR [rsp+416]
    xor r9d, eax
    add r8d, r9d
    lea r9, [rip+gak_sha_k]
    add r8d, DWORD PTR [r9+rcx*4]
    add r8d, DWORD PTR [rsp+96+rcx*4]
    mov eax, DWORD PTR [rsp+392]
    mov r9d, eax
    ror r9d, 2
    mov r10d, eax
    ror r10d, 13
    xor r9d, r10d
    mov r10d, eax
    ror r10d, 22
    xor r9d, r10d
    mov r10d, eax
    and r10d, DWORD PTR [rsp+396]
    mov r11d, eax
    and r11d, DWORD PTR [rsp+400]
    xor r10d, r11d
    mov edi, DWORD PTR [rsp+396]
    and edi, DWORD PTR [rsp+400]
    xor r10d, edi
    add r9d, r10d
    mov eax, DWORD PTR [rsp+416]
    mov DWORD PTR [rsp+420], eax
    mov eax, DWORD PTR [rsp+412]
    mov DWORD PTR [rsp+416], eax
    mov eax, DWORD PTR [rsp+408]
    mov DWORD PTR [rsp+412], eax
    mov eax, DWORD PTR [rsp+404]
    add eax, r8d
    mov DWORD PTR [rsp+408], eax
    mov eax, DWORD PTR [rsp+400]
    mov DWORD PTR [rsp+404], eax
    mov eax, DWORD PTR [rsp+396]
    mov DWORD PTR [rsp+400], eax
    mov eax, DWORD PTR [rsp+392]
    mov DWORD PTR [rsp+396], eax
    add r8d, r9d
    mov DWORD PTR [rsp+392], r8d
    inc ecx
    cmp ecx, 64
    jb gak_sha_round
    xor ecx, ecx
gak_sha_accumulate:
    mov eax, DWORD PTR [rsp+352+rcx*4]
    add eax, DWORD PTR [rsp+392+rcx*4]
    mov DWORD PTR [rsp+352+rcx*4], eax
    inc ecx
    cmp ecx, 8
    jb gak_sha_accumulate
    inc r13
    jmp gak_sha_block
gak_sha_output:
    mov QWORD PTR [rsp+32], 32
    xor ecx, ecx
gak_sha_output_word:
    mov eax, DWORD PTR [rsp+352+rcx*4]
    bswap eax
    mov DWORD PTR [rsp+40+rcx*4], eax
    inc ecx
    cmp ecx, 8
    jb gak_sha_output_word
    lea rax, [rsp+32]
    mov edx, 32
    call gak_to_hex
    add rsp, 424
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
"#;
const CATCHABLE_RESULT_ERRORS: &[(&str, &str)] = &[
    ("gak_call_depth_error", "call depth exceeded"),
    ("gak_call_stack_error", "native call stack exceeds 512 KiB"),
    ("gak_overflow", "integer overflow"),
    ("gak_divzero", "division by zero"),
    ("gak_shift_range", "shift count must be in 0..63"),
    ("gak_range_start", "range start must not be negative"),
    ("gak_range_end", "range end must not be negative"),
    ("gak_range_limit", "range exceeds 100000 items"),
    ("gak_list_index", "list index out of range"),
    ("gak_cli_index", "argument index out of range"),
    ("gak_hex_invalid", "invalid hex data"),
    ("gak_hex_odd", "hex data needs an even number of digits"),
    ("gak_hex_limit", "hex data exceeds 1048576 bytes"),
    ("gak_str_limit", "string memory exceeds 64 MiB"),
    ("gak_text_slice_range", "text slice out of range"),
    ("gak_text_search_alloc", "text search allocation failed"),
    ("gak_bytes_index", "byte index out of range"),
    ("gak_binary_offset_negative", "offset must not be negative"),
    ("gak_binary_length_negative", "length must not be negative"),
    ("gak_binary_range_overflow", "range overflow"),
    ("gak_binary_out_of_bounds", "out of bounds"),
    (
        "gak_analyze_max",
        "max_bytes must be between 0 and 536870912",
    ),
    ("gak_binary_unknown_decoder", "unknown decoder"),
    ("gak_hexdump_limit", "hexdump length exceeds 4096 bytes"),
    (
        "gak_text_offset_negative",
        "text offset must not be negative",
    ),
    ("gak_max_chars_range", "max_chars out of range"),
    ("gak_max_chars_limit", "max_chars must be 1 to 4096"),
    (
        "gak_text_encoding",
        "text encoding must be ascii, utf16le, or utf16be",
    ),
    ("gak_text_offset_bounds", "text offset out of bounds"),
    ("gak_text_not_printable", "no printable text at offset"),
    (
        "gak_strings_minimum_range",
        "minimum string length out of range",
    ),
    (
        "gak_strings_minimum_limit",
        "minimum string length must be 1 to 4096",
    ),
    ("gak_strings_many", "too many strings"),
    ("gak_hunt_invalid_hex", "invalid hex pattern"),
    ("gak_hunt_hex_limit", "hex pattern exceeds 1048576 bytes"),
    (
        "gak_hunt_odd_hex",
        "hex pattern needs an even number of nibbles",
    ),
    ("gak_hunt_mask_limit", "masked hex pattern exceeds 64 bytes"),
    ("gak_hunt_empty", "empty search pattern"),
    ("gak_hunt_many", "too many matches"),
    ("gak_diff_limit_negative", "max_differences out of range"),
    ("gak_diff_limit", "max_differences must be at most 10000"),
    ("gak_diff_many", "LimitExceeded: too many differences"),
    ("gak_patch_empty", "patch data must not be empty"),
    (
        "gak_patch_limit",
        "LimitExceeded: patch exceeds 1048576 bytes",
    ),
    (
        "gak_splice_insert_limit",
        "LimitExceeded: splice insertion exceeds 1048576 bytes",
    ),
    (
        "gak_splice_empty",
        "splice must insert or remove at least one byte",
    ),
    ("gak_splice_size_overflow", "splice size overflow"),
    (
        "gak_splice_size_limit",
        "LimitExceeded: Source exceeds 536870912 bytes",
    ),
    (
        "gak_observation_value_range",
        "Observation value does not fit i64",
    ),
    (
        "gak_source_depth",
        "LimitExceeded: Source derivation depth exceeds 64",
    ),
    (
        "gak_bytes_limit",
        "LimitExceeded: bytes result exceeds 1048576 bytes",
    ),
    ("gak_repeat_negative", "repeat count must not be negative"),
    ("gak_repeat_count_limit", "repeat count exceeds 1048576"),
    ("gak_xor_empty_key", "xor key must not be empty"),
    ("gak_pack_negative", "pack expects a nonnegative value"),
    (
        "gak_pack_encoding",
        "pack encoding must be u8, u16le/be, u32le/be, or u64le/be",
    ),
    ("gak_pack_range_u8", "pack value out of range for u8"),
    ("gak_pack_range_u16le", "pack value out of range for u16le"),
    ("gak_pack_range_u16be", "pack value out of range for u16be"),
    ("gak_pack_range_u32le", "pack value out of range for u32le"),
    ("gak_pack_range_u32be", "pack value out of range for u32be"),
    (
        "gak_result_invalid",
        "result.fail needs a nonempty message of at most 4096 bytes",
    ),
    (
        "gak_result_message_success",
        "result.message requires a failed Result",
    ),
];
const DYNAMIC_RESULT_ERRORS: &[&str] = &[
    "gak_text_limit_dynamic",
    "gak_analyze_error_dynamic",
    "gak_python_error_dynamic",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scalar {
    Int,
    UInt,
    Bool,
    Str,
    Bytes,
    Source,
    Format,
    Section,
    Observation,
    Offsets,
    Diff,
    Regions,
    Region,
    Record(u32),
    Result(Option<ResultValue>),
    ListInt,
    ListUInt,
    ListBool,
    ListStr,
    ListBytes,
    ListSource,
    ListObservation,
    ListDiff,
    ListRecord(u32),
    ListEmpty,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResultValue {
    Int,
    UInt,
    Bool,
    Str,
    Bytes,
    Source,
    Format,
    Section,
    Observation,
    Offsets,
    Diff,
    Regions,
    Region,
    Record(u32),
}

impl ResultValue {
    fn from_scalar(kind: Scalar) -> Option<Self> {
        match kind {
            Scalar::Int => Some(Self::Int),
            Scalar::UInt => Some(Self::UInt),
            Scalar::Bool => Some(Self::Bool),
            Scalar::Str => Some(Self::Str),
            Scalar::Bytes => Some(Self::Bytes),
            Scalar::Source => Some(Self::Source),
            Scalar::Format => Some(Self::Format),
            Scalar::Section => Some(Self::Section),
            Scalar::Observation => Some(Self::Observation),
            Scalar::Offsets => Some(Self::Offsets),
            Scalar::Diff => Some(Self::Diff),
            Scalar::Regions => Some(Self::Regions),
            Scalar::Region => Some(Self::Region),
            Scalar::Record(id) => Some(Self::Record(id)),
            _ => None,
        }
    }

    fn scalar(self) -> Scalar {
        match self {
            Self::Int => Scalar::Int,
            Self::UInt => Scalar::UInt,
            Self::Bool => Scalar::Bool,
            Self::Str => Scalar::Str,
            Self::Bytes => Scalar::Bytes,
            Self::Source => Scalar::Source,
            Self::Format => Scalar::Format,
            Self::Section => Scalar::Section,
            Self::Observation => Scalar::Observation,
            Self::Offsets => Scalar::Offsets,
            Self::Diff => Scalar::Diff,
            Self::Regions => Scalar::Regions,
            Self::Region => Scalar::Region,
            Self::Record(id) => Scalar::Record(id),
        }
    }
}

impl Scalar {
    fn list_of(element: Self) -> Result<Self, String> {
        match element {
            Self::Int => Ok(Self::ListInt),
            Self::UInt => Ok(Self::ListUInt),
            Self::Bool => Ok(Self::ListBool),
            Self::Str => Ok(Self::ListStr),
            Self::Bytes => Ok(Self::ListBytes),
            Self::Source => Ok(Self::ListSource),
            Self::Observation => Ok(Self::ListObservation),
            Self::Diff => Ok(Self::ListDiff),
            Self::Record(id) => Ok(Self::ListRecord(id)),
            _ => Err("native nested lists are not yet supported".into()),
        }
    }

    fn element(self) -> Option<Self> {
        match self {
            Self::ListInt => Some(Self::Int),
            Self::ListUInt => Some(Self::UInt),
            Self::ListBool => Some(Self::Bool),
            Self::ListStr => Some(Self::Str),
            Self::ListBytes => Some(Self::Bytes),
            Self::ListSource => Some(Self::Source),
            Self::ListObservation => Some(Self::Observation),
            Self::ListDiff => Some(Self::Diff),
            Self::ListRecord(id) => Some(Self::Record(id)),
            _ => None,
        }
    }

    fn accepts(self, actual: Self) -> bool {
        self == actual
            || (actual == Self::ListEmpty && self.element().is_some())
            || matches!((self, actual), (Self::Result(Some(_)), Self::Result(None)))
    }

    fn merge(self, other: Self) -> Option<Self> {
        if self.accepts(other) {
            Some(self)
        } else if other.accepts(self) {
            Some(other)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
struct Binding {
    slot: usize,
    kind: Scalar,
    mutable: bool,
}

#[derive(Clone)]
struct NativeFunction {
    module: PathBuf,
    params: Vec<Param>,
    result_type: Option<String>,
    body: FunctionBody,
}

#[derive(Clone)]
struct NativeRecord {
    name: String,
    module: PathBuf,
    fields: Vec<(String, Scalar)>,
}

struct NativeModule {
    path: PathBuf,
    imports: HashMap<String, NativeImport>,
    statements: Vec<Stmt>,
}

#[derive(Clone)]
enum NativeImport {
    Local(PathBuf),
    Python(PathBuf, String),
    Process,
    Net,
    Iter,
    Cli,
    List,
    Result,
    Bytes,
    Text,
    Binary,
    Formats,
}

struct Codegen {
    code: String,
    data: String,
    labels: usize,
    slots: usize,
    windows: bool,
    functions: HashMap<(PathBuf, String), NativeFunction>,
    records: HashMap<u32, NativeRecord>,
    record_lookup: HashMap<(PathBuf, String), u32>,
    module_imports: HashMap<PathBuf, HashMap<String, NativeImport>>,
    module_scopes: HashMap<PathBuf, HashMap<String, Binding>>,
    root_module: PathBuf,
    active_module: PathBuf,
    root_scope: HashMap<String, Binding>,
    active_calls: Vec<(PathBuf, String)>,
    active_frames: Vec<ActiveFrame>,
    return_contexts: Vec<ReturnContext>,
    loop_targets: Vec<(String, String)>,
    error_prefixes: Vec<String>,
    uses_file_read: bool,
    uses_python: bool,
    uses_process: bool,
    uses_net: bool,
    uses_text: bool,
    uses_formats: bool,
}

#[derive(Clone)]
struct ReturnContext {
    label: String,
    types: Vec<Scalar>,
    result_type: Option<Scalar>,
    expected_scalar: Option<Scalar>,
    error_depth: usize,
    stack_slot: Option<usize>,
    depth_slot: Option<usize>,
    base_slot: Option<usize>,
}

#[derive(Clone)]
struct ActiveFrame {
    key: (PathBuf, String),
    body_label: String,
    params: Vec<(usize, Scalar)>,
    return_kind: Option<Scalar>,
}

fn module_target(
    importer: &Path,
    target: &str,
    project: &project::Project,
) -> Result<PathBuf, String> {
    if target.starts_with("std.") || target.starts_with("py.") || target.starts_with("py:") {
        return Err(format!(
            "native compiler does not yet support standard or Python module {target}"
        ));
    }
    let candidate = if let Some(package_target) = target.strip_prefix("pkg.") {
        let (package, module) = package_target
            .split_once('.')
            .unwrap_or((package_target, "main"));
        let base = project
            .packages
            .get(package)
            .ok_or_else(|| format!("unknown native package {package}"))?;
        project::source_module_path(base, module)?
    } else {
        project::source_module_path(importer.parent().ok_or("module has no parent")?, target)?
    };
    let path = candidate
        .canonicalize()
        .map_err(|e| format!("cannot read native module {}: {e}", candidate.display()))?;
    if !path.starts_with(&project.root) {
        return Err(format!("native module outside project: {}", path.display()));
    }
    Ok(path)
}

fn python_module_target(
    importer: &Path,
    target: &str,
    project: &project::Project,
) -> Result<(PathBuf, String), String> {
    let filename = if let Some(module) = target.strip_prefix("py.") {
        format!("{}.py", module.replace('.', "/"))
    } else {
        let module = target.strip_prefix("py:").ok_or("invalid Python import")?;
        if module.ends_with(".py") {
            module.to_owned()
        } else {
            format!("{module}.py")
        }
    };
    let requested = importer
        .parent()
        .ok_or("module has no parent")?
        .join(filename);
    let path = requested
        .canonicalize()
        .map_err(|e| format!("cannot read Python module {}: {e}", requested.display()))?;
    if !path.starts_with(&project.root) {
        return Err(format!("Python import outside project: {}", path.display()));
    }
    let metadata = fs::metadata(&path)
        .map_err(|e| format!("cannot inspect Python module {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "Python module is not a regular file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_SOURCE {
        return Err(format!("Python module exceeds 8 MiB: {}", path.display()));
    }
    let source = fs::read(&path)
        .map_err(|e| format!("cannot read Python module {}: {e}", path.display()))?;
    if source.len() as u64 > MAX_SOURCE {
        return Err(format!("Python module exceeds 8 MiB: {}", path.display()));
    }
    let digest = Sha256::digest(source);
    Ok((
        path,
        digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    ))
}

fn native_python_module_path(entry: &Path, module: &Path) -> Result<String, String> {
    let base = entry.parent().ok_or("native entry has no parent")?;
    let base_parts = base.components().collect::<Vec<_>>();
    let module_parts = module.components().collect::<Vec<_>>();
    let shared = base_parts
        .iter()
        .zip(&module_parts)
        .take_while(|(left, right)| left == right)
        .count();
    if shared == 0 {
        return Err("Python module and native executable must be on the same volume".into());
    }
    let mut relative = PathBuf::new();
    for _ in shared..base_parts.len() {
        relative.push("..");
    }
    for part in &module_parts[shared..] {
        relative.push(part.as_os_str());
    }
    let relative = relative
        .to_str()
        .ok_or("Python module path is not Unicode")?
        .replace('\\', "/");
    Ok(format!("galeikan-exe:{relative}"))
}

fn collect_module(
    path: PathBuf,
    project: &project::Project,
    checked_hashes: &HashMap<PathBuf, [u8; 32]>,
    loading: &mut HashSet<PathBuf>,
    modules: &mut HashMap<PathBuf, NativeModule>,
    order: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if modules.contains_key(&path) {
        return Ok(());
    }
    if !loading.insert(path.clone()) {
        return Err(format!("native cyclic import: {}", path.display()));
    }
    if loading.len() > 64 {
        return Err("native import depth exceeds 64 modules".into());
    }
    let mut source_bytes = Vec::new();
    fs::File::open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .take(MAX_SOURCE + 1)
        .read_to_end(&mut source_bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if source_bytes.len() as u64 > MAX_SOURCE {
        return Err(format!("{}: source exceeds 8 MiB", path.display()));
    }
    let actual_hash: [u8; 32] = Sha256::digest(&source_bytes).into();
    if checked_hashes.get(&path) != Some(&actual_hash) {
        return Err(format!(
            "{}: source changed after validation; retry compilation",
            path.display()
        ));
    }
    let source = String::from_utf8(source_bytes)
        .map_err(|_| format!("{}: source is not UTF-8", path.display()))?;
    let statements =
        syntax::parse(syntax::lex(&source).map_err(|e| format!("{}:{e}", path.display()))?)
            .map_err(|e| format!("{}:{e}", path.display()))?;
    let mut imports = HashMap::new();
    for statement in &statements {
        if let StmtKind::Import(target, alias, _) = &statement.kind {
            if target == "std.iter" {
                imports.insert(alias.clone(), NativeImport::Iter);
                continue;
            }
            if target == "std.cli" {
                imports.insert(alias.clone(), NativeImport::Cli);
                continue;
            }
            if target == "std.list" {
                imports.insert(alias.clone(), NativeImport::List);
                continue;
            }
            if target == "std.result" {
                imports.insert(alias.clone(), NativeImport::Result);
                continue;
            }
            if target == "std.bytes" {
                imports.insert(alias.clone(), NativeImport::Bytes);
                continue;
            }
            if target == "std.text" {
                imports.insert(alias.clone(), NativeImport::Text);
                continue;
            }
            if target == "std.binary" {
                imports.insert(alias.clone(), NativeImport::Binary);
                continue;
            }
            if target == "std.formats" {
                imports.insert(alias.clone(), NativeImport::Formats);
                continue;
            }
            if target == "std.process" {
                imports.insert(alias.clone(), NativeImport::Process);
                continue;
            }
            if target == "std.net" {
                imports.insert(alias.clone(), NativeImport::Net);
                continue;
            }
            if target.starts_with("py.") || target.starts_with("py:") {
                if !statements.iter().any(|item| matches!(&item.kind,
                    StmtKind::Requires(effects) if effects.iter().any(|effect| effect == "python.exec")
                )) {
                    return Err(format!("{}:{}:{}: python.exec was not declared", path.display(), statement.line, statement.col));
                }
                let (python, hash) = python_module_target(&path, target, project).map_err(|e| {
                    format!(
                        "{}:{}:{}: {e}",
                        path.display(),
                        statement.line,
                        statement.col
                    )
                })?;
                imports.insert(alias.clone(), NativeImport::Python(python, hash));
                continue;
            }
            let child = module_target(&path, target, project).map_err(|e| {
                format!(
                    "{}:{}:{}: {e}",
                    path.display(),
                    statement.line,
                    statement.col
                )
            })?;
            collect_module(
                child.clone(),
                project,
                checked_hashes,
                loading,
                modules,
                order,
            )?;
            imports.insert(alias.clone(), NativeImport::Local(child));
        }
    }
    loading.remove(&path);
    order.push(path.clone());
    modules.insert(
        path.clone(),
        NativeModule {
            path,
            imports,
            statements,
        },
    );
    Ok(())
}

pub fn compile(script: &Path) -> Result<PathBuf, String> {
    if !cfg!(any(target_os = "windows", target_os = "linux")) || !cfg!(target_arch = "x86_64") {
        return Err("native compiler currently requires Windows or Linux x86-64".into());
    }
    let checked_hashes = runtime::checked_source_hashes(script)?;
    let path = script
        .canonicalize()
        .map_err(|e| format!("cannot read script {}: {e}", script.display()))?;
    let project = project::resolve(&path)?;
    let mut modules = HashMap::new();
    let mut order = Vec::new();
    collect_module(
        path.clone(),
        &project,
        &checked_hashes,
        &mut HashSet::new(),
        &mut modules,
        &mut order,
    )?;
    if order.len() > 4096 {
        return Err("native program exceeds 4096 modules".into());
    }
    let mut records = HashMap::new();
    let mut record_lookup = HashMap::new();
    for module_path in &order {
        let module = &modules[module_path];
        for statement in &module.statements {
            if let StmtKind::Struct(name, fields) = &statement.kind {
                let native_fields = fields
                    .iter()
                    .map(|field| {
                        Ok((
                            field.name.clone(),
                            native_type(
                                field
                                    .annotation
                                    .as_deref()
                                    .ok_or("struct field type missing")?,
                                module_path,
                                &module.imports,
                                &record_lookup,
                            )?,
                        ))
                    })
                    .collect::<Result<Vec<_>, String>>()
                    .map_err(|e| {
                        format!(
                            "{}:{}:{}: {e}",
                            module.path.display(),
                            statement.line,
                            statement.col
                        )
                    })?;
                let id = u32::try_from(records.len() + 1)
                    .map_err(|_| "native program has too many struct types")?;
                records.insert(
                    id,
                    NativeRecord {
                        name: name.clone(),
                        module: module_path.clone(),
                        fields: native_fields,
                    },
                );
                record_lookup.insert((module_path.clone(), name.clone()), id);
            }
        }
    }
    let mut functions = HashMap::new();
    for module_path in &order {
        let module = &modules[module_path];
        for statement in &module.statements {
            if let StmtKind::Function(name, params, result_type, body) = &statement.kind {
                for param in params {
                    if let Some(annotation) = &param.annotation {
                        native_type(annotation, module_path, &module.imports, &record_lookup)?;
                    }
                }
                if let Some(result_type) = result_type {
                    native_type(result_type, module_path, &module.imports, &record_lookup)?;
                }
                functions.insert(
                    (module_path.clone(), name.clone()),
                    NativeFunction {
                        module: module_path.clone(),
                        params: params.clone(),
                        result_type: result_type.clone(),
                        body: body.clone(),
                    },
                );
            }
        }
    }
    let module_imports = modules
        .iter()
        .map(|(key, module)| (key.clone(), module.imports.clone()))
        .collect();
    let mut generator = Codegen {
        code: String::new(),
        data: String::new(),
        labels: 0,
        slots: 0,
        windows: cfg!(target_os = "windows"),
        functions,
        records,
        record_lookup,
        module_imports,
        module_scopes: HashMap::new(),
        root_module: path.clone(),
        active_module: path.clone(),
        root_scope: HashMap::new(),
        active_calls: Vec::new(),
        active_frames: Vec::new(),
        return_contexts: Vec::new(),
        loop_targets: Vec::new(),
        error_prefixes: Vec::new(),
        uses_file_read: false,
        uses_python: false,
        uses_process: false,
        uses_net: false,
        uses_text: false,
        uses_formats: false,
    };
    for module_path in &order {
        let module = &modules[module_path];
        let is_root = module_path == &path;
        generator.active_module = module_path.clone();
        let mut scope = HashMap::new();
        for statement in &module.statements {
            let root_action = is_root
                && matches!(
                    statement.kind,
                    StmtKind::Assign(_, _)
                        | StmtKind::Print(_)
                        | StmtKind::Impact(_)
                        | StmtKind::While(_, _)
                        | StmtKind::For(_, _, _)
                        | StmtKind::If(_, _, _)
                );
            let skip_action = root_action.then(|| generator.label());
            if let Some(label) = &skip_action {
                writeln!(
                    generator.code,
                    "    cmp BYTE PTR [rip+gak_native_call_mode], 0\n    jne {label}"
                )
                .unwrap();
            }
            let error_prefix = match &statement.kind {
                StmtKind::Let(_, _, _) | StmtKind::Var(_, _, _) => {
                    format!("{}:{}: ", module.path.display(), statement.line)
                }
                _ => format!(
                    "{}:{}:{}: ",
                    module.path.display(),
                    statement.line,
                    statement.col
                ),
            };
            generator.error_prefixes.push(error_prefix);
            let start = generator.code.len();
            let result = match &statement.kind {
                StmtKind::Requires(effects)
                    if effects.iter().all(|effect| {
                        effect == "file.read"
                            || effect == "python.exec"
                            || effect == "process.inspect"
                            || effect == "net.connect"
                    }) =>
                {
                    Ok(())
                }
                StmtKind::Import(_, _, _)
                | StmtKind::Function(_, _, _, _)
                | StmtKind::Struct(_, _) => Ok(()),
                StmtKind::Let(name, annotation, expr) => {
                    generator.binding(name, annotation.as_deref(), expr, false, &mut scope)
                }
                StmtKind::Var(name, annotation, expr) => {
                    generator.binding(name, annotation.as_deref(), expr, true, &mut scope)
                }
                StmtKind::Assign(name, expr) if is_root => {
                    generator.tick();
                    generator.assign(name, expr, &scope)
                }
                StmtKind::Print(expr) if is_root => {
                    generator.tick();
                    generator.print(expr, &scope)
                }
                StmtKind::Impact(expr) if is_root => {
                    generator.tick();
                    generator.impact(expr, &scope)
                }
                StmtKind::While(condition, body) if is_root => {
                    generator.tick();
                    generator.while_loop(condition, body, &scope)
                }
                StmtKind::For(name, iterable, body) if is_root => {
                    generator.tick();
                    generator.for_range(name, iterable, body, &scope)
                }
                StmtKind::If(condition, yes, no) if is_root => {
                    generator.tick();
                    generator.if_statement(condition, yes, no, &scope)
                }
                _ => Err("this statement or effect is not supported by the native compiler".into()),
            };
            if result.is_ok() {
                generator.capture_runtime_errors(start)?;
            }
            if let Some(label) = skip_action {
                writeln!(generator.code, "{label}:").unwrap();
            }
            generator.error_prefixes.pop();
            result.map_err(|e| {
                format!(
                    "{}:{}:{}: {e}",
                    module.path.display(),
                    statement.line,
                    statement.col
                )
            })?;
            generator
                .module_scopes
                .insert(module_path.clone(), scope.clone());
            if is_root {
                generator.root_scope = scope.clone();
            }
            generator.ensure_size()?;
        }
    }
    generator.emit_native_call_dispatch(&modules[&path])?;
    let uses_file_read = generator.uses_file_read;
    let uses_python = generator.uses_python;
    let uses_process = generator.uses_process;
    let uses_net = generator.uses_net;
    let uses_text = generator.uses_text;
    let uses_formats = generator.uses_formats;
    let assembly = generator.finish()?;
    let source_extension = path
        .extension()
        .and_then(|part| part.to_str())
        .filter(|part| matches!(*part, "gak" | "gaks"))
        .unwrap_or("gak");
    let assembly_path = if cfg!(target_os = "windows") {
        path.with_extension(format!("{source_extension}.win64.S"))
    } else {
        path.with_extension(format!("{source_extension}.linux64.S"))
    };
    let output = if cfg!(target_os = "windows") {
        path.with_extension(format!("{source_extension}.exe"))
    } else {
        path.with_extension(format!("{source_extension}.native"))
    };
    fs::write(&assembly_path, assembly)
        .map_err(|e| format!("cannot write {}: {e}", assembly_path.display()))?;
    let file_runtime_path = if uses_file_read || uses_python || uses_process || uses_net {
        let helper_path = path.with_extension(format!("{source_extension}.native_file.c"));
        fs::write(&helper_path, include_str!("native_file.c"))
            .map_err(|e| format!("cannot write {}: {e}", helper_path.display()))?;
        Some(helper_path)
    } else {
        None
    };
    let python_runtime_path = if uses_python {
        let helper_path = path.with_extension(format!("{source_extension}.native_python.c"));
        let runner = include_bytes!("native_python_runner.py")
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let helper =
            include_str!("native_python.c").replace("__GAK_PYTHON_RUNNER_BYTES__", &runner);
        fs::write(&helper_path, helper)
            .map_err(|e| format!("cannot write {}: {e}", helper_path.display()))?;
        Some(helper_path)
    } else {
        None
    };
    let net_runtime_path = if uses_net {
        let helper_path = path.with_extension(format!("{source_extension}.native_net.c"));
        fs::write(&helper_path, include_str!("native_net.c"))
            .map_err(|e| format!("cannot write {}: {e}", helper_path.display()))?;
        Some(helper_path)
    } else {
        None
    };
    let text_runtime_path = if uses_text {
        let helper_path = path.with_extension(format!("{source_extension}.native_text.c"));
        fs::write(&helper_path, include_str!("native_text.c"))
            .map_err(|e| format!("cannot write {}: {e}", helper_path.display()))?;
        Some(helper_path)
    } else {
        None
    };
    let formats_runtime_path = if uses_formats {
        let helper_path = path.with_extension(format!("{source_extension}.native_formats.c"));
        fs::write(&helper_path, include_str!("native_formats.c"))
            .map_err(|e| format!("cannot write {}: {e}", helper_path.display()))?;
        Some(helper_path)
    } else {
        None
    };
    let call_runtime_path = path.with_extension(format!("{source_extension}.native_call.c"));
    fs::write(&call_runtime_path, include_str!("native_call.c"))
        .map_err(|e| format!("cannot write {}: {e}", call_runtime_path.display()))?;
    let mut compiler = Command::new("gcc");
    if cfg!(windows) {
        compiler.arg("-Wl,--dynamicbase,--nxcompat,--high-entropy-va");
    } else {
        compiler
            .arg("-pie")
            .arg("-Wl,-z,relro,-z,now,-z,noexecstack");
        if uses_net {
            compiler.arg("-pthread");
        }
    }
    compiler
        .arg("-x")
        .arg("assembler")
        .arg("-o")
        .arg(gcc_path(&output))
        .arg(gcc_path(&assembly_path));
    if let Some(helper_path) = &file_runtime_path {
        compiler
            .arg("-x")
            .arg("c")
            .arg("-std=c11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(gcc_path(helper_path));
    }
    if let Some(helper_path) = &python_runtime_path {
        compiler
            .arg("-x")
            .arg("c")
            .arg("-std=c11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(gcc_path(helper_path));
    }
    if let Some(helper_path) = &net_runtime_path {
        compiler
            .arg("-x")
            .arg("c")
            .arg("-std=c11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(gcc_path(helper_path));
    }
    if let Some(helper_path) = &text_runtime_path {
        compiler
            .arg("-x")
            .arg("c")
            .arg("-std=c11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(gcc_path(helper_path));
    }
    if let Some(helper_path) = &formats_runtime_path {
        compiler
            .arg("-x")
            .arg("c")
            .arg("-std=c11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(gcc_path(helper_path));
    }
    compiler
        .arg("-x")
        .arg("c")
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg(gcc_path(&call_runtime_path));
    if cfg!(windows) {
        compiler.arg("-lshell32");
        if uses_net {
            compiler.arg("-lws2_32");
        }
    }
    let result = compiler
        .output()
        .map_err(|e| format!("cannot start gcc: {e}"))?;
    if !result.status.success() {
        let diagnostic = String::from_utf8_lossy(&result.stderr);
        return Err(format!(
            "native link failed: {}",
            diagnostic.chars().take(4096).collect::<String>()
        ));
    }
    if cfg!(target_os = "windows") {
        let rendered = output.to_string_lossy();
        Ok(PathBuf::from(
            rendered.strip_prefix(r"\\?\").unwrap_or(&rendered),
        ))
    } else {
        Ok(output)
    }
}

fn gcc_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if cfg!(target_os = "windows") {
        if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
            return format!("//{}", unc.replace('\\', "/"));
        }
        rendered
            .strip_prefix(r"\\?\")
            .unwrap_or(&rendered)
            .replace('\\', "/")
    } else {
        rendered.into_owned()
    }
}

fn scalar_type(annotation: &str) -> Result<Scalar, String> {
    match annotation {
        "i64" => Ok(Scalar::Int),
        "u64" => Ok(Scalar::UInt),
        "bool" => Ok(Scalar::Bool),
        "str" => Ok(Scalar::Str),
        "bytes" => Ok(Scalar::Bytes),
        "Source" => Ok(Scalar::Source),
        "Format" => Ok(Scalar::Format),
        "Section" => Ok(Scalar::Section),
        "Observation" => Ok(Scalar::Observation),
        "Offsets" => Ok(Scalar::Offsets),
        "Diff" => Ok(Scalar::Diff),
        "Regions" => Ok(Scalar::Regions),
        "Region" => Ok(Scalar::Region),
        _ => Err(format!(
            "native compiler supports i64, u64, bool, str, bytes, Source, and declared struct types; got {annotation}"
        )),
    }
}

fn native_call_tag(kind: Scalar) -> Option<u64> {
    match kind {
        Scalar::Int => Some(1),
        Scalar::UInt => Some(2),
        Scalar::Bool => Some(3),
        Scalar::Str => Some(4),
        Scalar::Bytes => Some(5),
        Scalar::Source => Some(12),
        Scalar::Observation => Some(13),
        Scalar::ListInt => Some(6),
        Scalar::ListUInt => Some(7),
        Scalar::ListBool => Some(8),
        Scalar::ListStr => Some(9),
        Scalar::ListBytes => Some(10),
        _ => None,
    }
}

fn native_type(
    annotation: &str,
    module: &Path,
    imports: &HashMap<String, NativeImport>,
    records: &HashMap<(PathBuf, String), u32>,
) -> Result<Scalar, String> {
    if let Some(inner) = annotation
        .strip_prefix("Result<")
        .and_then(|s| s.strip_suffix('>'))
    {
        let kind = native_type(inner, module, imports, records)?;
        return ResultValue::from_scalar(kind)
            .map(|value| Scalar::Result(Some(value)))
            .ok_or_else(|| format!("native Result cannot wrap {inner}"));
    }
    if let Some(inner) = annotation
        .strip_prefix("List<")
        .and_then(|s| s.strip_suffix('>'))
    {
        return Scalar::list_of(native_type(inner, module, imports, records)?);
    }
    if let Some(id) = records.get(&(module.to_path_buf(), annotation.to_owned())) {
        return Ok(Scalar::Record(*id));
    }
    if let Some((alias, name)) = annotation.split_once('.') {
        if let Some(NativeImport::Local(child)) = imports.get(alias) {
            return records
                .get(&(child.clone(), name.to_owned()))
                .copied()
                .map(Scalar::Record)
                .ok_or_else(|| format!("unknown native struct type {annotation}"));
        }
    }
    scalar_type(annotation)
}

impl Codegen {
    fn emit_native_call_dispatch(&mut self, module: &NativeModule) -> Result<(), String> {
        let mut callable = Vec::new();
        for statement in &module.statements {
            let StmtKind::Function(name, params, Some(result), _) = &statement.kind else {
                continue;
            };
            if name.starts_with("__galeikan_method_") {
                continue;
            }
            let result_kind = self.type_name(&module.path, result)?;
            let Some(result_tag) = native_call_tag(result_kind) else {
                continue;
            };
            let mut parameter_kinds = Vec::with_capacity(params.len());
            for param in params {
                let Some(annotation) = &param.annotation else {
                    break;
                };
                let kind = self.type_name(&module.path, annotation)?;
                if matches!(kind, Scalar::Source | Scalar::Observation)
                    || native_call_tag(kind).is_none()
                {
                    break;
                }
                parameter_kinds.push(kind);
            }
            if parameter_kinds.len() == params.len() {
                callable.push((name.clone(), parameter_kinds, result_kind, result_tag));
            }
        }

        let done = self.label();
        let next_call = self.label();
        let retry = self.label();
        writeln!(
            self.code,
            "    cmp BYTE PTR [rip+gak_native_call_mode], 0\n    je {done}\n{next_call}:\ngak_native_call_dispatch:\n    mov BYTE PTR [rip+gak_native_call_dispatch_active], 1"
        )
        .unwrap();
        if !callable.is_empty() {
            self.code.push_str("    call gak_native_call_function\n");
            let name_slot = self.reserve_slot()?;
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", name_slot * 8).unwrap();
            for (name, param_kinds, result_kind, result_tag) in callable {
                let checkpoint = (
                    self.code.len(),
                    self.data.len(),
                    self.labels,
                    self.slots,
                    self.active_module.clone(),
                    self.active_calls.clone(),
                    self.active_frames.clone(),
                    self.return_contexts.clone(),
                    self.loop_targets.clone(),
                    self.error_prefixes.clone(),
                    self.uses_file_read,
                    self.uses_python,
                    self.uses_process,
                    self.uses_net,
                    self.uses_text,
                    self.uses_formats,
                );
                let compiled = (|| -> Result<(), String> {
                    let next = self.label();
                    let boxed_name = self.literal(&name)?;
                    writeln!(
                    self.code,
                    "    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{boxed_name}+8]\n    call strcmp\n    test eax, eax\n    jne {next}",
                    self.arg0(),
                    name_slot * 8,
                    self.arg1()
                )
                .unwrap();
                    writeln!(
                        self.code,
                        "    mov {}, {}\n    call gak_native_call_expect_arity\n    call gak_native_call_error_pending\n    test eax, eax\n    jnz {retry}",
                        self.arg0(),
                        param_kinds.len()
                    )
                    .unwrap();
                    let mut scope = self.root_scope.clone();
                    let mut arguments = Vec::with_capacity(param_kinds.len());
                    for (index, kind) in param_kinds.iter().copied().enumerate() {
                        writeln!(
                            self.code,
                            "    mov {}, {}\n    mov {}, {}\n    call gak_native_call_arg",
                            self.arg0(),
                            index,
                            self.arg1(),
                            native_call_tag(kind).unwrap()
                        )
                        .unwrap();
                        let slot = self.reserve_slot()?;
                        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    call gak_native_call_error_pending\n    test eax, eax\n    jnz {retry}", slot * 8).unwrap();
                        let temporary = format!("__galeikan_native_call_arg_{slot}");
                        scope.insert(
                            temporary.clone(),
                            Binding {
                                slot,
                                kind,
                                mutable: false,
                            },
                        );
                        arguments.push(Expr {
                            kind: ExprKind::Var(temporary),
                            line: 0,
                            col: 0,
                        });
                    }
                    let actual = self.function_call_resolved(
                        (module.path.clone(), name.clone()),
                        &name,
                        &arguments,
                        &scope,
                    )?;
                    if !result_kind.accepts(actual) {
                        return Err(format!(
                            "native callable {name} has an incompatible return type"
                        ));
                    }
                    writeln!(
                    self.code,
                    "    mov {}, rax\n    mov {}, {result_tag}\n    call gak_native_call_result\n    jmp {retry}\n{next}:",
                    self.arg1(),
                    self.arg0()
                )
                .unwrap();
                    Ok(())
                })();
                if compiled.is_err() {
                    self.code.truncate(checkpoint.0);
                    self.data.truncate(checkpoint.1);
                    self.labels = checkpoint.2;
                    self.slots = checkpoint.3;
                    self.active_module = checkpoint.4;
                    self.active_calls = checkpoint.5;
                    self.active_frames = checkpoint.6;
                    self.return_contexts = checkpoint.7;
                    self.loop_targets = checkpoint.8;
                    self.error_prefixes = checkpoint.9;
                    self.uses_file_read = checkpoint.10;
                    self.uses_python = checkpoint.11;
                    self.uses_process = checkpoint.12;
                    self.uses_net = checkpoint.13;
                    self.uses_text = checkpoint.14;
                    self.uses_formats = checkpoint.15;
                }
            }
        }
        writeln!(self.code, "    call gak_native_call_unknown\n{retry}:\n    call gak_native_call_next\n    test eax, eax\n    jnz {next_call}\n{done}:\n    mov BYTE PTR [rip+gak_native_call_dispatch_active], 0").unwrap();
        self.ensure_size()
    }

    fn type_name(&self, module: &Path, annotation: &str) -> Result<Scalar, String> {
        native_type(
            annotation,
            module,
            self.module_imports
                .get(module)
                .ok_or("native module imports unavailable")?,
            &self.record_lookup,
        )
    }

    fn field(&mut self, kind: Scalar, name: &str) -> Result<Scalar, String> {
        let Scalar::Record(id) = kind else {
            return Err(format!("field {name} needs a struct value"));
        };
        let record = self.records.get(&id).ok_or("unknown native struct type")?;
        let (index, (_, field_type)) = record
            .fields
            .iter()
            .enumerate()
            .find(|(_, (field, _))| field == name)
            .ok_or_else(|| format!("unknown field {name} on struct {}", record.name))?;
        writeln!(self.code, "    mov rax, QWORD PTR [rax+{}]", index * 8).unwrap();
        Ok(*field_type)
    }

    fn imported_module(&self, alias: &str) -> Result<PathBuf, String> {
        match self
            .module_imports
            .get(&self.active_module)
            .and_then(|imports| imports.get(alias))
        {
            Some(NativeImport::Local(path)) => Ok(path.clone()),
            Some(NativeImport::Python(_, _)) => {
                Err("Python functions need a declared scalar result type in native code".into())
            }
            Some(NativeImport::Process) => {
                Err("std.process functions must be called directly".into())
            }
            Some(NativeImport::Net) => Err("std.net functions must be called directly".into()),
            Some(NativeImport::Iter) => {
                Err("std.iter.range is available natively only as a for iterable".into())
            }
            Some(NativeImport::Cli) => Err("std.cli functions must be called directly".into()),
            Some(NativeImport::List) => Err("std.list functions must be called directly".into()),
            Some(NativeImport::Result) => {
                Err("std.result functions must be called directly".into())
            }
            Some(NativeImport::Bytes) => Err("std.bytes functions must be called directly".into()),
            Some(NativeImport::Text) => Err("std.text functions must be called directly".into()),
            Some(NativeImport::Binary) => {
                Err("std.binary functions must be called directly".into())
            }
            Some(NativeImport::Formats) => {
                Err("std.formats functions must be called directly".into())
            }
            None => Err(format!("unknown native module {alias}")),
        }
    }

    fn ensure_size(&self) -> Result<(), String> {
        if self.code.len() + self.data.len() > MAX_NATIVE_CODE {
            Err("native generated code exceeds 16 MiB".into())
        } else {
            Ok(())
        }
    }

    fn reserve_slot(&mut self) -> Result<usize, String> {
        if self.slots >= MAX_SLOTS {
            return Err(format!("native program exceeds {MAX_SLOTS} stack slots"));
        }
        self.slots += 1;
        Ok(self.slots)
    }

    fn tick(&mut self) {
        self.code.push_str("    mov r11, QWORD PTR [rip+gak_steps]\n    inc r11\n    cmp r11, 1000000\n    ja gak_limit\n    mov QWORD PTR [rip+gak_steps], r11\n");
    }

    fn label(&mut self) -> String {
        self.labels += 1;
        format!("gak_label_{}", self.labels)
    }

    fn literal(&mut self, value: &str) -> Result<String, String> {
        let label = self.label();
        writeln!(self.data, ".align 8\n{label}: .quad {}", value.len()).unwrap();
        write!(self.data, "    .byte ").unwrap();
        for byte in value.bytes() {
            write!(self.data, "{byte},").unwrap();
        }
        writeln!(self.data, "0").unwrap();
        Ok(label)
    }

    fn arg0(&self) -> &'static str {
        if self.windows {
            "rcx"
        } else {
            "rdi"
        }
    }

    fn arg1(&self) -> &'static str {
        if self.windows {
            "rdx"
        } else {
            "rsi"
        }
    }

    fn arg2(&self) -> &'static str {
        if self.windows {
            "r8"
        } else {
            "rdx"
        }
    }

    fn arg3(&self) -> &'static str {
        if self.windows {
            "r9"
        } else {
            "rcx"
        }
    }

    fn python_import(&self, name: &str) -> Option<(PathBuf, String, String)> {
        let (alias, function) = name.split_once('.')?;
        let NativeImport::Python(path, digest) =
            self.module_imports.get(&self.active_module)?.get(alias)?
        else {
            return None;
        };
        Some((path.clone(), digest.clone(), function.to_owned()))
    }

    fn python_kind(kind: Scalar) -> Result<u64, String> {
        match kind {
            Scalar::Int => Ok(1),
            Scalar::UInt => Ok(2),
            Scalar::Bool => Ok(3),
            Scalar::Str => Ok(4),
            Scalar::Bytes => Ok(5),
            Scalar::ListInt => Ok(6),
            Scalar::ListUInt => Ok(7),
            Scalar::ListBool => Ok(8),
            Scalar::ListStr => Ok(9),
            Scalar::ListBytes => Ok(10),
            _ => Err("native Python calls support scalar values and homogeneous lists of i64, u64, bool, str, or bytes".into()),
        }
    }

    fn python_check(&mut self) {
        let ready = self.label();
        writeln!(self.code, "    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_python_error]\n    jmp gak_python_error_dynamic\n{ready}:").unwrap();
    }

    fn python_call(
        &mut self,
        path: &Path,
        digest: &str,
        function: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
        expected: Scalar,
        get_value: bool,
    ) -> Result<Scalar, String> {
        let tag = Self::python_kind(expected)?;
        if args.len() > 64 {
            return Err("native Python call exceeds 64 arguments".into());
        }
        self.uses_python = true;
        let module_path = native_python_module_path(&self.root_module, path)?;
        let module_label = self.literal(&module_path)?;
        let digest_label = self.literal(digest)?;
        let function_label = self.literal(function)?;
        let request_slot = self.reserve_slot()?;
        writeln!(self.code, "    lea {}, [rip+{module_label}]", self.arg0()).unwrap();
        writeln!(self.code, "    lea {}, [rip+{digest_label}]", self.arg1()).unwrap();
        writeln!(self.code, "    lea {}, [rip+{function_label}]", self.arg2()).unwrap();
        writeln!(self.code, "    mov {}, {tag}", self.arg3()).unwrap();
        self.code.push_str(if get_value {
            "    call gak_python_request_get\n"
        } else {
            "    call gak_python_request_new\n"
        });
        self.python_check();
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax",
            request_slot * 8
        )
        .unwrap();
        for arg in args {
            let kind = self.expr(arg, scope)?;
            let arg_tag = Self::python_kind(kind)?;
            writeln!(self.code, "    mov {}, rax", self.arg2()).unwrap();
            writeln!(
                self.code,
                "    mov {}, QWORD PTR [rbp-{}]",
                self.arg0(),
                request_slot * 8
            )
            .unwrap();
            writeln!(self.code, "    mov {}, {arg_tag}", self.arg1()).unwrap();
            self.code.push_str("    call gak_python_request_arg\n");
            self.python_check();
        }
        writeln!(
            self.code,
            "    mov {}, QWORD PTR [rbp-{}]",
            self.arg0(),
            request_slot * 8
        )
        .unwrap();
        self.code.push_str("    call gak_native_python_call\n");
        self.python_check();
        self.code.push_str("    mov rax, QWORD PTR [rax+8]\n");
        Ok(expected)
    }

    fn expr_expected(
        &mut self,
        expr: &Expr,
        scope: &HashMap<String, Binding>,
        expected: Option<Scalar>,
    ) -> Result<Scalar, String> {
        if let Some(expected) = expected {
            match &expr.kind {
                ExprKind::Call(name, args) => {
                    if let Some((path, digest, function)) = self.python_import(name) {
                        return self
                            .python_call(&path, &digest, &function, args, scope, expected, false);
                    }
                }
                ExprKind::Var(name) => {
                    if let Some((path, digest, function)) = self.python_import(name) {
                        return self.python_call(
                            &path,
                            &digest,
                            &function,
                            &[],
                            scope,
                            expected,
                            true,
                        );
                    }
                }
                _ => {}
            }
        }
        self.expr(expr, scope)
    }

    fn binding(
        &mut self,
        name: &str,
        annotation: Option<&str>,
        expr: &Expr,
        mutable: bool,
        scope: &mut HashMap<String, Binding>,
    ) -> Result<(), String> {
        let expected = annotation
            .map(|annotation| self.type_name(&self.active_module, annotation))
            .transpose()?;
        let mut kind = self.expr_expected(expr, scope, expected)?;
        if let Some(annotation) = annotation {
            let expected = expected.unwrap();
            if !expected.accepts(kind) {
                return Err(format!("binding {name} expects {annotation}"));
            }
            kind = expected;
        }
        let slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
        scope.insert(
            name.into(),
            Binding {
                slot,
                kind,
                mutable,
            },
        );
        Ok(())
    }

    fn assign(
        &mut self,
        name: &str,
        expr: &Expr,
        scope: &HashMap<String, Binding>,
    ) -> Result<(), String> {
        let binding = scope
            .get(name)
            .ok_or_else(|| format!("unknown native binding {name}"))?;
        if !binding.mutable {
            return Err(format!("cannot assign to immutable binding {name}"));
        }
        let kind = self.expr_expected(expr, scope, Some(binding.kind))?;
        if !binding.kind.accepts(kind) {
            return Err(format!("assignment to {name} changes type"));
        }
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax",
            binding.slot * 8
        )
        .unwrap();
        Ok(())
    }

    fn print(&mut self, expr: &Expr, scope: &HashMap<String, Binding>) -> Result<(), String> {
        let kind = self.expr(expr, scope)?;
        self.print_value(kind, 0)?;
        self.write_const("\n")
    }

    fn impact(&mut self, expr: &Expr, scope: &HashMap<String, Binding>) -> Result<(), String> {
        let kind = self.expr(expr, scope)?;
        match kind {
            Scalar::Observation => self.print_impact_observation()?,
            Scalar::Diff => self.print_impact_diff()?,
            _ => return Err("impact expects Observation or Diff in native programs".into()),
        }
        self.write_const("\n")
    }

    fn print_impact_source_fields(
        &mut self,
        source_slot: usize,
        depth: usize,
        label_name: &str,
        origin_name: &str,
        sha_name: &str,
        size_name: Option<&str>,
    ) -> Result<(), String> {
        self.write_const(&format!("{label_name}: \""))?;
        self.print_source_label(source_slot, depth)?;
        self.write_const(&format!("\", {origin_name}: \""))?;
        self.print_source_origin(source_slot, depth)?;
        self.write_const(&format!("\", {sha_name}: "))?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+40]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        if let Some(size_name) = size_name {
            self.write_const(&format!(", {size_name}: "))?;
            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+24]\n    sub rax, QWORD PTR [r10+16]", source_slot * 8).unwrap();
            self.print_value(Scalar::UInt, depth)?;
        }
        Ok(())
    }

    fn print_impact_observation(&mut self) -> Result<(), String> {
        let observation_slot = self.reserve_slot()?;
        let source_slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov QWORD PTR [rbp-{}], r10", observation_slot * 8, source_slot * 8).unwrap();
        self.write_const("impact { ")?;
        self.print_impact_source_fields(source_slot, 0, "source", "origin", "sha256", None)?;
        self.write_const(", range: [")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+8]",
            observation_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, 0)?;
        self.write_const("..")?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+8]\n    add rax, QWORD PTR [r10+16]", observation_slot * 8).unwrap();
        self.print_value(Scalar::UInt, 0)?;
        self.write_const("), decoder: ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+24]",
            observation_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, 0)?;
        self.write_const(", value: ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+32]",
            observation_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, 0)?;
        self.write_const(" }")
    }

    fn print_impact_diff(&mut self) -> Result<(), String> {
        let diff_slot = self.reserve_slot()?;
        let source_slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov QWORD PTR [rbp-{}], r10", diff_slot * 8, source_slot * 8).unwrap();
        self.write_const("impact { ")?;
        self.print_impact_source_fields(
            source_slot,
            0,
            "left",
            "left_origin",
            "left_sha256",
            Some("left_size"),
        )?;
        self.write_const(", ")?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r10+8]\n    mov QWORD PTR [rbp-{}], r10", diff_slot * 8, source_slot * 8).unwrap();
        self.print_impact_source_fields(
            source_slot,
            0,
            "right",
            "right_origin",
            "right_sha256",
            Some("right_size"),
        )?;
        self.write_const(", offsets: ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+16]",
            diff_slot * 8
        )
        .unwrap();
        self.print_offsets(0)?;
        self.write_const(" }")
    }

    fn write_const(&mut self, value: &str) -> Result<(), String> {
        let label = self.literal(value)?;
        writeln!(
            self.code,
            "    lea rax, [rip+{label}+8]\n    mov edx, {}\n    call gak_write_span",
            value.len()
        )
        .unwrap();
        Ok(())
    }

    fn print_value(&mut self, kind: Scalar, depth: usize) -> Result<(), String> {
        if depth > 32 {
            return Err("native printable type nesting exceeds 32 levels".into());
        }
        match kind {
            Scalar::Int | Scalar::UInt => {
                let format = if kind == Scalar::Int {
                    "gak_int_inner_fmt"
                } else {
                    "gak_uint_inner_fmt"
                };
                writeln!(self.code, "    mov {}, rax", self.arg1()).unwrap();
                writeln!(self.code, "    lea {}, [rip+{format}]", self.arg0()).unwrap();
                if !self.windows {
                    self.code.push_str("    xor eax, eax\n");
                }
                self.code.push_str("    call printf\n");
            }
            Scalar::Bool => {
                let is_false = self.label();
                let done = self.label();
                writeln!(self.code, "    test rax, rax\n    jz {is_false}").unwrap();
                self.write_const("true")?;
                writeln!(self.code, "    jmp {done}\n{is_false}:").unwrap();
                self.write_const("false")?;
                writeln!(self.code, "{done}:").unwrap();
            }
            Scalar::Str => {
                self.code.push_str(
                    "    mov rdx, QWORD PTR [rax]\n    lea rax, [rax+8]\n    call gak_write_span\n",
                );
            }
            Scalar::Bytes => self.print_bytes(depth + 1)?,
            Scalar::Source => self.print_source(depth + 1)?,
            Scalar::Format => self.print_format(depth + 1)?,
            Scalar::Section => self.print_section(depth + 1)?,
            Scalar::Observation => self.print_observation(depth + 1)?,
            Scalar::Offsets => self.print_offsets(depth + 1)?,
            Scalar::Regions => {
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                self.write_const("regions(count: ")?;
                writeln!(
                    self.code,
                    "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10]",
                    slot * 8
                )
                .unwrap();
                self.print_value(Scalar::Int, depth + 1)?;
                self.write_const(")")?;
            }
            Scalar::Region => self.print_region(depth + 1)?,
            Scalar::Diff => self.print_diff(depth + 1)?,
            Scalar::Record(id) => {
                let record = self
                    .records
                    .get(&id)
                    .cloned()
                    .ok_or("unknown native struct type")?;
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                self.write_const(&format!("{}(", record.name))?;
                for (index, (name, field)) in record.fields.iter().enumerate() {
                    if index != 0 {
                        self.write_const(", ")?;
                    }
                    self.write_const(&format!("{name}: "))?;
                    writeln!(
                        self.code,
                        "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+{}]",
                        slot * 8,
                        index * 8
                    )
                    .unwrap();
                    self.print_value(*field, depth + 1)?;
                }
                self.write_const(")")?;
            }
            Scalar::ListEmpty => self.write_const("[]")?,
            Scalar::Result(value) => self.print_result(value, depth + 1)?,
            list => {
                let element = list.element().ok_or("native value has no printable type")?;
                self.print_list(element, depth + 1)?;
            }
        }
        Ok(())
    }

    fn print_region(&mut self, depth: usize) -> Result<(), String> {
        let slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
        self.write_const("region(pid: ")?;
        for (offset, prefix, kind) in [
            (0, "", Scalar::Int),
            (8, ", start: 0x", Scalar::UInt),
            (16, ", size: ", Scalar::Int),
            (24, ", access: ", Scalar::Str),
            (32, ", label: \"", Scalar::Str),
            (40, "\", image_backed: ", Scalar::Bool),
        ] {
            self.write_const(prefix)?;
            writeln!(
                self.code,
                "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+{offset}]",
                slot * 8
            )
            .unwrap();
            if offset == 8 {
                let format = self.literal("%llx")?;
                writeln!(
                    self.code,
                    "    mov {}, rax\n    lea {}, [rip+{format}+8]",
                    self.arg1(),
                    self.arg0()
                )
                .unwrap();
                if !self.windows {
                    self.code.push_str("    xor eax, eax\n");
                }
                self.code.push_str("    call printf\n");
            } else {
                if offset == 32 {
                    writeln!(
                        self.code,
                        "    mov {}, QWORD PTR [rbp-{}]\n    call gak_native_region_escaped_label",
                        self.arg0(),
                        slot * 8
                    )
                    .unwrap();
                    self.process_checked_result();
                    self.uses_process = true;
                }
                self.print_value(kind, depth + 1)?;
            }
        }
        self.write_const(")")
    }

    fn print_list(&mut self, element: Scalar, depth: usize) -> Result<(), String> {
        let list_slot = self.reserve_slot()?;
        let index_slot = self.reserve_slot()?;
        let start = self.label();
        let no_separator = self.label();
        let truncated = self.label();
        let end = self.label();
        let done = self.label();
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax\n    mov QWORD PTR [rbp-{}], 0",
            list_slot * 8,
            index_slot * 8
        )
        .unwrap();
        self.write_const("[")?;
        writeln!(self.code, "{start}:\n    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [r10]\n    mov rax, QWORD PTR [rbp-{}]\n    cmp rax, r11\n    jae {end}\n    cmp rax, 16\n    jae {truncated}\n    test rax, rax\n    jz {no_separator}", list_slot * 8, index_slot * 8).unwrap();
        self.write_const(", ")?;
        writeln!(self.code, "{no_separator}:\n    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+r11*8+8]", list_slot * 8, index_slot * 8).unwrap();
        self.print_value(element, depth)?;
        writeln!(
            self.code,
            "    add QWORD PTR [rbp-{}], 1\n    jmp {start}\n{truncated}:",
            index_slot * 8
        )
        .unwrap();
        self.write_const(", ...")?;
        writeln!(self.code, "{end}:").unwrap();
        self.write_const("]")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    cmp QWORD PTR [r10], 16\n    jbe {done}",
            list_slot * 8
        )
        .unwrap();
        self.write_const(" (")?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10]\n    mov {}, rax\n    lea {}, [rip+gak_uint_inner_fmt]", list_slot * 8, self.arg1(), self.arg0()).unwrap();
        if !self.windows {
            self.code.push_str("    xor eax, eax\n");
        }
        self.code.push_str("    call printf\n");
        self.write_const(" items)")?;
        writeln!(self.code, "{done}:").unwrap();
        Ok(())
    }

    fn print_offsets(&mut self, depth: usize) -> Result<(), String> {
        let offsets_slot = self.reserve_slot()?;
        let index_slot = self.reserve_slot()?;
        let start = self.label();
        let no_separator = self.label();
        let end = self.label();
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax\n    mov QWORD PTR [rbp-{}], 0",
            offsets_slot * 8,
            index_slot * 8
        )
        .unwrap();
        self.write_const("[")?;
        writeln!(self.code, "{start}:\n    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [rbp-{}]\n    cmp r11, QWORD PTR [r10]\n    jae {end}\n    test r11, r11\n    jz {no_separator}", offsets_slot * 8, index_slot * 8).unwrap();
        self.write_const(", ")?;
        writeln!(self.code, "{no_separator}:\n    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+r11*8+8]", offsets_slot * 8, index_slot * 8).unwrap();
        self.print_value(Scalar::Int, depth)?;
        writeln!(
            self.code,
            "    add QWORD PTR [rbp-{}], 1\n    jmp {start}\n{end}:",
            index_slot * 8
        )
        .unwrap();
        self.write_const("]")
    }

    fn print_diff(&mut self, depth: usize) -> Result<(), String> {
        let diff_slot = self.reserve_slot()?;
        let source_slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", diff_slot * 8).unwrap();
        self.write_const("diff(")?;
        for (index, offset) in [0, 8].into_iter().enumerate() {
            if index != 0 {
                self.write_const(", ")?;
            }
            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r10+{offset}]\n    mov QWORD PTR [rbp-{}], r10", diff_slot * 8, source_slot * 8).unwrap();
            self.write_const("\"")?;
            self.print_source_label(source_slot, depth)?;
            self.write_const("\" [sha256:")?;
            writeln!(
                self.code,
                "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+40]",
                source_slot * 8
            )
            .unwrap();
            self.print_value(Scalar::Str, depth)?;
            self.write_const("; ")?;
            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+24]\n    sub rax, QWORD PTR [r10+16]", source_slot * 8).unwrap();
            self.print_value(Scalar::UInt, depth)?;
            self.write_const(" bytes]")?;
        }
        self.write_const(", offsets: ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+16]",
            diff_slot * 8
        )
        .unwrap();
        self.print_offsets(depth)?;
        self.write_const(")")
    }

    fn source_sha256(&mut self) {
        self.code.push_str("    mov rax, QWORD PTR [rax+40]\n");
    }

    fn print_source_address(&mut self, source_slot: usize, origin: bool) -> Result<(), String> {
        let absent = self.label();
        let elf = self.label();
        let printed_prefix = self.label();
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [r10+96]\n    test r11, r11\n    jz {absent}\n    cmp r11, 2\n    je {elf}", source_slot * 8).unwrap();
        self.write_const(if origin { "PE RVA 0x" } else { " @ PE RVA 0x" })?;
        writeln!(self.code, "    jmp {printed_prefix}\n{elf}:").unwrap();
        self.write_const(if origin { "ELF VA 0x" } else { " @ ELF VA 0x" })?;
        writeln!(
            self.code,
            "{printed_prefix}:\n    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+104]",
            source_slot * 8
        )
        .unwrap();
        let format = self.literal("%llx")?;
        writeln!(
            self.code,
            "    mov {}, rax\n    lea {}, [rip+{format}+8]",
            self.arg1(),
            self.arg0()
        )
        .unwrap();
        if !self.windows {
            self.code.push_str("    xor eax, eax\n");
        }
        self.code.push_str("    call printf\n");
        if origin {
            self.write_const("; ")?;
        }
        writeln!(self.code, "{absent}:").unwrap();
        Ok(())
    }

    fn print_source_label(&mut self, source_slot: usize, depth: usize) -> Result<(), String> {
        let child_slot = self.reserve_slot()?;
        let index_slot = self.reserve_slot()?;
        let mut chain_base = 0;
        for _ in 0..65 {
            chain_base = self.reserve_slot()?;
        }
        let walk = self.label();
        let suffix = self.label();
        let label_done = self.label();
        let range = self.label();
        let patch = self.label();
        let splice = self.label();
        let suffix_done = self.label();
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    xor ecx, ecx\n    lea r11, [rbp-{}]\n{walk}:\n    cmp ecx, 65\n    jae gak_source_depth\n    mov QWORD PTR [r11+rcx*8], r10\n    inc ecx\n    mov r10, QWORD PTR [r10+8]\n    test r10, r10\n    jnz {walk}\n    sub ecx, 2\n    movsxd rcx, ecx\n    mov QWORD PTR [rbp-{}], rcx\n    mov rax, QWORD PTR [r11+rcx*8+8]\n    mov rax, QWORD PTR [rax+80]", source_slot * 8, chain_base * 8, index_slot * 8).unwrap();
        self.print_value(Scalar::Str, depth)?;
        writeln!(self.code, "{suffix}:\n    mov rcx, QWORD PTR [rbp-{}]\n    test rcx, rcx\n    js {label_done}\n    lea r11, [rbp-{}]\n    mov r10, QWORD PTR [r11+rcx*8]\n    mov QWORD PTR [rbp-{}], r10\n    cmp QWORD PTR [r10+48], 2\n    je {patch}\n    cmp QWORD PTR [r10+48], 3\n    je {splice}\n    jmp {range}\n{patch}:", index_slot * 8, chain_base * 8, child_slot * 8).unwrap();
        self.write_const(" patched")?;
        writeln!(self.code, "    jmp {range}\n{splice}:").unwrap();
        self.write_const(" spliced")?;
        writeln!(self.code, "{range}:").unwrap();
        self.write_const("[")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+56]",
            child_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const("..")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+64]",
            child_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(")")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    cmp QWORD PTR [r10+48], 3\n    jne {suffix_done}",
            child_slot * 8
        )
        .unwrap();
        self.write_const("->")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+72]",
            child_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        writeln!(self.code, "{suffix_done}:").unwrap();
        self.print_source_address(child_slot, false)?;
        writeln!(
            self.code,
            "    sub QWORD PTR [rbp-{}], 1\n    jmp {suffix}\n{label_done}:",
            index_slot * 8
        )
        .unwrap();
        Ok(())
    }

    fn print_source(&mut self, depth: usize) -> Result<(), String> {
        let source_slot = self.reserve_slot()?;
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax",
            source_slot * 8
        )
        .unwrap();
        self.write_const("source(\"")?;
        self.print_source_label(source_slot, depth)?;
        self.write_const("\", origin: \"")?;
        self.print_source_origin(source_slot, depth)?;
        self.write_const("\", sha256: ")?;
        writeln!(
            self.code,
            "    mov rax, QWORD PTR [rbp-{}]",
            source_slot * 8
        )
        .unwrap();
        self.source_sha256();
        self.print_value(Scalar::Str, depth)?;
        self.write_const(", ")?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+24]\n    sub rax, QWORD PTR [r10+16]", source_slot * 8).unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(" bytes)")
    }

    fn print_format(&mut self, depth: usize) -> Result<(), String> {
        let format_slot = self.reserve_slot()?;
        let source_slot = self.reserve_slot()?;
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov QWORD PTR [rbp-{}], r10",
            format_slot * 8,
            source_slot * 8
        )
        .unwrap();
        self.print_source_label(source_slot, depth)?;
        self.write_const(" [sha256:")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+40]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        self.write_const("] ")?;
        let ready = self.label();
        writeln!(
            self.code,
            "    mov {}, QWORD PTR [rbp-{}]\n    call gak_native_formats_summary\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:",
            self.arg0(),
            format_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)
    }

    fn print_hex_u64(&mut self) -> Result<(), String> {
        let format = self.literal("%llx")?;
        writeln!(
            self.code,
            "    mov {}, rax\n    lea {}, [rip+{format}+8]",
            self.arg1(),
            self.arg0()
        )
        .unwrap();
        if !self.windows {
            self.code.push_str("    xor eax, eax\n");
        }
        self.code.push_str("    call printf\n");
        Ok(())
    }

    fn print_section(&mut self, depth: usize) -> Result<(), String> {
        let section_slot = self.reserve_slot()?;
        let source_slot = self.reserve_slot()?;
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov QWORD PTR [rbp-{}], r10",
            section_slot * 8,
            source_slot * 8
        )
        .unwrap();
        self.write_const("section(\"")?;
        let ready = self.label();
        writeln!(
            self.code,
            "    mov {}, QWORD PTR [rbp-{}]\n    call gak_native_formats_section_display_name\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:",
            self.arg0(),
            section_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        self.write_const("\", file=[")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+16]",
            section_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const("..")?;
        let no_overflow = self.label();
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+16]\n    add rax, QWORD PTR [r10+24]\n    jnc {no_overflow}\n    mov rax, -1\n{no_overflow}:",
            section_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const("), va=0x")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+32]",
            section_slot * 8
        )
        .unwrap();
        self.print_hex_u64()?;
        self.write_const(", virtual_size=")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+40]",
            section_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(", flags=0x")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+48]",
            section_slot * 8
        )
        .unwrap();
        self.print_hex_u64()?;
        for (offset, prefix) in [(56, ", writable="), (64, ", executable=")] {
            self.write_const(prefix)?;
            writeln!(
                self.code,
                "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+{offset}]",
                section_slot * 8
            )
            .unwrap();
            self.print_value(Scalar::Bool, depth)?;
        }
        self.write_const(", source_sha256:")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+40]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        self.write_const(")")
    }

    fn print_source_origin(&mut self, source_slot: usize, depth: usize) -> Result<(), String> {
        self.print_source_address(source_slot, true)?;
        let view_origin = self.label();
        let patch_origin = self.label();
        let splice_origin = self.label();
        let print_parent_sha = self.label();
        let origin_suffix = self.label();
        let origin_done = self.label();
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    cmp QWORD PTR [r10+8], 0\n    je {origin_done}_root\n    cmp QWORD PTR [r10+48], 2\n    je {patch_origin}\n    cmp QWORD PTR [r10+48], 3\n    je {splice_origin}\n    jmp {view_origin}", source_slot * 8)
        .unwrap();
        writeln!(self.code, "{origin_done}_root:").unwrap();
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+88]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        writeln!(self.code, "    jmp {origin_done}\n{patch_origin}:").unwrap();
        self.write_const("patch of sha256:")?;
        writeln!(self.code, "    jmp {print_parent_sha}\n{view_origin}:").unwrap();
        self.write_const("view of sha256:")?;
        writeln!(self.code, "    jmp {print_parent_sha}\n{splice_origin}:").unwrap();
        self.write_const("splice of sha256:")?;
        writeln!(self.code, "{print_parent_sha}:").unwrap();
        writeln!(
            self.code,
            "    mov rax, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [rax+8]",
            source_slot * 8
        )
        .unwrap();
        self.source_sha256();
        self.print_value(Scalar::Str, depth)?;
        self.write_const(" [")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+56]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const("..")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+64]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(")")?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    cmp QWORD PTR [r10+48], 3\n    jne {origin_suffix}", source_slot * 8).unwrap();
        self.write_const(" -> ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+72]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(" bytes")?;
        writeln!(self.code, "{origin_suffix}:").unwrap();
        writeln!(self.code, "{origin_done}:").unwrap();
        Ok(())
    }

    fn print_observation(&mut self, depth: usize) -> Result<(), String> {
        let observation_slot = self.reserve_slot()?;
        let source_slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov QWORD PTR [rbp-{}], r10", observation_slot * 8, source_slot * 8).unwrap();
        self.print_source_label(source_slot, depth)?;
        self.write_const(" @ [")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+8]",
            observation_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const("..")?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+8]\n    add rax, QWORD PTR [r10+16]", observation_slot * 8).unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(") ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+24]",
            observation_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        self.write_const(" = ")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+32]",
            observation_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(" [sha256:")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10+40]",
            source_slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        self.write_const("]")
    }

    fn print_bytes(&mut self, depth: usize) -> Result<(), String> {
        let slot = self.reserve_slot()?;
        let ready = self.label();
        let done = self.label();
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
        self.write_const("bytes(")?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10]",
            slot * 8
        )
        .unwrap();
        self.print_value(Scalar::UInt, depth)?;
        self.write_const(" bytes, hex:")?;
        writeln!(self.code, "    mov rax, QWORD PTR [rbp-{}]\n    mov rdx, QWORD PTR [rax]\n    cmp rdx, 64\n    jbe {ready}\n    mov edx, 64\n{ready}:\n    call gak_to_hex", slot * 8).unwrap();
        self.print_value(Scalar::Str, depth)?;
        writeln!(
            self.code,
            "    mov r10, QWORD PTR [rbp-{}]\n    cmp QWORD PTR [r10], 64\n    jbe {done}",
            slot * 8
        )
        .unwrap();
        self.write_const("...")?;
        writeln!(self.code, "{done}:").unwrap();
        self.write_const(")")
    }

    fn print_result(&mut self, value: Option<ResultValue>, depth: usize) -> Result<(), String> {
        let slot = self.reserve_slot()?;
        let error = self.label();
        let suffix = self.label();
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax\n    cmp QWORD PTR [rax], 0\n    jne {error}",
            slot * 8
        )
        .unwrap();
        if let Some(value) = value {
            self.write_const("ok(")?;
            writeln!(
                self.code,
                "    mov rax, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [rax+8]",
                slot * 8
            )
            .unwrap();
            self.print_value(value.scalar(), depth)?;
        } else {
            self.code.push_str("    jmp gak_result_untyped_success\n");
        }
        writeln!(self.code, "    jmp {suffix}\n{error}:").unwrap();
        self.write_const("error(")?;
        writeln!(
            self.code,
            "    mov rax, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [rax+8]",
            slot * 8
        )
        .unwrap();
        self.print_value(Scalar::Str, depth)?;
        writeln!(self.code, "{suffix}:").unwrap();
        self.write_const(")")?;
        Ok(())
    }

    fn nested_block_steps(
        &mut self,
        body: &[BlockStmt],
        scope: &mut HashMap<String, Binding>,
    ) -> Result<(), String> {
        let parent_prefix = self
            .error_prefixes
            .pop()
            .ok_or("missing native action location")?;
        let result = body.iter().try_for_each(|step| {
            self.tick();
            self.block_step(step, scope)
        });
        self.error_prefixes.push(parent_prefix);
        result
    }

    fn while_loop(
        &mut self,
        condition: &Expr,
        body: &[BlockStmt],
        scope: &HashMap<String, Binding>,
    ) -> Result<(), String> {
        let start = self.label();
        let end = self.label();
        writeln!(self.code, "{start}:").unwrap();
        self.tick();
        if self.expr(condition, scope)? != Scalar::Bool {
            return Err("while condition must be bool".into());
        }
        self.code.push_str("    test rax, rax\n");
        writeln!(self.code, "    jz {end}").unwrap();
        self.loop_targets.push((end.clone(), start.clone()));
        let mut inner = scope.clone();
        let body_result = self.nested_block_steps(body, &mut inner);
        self.loop_targets.pop();
        body_result?;
        writeln!(self.code, "    jmp {start}\n{end}:").unwrap();
        Ok(())
    }

    fn if_statement(
        &mut self,
        condition: &Expr,
        yes: &[BlockStmt],
        no: &[BlockStmt],
        scope: &HashMap<String, Binding>,
    ) -> Result<(), String> {
        if self.expr(condition, scope)? != Scalar::Bool {
            return Err("if condition must be bool".into());
        }
        let otherwise = self.label();
        let end = self.label();
        self.code.push_str("    test rax, rax\n");
        writeln!(self.code, "    jz {otherwise}").unwrap();
        let mut yes_scope = scope.clone();
        self.nested_block_steps(yes, &mut yes_scope)?;
        writeln!(self.code, "    jmp {end}\n{otherwise}:").unwrap();
        let mut no_scope = scope.clone();
        self.nested_block_steps(no, &mut no_scope)?;
        writeln!(self.code, "{end}:").unwrap();
        Ok(())
    }

    fn for_range(
        &mut self,
        name: &str,
        iterable: &Expr,
        body: &[BlockStmt],
        scope: &HashMap<String, Binding>,
    ) -> Result<(), String> {
        let ExprKind::Call(call, args) = &iterable.kind else {
            return self.for_list(name, iterable, body, scope);
        };
        let Some((alias, function)) = call.split_once('.') else {
            return self.for_list(name, iterable, body, scope);
        };
        if function != "range"
            || !matches!(
                self.module_imports
                    .get(&self.active_module)
                    .and_then(|imports| imports.get(alias)),
                Some(NativeImport::Iter)
            )
            || !(1..=2).contains(&args.len())
        {
            return self.for_list(name, iterable, body, scope);
        }
        let index_slot = self.reserve_slot()?;
        let end_slot = self.reserve_slot()?;
        let item_slot = self.reserve_slot()?;
        if args.len() == 2 {
            if self.expr(&args[0], scope)? != Scalar::Int {
                return Err("range start must be i64".into());
            }
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", index_slot * 8).unwrap();
        } else {
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], 0", index_slot * 8).unwrap();
        }
        if self.expr(args.last().unwrap(), scope)? != Scalar::Int {
            return Err("range end must be i64".into());
        }
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", end_slot * 8).unwrap();
        let checked = self.label();
        writeln!(
            self.code,
            "    mov rax, QWORD PTR [rbp-{}]\n    test rax, rax\n    js gak_range_start\n    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_range_end\n    cmp r10, rax\n    jle {checked}\n    sub r10, rax\n    cmp r10, {MAX_RANGE_ITEMS}\n    jg gak_range_limit\n{checked}:",
            index_slot * 8,
            end_slot * 8
        )
        .unwrap();
        let start = self.label();
        let end = self.label();
        let next = self.label();
        writeln!(
            self.code,
            "{start}:\n    mov rax, QWORD PTR [rbp-{}]\n    cmp rax, QWORD PTR [rbp-{}]\n    jge {end}",
            index_slot * 8,
            end_slot * 8
        )
        .unwrap();
        self.tick();
        writeln!(
            self.code,
            "    mov rax, QWORD PTR [rbp-{}]\n    mov QWORD PTR [rbp-{}], rax",
            index_slot * 8,
            item_slot * 8
        )
        .unwrap();
        let mut inner = scope.clone();
        inner.insert(
            name.into(),
            Binding {
                slot: item_slot,
                kind: Scalar::Int,
                mutable: false,
            },
        );
        self.loop_targets.push((end.clone(), next.clone()));
        let body_result = self.nested_block_steps(body, &mut inner);
        self.loop_targets.pop();
        body_result?;
        writeln!(
            self.code,
            "{next}:\n    mov rax, QWORD PTR [rbp-{}]\n    add rax, 1\n    jo gak_overflow\n    mov QWORD PTR [rbp-{}], rax\n    jmp {start}\n{end}:",
            index_slot * 8,
            index_slot * 8
        )
        .unwrap();
        Ok(())
    }

    fn for_list(
        &mut self,
        name: &str,
        iterable: &Expr,
        body: &[BlockStmt],
        scope: &HashMap<String, Binding>,
    ) -> Result<(), String> {
        let kind = self.expr(iterable, scope)?;
        let element = if kind == Scalar::Offsets {
            Scalar::Int
        } else if kind == Scalar::Regions {
            Scalar::Region
        } else {
            kind.element()
                .ok_or("native for needs a typed List, Offsets, or std.iter.range(...) iterable")?
        };
        let list_slot = self.reserve_slot()?;
        let index_slot = self.reserve_slot()?;
        let item_slot = self.reserve_slot()?;
        writeln!(
            self.code,
            "    mov QWORD PTR [rbp-{}], rax\n    mov QWORD PTR [rbp-{}], 0",
            list_slot * 8,
            index_slot * 8
        )
        .unwrap();
        let start = self.label();
        let end = self.label();
        let next = self.label();
        writeln!(self.code, "{start}:\n    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [rbp-{}]\n    cmp rax, QWORD PTR [r10]\n    jae {end}", list_slot * 8, index_slot * 8).unwrap();
        self.tick();
        writeln!(
            self.code,
            "    mov rax, QWORD PTR [r10+rax*8+8]\n    mov QWORD PTR [rbp-{}], rax",
            item_slot * 8
        )
        .unwrap();
        let mut inner = scope.clone();
        inner.insert(
            name.into(),
            Binding {
                slot: item_slot,
                kind: element,
                mutable: false,
            },
        );
        self.loop_targets.push((end.clone(), next.clone()));
        let body_result = self.nested_block_steps(body, &mut inner);
        self.loop_targets.pop();
        body_result?;
        writeln!(
            self.code,
            "{next}:\n    add QWORD PTR [rbp-{}], 1\n    jmp {start}\n{end}:",
            index_slot * 8
        )
        .unwrap();
        Ok(())
    }

    fn block_step(
        &mut self,
        step: &BlockStmt,
        scope: &mut HashMap<String, Binding>,
    ) -> Result<(), String> {
        self.error_prefixes.push(format!(
            "{}:{}:{}: ",
            self.active_module.display(),
            step.line,
            step.col
        ));
        let start = self.code.len();
        let result = match &step.kind {
            BlockStmtKind::Let(name, annotation, expr) => {
                self.binding(name, annotation.as_deref(), expr, false, scope)
            }
            BlockStmtKind::Var(name, annotation, expr) => {
                self.binding(name, annotation.as_deref(), expr, true, scope)
            }
            BlockStmtKind::Assign(name, expr) => self.assign(name, expr, scope),
            BlockStmtKind::Print(expr) => self.print(expr, scope),
            BlockStmtKind::Impact(expr) => self.impact(expr, scope),
            BlockStmtKind::Return(expr) => {
                if self.return_contexts.is_empty() {
                    return Err(format!(
                        "{}:{}: return outside function",
                        step.line, step.col
                    ));
                }
                let expected_scalar = self.return_contexts.last().unwrap().expected_scalar;
                let kind = self.expr_expected(expr, scope, expected_scalar)?;
                let expected = self.return_contexts.last().unwrap().result_type;
                let kind = self.normalize_result_return(kind, expected)?;
                let context = self.return_contexts.last_mut().unwrap();
                context.types.push(kind);
                writeln!(self.code, "    jmp {}", context.label).unwrap();
                Ok(())
            }
            BlockStmtKind::Break | BlockStmtKind::Continue => {
                let (end, next) = self
                    .loop_targets
                    .last()
                    .ok_or("loop control outside loop")?;
                let target = if matches!(step.kind, BlockStmtKind::Break) {
                    end
                } else {
                    next
                };
                writeln!(self.code, "    jmp {target}").unwrap();
                Ok(())
            }
            BlockStmtKind::For(name, iterable, body) => self.for_range(name, iterable, body, scope),
            BlockStmtKind::While(condition, body) => self.while_loop(condition, body, scope),
            BlockStmtKind::If(condition, yes, no) => self.if_statement(condition, yes, no, scope),
        };
        if result.is_ok() {
            self.capture_runtime_errors(start)?;
        }
        self.error_prefixes.pop();
        result.map_err(|e| format!("{}:{}: {e}", step.line, step.col))?;
        self.ensure_size()
    }

    fn capture_runtime_errors(&mut self, start: usize) -> Result<(), String> {
        let handler = self
            .return_contexts
            .iter()
            .rev()
            .find(|context| context.result_type.is_some())
            .cloned();
        let mut segment = self.code[start..].to_owned();
        let mut catches = Vec::new();
        for &(target, message) in CATCHABLE_RESULT_ERRORS {
            if segment.contains(target) {
                let label = self.label();
                segment = segment.replace(target, &label);
                catches.push((label, Some(message)));
            }
        }
        for &target in DYNAMIC_RESULT_ERRORS {
            if segment.contains(target) {
                let label = self.label();
                segment = segment.replace(target, &label);
                catches.push((label, None));
            }
        }
        if catches.is_empty() {
            return Ok(());
        }
        self.code.truncate(start);
        self.code.push_str(&segment);
        let done = self.label();
        writeln!(self.code, "    jmp {done}").unwrap();
        let depth = handler.as_ref().map_or(0, |context| context.error_depth);
        let prefixes = self.error_prefixes[depth..]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        for (label, message) in catches {
            if message.is_none() {
                writeln!(
                    self.code,
                    "{label}:\n    mov edx, 1\n    call gak_alloc_result"
                )
                .unwrap();
                for prefix in &prefixes {
                    let prefix_label = self.literal(prefix)?;
                    writeln!(
                        self.code,
                        "    lea r10, [rip+{prefix_label}]\n    call gak_prefix_result"
                    )
                    .unwrap();
                }
                if let Some(context) = &handler {
                    self.restore_return_context(context);
                    writeln!(self.code, "    jmp {}", context.label).unwrap();
                } else {
                    self.code.push_str("    jmp gak_uncaught_result\n");
                }
                continue;
            }
            let message = message.expect("static runtime error has a message");
            if let Some(context) = &handler {
                let message_label = self.literal(message)?;
                writeln!(self.code, "{label}:\n    lea rax, [rip+{message_label}]\n    mov edx, 1\n    call gak_alloc_result").unwrap();
                for prefix in &prefixes {
                    let prefix_label = self.literal(prefix)?;
                    writeln!(
                        self.code,
                        "    lea r10, [rip+{prefix_label}]\n    call gak_prefix_result"
                    )
                    .unwrap();
                }
                self.restore_return_context(context);
                writeln!(self.code, "    jmp {}", context.label).unwrap();
            } else {
                let mut full = message.to_string();
                for prefix in &prefixes {
                    full.insert_str(0, prefix);
                }
                full.push('\n');
                let message_label = self.literal(&full)?;
                writeln!(self.code, "{label}:\n    lea rax, [rip+{message_label}+8]\n    mov r11, {}\n    jmp gak_error", full.len()).unwrap();
            }
        }
        writeln!(self.code, "{done}:").unwrap();
        Ok(())
    }

    fn restore_return_context(&mut self, context: &ReturnContext) {
        if let (Some(stack), Some(depth), Some(base)) =
            (context.stack_slot, context.depth_slot, context.base_slot)
        {
            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [rbp-{}]\n    mov rsp, QWORD PTR [rbp-{}]\n    mov QWORD PTR [rip+gak_call_depth], r11\n    mov rbp, r10", base * 8, depth * 8, stack * 8).unwrap();
        }
    }

    fn record_constructor(
        &mut self,
        id: u32,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        let record = self
            .records
            .get(&id)
            .cloned()
            .ok_or("unknown native struct type")?;
        if args.len() != record.fields.len() {
            return Err(format!("{name} expects {} arguments", record.fields.len()));
        }
        let mut slots = Vec::with_capacity(args.len());
        for (arg, (field, expected)) in args.iter().zip(&record.fields) {
            let actual = self.expr(arg, scope)?;
            if !expected.accepts(actual) {
                return Err(format!("{name} field {field} has the wrong type"));
            }
            let slot = self.reserve_slot()?;
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
            slots.push(slot);
        }
        let bytes = (record.fields.len() * 8).max(1);
        writeln!(
            self.code,
            "    mov r11, QWORD PTR [rip+gak_record_bytes]\n    add r11, {bytes}\n    cmp r11, 67108864\n    ja gak_record_limit\n    mov QWORD PTR [rip+gak_record_bytes], r11\n    mov {}, {bytes}\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure",
            self.arg0()
        )
        .unwrap();
        for (index, slot) in slots.iter().enumerate() {
            writeln!(
                self.code,
                "    mov r10, QWORD PTR [rbp-{}]\n    mov QWORD PTR [rax+{}], r10",
                slot * 8,
                index * 8
            )
            .unwrap();
        }
        Ok(Scalar::Record(id))
    }

    fn function_call(
        &mut self,
        name: &str,
        args: &[Expr],
        caller_scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        if let Some((alias, function)) = name.split_once('.') {
            match self
                .module_imports
                .get(&self.active_module)
                .and_then(|imports| imports.get(alias))
            {
                Some(NativeImport::Python(_, _)) => {
                    return Err("native Python calls need a declared scalar result type".into())
                }
                Some(NativeImport::Process) => {
                    return self.process_call(function, args, caller_scope)
                }
                Some(NativeImport::Net) => return self.net_call(function, args, caller_scope),
                Some(NativeImport::Cli) => return self.cli_call(function, args, caller_scope),
                Some(NativeImport::List) => return self.list_call(function, args, caller_scope),
                Some(NativeImport::Result) => {
                    return self.result_call(function, args, caller_scope)
                }
                Some(NativeImport::Bytes) => return self.bytes_call(function, args, caller_scope),
                Some(NativeImport::Text) => return self.text_call(function, args, caller_scope),
                Some(NativeImport::Binary) => {
                    return self.binary_call(function, args, caller_scope)
                }
                Some(NativeImport::Formats) => {
                    return self.formats_call(function, args, caller_scope)
                }
                _ => {}
            }
        }
        if let Some((receiver_path, method)) = name.rsplit_once('.') {
            let first = receiver_path.split('.').next().unwrap_or(receiver_path);
            let imported_value = receiver_path
                .split_once('.')
                .and_then(|(alias, path)| {
                    let NativeImport::Local(child) =
                        self.module_imports.get(&self.active_module)?.get(alias)?
                    else {
                        return None;
                    };
                    self.module_scopes
                        .get(child)?
                        .get(path.split('.').next().unwrap_or(path))
                })
                .is_some();
            if caller_scope.contains_key(first) || imported_value {
                let receiver = Expr {
                    kind: ExprKind::Var(receiver_path.to_owned()),
                    line: 0,
                    col: 0,
                };
                return self.method_call(&receiver, method, args, caller_scope);
            }
        }
        let (target_module, function_name) = if let Some((alias, function)) = name.split_once('.') {
            (self.imported_module(alias)?, function.to_string())
        } else {
            (self.active_module.clone(), name.to_string())
        };
        self.function_call_resolved((target_module, function_name), name, args, caller_scope)
    }

    fn cli_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("count", []) => {
                self.code
                    .push_str("    mov rax, QWORD PTR [rip+gak_argc]\n    sub rax, 1\n");
                Ok(Scalar::Int)
            }
            ("int" | "arg", [index]) => {
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("cli.{name} index must be i64"));
                }
                self.code.push_str("    test rax, rax\n    js gak_cli_index\n    mov r10, QWORD PTR [rip+gak_argc]\n    sub r10, 1\n    cmp rax, r10\n    jae gak_cli_index\n    add rax, 1\n");
                if self.windows {
                    self.code.push_str("    call gak_cli_utf8_arg\n");
                } else {
                    self.code.push_str("    mov r10, QWORD PTR [rip+gak_argv]\n    mov rax, QWORD PTR [r10+rax*8]\n");
                }
                if name == "int" {
                    self.code.push_str("    call gak_parse_i64\n");
                    Ok(Scalar::Int)
                } else {
                    self.code.push_str("    call gak_box_c_string\n");
                    Ok(Scalar::Str)
                }
            }
            _ => Err(format!("unknown native CLI function {name}")),
        }
    }

    fn result_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("ok", [value]) => {
                let kind = self.expr(value, scope)?;
                let value = ResultValue::from_scalar(kind)
                    .ok_or("result.ok supports scalar and struct values")?;
                self.code
                    .push_str("    xor edx, edx\n    call gak_alloc_result\n");
                Ok(Scalar::Result(Some(value)))
            }
            ("fail", [message]) => {
                if self.expr(message, scope)? != Scalar::Str {
                    return Err("result.fail message must be str".into());
                }
                self.code
                    .push_str("    call gak_check_result_message\n    test rax, rax\n    jz gak_result_invalid\n    mov edx, 1\n    call gak_alloc_result\n");
                Ok(Scalar::Result(None))
            }
            ("is_ok" | "is_error" | "message", [result]) => {
                if !matches!(self.expr(result, scope)?, Scalar::Result(_)) {
                    return Err(format!("result.{name} expects Result<T>"));
                }
                match name {
                    "is_ok" => self.code.push_str(
                        "    cmp QWORD PTR [rax], 0\n    sete al\n    movzx eax, al\n",
                    ),
                    "is_error" => self.code.push_str(
                        "    cmp QWORD PTR [rax], 0\n    setne al\n    movzx eax, al\n",
                    ),
                    _ => self.code.push_str("    cmp QWORD PTR [rax], 1\n    jne gak_result_message_success\n    mov rax, QWORD PTR [rax+8]\n"),
                }
                Ok(if name == "message" {
                    Scalar::Str
                } else {
                    Scalar::Bool
                })
            }
            ("recover", [result, fallback]) => {
                let kind = self.expr(result, scope)?;
                let Scalar::Result(inner) = kind else {
                    return Err("result.recover expects Result<T>".into());
                };
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                let fallback_kind = self.expr(fallback, scope)?;
                let output = if let Some(inner) = inner {
                    let output = inner.scalar();
                    if !output.accepts(fallback_kind) {
                        return Err("result.recover fallback has the wrong type".into());
                    }
                    output
                } else {
                    fallback_kind
                };
                let done = self.label();
                writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    cmp QWORD PTR [r10], 0\n    jne {done}\n    mov rax, QWORD PTR [r10+8]\n{done}:", slot * 8).unwrap();
                Ok(output)
            }
            _ => Err(format!(
                "unknown native result function or wrong arguments: {name}"
            )),
        }
    }

    fn process_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("self_pid", []) => {
                self.uses_process = true;
                self.code.push_str("    call gak_native_process_self_pid\n");
                Ok(Scalar::Int)
            }
            (
                "regions" | "images" | "modules" | "thread_ids" | "children" | "executable"
                | "parent_pid",
                [pid],
            ) => {
                if self.expr(pid, scope)? != Scalar::Int {
                    return Err(format!("process.{name} pid must be i64"));
                }
                if matches!(
                    name,
                    "modules" | "thread_ids" | "children" | "executable" | "parent_pid"
                ) {
                    writeln!(
                        self.code,
                        "    mov {}, rax\n    call {}",
                        self.arg0(),
                        match name {
                            "modules" => "gak_native_process_modules",
                            "thread_ids" => "gak_native_process_thread_ids",
                            "children" => "gak_native_process_children",
                            "executable" => "gak_native_process_executable",
                            _ => "gak_native_process_parent_pid",
                        }
                    )
                    .unwrap();
                } else {
                    writeln!(
                        self.code,
                        "    mov {}, rax\n    mov {}, {}\n    call gak_native_process_regions",
                        self.arg0(),
                        self.arg1(),
                        u8::from(name == "images")
                    )
                    .unwrap();
                }
                self.process_checked_result();
                if name == "parent_pid" {
                    self.code.push_str("    dec rax\n");
                }
                self.uses_process = true;
                Ok(match name {
                    "modules" => Scalar::ListStr,
                    "thread_ids" | "children" => Scalar::ListInt,
                    "executable" => Scalar::Str,
                    "parent_pid" => Scalar::Int,
                    _ => Scalar::Regions,
                })
            }
            ("count", [regions]) => {
                if self.expr(regions, scope)? != Scalar::Regions {
                    return Err("process.count expects Regions".into());
                }
                self.code.push_str("    mov rax, QWORD PTR [rax]\n");
                Ok(Scalar::Int)
            }
            ("at" | "locate" | "locate_u64", [regions, index]) => {
                if self.expr(regions, scope)? != Scalar::Regions {
                    return Err(format!("process.{name} expects Regions"));
                }
                let regions_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    regions_slot * 8
                )
                .unwrap();
                let expected = if name == "locate_u64" {
                    Scalar::UInt
                } else {
                    Scalar::Int
                };
                if self.expr(index, scope)? != expected {
                    return Err(format!("process.{name} index/address has the wrong type"));
                }
                writeln!(
                    self.code,
                    "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call {}",
                    self.arg0(),
                    regions_slot * 8,
                    self.arg1(),
                    if name == "at" {
                        "gak_native_process_at"
                    } else {
                        "gak_native_process_locate"
                    }
                )
                .unwrap();
                self.process_checked_result();
                self.uses_process = true;
                Ok(Scalar::Region)
            }
            (
                "pid" | "start" | "start_u64" | "size" | "end" | "end_u64" | "access" | "label"
                | "image_backed",
                [region],
            ) => {
                if self.expr(region, scope)? != Scalar::Region {
                    return Err(format!("process.{name} expects Region"));
                }
                let (offset, kind) = match name {
                    "pid" => (0, Scalar::Int),
                    "start" => (8, Scalar::Int),
                    "start_u64" => (8, Scalar::UInt),
                    "size" => (16, Scalar::Int),
                    "end" => (8, Scalar::Int),
                    "end_u64" => (8, Scalar::UInt),
                    "access" => (24, Scalar::Str),
                    "label" => (32, Scalar::Str),
                    _ => (40, Scalar::Bool),
                };
                if name == "end" || name == "end_u64" {
                    self.code.push_str("    mov r10, QWORD PTR [rax+8]\n    add r10, QWORD PTR [rax+16]\n    jc gak_overflow\n    mov rax, r10\n");
                } else {
                    writeln!(self.code, "    mov rax, QWORD PTR [rax+{offset}]").unwrap();
                }
                if name == "start" || name == "end" || name == "size" {
                    let ready = self.label();
                    let message = self.literal(&format!("region {name} outside i64 range"))?;
                    writeln!(self.code, "    test rax, rax\n    jns {ready}\n    lea rax, [rip+{message}]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
                }
                Ok(kind)
            }
            ("offset" | "offset_u64" | "address" | "address_u64", [region, value]) => {
                if self.expr(region, scope)? != Scalar::Region {
                    return Err(format!("process.{name} expects Region"));
                }
                let region_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    region_slot * 8
                )
                .unwrap();
                let expected = if name == "offset_u64" {
                    Scalar::UInt
                } else {
                    Scalar::Int
                };
                if self.expr(value, scope)? != expected {
                    return Err(format!("process.{name} value has the wrong type"));
                }
                writeln!(
                    self.code,
                    "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call {}",
                    self.arg0(),
                    region_slot * 8,
                    self.arg1(),
                    if name.starts_with("offset") {
                        "gak_native_region_offset"
                    } else {
                        "gak_native_region_address"
                    }
                )
                .unwrap();
                let ready = self.label();
                writeln!(self.code, "    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_file_error]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
                if name == "address" || name.starts_with("offset") {
                    let in_range = self.label();
                    let message = self.literal(if name == "address" {
                        "region address outside i64 range"
                    } else {
                        "region offset outside i64 range"
                    })?;
                    writeln!(self.code, "    test rax, rax\n    jns {in_range}\n    lea rax, [rip+{message}]\n    jmp gak_analyze_error_dynamic\n{in_range}:").unwrap();
                }
                self.uses_process = true;
                Ok(if name == "address_u64" {
                    Scalar::UInt
                } else {
                    Scalar::Int
                })
            }
            ("reference" | "resolve", [region, value]) => {
                if self.expr(region, scope)? != Scalar::Region {
                    return Err(format!("process.{name} expects Region"));
                }
                let region_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    region_slot * 8
                )
                .unwrap();
                let expected = if name == "reference" {
                    Scalar::UInt
                } else {
                    Scalar::Str
                };
                if self.expr(value, scope)? != expected {
                    return Err(format!("process.{name} value has the wrong type"));
                }
                writeln!(
                    self.code,
                    "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call {}",
                    self.arg0(),
                    region_slot * 8,
                    self.arg1(),
                    if name == "reference" {
                        "gak_native_region_reference"
                    } else {
                        "gak_native_region_resolve"
                    }
                )
                .unwrap();
                if name == "reference" {
                    self.process_checked_result();
                } else {
                    let ready = self.label();
                    writeln!(self.code, "    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_file_error]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
                }
                self.uses_process = true;
                Ok(if name == "reference" {
                    Scalar::Str
                } else {
                    Scalar::UInt
                })
            }
            (
                "snapshot_region" | "snapshot_ref" | "snapshot_at" | "snapshot_at_u64",
                [owner, address, length],
            ) => {
                let owner_kind = if name == "snapshot_region" || name == "snapshot_ref" {
                    Scalar::Region
                } else {
                    Scalar::Regions
                };
                if self.expr(owner, scope)? != owner_kind {
                    return Err(format!("process.{name} owner has the wrong type"));
                }
                let owner_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", owner_slot * 8).unwrap();
                let address_kind = if name == "snapshot_ref" {
                    Scalar::Str
                } else if name == "snapshot_at_u64" {
                    Scalar::UInt
                } else {
                    Scalar::Int
                };
                if self.expr(address, scope)? != address_kind {
                    return Err(format!("process.{name} address/offset has the wrong type"));
                }
                let address_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    address_slot * 8
                )
                .unwrap();
                if self.expr(length, scope)? != Scalar::Int {
                    return Err(format!("process.{name} length must be i64"));
                }
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call {}", self.arg0(), owner_slot * 8, self.arg1(), address_slot * 8, self.arg2(), match name { "snapshot_region" => "gak_native_process_snapshot_region", "snapshot_ref" => "gak_native_process_snapshot_ref", _ => "gak_native_process_snapshot_at" }).unwrap();
                self.process_source_result()?;
                self.uses_process = true;
                Ok(Scalar::Source)
            }
            ("snapshot" | "snapshot_u64", [pid, address, length]) => {
                if self.expr(pid, scope)? != Scalar::Int {
                    return Err("process.snapshot pid must be i64".into());
                }
                let pid_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", pid_slot * 8).unwrap();
                let expected_address = if name == "snapshot_u64" {
                    Scalar::UInt
                } else {
                    Scalar::Int
                };
                if self.expr(address, scope)? != expected_address {
                    return Err(format!("process.{name} address has the wrong type"));
                }
                let address_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    address_slot * 8
                )
                .unwrap();
                if self.expr(length, scope)? != Scalar::Int {
                    return Err(format!("process.{name} length must be i64"));
                }
                let ready = self.label();
                let result_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_process_snapshot\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_file_error]\n    jmp gak_analyze_error_dynamic\n{ready}:\n    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov r11, QWORD PTR [r10]\n    mov r8, QWORD PTR [rip+gak_source_backing_bytes]\n    lea r9, [r11+8]\n    add r8, r9\n    jc gak_source_backing_limit\n    cmp r8, 536870920\n    ja gak_source_backing_limit\n    mov QWORD PTR [rip+gak_source_backing_bytes], r8\n    mov rax, r10\n    xor edx, edx\n    xor r10d, r10d\n    xor r8d, r8d\n    call gak_alloc_source\n    mov r11, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r11+8]\n    mov QWORD PTR [rax+80], r10\n    mov r10, QWORD PTR [r11+16]\n    mov QWORD PTR [rax+88], r10", self.arg0(), pid_slot * 8, self.arg1(), address_slot * 8, self.arg2(), result_slot * 8, result_slot * 8).unwrap();
                self.uses_process = true;
                Ok(Scalar::Source)
            }
            _ => Err(format!(
                "unknown native process function or wrong arguments: {name}"
            )),
        }
    }

    fn process_checked_result(&mut self) {
        let ready = self.label();
        writeln!(self.code, "    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_file_error]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
    }

    fn process_source_result(&mut self) -> Result<(), String> {
        self.process_checked_result();
        let slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov r11, QWORD PTR [r10]\n    mov r8, QWORD PTR [rip+gak_source_backing_bytes]\n    lea r9, [r11+8]\n    add r8, r9\n    jc gak_source_backing_limit\n    cmp r8, 536870920\n    ja gak_source_backing_limit\n    mov QWORD PTR [rip+gak_source_backing_bytes], r8\n    mov rax, r10\n    xor edx, edx\n    xor r10d, r10d\n    xor r8d, r8d\n    call gak_alloc_source\n    mov r11, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r11+8]\n    mov QWORD PTR [rax+80], r10\n    mov r10, QWORD PTR [r11+16]\n    mov QWORD PTR [rax+88], r10", slot * 8, slot * 8).unwrap();
        Ok(())
    }

    fn net_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        if !matches!(name, "exchange" | "datagram") || args.len() != 5 {
            return Err(format!(
                "unknown native net function or wrong arguments: {name}"
            ));
        }
        let mut slots = Vec::with_capacity(5);
        for (index, argument) in args.iter().enumerate() {
            let kind = self.expr(argument, scope)?;
            let expected = match index {
                0 => kind == Scalar::Str,
                2 => matches!(kind, Scalar::Str | Scalar::Bytes),
                _ => kind == Scalar::Int,
            };
            if !expected {
                return Err(format!(
                    "net.{name} argument {} has the wrong type",
                    index + 1
                ));
            }
            let slot = self.reserve_slot()?;
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
            slots.push(slot);
        }
        for (index, slot) in slots.iter().take(4).enumerate() {
            let register = match index {
                0 => self.arg0(),
                1 => self.arg1(),
                2 => self.arg2(),
                _ => self.arg3(),
            };
            writeln!(
                self.code,
                "    mov {register}, QWORD PTR [rbp-{}]",
                slot * 8
            )
            .unwrap();
        }
        if self.windows {
            writeln!(self.code, "    sub rsp, 48\n    mov r10, QWORD PTR [rbp-{}]\n    mov QWORD PTR [rsp+32], r10\n    call gak_native_net_{name}\n    add rsp, 48", slots[4] * 8).unwrap();
        } else {
            writeln!(
                self.code,
                "    mov r8, QWORD PTR [rbp-{}]\n    call gak_native_net_{name}",
                slots[4] * 8
            )
            .unwrap();
        }
        self.process_source_result()?;
        self.uses_net = true;
        Ok(Scalar::Source)
    }

    fn formats_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("symbol_count" | "static_symbol_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                self.uses_formats = true;
                let ready = self.label();
                let mode = if name == "static_symbol_count" { 1 } else { 0 };
                writeln!(self.code, "    mov {}, rax\n    mov {}, {mode}\n    call gak_native_formats_symbol_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), self.arg1()).unwrap();
                return Ok(Scalar::Int);
            }
            (
                "symbol_name"
                | "symbol_binding"
                | "symbol_type"
                | "symbol_visibility"
                | "symbol_role"
                | "symbol_address"
                | "symbol_size"
                | "symbol_section"
                | "symbol_defined"
                | "symbol_summary"
                | "static_symbol_name"
                | "static_symbol_binding"
                | "static_symbol_type"
                | "static_symbol_visibility"
                | "static_symbol_role"
                | "static_symbol_address"
                | "static_symbol_size"
                | "static_symbol_section"
                | "static_symbol_defined"
                | "static_symbol_summary",
                [report, index],
            ) => {
                let mode = if name.starts_with("static_") { 1 } else { 0 };
                let property = name.strip_prefix("static_").unwrap_or(name);
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                self.uses_formats = true;
                let ready = self.label();
                if matches!(
                    property,
                    "symbol_size" | "symbol_section" | "symbol_defined"
                ) {
                    let part = match property {
                        "symbol_size" => 0,
                        "symbol_section" => 1,
                        _ => 2,
                    };
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    mov {}, {mode}\n    call gak_native_formats_symbol_number\n    mov r11, QWORD PTR [rip+gak_formats_error]\n    test r11, r11\n    jz {ready}\n    mov rax, r11\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2(), self.arg3()).unwrap();
                    return Ok(if property == "symbol_defined" {
                        Scalar::Bool
                    } else {
                        Scalar::Int
                    });
                }
                let part = match property {
                    "symbol_name" => 0,
                    "symbol_binding" => 1,
                    "symbol_type" => 2,
                    "symbol_visibility" => 3,
                    "symbol_role" => 4,
                    "symbol_address" => 5,
                    _ => 6,
                };
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    mov {}, {mode}\n    call gak_native_formats_symbol_text\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2(), self.arg3()).unwrap();
                return Ok(Scalar::Str);
            }
            ("relocation_location", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.relocation_location expects Format".into());
                }
                self.uses_formats = true;
                writeln!(
                    self.code,
                    "    mov {}, rax\n    call gak_native_formats_relocation_location",
                    self.arg0()
                )
                .unwrap();
                return Ok(Scalar::Str);
            }
            ("relocation_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.relocation_count expects Format".into());
                }
                self.uses_formats = true;
                let ready = self.label();
                writeln!(self.code, "    mov {}, rax\n    call gak_native_formats_relocation_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0()).unwrap();
                return Ok(Scalar::Int);
            }
            (
                "relocation_rva" | "relocation_address" | "relocation_type" | "relocation_kind"
                | "relocation_summary" | "relocation_symbol" | "relocation_addend",
                [report, index],
            ) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                self.uses_formats = true;
                let ready = self.label();
                if matches!(
                    name,
                    "relocation_rva"
                        | "relocation_type"
                        | "relocation_symbol"
                        | "relocation_addend"
                ) {
                    let part = match name {
                        "relocation_rva" => 0,
                        "relocation_type" => 1,
                        "relocation_symbol" => 2,
                        _ => 3,
                    };
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    call gak_native_formats_relocation_number\n    mov r11, QWORD PTR [rip+gak_formats_error]\n    test r11, r11\n    jz {ready}\n    mov rax, r11\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                    return Ok(Scalar::Int);
                }
                let part = match name {
                    "relocation_address" => 0,
                    "relocation_kind" => 1,
                    _ => 2,
                };
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    call gak_native_formats_relocation_text\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                return Ok(Scalar::Str);
            }
            ("certificate_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.certificate_count expects Format".into());
                }
                self.uses_formats = true;
                let ready = self.label();
                writeln!(self.code, "    mov {}, rax\n    call gak_native_formats_certificate_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0()).unwrap();
                return Ok(Scalar::Int);
            }
            ("debug_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.debug_count expects Format".into());
                }
                self.uses_formats = true;
                let ready = self.label();
                writeln!(self.code, "    mov {}, rax\n    call gak_native_formats_debug_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0()).unwrap();
                return Ok(Scalar::Int);
            }
            (
                "debug_data" | "debug_size" | "debug_timestamp" | "debug_kind" | "debug_type"
                | "debug_pdb_path" | "debug_pdb_guid" | "debug_pdb_age",
                [report, index],
            ) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                self.uses_formats = true;
                if name == "debug_data" {
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_debug_data", self.arg0(), report_slot * 8, self.arg1()).unwrap();
                    return self.formats_range_result();
                }
                let ready = self.label();
                if matches!(name, "debug_type" | "debug_pdb_path" | "debug_pdb_guid") {
                    let part = match name {
                        "debug_type" => 0,
                        "debug_pdb_path" => 1,
                        _ => 2,
                    };
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    call gak_native_formats_debug_text\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                    return Ok(Scalar::Str);
                }
                let part = match name {
                    "debug_kind" => 0,
                    "debug_timestamp" => 1,
                    "debug_size" => 2,
                    _ => 3,
                };
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    call gak_native_formats_debug_number\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                return Ok(Scalar::Int);
            }
            (
                "certificate_data"
                | "certificate_offset"
                | "certificate_size"
                | "certificate_revision"
                | "certificate_type",
                [report, index],
            ) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                self.uses_formats = true;
                if name == "certificate_data" {
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_certificate_data", self.arg0(), report_slot * 8, self.arg1()).unwrap();
                    return self.formats_range_result();
                }
                let part = match name {
                    "certificate_offset" => 0,
                    "certificate_size" => 1,
                    "certificate_revision" => 2,
                    _ => 3,
                };
                let ready = self.label();
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    call gak_native_formats_certificate_number\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                return Ok(Scalar::Int);
            }
            ("export_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.export_count expects Format".into());
                }
                self.uses_formats = true;
                let ready = self.label();
                writeln!(self.code, "    mov {}, rax\n    call gak_native_formats_export_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0()).unwrap();
                return Ok(Scalar::Int);
            }
            (
                "export_name" | "export_ordinal" | "export_address" | "export_target"
                | "export_kind" | "export_summary",
                [report, index],
            ) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                self.uses_formats = true;
                let ready = self.label();
                if matches!(name, "export_ordinal" | "export_address") {
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {}\n    call gak_native_formats_export_number\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2(), if name == "export_address" { 1 } else { 0 }).unwrap();
                    return Ok(Scalar::Int);
                }
                let part = match name {
                    "export_name" => 0,
                    "export_target" => 1,
                    "export_kind" => 2,
                    _ => 3,
                };
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {part}\n    call gak_native_formats_export_text\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                return Ok(Scalar::Str);
            }
            ("import_count" | "delay_import_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                self.uses_formats = true;
                let ready = self.label();
                writeln!(self.code, "    mov {}, rax\n    mov {}, {}\n    call gak_native_formats_import_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), self.arg1(), if name.starts_with("delay_") { 1 } else { 0 }).unwrap();
                return Ok(Scalar::Int);
            }
            (
                "import_library"
                | "import_symbol"
                | "import_kind"
                | "import_summary"
                | "delay_import_library"
                | "delay_import_symbol"
                | "delay_import_kind"
                | "delay_import_summary",
                [report, index],
            ) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                let part = if name.ends_with("_library") {
                    0
                } else if name.ends_with("_symbol") {
                    1
                } else if name.ends_with("_kind") {
                    2
                } else {
                    3
                };
                self.uses_formats = true;
                let ready = self.label();
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {}\n    mov {}, {part}\n    call gak_native_formats_import_text\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2(), if name.starts_with("delay_") { 1 } else { 0 }, self.arg3()).unwrap();
                return Ok(Scalar::Str);
            }
            ("dependency_count" | "needed_count" | "delay_dependency_count", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                self.uses_formats = true;
                let ready = self.label();
                let mode = if name == "needed_count" {
                    1
                } else if name == "delay_dependency_count" {
                    2
                } else {
                    0
                };
                writeln!(self.code, "    mov {}, rax\n    mov {}, {mode}\n    call gak_native_formats_dependency_count\n    cmp rax, -1\n    jne {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), self.arg1()).unwrap();
                return Ok(Scalar::Int);
            }
            ("dependency_name" | "needed_name" | "delay_dependency_name", [report, index]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} index must be i64"));
                }
                self.uses_formats = true;
                let ready = self.label();
                let mode = if name == "needed_name" {
                    1
                } else if name == "delay_dependency_name" {
                    2
                } else {
                    0
                };
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    mov {}, {mode}\n    call gak_native_formats_dependency_name\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1(), self.arg2()).unwrap();
                return Ok(Scalar::Str);
            }
            ("overlay", [report]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.overlay expects Format".into());
                }
                self.uses_formats = true;
                writeln!(
                    self.code,
                    "    mov {}, rax\n    call gak_native_formats_overlay",
                    self.arg0()
                )
                .unwrap();
                return self.formats_range_result();
            }
            ("entry_view", [report, count]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err("formats.entry_view expects Format".into());
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(count, scope)? != Scalar::Int {
                    return Err("formats.entry_view length must be i64".into());
                }
                self.uses_formats = true;
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_entry_view", self.arg0(), report_slot * 8, self.arg1()).unwrap();
                return self.formats_range_result();
            }
            ("rva" | "va", [report, address, count]) => {
                if self.expr(report, scope)? != Scalar::Format {
                    return Err(format!("formats.{name} expects Format"));
                }
                let report_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    report_slot * 8
                )
                .unwrap();
                if self.expr(address, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} address must be i64"));
                }
                let address_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    address_slot * 8
                )
                .unwrap();
                if self.expr(count, scope)? != Scalar::Int {
                    return Err(format!("formats.{name} length must be i64"));
                }
                self.uses_formats = true;
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_{name}", self.arg0(), report_slot * 8, self.arg1(), address_slot * 8, self.arg2()).unwrap();
                return self.formats_range_result();
            }
            _ => {}
        }
        if let ("section", [report, index]) = (name, args) {
            if self.expr(report, scope)? != Scalar::Format {
                return Err("formats.section expects Format".into());
            }
            let report_slot = self.reserve_slot()?;
            writeln!(
                self.code,
                "    mov QWORD PTR [rbp-{}], rax",
                report_slot * 8
            )
            .unwrap();
            if self.expr(index, scope)? != Scalar::Int {
                return Err("formats.section index must be i64".into());
            }
            self.uses_formats = true;
            let ready = self.label();
            writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_section\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1()).unwrap();
            return Ok(Scalar::Section);
        }
        if let [section] = args {
            let (result, helper) = match name {
                "name" => (Scalar::Str, "gak_native_formats_section_name"),
                "address" => (Scalar::Str, "gak_native_formats_section_address"),
                "flags" => (Scalar::Str, "gak_native_formats_section_flags"),
                "offset" => (Scalar::Int, "gak_native_formats_section_offset"),
                "size" => (Scalar::Int, "gak_native_formats_section_size"),
                "virtual_size" => (Scalar::Int, "gak_native_formats_section_virtual_size"),
                "writable" => (Scalar::Bool, "gak_native_formats_section_writable"),
                "executable" => (Scalar::Bool, "gak_native_formats_section_executable"),
                "data" => (Scalar::Source, "gak_native_formats_section_data"),
                _ => (Scalar::Section, ""),
            };
            if !helper.is_empty() {
                if self.expr(section, scope)? != Scalar::Section {
                    return Err(format!("formats.{name} expects Section"));
                }
                self.uses_formats = true;
                writeln!(self.code, "    mov {}, rax\n    call {helper}", self.arg0()).unwrap();
                if matches!(name, "name" | "address" | "flags" | "data") {
                    let ready = self.label();
                    writeln!(self.code, "    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
                }
                if name == "data" {
                    self.code.push_str("    mov r9, rax\n    mov rdx, QWORD PTR [r9]\n    mov r8, QWORD PTR [rdx+32]\n    cmp r8, 64\n    jae gak_source_depth\n    inc r8\n    mov r10, QWORD PTR [r9+16]\n    add r10, QWORD PTR [rdx+16]\n    mov r11, r10\n    add r11, QWORD PTR [r9+24]\n    mov rax, QWORD PTR [rdx]\n    call gak_alloc_source\n");
                }
                if matches!(name, "offset" | "size" | "virtual_size") {
                    let message = self.literal(match name {
                        "offset" => "section offset outside i64 range",
                        "size" => "section size outside i64 range",
                        _ => "virtual section size outside i64 range",
                    })?;
                    let ready = self.label();
                    writeln!(self.code, "    test rax, rax\n    jns {ready}\n    lea rax, [rip+{message}]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
                }
                return Ok(result);
            }
        }
        if let ("field", [report, field]) = (name, args) {
            if self.expr(report, scope)? != Scalar::Format {
                return Err("formats.field expects Format".into());
            }
            let report_slot = self.reserve_slot()?;
            writeln!(
                self.code,
                "    mov QWORD PTR [rbp-{}], rax",
                report_slot * 8
            )
            .unwrap();
            if self.expr(field, scope)? != Scalar::Str {
                return Err("formats.field name must be str".into());
            }
            self.uses_formats = true;
            let ready = self.label();
            writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_field\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:\n    mov r9, rax\n    mov rax, QWORD PTR [r9]\n    mov rdx, QWORD PTR [r9+8]\n    mov r10, QWORD PTR [r9+16]\n    mov r8, QWORD PTR [r9+24]\n    mov r11, QWORD PTR [r9+32]\n    call gak_alloc_observation", self.arg0(), report_slot * 8, self.arg1()).unwrap();
            return Ok(Scalar::Observation);
        }
        if let ("signal", [report, signal]) = (name, args) {
            if self.expr(report, scope)? != Scalar::Format {
                return Err("formats.signal expects Format".into());
            }
            let report_slot = self.reserve_slot()?;
            writeln!(
                self.code,
                "    mov QWORD PTR [rbp-{}], rax",
                report_slot * 8
            )
            .unwrap();
            if self.expr(signal, scope)? != Scalar::Str {
                return Err("formats.signal name must be str".into());
            }
            self.uses_formats = true;
            let ready = self.label();
            writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_formats_signal\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:", self.arg0(), report_slot * 8, self.arg1()).unwrap();
            return Ok(Scalar::Str);
        }
        let (argument, result, helper) = match (name, args) {
            ("probe", [source]) => (source, Scalar::Format, "gak_native_formats_probe"),
            ("kind", [report]) => (report, Scalar::Str, "gak_native_formats_kind"),
            ("bits", [report]) => (report, Scalar::Int, "gak_native_formats_bits"),
            ("endian", [report]) => (report, Scalar::Str, "gak_native_formats_endian"),
            ("arch", [report]) => (report, Scalar::Str, "gak_native_formats_arch"),
            ("count", [report]) => (report, Scalar::Int, "gak_native_formats_count"),
            _ => return Err(format!("native formats.{name} is not yet supported")),
        };
        let expected = if name == "probe" {
            Scalar::Source
        } else {
            Scalar::Format
        };
        if self.expr(argument, scope)? != expected {
            return Err(format!(
                "formats.{name} expects {}",
                if name == "probe" { "Source" } else { "Format" }
            ));
        }
        self.uses_formats = true;
        writeln!(self.code, "    mov {}, rax\n    call {helper}", self.arg0()).unwrap();
        if name == "probe" {
            let ready = self.label();
            writeln!(self.code, "    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:").unwrap();
        }
        Ok(result)
    }

    fn formats_range_result(&mut self) -> Result<Scalar, String> {
        let ready = self.label();
        let range_slot = self.reserve_slot()?;
        writeln!(self.code, "    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_formats_error]\n    jmp gak_analyze_error_dynamic\n{ready}:\n    mov QWORD PTR [rbp-{}], rax\n    mov r9, rax\n    mov rdx, QWORD PTR [r9]\n    mov r8, QWORD PTR [rdx+32]\n    cmp r8, 64\n    jae gak_source_depth\n    inc r8\n    mov r10, QWORD PTR [r9+8]\n    add r10, QWORD PTR [rdx+16]\n    mov r11, QWORD PTR [r9+16]\n    add r11, QWORD PTR [rdx+16]\n    mov rax, QWORD PTR [rdx]\n    call gak_alloc_source\n    mov r9, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r9+24]\n    mov QWORD PTR [rax+96], r10\n    mov r10, QWORD PTR [r9+32]\n    mov QWORD PTR [rax+104], r10", range_slot * 8, range_slot * 8).unwrap();
        Ok(Scalar::Source)
    }

    fn binary_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("from_hex", _) => self.bytes_call("from_hex", args, scope),
            ("analyze", [path, max_bytes]) => {
                if self.expr(path, scope)? != Scalar::Str {
                    return Err("binary.analyze path must be str".into());
                }
                let path_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", path_slot * 8).unwrap();
                if self.expr(max_bytes, scope)? != Scalar::Int {
                    return Err("binary.analyze max_bytes must be i64".into());
                }
                let module_dir = self
                    .active_module
                    .parent()
                    .and_then(|path| path.to_str())
                    .ok_or("native module directory is not UTF-8")?
                    .to_owned();
                let base = self.literal(&module_dir)?;
                let ready = self.label();
                let result_slot = self.reserve_slot()?;
                writeln!(self.code, "    test rax, rax\n    js gak_analyze_max\n    cmp rax, 536870912\n    ja gak_analyze_max\n    mov {}, rax\n    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{base}]\n    call gak_native_read_file\n    test rax, rax\n    jnz {ready}\n    mov rax, QWORD PTR [rip+gak_file_error]\n    jmp gak_analyze_error_dynamic\n{ready}:\n    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax]\n    mov r11, QWORD PTR [r10]\n    mov r8, QWORD PTR [rip+gak_source_backing_bytes]\n    lea r9, [r11+8]\n    add r8, r9\n    jc gak_source_backing_limit\n    cmp r8, 536870920\n    ja gak_source_backing_limit\n    mov QWORD PTR [rip+gak_source_backing_bytes], r8\n    mov rax, r10\n    xor edx, edx\n    xor r10d, r10d\n    xor r8d, r8d\n    call gak_alloc_source\n    mov r11, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r11+8]\n    mov QWORD PTR [rax+80], r10\n    mov r10, QWORD PTR [r11+16]\n    mov QWORD PTR [rax+88], r10", self.arg1(), self.arg0(), path_slot * 8, self.arg2(), result_slot * 8, result_slot * 8).unwrap();
                self.uses_file_read = true;
                Ok(Scalar::Source)
            }
            ("snapshot", [data]) => {
                if self.expr(data, scope)? != Scalar::Bytes {
                    return Err("binary.snapshot expects bytes".into());
                }
                self.code.push_str("    xor edx, edx\n    xor r10d, r10d\n    mov r11, QWORD PTR [rax]\n    xor r8d, r8d\n    call gak_alloc_source\n");
                Ok(Scalar::Source)
            }
            ("size", [data]) => {
                match self.expr(data, scope)? {
                    Scalar::Bytes => self.code.push_str("    mov rax, QWORD PTR [rax]\n"),
                    Scalar::Source => self.code.push_str(
                        "    mov r10, QWORD PTR [rax+24]\n    sub r10, QWORD PTR [rax+16]\n    mov rax, r10\n",
                    ),
                    _ => return Err("binary.size expects bytes or Source".into()),
                }
                Ok(Scalar::Int)
            }
            ("sha256", [data]) => {
                match self.expr(data, scope)? {
                    Scalar::Bytes => self.code.push_str(
                        "    mov rdx, QWORD PTR [rax]\n    lea rax, [rax+8]\n    call gak_sha256\n",
                    ),
                    Scalar::Source => self.source_sha256(),
                    _ => return Err("binary.sha256 expects bytes or Source".into()),
                }
                Ok(Scalar::Str)
            }
            ("entropy", [source]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.entropy expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                let decoder = self.literal("entropy_milli")?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rax+16]\n    mov rdx, QWORD PTR [rax+24]\n    sub rdx, r10\n    mov r11, QWORD PTR [rax]\n    lea rax, [r11+r10+8]\n    call gak_entropy_milli\n    mov r8, rax\n    mov rax, QWORD PTR [rbp-{}]\n    xor edx, edx\n    mov r10, QWORD PTR [rax+24]\n    sub r10, QWORD PTR [rax+16]\n    lea r11, [rip+{decoder}]\n    call gak_alloc_observation", source_slot * 8, source_slot * 8).unwrap();
                Ok(Scalar::Observation)
            }
            ("deep", [source, offset, decoder]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.deep expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                if self.expr(offset, scope)? != Scalar::Int {
                    return Err("binary.deep offset must be i64".into());
                }
                let offset_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    offset_slot * 8
                )
                .unwrap();
                if self.expr(decoder, scope)? != Scalar::Str {
                    return Err("binary.deep decoder must be str".into());
                }
                let decoder_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_binary_offset_negative", decoder_slot * 8, offset_slot * 8).unwrap();
                let done = self.label();
                for (format, width, big_endian) in [
                    ("u8", 1_usize, false),
                    ("u16le", 2, false),
                    ("u16be", 2, true),
                    ("u32le", 4, false),
                    ("u32be", 4, true),
                    ("u64le", 8, false),
                    ("u64be", 8, true),
                ] {
                    let next = self.label();
                    let literal = self.literal(format)?;
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{literal}]\n    call gak_str_eq\n    test eax, eax\n    jz {next}", self.arg0(), decoder_slot * 8, self.arg1()).unwrap();
                    writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [rbp-{}]\n    mov r8, QWORD PTR [r11+24]\n    sub r8, QWORD PTR [r11+16]\n    mov r9, r10\n    add r9, {width}\n    jc gak_binary_range_overflow\n    cmp r9, r8\n    ja gak_binary_out_of_bounds\n    add r10, QWORD PTR [r11+16]\n    mov r11, QWORD PTR [r11]\n    lea r11, [r11+r10+8]\n    xor eax, eax", offset_slot * 8, source_slot * 8).unwrap();
                    for index in 0..width {
                        if big_endian {
                            self.code.push_str("    shl rax, 8\n");
                        }
                        writeln!(self.code, "    movzx r10d, BYTE PTR [r11+{index}]").unwrap();
                        if !big_endian && index != 0 {
                            writeln!(self.code, "    shl r10, {}", index * 8).unwrap();
                        }
                        self.code.push_str("    or rax, r10\n");
                    }
                    writeln!(self.code, "    mov r8, rax\n    mov rax, QWORD PTR [rbp-{}]\n    mov rdx, QWORD PTR [rbp-{}]\n    mov r10d, {width}\n    mov r11, QWORD PTR [rbp-{}]\n    call gak_alloc_observation\n    jmp {done}\n{next}:", source_slot * 8, offset_slot * 8, decoder_slot * 8).unwrap();
                }
                writeln!(self.code, "    jmp gak_binary_unknown_decoder\n{done}:").unwrap();
                Ok(Scalar::Observation)
            }
            ("value" | "value_u64" | "offset" | "width", [observation]) => {
                if self.expr(observation, scope)? != Scalar::Observation {
                    return Err(format!("binary.{name} expects Observation"));
                }
                match name {
                    "value" => self.code.push_str("    mov rax, QWORD PTR [rax+32]\n    test rax, rax\n    js gak_observation_value_range\n"),
                    "value_u64" => self.code.push_str("    mov rax, QWORD PTR [rax+32]\n"),
                    "offset" => self.code.push_str("    mov rax, QWORD PTR [rax+8]\n"),
                    "width" => self.code.push_str("    mov rax, QWORD PTR [rax+16]\n"),
                    _ => unreachable!(),
                }
                Ok(if name == "value_u64" {
                    Scalar::UInt
                } else {
                    Scalar::Int
                })
            }
            ("hexdump", [source]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.hexdump expects Source".into());
                }
                let ready = self.label();
                writeln!(self.code, "    mov r10, QWORD PTR [rax+16]\n    mov rdx, QWORD PTR [rax+24]\n    sub rdx, r10\n    cmp rdx, 256\n    jbe {ready}\n    mov edx, 256\n{ready}:\n    mov r11, QWORD PTR [rax]\n    lea rax, [r11+r10+8]\n    xor r10d, r10d\n    call gak_hexdump").unwrap();
                Ok(Scalar::Str)
            }
            ("hexdump", [source, offset, length]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.hexdump expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                if self.expr(offset, scope)? != Scalar::Int {
                    return Err("binary.hexdump offset must be i64".into());
                }
                let offset_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    offset_slot * 8
                )
                .unwrap();
                if self.expr(length, scope)? != Scalar::Int {
                    return Err("binary.hexdump length must be i64".into());
                }
                writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_binary_offset_negative\n    test rax, rax\n    js gak_binary_length_negative\n    mov rdx, rax\n    add r10, rdx\n    jc gak_binary_range_overflow\n    mov r11, QWORD PTR [rbp-{}]\n    mov r8, QWORD PTR [r11+24]\n    sub r8, QWORD PTR [r11+16]\n    cmp r10, r8\n    ja gak_binary_out_of_bounds\n    cmp rdx, 4096\n    ja gak_hexdump_limit\n    mov r10, QWORD PTR [rbp-{}]\n    add r10, QWORD PTR [r11+16]\n    mov r11, QWORD PTR [r11]\n    lea rax, [r11+r10+8]\n    mov r10, QWORD PTR [rbp-{}]\n    call gak_hexdump", offset_slot * 8, source_slot * 8, offset_slot * 8, offset_slot * 8).unwrap();
                Ok(Scalar::Str)
            }
            ("read_text", [source, offset, max_chars, encoding]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.read_text expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                if self.expr(offset, scope)? != Scalar::Int {
                    return Err("binary.read_text offset must be i64".into());
                }
                let offset_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    offset_slot * 8
                )
                .unwrap();
                if self.expr(max_chars, scope)? != Scalar::Int {
                    return Err("binary.read_text max_chars must be i64".into());
                }
                let max_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", max_slot * 8).unwrap();
                if self.expr(encoding, scope)? != Scalar::Str {
                    return Err("binary.read_text encoding must be str".into());
                }
                let encoding_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_text_offset_negative\n    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_max_chars_range\n    cmp r10, 1\n    jb gak_max_chars_limit\n    cmp r10, 4096\n    ja gak_max_chars_limit", encoding_slot * 8, offset_slot * 8, max_slot * 8).unwrap();
                let ascii = self.literal("ascii")?;
                let utf16le = self.literal("utf16le")?;
                let utf16be = self.literal("utf16be")?;
                let utf16_label = self.label();
                let utf16be_label = self.label();
                let ready = self.label();
                let not_limit = self.label();
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{ascii}]\n    call gak_str_eq\n    test eax, eax\n    jz {utf16_label}\n    mov r8d, 1\n    jmp {ready}\n{utf16_label}:\n    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{utf16le}]\n    call gak_str_eq\n    test eax, eax\n    jz {utf16be_label}\n    mov r8d, 2\n    jmp {ready}\n{utf16be_label}:\n    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{utf16be}]\n    call gak_str_eq\n    test eax, eax\n    jz gak_text_encoding\n    mov r8d, 3\n{ready}:\n    mov r11, QWORD PTR [rbp-{}]\n    mov rdx, QWORD PTR [r11+24]\n    sub rdx, QWORD PTR [r11+16]\n    mov r10, QWORD PTR [rbp-{}]\n    cmp r10, rdx\n    jae gak_text_offset_bounds\n    mov r9, QWORD PTR [r11+16]\n    mov r11, QWORD PTR [r11]\n    lea rax, [r11+r9+8]\n    mov r11, QWORD PTR [rbp-{}]\n    call gak_read_text\n    cmp rax, -1\n    jne {not_limit}\n    mov rax, QWORD PTR [rbp-{}]\n    call gak_text_limit_message\n    jmp gak_text_limit_dynamic\n{not_limit}:\n    test rax, rax\n    jz gak_text_not_printable", self.arg0(), encoding_slot * 8, self.arg1(), self.arg0(), encoding_slot * 8, self.arg1(), self.arg0(), encoding_slot * 8, self.arg1(), source_slot * 8, offset_slot * 8, max_slot * 8, max_slot * 8).unwrap();
                Ok(Scalar::Str)
            }
            ("strings", [source, minimum, encoding]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.strings expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                if self.expr(minimum, scope)? != Scalar::Int {
                    return Err("binary.strings minimum must be i64".into());
                }
                let minimum_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    minimum_slot * 8
                )
                .unwrap();
                if self.expr(encoding, scope)? != Scalar::Str {
                    return Err("binary.strings encoding must be str".into());
                }
                let encoding_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_strings_minimum_range\n    cmp r10, 1\n    jb gak_strings_minimum_limit\n    cmp r10, 4096\n    ja gak_strings_minimum_limit", encoding_slot * 8, minimum_slot * 8).unwrap();
                let ascii = self.literal("ascii")?;
                let utf16le = self.literal("utf16le")?;
                let utf16be = self.literal("utf16be")?;
                let utf16_label = self.label();
                let utf16be_label = self.label();
                let ready = self.label();
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{ascii}]\n    call gak_str_eq\n    test eax, eax\n    jz {utf16_label}\n    mov r11d, 1\n    jmp {ready}\n{utf16_label}:\n    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{utf16le}]\n    call gak_str_eq\n    test eax, eax\n    jz {utf16be_label}\n    mov r11d, 2\n    jmp {ready}\n{utf16be_label}:\n    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{utf16be}]\n    call gak_str_eq\n    test eax, eax\n    jz gak_text_encoding\n    mov r11d, 3\n{ready}:\n    mov r8, QWORD PTR [rbp-{}]\n    mov rdx, QWORD PTR [r8+24]\n    sub rdx, QWORD PTR [r8+16]\n    mov r10, QWORD PTR [r8+16]\n    mov r8, QWORD PTR [r8]\n    lea rax, [r8+r10+8]\n    mov r10, QWORD PTR [rbp-{}]\n    call gak_find_strings\n    cmp rax, -1\n    je gak_strings_many", self.arg0(), encoding_slot * 8, self.arg1(), self.arg0(), encoding_slot * 8, self.arg1(), self.arg0(), encoding_slot * 8, self.arg1(), source_slot * 8, minimum_slot * 8).unwrap();
                Ok(Scalar::Offsets)
            }
            ("hunt", [source, pattern]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.hunt expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                let pattern_kind = self.expr(pattern, scope)?;
                if !matches!(pattern_kind, Scalar::Bytes | Scalar::Str) {
                    return Err("binary.hunt pattern must be bytes or str".into());
                }
                let pattern_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    pattern_slot * 8
                )
                .unwrap();
                let raw = self.label();
                let ready = self.label();
                if pattern_kind == Scalar::Str {
                    writeln!(self.code, "    cmp QWORD PTR [rax], 4\n    jb {raw}\n    cmp DWORD PTR [rax+8], 0x3a786568\n    jne {raw}\n    call gak_parse_hunt_hex\n    test r11d, r11d\n    jz {ready}\n    cmp r11d, 1\n    je gak_hunt_invalid_hex\n    cmp r11d, 2\n    je gak_hunt_hex_limit\n    cmp r11d, 3\n    je gak_hunt_odd_hex\n    jmp gak_hunt_mask_limit\n{raw}:").unwrap();
                }
                writeln!(self.code, "    mov rax, QWORD PTR [rbp-{}]\n    xor edx, edx\n    xor r10d, r10d\n{ready}:\n    cmp QWORD PTR [rax], 0\n    je gak_hunt_empty", pattern_slot * 8).unwrap();
                let needle_slot = self.reserve_slot()?;
                let mask_slot = self.reserve_slot()?;
                let mode_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov QWORD PTR [rbp-{}], rdx\n    mov QWORD PTR [rbp-{}], r10\n    mov r11, QWORD PTR [rbp-{}]\n    mov rdx, QWORD PTR [r11+24]\n    sub rdx, QWORD PTR [r11+16]\n    mov r8, QWORD PTR [r11]\n    mov r10, QWORD PTR [r11+16]\n    lea rax, [r8+r10+8]\n    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [rbp-{}]\n    mov r8, QWORD PTR [rbp-{}]\n    call gak_hunt_search\n    cmp rax, -1\n    je gak_hunt_many", needle_slot * 8, mask_slot * 8, mode_slot * 8, source_slot * 8, needle_slot * 8, mask_slot * 8, mode_slot * 8).unwrap();
                Ok(Scalar::Offsets)
            }
            ("diff", [left, right, limit]) => {
                if self.expr(left, scope)? != Scalar::Source {
                    return Err("binary.diff left must be Source".into());
                }
                let left_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", left_slot * 8).unwrap();
                if self.expr(right, scope)? != Scalar::Source {
                    return Err("binary.diff right must be Source".into());
                }
                let right_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", right_slot * 8).unwrap();
                if self.expr(limit, scope)? != Scalar::Int {
                    return Err("binary.diff max_differences must be i64".into());
                }
                writeln!(self.code, "    test rax, rax\n    js gak_diff_limit_negative\n    cmp rax, 10000\n    ja gak_diff_limit\n    mov r10, rax\n    mov rax, QWORD PTR [rbp-{}]\n    mov rdx, QWORD PTR [rbp-{}]\n    call gak_diff_source\n    cmp rax, -1\n    je gak_diff_many", left_slot * 8, right_slot * 8).unwrap();
                Ok(Scalar::Diff)
            }
            ("diff_offsets", [diff]) => {
                if self.expr(diff, scope)? != Scalar::Diff {
                    return Err("binary.diff_offsets expects Diff".into());
                }
                self.code.push_str("    mov rax, QWORD PTR [rax+16]\n");
                Ok(Scalar::Offsets)
            }
            ("diff_count", [diff]) => {
                if self.expr(diff, scope)? != Scalar::Diff {
                    return Err("binary.diff_count expects Diff".into());
                }
                self.code
                    .push_str("    mov rax, QWORD PTR [rax+16]\n    mov rax, QWORD PTR [rax]\n");
                Ok(Scalar::Int)
            }
            ("patch", [source, offset, replacement]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.patch expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                if self.expr(offset, scope)? != Scalar::Int {
                    return Err("binary.patch offset must be i64".into());
                }
                let offset_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    offset_slot * 8
                )
                .unwrap();
                if self.expr(replacement, scope)? != Scalar::Bytes {
                    return Err("binary.patch replacement must be bytes".into());
                }
                writeln!(self.code, "    mov r11, QWORD PTR [rax]\n    test r11, r11\n    jz gak_patch_empty\n    cmp r11, 1048576\n    ja gak_patch_limit\n    mov rdx, QWORD PTR [rbp-{}]\n    test rdx, rdx\n    js gak_binary_offset_negative\n    mov r8, rdx\n    add r8, r11\n    jc gak_binary_range_overflow\n    mov r10, QWORD PTR [rbp-{}]\n    mov r11, QWORD PTR [r10+24]\n    sub r11, QWORD PTR [r10+16]\n    cmp r8, r11\n    ja gak_binary_out_of_bounds\n    cmp QWORD PTR [r10+32], 64\n    jae gak_source_depth\n    mov r10, rax\n    mov rax, QWORD PTR [rbp-{}]\n    call gak_patch_source", offset_slot * 8, source_slot * 8, source_slot * 8).unwrap();
                Ok(Scalar::Source)
            }
            ("splice", [source, offset, removed, replacement]) => {
                if self.expr(source, scope)? != Scalar::Source {
                    return Err("binary.splice expects Source".into());
                }
                let source_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    source_slot * 8
                )
                .unwrap();
                if self.expr(offset, scope)? != Scalar::Int {
                    return Err("binary.splice offset must be i64".into());
                }
                let offset_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    offset_slot * 8
                )
                .unwrap();
                if self.expr(removed, scope)? != Scalar::Int {
                    return Err("binary.splice removed length must be i64".into());
                }
                let removed_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    removed_slot * 8
                )
                .unwrap();
                if self.expr(replacement, scope)? != Scalar::Bytes {
                    return Err("binary.splice insertion must be bytes".into());
                }
                let replacement_slot = self.reserve_slot()?;
                let nonempty = self.label();
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r11, QWORD PTR [rax]\n    cmp r11, 1048576\n    ja gak_splice_insert_limit\n    mov rdx, QWORD PTR [rbp-{}]\n    test rdx, rdx\n    js gak_binary_offset_negative\n    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_binary_length_negative\n    mov r8, rdx\n    add r8, r10\n    jc gak_binary_range_overflow\n    mov r9, QWORD PTR [rbp-{}]\n    mov rcx, QWORD PTR [r9+24]\n    sub rcx, QWORD PTR [r9+16]\n    cmp r8, rcx\n    ja gak_binary_out_of_bounds\n    test r10, r10\n    jnz {nonempty}\n    test r11, r11\n    jz gak_splice_empty\n{nonempty}:\n    cmp QWORD PTR [r9+32], 64\n    jae gak_source_depth\n    sub rcx, r10\n    add rcx, r11\n    jc gak_splice_size_overflow\n    cmp rcx, 536870912\n    ja gak_splice_size_limit\n    mov rax, r9\n    mov r11, QWORD PTR [rbp-{}]\n    call gak_splice_source", replacement_slot * 8, offset_slot * 8, removed_slot * 8, source_slot * 8, replacement_slot * 8).unwrap();
                Ok(Scalar::Source)
            }
            ("extract" | "view", [data, offset, length]) => {
                let kind = self.expr(data, scope)?;
                if !matches!(kind, Scalar::Bytes | Scalar::Source)
                    || (name == "view" && kind != Scalar::Source)
                {
                    return Err(format!(
                        "binary.{name} expects {}",
                        if name == "view" {
                            "Source"
                        } else {
                            "bytes or Source"
                        }
                    ));
                }
                let data_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", data_slot * 8).unwrap();
                if self.expr(offset, scope)? != Scalar::Int {
                    return Err(format!("binary.{name} offset must be i64"));
                }
                let offset_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    offset_slot * 8
                )
                .unwrap();
                if self.expr(length, scope)? != Scalar::Int {
                    return Err(format!("binary.{name} length must be i64"));
                }
                writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    test r10, r10\n    js gak_binary_offset_negative\n    test rax, rax\n    js gak_binary_length_negative\n    add r10, rax\n    jc gak_binary_range_overflow\n    mov r11, QWORD PTR [rbp-{}]", offset_slot * 8, data_slot * 8).unwrap();
                if kind == Scalar::Source {
                    self.code.push_str("    mov r9, QWORD PTR [r11+24]\n    sub r9, QWORD PTR [r11+16]\n    cmp r10, r9\n");
                } else {
                    self.code.push_str("    cmp r10, QWORD PTR [r11]\n");
                }
                self.code.push_str("    ja gak_binary_out_of_bounds\n");
                if name == "view" {
                    writeln!(self.code, "    mov rdx, QWORD PTR [rbp-{}]\n    mov r8, QWORD PTR [rdx+32]\n    cmp r8, 64\n    jae gak_source_depth\n    inc r8\n    mov r10, QWORD PTR [rbp-{}]\n    add r10, QWORD PTR [rdx+16]\n    mov r11, r10\n    add r11, rax\n    mov rax, QWORD PTR [rdx]\n    call gak_alloc_source", data_slot * 8, offset_slot * 8).unwrap();
                    Ok(Scalar::Source)
                } else {
                    writeln!(
                        self.code,
                        "    mov r10, rax\n    mov rdx, QWORD PTR [rbp-{}]",
                        offset_slot * 8
                    )
                    .unwrap();
                    if kind == Scalar::Source {
                        writeln!(self.code, "    mov r11, QWORD PTR [rbp-{}]", data_slot * 8)
                            .unwrap();
                        self.code.push_str(
                            "    add rdx, QWORD PTR [r11+16]\n    mov rax, QWORD PTR [r11]\n",
                        );
                    } else {
                        writeln!(self.code, "    mov rax, QWORD PTR [rbp-{}]", data_slot * 8)
                            .unwrap();
                    }
                    self.code.push_str("    call gak_bytes_extract\n");
                    Ok(Scalar::Bytes)
                }
            }
            _ => Err(format!(
                "native binary function {name} is not yet supported"
            )),
        }
    }

    fn bytes_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("from_hex", [text]) => {
                if self.expr(text, scope)? != Scalar::Str {
                    return Err("bytes.from_hex expects str".into());
                }
                let done = self.label();
                writeln!(self.code, "    call gak_from_hex\n    test edx, edx\n    jz {done}\n    cmp edx, 1\n    je gak_hex_invalid\n    cmp edx, 2\n    je gak_hex_odd\n    jmp gak_hex_limit\n{done}:").unwrap();
                Ok(Scalar::Bytes)
            }
            ("to_hex", [data]) => {
                if self.expr(data, scope)? != Scalar::Bytes {
                    return Err("bytes.to_hex expects bytes".into());
                }
                self.code
                    .push_str("    mov rdx, QWORD PTR [rax]\n    call gak_to_hex\n");
                Ok(Scalar::Str)
            }
            ("at", [data, index]) => {
                if self.expr(data, scope)? != Scalar::Bytes {
                    return Err("bytes.at expects bytes".into());
                }
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err("bytes.at index must be i64".into());
                }
                writeln!(
                    self.code,
                    "    mov rdx, rax\n    mov rax, QWORD PTR [rbp-{}]\n    test rdx, rdx\n    js gak_bytes_index\n    cmp rdx, QWORD PTR [rax]\n    jae gak_bytes_index\n    call gak_bytes_at",
                    slot * 8
                )
                .unwrap();
                Ok(Scalar::Int)
            }
            ("concat" | "xor", [left, right]) => {
                if self.expr(left, scope)? != Scalar::Bytes {
                    return Err(format!("bytes.{name} expects bytes arguments"));
                }
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                if self.expr(right, scope)? != Scalar::Bytes {
                    return Err(format!("bytes.{name} expects bytes arguments"));
                }
                if name == "concat" {
                    writeln!(self.code, "    mov rdx, rax\n    mov rax, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [rax]\n    add r10, QWORD PTR [rdx]\n    jc gak_bytes_limit\n    cmp r10, 1048576\n    ja gak_bytes_limit\n    call gak_bytes_concat", slot * 8).unwrap();
                } else {
                    writeln!(self.code, "    cmp QWORD PTR [rax], 0\n    je gak_xor_empty_key\n    mov rdx, rax\n    mov rax, QWORD PTR [rbp-{}]\n    call gak_bytes_xor", slot * 8).unwrap();
                }
                Ok(Scalar::Bytes)
            }
            ("repeat", [data, count]) => {
                if self.expr(data, scope)? != Scalar::Bytes {
                    return Err("bytes.repeat expects bytes and i64".into());
                }
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                if self.expr(count, scope)? != Scalar::Int {
                    return Err("bytes.repeat expects bytes and i64".into());
                }
                writeln!(self.code, "    test rax, rax\n    js gak_repeat_negative\n    cmp rax, 1048576\n    ja gak_repeat_count_limit\n    mov rdx, rax\n    mov rax, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [rax]\n    imul r10, rdx\n    cmp r10, 1048576\n    ja gak_bytes_limit\n    call gak_bytes_repeat", slot * 8).unwrap();
                Ok(Scalar::Bytes)
            }
            ("pack", [value, encoding]) => {
                let kind = self.expr(value, scope)?;
                if !matches!(kind, Scalar::Int | Scalar::UInt) {
                    return Err("bytes.pack expects i64 or u64 value".into());
                }
                let value_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", value_slot * 8).unwrap();
                if self.expr(encoding, scope)? != Scalar::Str {
                    return Err("bytes.pack expects str encoding".into());
                }
                let encoding_slot = self.reserve_slot()?;
                writeln!(
                    self.code,
                    "    mov QWORD PTR [rbp-{}], rax",
                    encoding_slot * 8
                )
                .unwrap();
                if kind == Scalar::Int {
                    writeln!(self.code, "    mov rax, QWORD PTR [rbp-{}]\n    test rax, rax\n    js gak_pack_negative", value_slot * 8).unwrap();
                }
                let done = self.label();
                for (format, width, max, instruction) in [
                    ("u8", 1, Some(255_u64), "mov BYTE PTR [rax+8], r10b"),
                    ("u16le", 2, Some(65535), "mov WORD PTR [rax+8], r10w"),
                    (
                        "u16be",
                        2,
                        Some(65535),
                        "rol r10w, 8\n    mov WORD PTR [rax+8], r10w",
                    ),
                    (
                        "u32le",
                        4,
                        Some(u32::MAX as u64),
                        "mov DWORD PTR [rax+8], r10d",
                    ),
                    (
                        "u32be",
                        4,
                        Some(u32::MAX as u64),
                        "bswap r10d\n    mov DWORD PTR [rax+8], r10d",
                    ),
                    ("u64le", 8, None, "mov QWORD PTR [rax+8], r10"),
                    (
                        "u64be",
                        8,
                        None,
                        "bswap r10\n    mov QWORD PTR [rax+8], r10",
                    ),
                ] {
                    let next = self.label();
                    let label = self.literal(format)?;
                    writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{label}]\n    call gak_str_eq\n    test eax, eax\n    jz {next}", self.arg0(), encoding_slot * 8, self.arg1()).unwrap();
                    if let Some(max) = max {
                        writeln!(self.code, "    mov rax, QWORD PTR [rbp-{}]\n    mov r10, {max}\n    cmp rax, r10\n    ja gak_pack_range_{format}", value_slot * 8).unwrap();
                    }
                    writeln!(self.code, "    mov eax, {width}\n    call gak_alloc_bytes\n    mov r10, QWORD PTR [rbp-{}]\n    {instruction}\n    jmp {done}\n{next}:", value_slot * 8).unwrap();
                }
                writeln!(self.code, "    jmp gak_pack_encoding\n{done}:").unwrap();
                Ok(Scalar::Bytes)
            }
            _ => Err(format!("native bytes function {name} is not yet supported")),
        }
    }

    fn text_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        self.uses_text = true;
        match (name, args) {
            ("length" | "byte_length", [value]) => {
                if self.expr(value, scope)? != Scalar::Str {
                    return Err(format!("text.{name} expects str"));
                }
                if name == "byte_length" {
                    self.code.push_str("    mov rax, QWORD PTR [rax]\n");
                } else {
                    writeln!(
                        self.code,
                        "    mov {}, rax\n    call gak_native_text_length",
                        self.arg0()
                    )
                    .unwrap();
                }
                Ok(Scalar::Int)
            }
            ("find" | "contains" | "starts_with" | "ends_with", [value, needle]) => {
                if self.expr(value, scope)? != Scalar::Str {
                    return Err(format!("text.{name} expects str arguments"));
                }
                let value_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", value_slot * 8).unwrap();
                if self.expr(needle, scope)? != Scalar::Str {
                    return Err(format!("text.{name} expects str arguments"));
                }
                let helper = if name == "contains" { "find" } else { name };
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    call gak_native_text_{helper}", self.arg0(), value_slot * 8, self.arg1()).unwrap();
                if matches!(name, "find" | "contains") {
                    self.code
                        .push_str("    cmp rax, -2\n    je gak_text_search_alloc\n");
                }
                if name == "contains" {
                    self.code
                        .push_str("    cmp rax, -1\n    setne al\n    movzx eax, al\n");
                } else if name != "find" {
                    self.code.push_str("    movzx eax, al\n");
                }
                Ok(if name == "find" {
                    Scalar::Int
                } else {
                    Scalar::Bool
                })
            }
            ("slice", [value, start, count]) => {
                if self.expr(value, scope)? != Scalar::Str {
                    return Err("text.slice expects str, i64, i64".into());
                }
                let value_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", value_slot * 8).unwrap();
                if self.expr(start, scope)? != Scalar::Int {
                    return Err("text.slice expects str, i64, i64".into());
                }
                let start_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", start_slot * 8).unwrap();
                if self.expr(count, scope)? != Scalar::Int {
                    return Err("text.slice expects str, i64, i64".into());
                }
                let length_slot = self.reserve_slot()?;
                let begin_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    mov {}, QWORD PTR [rbp-{}]\n    mov {}, rax\n    lea {}, [rbp-{}]\n    call gak_native_text_slice_bounds\n    test eax, eax\n    jz gak_text_slice_range", self.arg0(), value_slot * 8, self.arg1(), start_slot * 8, self.arg2(), self.arg3(), begin_slot * 8).unwrap();
                writeln!(self.code, "    mov r11, QWORD PTR [rbp-{}]\n    cmp r11, 67108856\n    ja gak_str_limit\n    lea r8, [r11+8]\n    mov r9, QWORD PTR [rip+gak_str_bytes]\n    add r9, r8\n    jc gak_str_limit\n    cmp r9, 67108864\n    ja gak_str_limit\n    mov rax, r11\n    call gak_alloc_str", length_slot * 8).unwrap();
                let result_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    lea {}, [rax+8]\n    mov r11, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [rbp-{}]\n    lea {}, [r11+r10+8]\n    mov {}, QWORD PTR [rbp-{}]\n    call memcpy\n    mov rax, QWORD PTR [rbp-{}]", result_slot * 8, self.arg0(), value_slot * 8, begin_slot * 8, self.arg1(), self.arg2(), length_slot * 8, result_slot * 8).unwrap();
                Ok(Scalar::Str)
            }
            _ => Err(format!(
                "unknown native text function or wrong arguments: {name}"
            )),
        }
    }

    fn list_call(
        &mut self,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        match (name, args) {
            ("count", [list]) => {
                let kind = self.expr(list, scope)?;
                if kind.element().is_none() && kind != Scalar::ListEmpty {
                    return Err("list.count needs a List value".into());
                }
                self.code.push_str("    mov rax, QWORD PTR [rax]\n");
                Ok(Scalar::Int)
            }
            ("append", [list, value]) => {
                let list_kind = self.expr(list, scope)?;
                if list_kind.element().is_none() && list_kind != Scalar::ListEmpty {
                    return Err("list.append needs a List value".into());
                }
                let list_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", list_slot * 8).unwrap();
                let value_kind = self.expr(value, scope)?;
                let result_kind = if list_kind == Scalar::ListEmpty {
                    Scalar::list_of(value_kind)?
                } else if list_kind.element() == Some(value_kind) {
                    list_kind
                } else {
                    return Err("list.append element has the wrong type".into());
                };
                let value_slot = self.reserve_slot()?;
                let result_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10]\n    add rax, 1\n    call gak_alloc_list\n    mov QWORD PTR [rbp-{}], rax", value_slot * 8, list_slot * 8, result_slot * 8).unwrap();
                self.copy_list_items(result_slot, list_slot, 0);
                writeln!(self.code, "    mov rax, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r10]\n    mov r11, QWORD PTR [rbp-{}]\n    mov QWORD PTR [rax+r10*8+8], r11", result_slot * 8, list_slot * 8, value_slot * 8).unwrap();
                Ok(result_kind)
            }
            ("concat", [left, right]) => {
                let left_kind = self.expr(left, scope)?;
                if left_kind.element().is_none() && left_kind != Scalar::ListEmpty {
                    return Err("list.concat needs List values".into());
                }
                let left_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", left_slot * 8).unwrap();
                let right_kind = self.expr(right, scope)?;
                if right_kind.element().is_none() && right_kind != Scalar::ListEmpty {
                    return Err("list.concat needs List values".into());
                }
                let result_kind = if left_kind == Scalar::ListEmpty {
                    right_kind
                } else if right_kind == Scalar::ListEmpty || left_kind == right_kind {
                    left_kind
                } else {
                    return Err("list.concat values have different element types".into());
                };
                let right_slot = self.reserve_slot()?;
                let result_slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax\n    mov r10, QWORD PTR [rbp-{}]\n    mov rax, QWORD PTR [r10]\n    mov r10, QWORD PTR [rbp-{}]\n    add rax, QWORD PTR [r10]\n    call gak_alloc_list\n    mov QWORD PTR [rbp-{}], rax", right_slot * 8, left_slot * 8, right_slot * 8, result_slot * 8).unwrap();
                self.copy_list_items(result_slot, left_slot, 0);
                self.copy_list_items(result_slot, right_slot, left_slot);
                writeln!(
                    self.code,
                    "    mov rax, QWORD PTR [rbp-{}]",
                    result_slot * 8
                )
                .unwrap();
                Ok(result_kind)
            }
            _ => Err(format!("unknown native list function {name}")),
        }
    }

    fn copy_list_items(&mut self, dest_slot: usize, source_slot: usize, offset_slot: usize) {
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    lea {}, [r10+8]\n    mov r10, QWORD PTR [rbp-{}]\n    lea {}, [r10+8]\n    mov r10, QWORD PTR [r10]\n    shl r10, 3\n    mov {}, r10", dest_slot * 8, self.arg0(), source_slot * 8, self.arg1(), if self.windows { "r8" } else { "rdx" }).unwrap();
        if offset_slot != 0 {
            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r10, QWORD PTR [r10]\n    lea {}, [{}+r10*8]", offset_slot * 8, self.arg0(), self.arg0()).unwrap();
        }
        self.code.push_str("    call memcpy\n");
    }

    fn method_call(
        &mut self,
        receiver: &Expr,
        method: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        let Scalar::Record(id) = self.expr(receiver, scope)? else {
            return Err(format!("method {method} needs a class value"));
        };
        let record = self.records.get(&id).ok_or("unknown class type")?;
        let key = (
            record.module.clone(),
            syntax::class_method_key(&record.name, method),
        );
        if !self.functions.contains_key(&key) {
            return Err(format!("unknown method {method} on {}", record.name));
        }
        let slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
        let temporary = format!("__galeikan_receiver_{slot}");
        let mut method_scope = scope.clone();
        method_scope.insert(
            temporary.clone(),
            Binding {
                slot,
                kind: Scalar::Record(id),
                mutable: false,
            },
        );
        let mut method_args = Vec::with_capacity(args.len() + 1);
        method_args.push(Expr {
            kind: ExprKind::Var(temporary),
            line: receiver.line,
            col: receiver.col,
        });
        method_args.extend_from_slice(args);
        self.function_call_resolved(key, method, &method_args, &method_scope)
    }

    fn function_call_resolved(
        &mut self,
        key: (PathBuf, String),
        name: &str,
        args: &[Expr],
        caller_scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        if let Some(id) = self.record_lookup.get(&key).copied() {
            return self.record_constructor(id, name, args, caller_scope);
        }
        let function = self
            .functions
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("native function {name} is unavailable"))?;
        let expected_type = function
            .result_type
            .as_deref()
            .map(|annotation| self.type_name(&function.module, annotation))
            .transpose()?;
        let result_type = expected_type.filter(|kind| matches!(kind, Scalar::Result(_)));
        if function.params.len() != args.len() {
            return Err(format!(
                "{name} expects {} arguments",
                function.params.len()
            ));
        }
        if let Some(frame) = self
            .active_frames
            .iter()
            .rev()
            .find(|frame| frame.key == key)
            .cloned()
        {
            return self.recursive_call(&frame, &function, name, args, caller_scope);
        }
        if self.active_calls.len() >= 64 {
            return Err("native inline call depth exceeds 64".into());
        }
        let mut locals = if function.module == self.root_module {
            self.root_scope.clone()
        } else {
            self.module_scopes
                .get(&function.module)
                .cloned()
                .unwrap_or_default()
        };
        let mut param_slots = Vec::with_capacity(args.len());
        for (param, arg) in function.params.iter().zip(args) {
            let expected = param
                .annotation
                .as_deref()
                .map(|annotation| self.type_name(&function.module, annotation))
                .transpose()?;
            let kind = self.expr_expected(arg, caller_scope, expected)?;
            if let Some(annotation) = &param.annotation {
                if !self.type_name(&function.module, annotation)?.accepts(kind) {
                    return Err(format!(
                        "{name}: parameter {} expects {annotation}",
                        param.name
                    ));
                }
            }
            let slot = self.reserve_slot()?;
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
            locals.insert(
                param.name.clone(),
                Binding {
                    slot,
                    kind: if let Some(annotation) = &param.annotation {
                        self.type_name(&function.module, annotation)?
                    } else {
                        kind
                    },
                    mutable: false,
                },
            );
            param_slots.push((slot, locals[&param.name].kind));
        }
        let body_label = self.label();
        let after_label = self.label();
        let call_reserve = if self.windows { 40 } else { 8 };
        writeln!(self.code, "    call {body_label}\n    jmp {after_label}\n{body_label}:\n    sub rsp, {call_reserve}").unwrap();
        let (stack_slot, depth_slot, base_slot) = if result_type.is_some() {
            let stack = self.reserve_slot()?;
            let depth = self.reserve_slot()?;
            let base = self.reserve_slot()?;
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rsp\n    mov r10, QWORD PTR [rip+gak_call_depth]\n    mov QWORD PTR [rbp-{}], r10\n    mov QWORD PTR [rbp-{}], rbp", stack * 8, depth * 8, base * 8).unwrap();
            (Some(stack), Some(depth), Some(base))
        } else {
            (None, None, None)
        };
        self.active_calls.push(key);
        self.active_frames.push(ActiveFrame {
            key: self.active_calls.last().unwrap().clone(),
            body_label,
            params: param_slots,
            return_kind: expected_type,
        });
        let caller_module = std::mem::replace(&mut self.active_module, function.module.clone());
        let kind = match &function.body {
            FunctionBody::Expression(expr) => {
                if result_type.is_some() {
                    let return_label = self.label();
                    self.return_contexts.push(ReturnContext {
                        label: return_label.clone(),
                        types: Vec::new(),
                        result_type,
                        expected_scalar: expected_type,
                        error_depth: self.error_prefixes.len(),
                        stack_slot,
                        depth_slot,
                        base_slot,
                    });
                    let expression_start = self.code.len();
                    let kind = self.expr_expected(expr, &locals, expected_type)?;
                    let kind = self.normalize_result_return(kind, result_type)?;
                    self.capture_runtime_errors(expression_start)?;
                    self.return_contexts.pop();
                    writeln!(self.code, "{return_label}:").unwrap();
                    kind
                } else {
                    self.expr_expected(expr, &locals, expected_type)?
                }
            }
            FunctionBody::Block(steps, result) => {
                let return_label = self.label();
                self.return_contexts.push(ReturnContext {
                    label: return_label,
                    types: Vec::new(),
                    result_type,
                    expected_scalar: expected_type,
                    error_depth: self.error_prefixes.len(),
                    stack_slot,
                    depth_slot,
                    base_slot,
                });
                for step in steps {
                    self.tick();
                    self.block_step(step, &mut locals)?;
                }
                let fallback_start = self.code.len();
                let fallback_kind = result
                    .as_ref()
                    .map(|expr| self.expr_expected(expr, &locals, expected_type))
                    .transpose()?;
                let fallback_kind = fallback_kind
                    .map(|kind| self.normalize_result_return(kind, result_type))
                    .transpose()?;
                self.capture_runtime_errors(fallback_start)?;
                let context = self.return_contexts.pop().unwrap();
                let mut kind = fallback_kind
                    .or_else(|| context.types.first().copied())
                    .ok_or_else(|| format!("{name}: function has no return value"))?;
                for returned in context.types {
                    kind = kind
                        .merge(returned)
                        .ok_or_else(|| format!("{name}: return paths have different types"))?;
                }
                if fallback_kind.is_none() {
                    self.code.push_str("    ud2\n");
                }
                writeln!(self.code, "{}:", context.label).unwrap();
                kind
            }
        };
        let kind = if let Some(annotation) = &function.result_type {
            let expected = expected_type.unwrap();
            if !expected.accepts(kind) {
                return Err(format!("{name}: return value expects {annotation}"));
            }
            expected
        } else {
            kind
        };
        self.active_calls.pop();
        self.active_frames.pop();
        self.active_module = caller_module;
        writeln!(
            self.code,
            "    add rsp, {call_reserve}\n    ret\n{after_label}:"
        )
        .unwrap();
        self.ensure_size()?;
        Ok(kind)
    }

    fn recursive_call(
        &mut self,
        frame: &ActiveFrame,
        function: &NativeFunction,
        name: &str,
        args: &[Expr],
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        let result = frame.return_kind.ok_or_else(|| {
            format!("native recursive function {name} needs a declared return type")
        })?;
        let mut arguments = Vec::with_capacity(args.len());
        for ((param, (target, expected)), arg) in
            function.params.iter().zip(&frame.params).zip(args)
        {
            let actual = self.expr_expected(arg, scope, Some(*expected))?;
            if !expected.accepts(actual) {
                return Err(format!(
                    "{name}: parameter {} has the wrong type",
                    param.name
                ));
            }
            let slot = self.reserve_slot()?;
            writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
            arguments.push((*target, slot));
        }
        let copy_slots = self.slots;
        let copy = self.label();
        let copied = self.label();
        writeln!(self.code, "    mov r10, QWORD PTR [rip+gak_call_depth]\n    cmp r10, 64\n    jae gak_call_depth_error\n    mov r10, QWORD PTR [rip+gak_main_rbp]\n    sub r10, rsp\n    add r10, gak_frame_reserve+48\n    cmp r10, 524288\n    jae gak_call_stack_error\n    add QWORD PTR [rip+gak_call_depth], 1\n    push rbp\n    mov rbp, rsp\n    sub rsp, gak_frame_reserve+8\n    mov r10, QWORD PTR [rbp]\n    sub r10, 8\n    lea r11, [rbp-8]\n    mov ecx, {copy_slots}\n{copy}:\n    test ecx, ecx\n    jz {copied}\n    mov rax, QWORD PTR [r10]\n    mov QWORD PTR [r11], rax\n    sub r10, 8\n    sub r11, 8\n    dec ecx\n    jmp {copy}\n{copied}:").unwrap();
        for (target, source) in arguments {
            writeln!(self.code, "    mov r10, QWORD PTR [rbp]\n    mov r11, QWORD PTR [r10-{}]\n    mov QWORD PTR [rbp-{}], r11", source * 8, target * 8).unwrap();
        }
        writeln!(
            self.code,
            "    call {}\n    mov rsp, rbp\n    pop rbp\n    sub QWORD PTR [rip+gak_call_depth], 1",
            frame.body_label
        )
        .unwrap();
        Ok(result)
    }

    fn normalize_result_return(
        &mut self,
        actual: Scalar,
        expected: Option<Scalar>,
    ) -> Result<Scalar, String> {
        let Some(Scalar::Result(inner)) = expected else {
            return Ok(actual);
        };
        let result = Scalar::Result(inner);
        if result.accepts(actual) {
            return Ok(result);
        }
        if inner.is_some_and(|value| value.scalar() == actual) {
            self.code
                .push_str("    xor edx, edx\n    call gak_alloc_result\n");
            return Ok(result);
        }
        Err("native Result return value has the wrong type".into())
    }

    fn expr(&mut self, expr: &Expr, scope: &HashMap<String, Binding>) -> Result<Scalar, String> {
        match &expr.kind {
            ExprKind::List(items) => {
                if items.len() > MAX_RANGE_ITEMS as usize {
                    return Err(format!("list exceeds {MAX_RANGE_ITEMS} items"));
                }
                let mut element = None;
                let mut slots = Vec::with_capacity(items.len());
                for item in items {
                    let kind = self.expr(item, scope)?;
                    if let Some(previous) = element {
                        if previous != kind {
                            return Err("list elements must have one type".into());
                        }
                    } else {
                        Scalar::list_of(kind)?;
                        element = Some(kind);
                    }
                    let slot = self.reserve_slot()?;
                    writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                    slots.push(slot);
                }
                writeln!(
                    self.code,
                    "    mov rax, {}\n    call gak_alloc_list",
                    items.len()
                )
                .unwrap();
                for (index, slot) in slots.iter().enumerate() {
                    writeln!(
                        self.code,
                        "    mov r10, QWORD PTR [rbp-{}]\n    mov QWORD PTR [rax+{}], r10",
                        slot * 8,
                        (index + 1) * 8
                    )
                    .unwrap();
                }
                match element {
                    Some(kind) => Scalar::list_of(kind),
                    None => Ok(Scalar::ListEmpty),
                }
            }
            ExprKind::Index(list, index) => {
                let list_kind = self.expr(list, scope)?;
                let element = list_kind
                    .element()
                    .ok_or("native indexing needs a typed List value")?;
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                if self.expr(index, scope)? != Scalar::Int {
                    return Err("list index must be i64".into());
                }
                writeln!(self.code, "    test rax, rax\n    js gak_list_index\n    mov r10, QWORD PTR [rbp-{}]\n    cmp rax, QWORD PTR [r10]\n    jae gak_list_index\n    mov rax, QWORD PTR [r10+rax*8+8]", slot * 8).unwrap();
                Ok(element)
            }
            ExprKind::Field(value, field) => {
                let kind = self.expr(value, scope)?;
                self.field(kind, field)
            }
            ExprKind::Int(value) => {
                writeln!(self.code, "    mov rax, {value}").unwrap();
                Ok(Scalar::Int)
            }
            ExprKind::UInt(value) => {
                writeln!(self.code, "    mov rax, {value}").unwrap();
                Ok(Scalar::UInt)
            }
            ExprKind::Bool(value) => {
                writeln!(self.code, "    mov eax, {}", u8::from(*value)).unwrap();
                Ok(Scalar::Bool)
            }
            ExprKind::Str(value) => {
                let label = self.literal(value)?;
                writeln!(self.code, "    lea rax, [rip+{label}]").unwrap();
                Ok(Scalar::Str)
            }
            ExprKind::Var(name) => {
                let (binding, fields) = if let Some((alias, key)) = name.split_once('.') {
                    if let Some(NativeImport::Local(module)) = self
                        .module_imports
                        .get(&self.active_module)
                        .and_then(|imports| imports.get(alias))
                    {
                        let (base, fields) = key.split_once('.').unwrap_or((key, ""));
                        (
                            self.module_scopes
                                .get(module)
                                .and_then(|scope| scope.get(base))
                                .copied(),
                            fields,
                        )
                    } else {
                        (scope.get(alias).copied(), key)
                    }
                } else {
                    (scope.get(name).copied(), "")
                };
                let binding = binding.ok_or_else(|| format!("unknown native binding {name}"))?;
                writeln!(
                    self.code,
                    "    mov rax, QWORD PTR [rbp-{}]",
                    binding.slot * 8
                )
                .unwrap();
                let mut kind = binding.kind;
                if !fields.is_empty() {
                    for field in fields.split('.') {
                        kind = self.field(kind, field)?;
                    }
                }
                Ok(kind)
            }
            ExprKind::Neg(inner) => {
                if self.expr(inner, scope)? != Scalar::Int {
                    return Err("negation expects i64".into());
                }
                self.code.push_str("    neg rax\n    jo gak_overflow\n");
                Ok(Scalar::Int)
            }
            ExprKind::BitNot(inner) => {
                let kind = self.expr(inner, scope)?;
                if !matches!(kind, Scalar::Int | Scalar::UInt) {
                    return Err("bitwise not expects i64 or u64".into());
                }
                self.code.push_str("    not rax\n");
                Ok(kind)
            }
            ExprKind::Not(inner) => {
                if self.expr(inner, scope)? != Scalar::Bool {
                    return Err("not expects bool".into());
                }
                self.code.push_str("    xor rax, 1\n");
                Ok(Scalar::Bool)
            }
            ExprKind::Binary(left, Op::And, right) => {
                if self.expr(left, scope)? != Scalar::Bool {
                    return Err("and expects bool".into());
                }
                let end = self.label();
                self.code.push_str("    test rax, rax\n");
                writeln!(self.code, "    jz {end}").unwrap();
                if self.expr(right, scope)? != Scalar::Bool {
                    return Err("and expects bool".into());
                }
                writeln!(self.code, "{end}:").unwrap();
                Ok(Scalar::Bool)
            }
            ExprKind::Binary(left, Op::Or, right) => {
                if self.expr(left, scope)? != Scalar::Bool {
                    return Err("or expects bool".into());
                }
                let end = self.label();
                self.code.push_str("    test rax, rax\n");
                writeln!(self.code, "    jnz {end}").unwrap();
                if self.expr(right, scope)? != Scalar::Bool {
                    return Err("or expects bool".into());
                }
                writeln!(self.code, "{end}:").unwrap();
                Ok(Scalar::Bool)
            }
            ExprKind::Binary(left, op, right) => self.binary(left, *op, right, scope),
            ExprKind::If(condition, yes, no) => {
                if self.expr(condition, scope)? != Scalar::Bool {
                    return Err("if condition must be bool".into());
                }
                let else_label = self.label();
                let end_label = self.label();
                self.code.push_str("    test rax, rax\n");
                writeln!(self.code, "    jz {else_label}").unwrap();
                let yes_kind = self.expr(yes, scope)?;
                writeln!(self.code, "    jmp {end_label}\n{else_label}:").unwrap();
                let no_kind = self.expr(no, scope)?;
                let kind = yes_kind
                    .merge(no_kind)
                    .ok_or("if branches must have the same native type")?;
                writeln!(self.code, "{end_label}:").unwrap();
                Ok(kind)
            }
            ExprKind::Match(subject, arms, default) => {
                let subject_kind = self.expr(subject, scope)?;
                if !matches!(
                    subject_kind,
                    Scalar::Int | Scalar::UInt | Scalar::Bool | Scalar::Str
                ) {
                    return Err("match subject must be i64, u64, bool, or str".into());
                }
                let slot = self.reserve_slot()?;
                writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", slot * 8).unwrap();
                let end = self.label();
                let mut branch_kind: Option<Scalar> = None;
                for (pattern, value) in arms {
                    let next = self.label();
                    match (subject_kind, pattern) {
                        (Scalar::Int, MatchPattern::Int(number)) => {
                            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r11, {number}\n    cmp r10, r11\n    jne {next}", slot * 8).unwrap();
                        }
                        (Scalar::UInt, MatchPattern::UInt(number)) => {
                            writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]\n    mov r11, {number}\n    cmp r10, r11\n    jne {next}", slot * 8).unwrap();
                        }
                        (Scalar::Bool, MatchPattern::Bool(flag)) => {
                            writeln!(
                                self.code,
                                "    cmp QWORD PTR [rbp-{}], {}\n    jne {next}",
                                slot * 8,
                                u8::from(*flag)
                            )
                            .unwrap();
                        }
                        (Scalar::Str, MatchPattern::Str(text)) => {
                            let label = self.literal(text)?;
                            writeln!(self.code, "    mov {}, QWORD PTR [rbp-{}]\n    lea {}, [rip+{label}]\n    call gak_str_eq\n    test eax, eax\n    jz {next}", self.arg0(), slot * 8, self.arg1()).unwrap();
                        }
                        _ => return Err("match pattern has a different scalar type".into()),
                    }
                    let kind = self.expr(value, scope)?;
                    branch_kind = Some(match branch_kind {
                        Some(previous) => previous
                            .merge(kind)
                            .ok_or("match branches must have the same native type")?,
                        None => kind,
                    });
                    writeln!(self.code, "    jmp {end}\n{next}:").unwrap();
                }
                let default_kind = self.expr(default, scope)?;
                let kind = match branch_kind {
                    Some(previous) => previous
                        .merge(default_kind)
                        .ok_or("match branches must have the same native type")?,
                    None => default_kind,
                };
                writeln!(self.code, "{end}:").unwrap();
                Ok(kind)
            }
            ExprKind::Call(name, args) => self.function_call(name, args, scope),
            ExprKind::MethodCall(receiver, method, args) => {
                self.method_call(receiver, method, args, scope)
            }
            ExprKind::Try(inner) => {
                let kind = self.expr(inner, scope)?;
                let Scalar::Result(value) = kind else {
                    return Err("? expects Result<T>".into());
                };
                let Some(value) = value else {
                    return Err("native ? needs a typed Result<T>".into());
                };
                let success = self.label();
                writeln!(self.code, "    cmp QWORD PTR [rax], 0\n    je {success}").unwrap();
                let handler = self
                    .return_contexts
                    .iter()
                    .rev()
                    .find(|context| context.result_type.is_some())
                    .cloned();
                let depth = handler.as_ref().map_or(0, |context| context.error_depth);
                for prefix in self.error_prefixes[depth..]
                    .iter()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    let label = self.literal(&prefix)?;
                    writeln!(
                        self.code,
                        "    lea r10, [rip+{label}]\n    call gak_prefix_result"
                    )
                    .unwrap();
                }
                if let Some(context) = handler {
                    self.restore_return_context(&context);
                    writeln!(self.code, "    jmp {}", context.label).unwrap();
                } else {
                    self.code.push_str("    jmp gak_uncaught_result\n");
                }
                writeln!(self.code, "{success}:\n    mov rax, QWORD PTR [rax+8]").unwrap();
                Ok(value.scalar())
            }
        }
    }

    fn binary(
        &mut self,
        left: &Expr,
        op: Op,
        right: &Expr,
        scope: &HashMap<String, Binding>,
    ) -> Result<Scalar, String> {
        let left_kind = self.expr(left, scope)?;
        let left_slot = self.reserve_slot()?;
        writeln!(self.code, "    mov QWORD PTR [rbp-{}], rax", left_slot * 8).unwrap();
        let right_kind = self.expr(right, scope)?;
        writeln!(self.code, "    mov r10, QWORD PTR [rbp-{}]", left_slot * 8).unwrap();
        if left_kind != right_kind
            || matches!(left_kind, Scalar::Record(_))
            || left_kind.element().is_some()
            || left_kind == Scalar::ListEmpty
        {
            return Err("native binary operator expects matching scalar values".into());
        }
        if left_kind == Scalar::Str {
            if matches!(op, Op::Add) {
                writeln!(
                    self.code,
                    "    mov r11, QWORD PTR [r10]\n    add r11, QWORD PTR [rax]\n    jc gak_str_limit\n    cmp r11, 67108856\n    ja gak_str_limit\n    lea r8, [r11+8]\n    mov r9, QWORD PTR [rip+gak_str_bytes]\n    add r9, r8\n    jc gak_str_limit\n    cmp r9, 67108864\n    ja gak_str_limit\n    mov {}, r10\n    mov {}, rax\n    call gak_str_concat",
                    self.arg0(),
                    self.arg1()
                )
                .unwrap();
                return Ok(Scalar::Str);
            }
            if !matches!(op, Op::Eq | Op::Ne) {
                return Err("native str supports addition and equality comparisons only".into());
            }
            writeln!(
                self.code,
                "    mov {}, r10\n    mov {}, rax\n    call gak_str_eq",
                self.arg0(),
                self.arg1()
            )
            .unwrap();
            if matches!(op, Op::Ne) {
                self.code.push_str("    xor eax, 1\n");
            }
            return Ok(Scalar::Bool);
        }
        match op {
            Op::BitAnd | Op::BitOr | Op::BitXor
                if matches!(left_kind, Scalar::Int | Scalar::UInt) =>
            {
                self.code.push_str(match op {
                    Op::BitAnd => "    and rax, r10\n",
                    Op::BitOr => "    or rax, r10\n",
                    Op::BitXor => "    xor rax, r10\n",
                    _ => unreachable!(),
                });
                Ok(left_kind)
            }
            Op::Shl | Op::Shr | Op::Ushr if matches!(left_kind, Scalar::Int | Scalar::UInt) => {
                self.code.push_str(
                    "    cmp rax, 63\n    ja gak_shift_range\n    mov rcx, rax\n    mov rax, r10\n",
                );
                self.code.push_str(match op {
                    Op::Shl => "    shl rax, cl\n",
                    Op::Shr if left_kind == Scalar::Int => "    sar rax, cl\n",
                    Op::Shr => "    shr rax, cl\n",
                    Op::Ushr => "    shr rax, cl\n",
                    _ => unreachable!(),
                });
                Ok(left_kind)
            }
            Op::Add | Op::Sub | Op::Mul | Op::Div if left_kind == Scalar::UInt => {
                match op {
                    Op::Add => self.code.push_str("    add rax, r10\n    jc gak_overflow\n"),
                    Op::Sub => self.code.push_str("    sub r10, rax\n    jc gak_overflow\n    mov rax, r10\n"),
                    Op::Mul => self.code.push_str("    mov r11, rax\n    mov rax, r10\n    mul r11\n    test rdx, rdx\n    jnz gak_overflow\n"),
                    Op::Div => self.code.push_str("    mov r11, rax\n    test r11, r11\n    jz gak_divzero\n    mov rax, r10\n    xor edx, edx\n    div r11\n"),
                    _ => unreachable!(),
                }
                Ok(Scalar::UInt)
            }
            Op::Add | Op::Sub | Op::Mul | Op::Div if left_kind == Scalar::Int => {
                match op {
                    Op::Add => self
                        .code
                        .push_str("    add rax, r10\n    jo gak_overflow\n"),
                    Op::Sub => self
                        .code
                        .push_str("    sub r10, rax\n    jo gak_overflow\n    mov rax, r10\n"),
                    Op::Mul => self
                        .code
                        .push_str("    imul rax, r10\n    jo gak_overflow\n"),
                    Op::Div => {
                        let safe = self.label();
                        writeln!(self.code, "    mov r11, rax\n    test r11, r11\n    jz gak_divzero\n    mov rax, r10\n    mov r10, 0x8000000000000000\n    cmp rax, r10\n    jne {safe}\n    cmp r11, -1\n    je gak_overflow\n{safe}:\n    cqo\n    idiv r11").unwrap();
                    }
                    _ => unreachable!(),
                }
                Ok(Scalar::Int)
            }
            Op::Eq | Op::Ne => {
                self.code.push_str("    cmp r10, rax\n");
                self.code.push_str(if matches!(op, Op::Eq) {
                    "    sete al\n"
                } else {
                    "    setne al\n"
                });
                self.code.push_str("    movzx rax, al\n");
                Ok(Scalar::Bool)
            }
            Op::Lt | Op::Le | Op::Gt | Op::Ge if left_kind == Scalar::Int => {
                self.code.push_str("    cmp r10, rax\n");
                self.code.push_str(match op {
                    Op::Lt => "    setl al\n",
                    Op::Le => "    setle al\n",
                    Op::Gt => "    setg al\n",
                    Op::Ge => "    setge al\n",
                    _ => unreachable!(),
                });
                self.code.push_str("    movzx rax, al\n");
                Ok(Scalar::Bool)
            }
            Op::Lt | Op::Le | Op::Gt | Op::Ge if left_kind == Scalar::UInt => {
                self.code.push_str("    cmp r10, rax\n");
                self.code.push_str(match op {
                    Op::Lt => "    setb al\n",
                    Op::Le => "    setbe al\n",
                    Op::Gt => "    seta al\n",
                    Op::Ge => "    setae al\n",
                    _ => unreachable!(),
                });
                self.code.push_str("    movzx rax, al\n");
                Ok(Scalar::Bool)
            }
            _ => Err("native operator is not valid for these scalar types".into()),
        }
    }

    fn finish(self) -> Result<String, String> {
        let shadow = if self.windows { 32 } else { 0 };
        let bytes = self
            .slots
            .checked_mul(8)
            .and_then(|n| n.checked_add(shadow))
            .ok_or("native frame size overflow")?;
        let reserve = (bytes + 15) & !15;
        let mut out = String::new();
        writeln!(out, ".equ gak_frame_reserve, {reserve}").unwrap();
        out.push_str(".intel_syntax noprefix\n.section .rodata\ngak_int_fmt: .asciz \"%lld\\n\"\ngak_true: .asciz \"true\"\ngak_false: .asciz \"false\"\ngak_overflow_msg: .ascii \"integer overflow\\n\"\ngak_overflow_msg_end:\ngak_divzero_msg: .ascii \"division by zero\\n\"\ngak_divzero_msg_end:\ngak_shift_range_msg: .ascii \"shift count must be in 0..63\\n\"\ngak_shift_range_msg_end:\ngak_limit_msg: .ascii \"execution exceeds 1000000 action steps\\n\"\ngak_limit_msg_end:\ngak_range_start_msg: .ascii \"range start must not be negative\\n\"\ngak_range_start_msg_end:\ngak_range_end_msg: .ascii \"range end must not be negative\\n\"\ngak_range_end_msg_end:\ngak_range_limit_msg: .ascii \"range exceeds 100000 items\\n\"\ngak_range_limit_msg_end:\ngak_record_limit_msg: .ascii \"native struct memory exceeds 64 MiB\\n\"\ngak_record_limit_msg_end:\ngak_alloc_failure_msg: .ascii \"native allocation failed\\n\"\ngak_alloc_failure_msg_end:\ngak_list_limit_msg: .ascii \"list exceeds 100000 items or 64 MiB of native allocations\\n\"\ngak_list_limit_msg_end:\ngak_list_index_msg: .ascii \"list index out of range\\n\"\ngak_list_index_msg_end:\n");
        out.push_str("gak_uint_fmt: .asciz \"%llu\\n\"\ngak_int_inner_fmt: .asciz \"%lld\"\ngak_uint_inner_fmt: .asciz \"%llu\"\ngak_result_ok_prefix: .ascii \"ok(\"\ngak_result_error_prefix: .ascii \"error(\"\ngak_result_suffix: .byte 41,10\n");
        out.push_str("gak_newline: .byte 10\ngak_call_depth_error_msg: .ascii \"call depth exceeded\\n\"\ngak_call_depth_error_msg_end:\ngak_call_stack_error_msg: .ascii \"native call stack exceeds 512 KiB\\n\"\ngak_call_stack_error_msg_end:\ngak_str_limit_msg: .ascii \"string memory exceeds 64 MiB\\n\"\ngak_str_limit_msg_end:\ngak_output_failure_msg: .ascii \"native output failed\\n\"\ngak_output_failure_msg_end:\n");
        out.push_str("gak_text_slice_range_msg: .ascii \"text slice out of range\\n\"\ngak_text_slice_range_msg_end:\n");
        out.push_str("gak_text_search_alloc_msg: .ascii \"text search allocation failed\\n\"\ngak_text_search_alloc_msg_end:\n");
        out.push_str("gak_hex_digits: .ascii \"0123456789abcdef\"\ngak_hex_invalid_msg: .ascii \"invalid hex data\\n\"\ngak_hex_invalid_msg_end:\ngak_hex_odd_msg: .ascii \"hex data needs an even number of digits\\n\"\ngak_hex_odd_msg_end:\ngak_hex_limit_msg: .ascii \"hex data exceeds 1048576 bytes\\n\"\ngak_hex_limit_msg_end:\ngak_bytes_limit_msg: .ascii \"LimitExceeded: bytes result exceeds 1048576 bytes\\n\"\ngak_bytes_limit_msg_end:\ngak_bytes_index_msg: .ascii \"byte index out of range\\n\"\ngak_bytes_index_msg_end:\n");
        out.push_str(".p2align 2\ngak_sha_iv:\n");
        for value in SHA256_IV {
            writeln!(out, "    .long 0x{value:08x}").unwrap();
        }
        out.push_str("gak_sha_k:\n");
        for value in SHA256_K {
            writeln!(out, "    .long 0x{value:08x}").unwrap();
        }
        out.push_str("gak_binary_offset_negative_msg: .ascii \"offset must not be negative\\n\"\ngak_binary_offset_negative_msg_end:\ngak_binary_length_negative_msg: .ascii \"length must not be negative\\n\"\ngak_binary_length_negative_msg_end:\ngak_binary_range_overflow_msg: .ascii \"range overflow\\n\"\ngak_binary_range_overflow_msg_end:\ngak_binary_out_of_bounds_msg: .ascii \"out of bounds\\n\"\ngak_binary_out_of_bounds_msg_end:\ngak_binary_unknown_decoder_msg: .ascii \"unknown decoder\\n\"\ngak_binary_unknown_decoder_msg_end:\ngak_hexdump_limit_msg: .ascii \"hexdump length exceeds 4096 bytes\\n\"\ngak_hexdump_limit_msg_end:\ngak_observation_value_range_msg: .ascii \"Observation value does not fit i64\\n\"\ngak_observation_value_range_msg_end:\ngak_observation_limit_msg: .ascii \"native Observation memory exceeds 64 MiB\\n\"\ngak_observation_limit_msg_end:\n");
        out.push_str("gak_analyze_max_msg: .ascii \"max_bytes must be between 0 and 536870912\\n\"\ngak_analyze_max_msg_end:\n");
        out.push_str("gak_text_offset_negative_msg: .ascii \"text offset must not be negative\\n\"\ngak_text_offset_negative_msg_end:\ngak_max_chars_range_msg: .ascii \"max_chars out of range\\n\"\ngak_max_chars_range_msg_end:\ngak_max_chars_limit_msg: .ascii \"max_chars must be 1 to 4096\\n\"\ngak_max_chars_limit_msg_end:\ngak_text_encoding_msg: .ascii \"text encoding must be ascii, utf16le, or utf16be\\n\"\ngak_text_encoding_msg_end:\ngak_text_offset_bounds_msg: .ascii \"text offset out of bounds\\n\"\ngak_text_offset_bounds_msg_end:\ngak_text_not_printable_msg: .ascii \"no printable text at offset\\n\"\ngak_text_not_printable_msg_end:\n");
        out.push_str("gak_strings_minimum_range_msg: .ascii \"minimum string length out of range\\n\"\ngak_strings_minimum_range_msg_end:\ngak_strings_minimum_limit_msg: .ascii \"minimum string length must be 1 to 4096\\n\"\ngak_strings_minimum_limit_msg_end:\ngak_strings_many_msg: .ascii \"too many strings\\n\"\ngak_strings_many_msg_end:\n");
        out.push_str("gak_hunt_invalid_hex_msg: .ascii \"invalid hex pattern\\n\"\ngak_hunt_invalid_hex_msg_end:\ngak_hunt_hex_limit_msg: .ascii \"hex pattern exceeds 1048576 bytes\\n\"\ngak_hunt_hex_limit_msg_end:\ngak_hunt_odd_hex_msg: .ascii \"hex pattern needs an even number of nibbles\\n\"\ngak_hunt_odd_hex_msg_end:\ngak_hunt_mask_limit_msg: .ascii \"masked hex pattern exceeds 64 bytes\\n\"\ngak_hunt_mask_limit_msg_end:\ngak_hunt_empty_msg: .ascii \"empty search pattern\\n\"\ngak_hunt_empty_msg_end:\ngak_hunt_many_msg: .ascii \"too many matches\\n\"\ngak_hunt_many_msg_end:\n");
        out.push_str("gak_diff_limit_negative_msg: .ascii \"max_differences out of range\\n\"\ngak_diff_limit_negative_msg_end:\ngak_diff_limit_msg: .ascii \"max_differences must be at most 10000\\n\"\ngak_diff_limit_msg_end:\ngak_diff_many_msg: .ascii \"LimitExceeded: too many differences\\n\"\ngak_diff_many_msg_end:\ngak_diff_memory_msg: .ascii \"native Diff memory exceeds 64 MiB\\n\"\ngak_diff_memory_msg_end:\n");
        out.push_str("gak_patch_empty_msg: .ascii \"patch data must not be empty\\n\"\ngak_patch_empty_msg_end:\ngak_patch_limit_msg: .ascii \"LimitExceeded: patch exceeds 1048576 bytes\\n\"\ngak_patch_limit_msg_end:\n");
        out.push_str("gak_splice_insert_limit_msg: .ascii \"LimitExceeded: splice insertion exceeds 1048576 bytes\\n\"\ngak_splice_insert_limit_msg_end:\ngak_splice_empty_msg: .ascii \"splice must insert or remove at least one byte\\n\"\ngak_splice_empty_msg_end:\ngak_splice_size_overflow_msg: .ascii \"splice size overflow\\n\"\ngak_splice_size_overflow_msg_end:\ngak_splice_size_limit_msg: .ascii \"LimitExceeded: Source exceeds 536870912 bytes\\n\"\ngak_splice_size_limit_msg_end:\n");
        out.push_str("gak_text_limit_prefix: .ascii \"LimitExceeded: text exceeds \"\ngak_text_limit_prefix_end:\ngak_text_limit_suffix: .ascii \" characters\"\ngak_text_limit_suffix_end:\n");
        out.push_str("gak_source_depth_msg: .ascii \"LimitExceeded: Source derivation depth exceeds 64\\n\"\ngak_source_depth_msg_end:\ngak_source_limit_msg: .ascii \"native Source memory exceeds 64 MiB\\n\"\ngak_source_limit_msg_end:\ngak_source_backing_limit_msg: .ascii \"native Source backing memory exceeds 512 MiB\\n\"\ngak_source_backing_limit_msg_end:\n");
        out.push_str("gak_repeat_negative_msg: .ascii \"repeat count must not be negative\\n\"\ngak_repeat_negative_msg_end:\ngak_repeat_count_limit_msg: .ascii \"repeat count exceeds 1048576\\n\"\ngak_repeat_count_limit_msg_end:\ngak_xor_empty_key_msg: .ascii \"xor key must not be empty\\n\"\ngak_xor_empty_key_msg_end:\n");
        out.push_str("gak_pack_negative_msg: .ascii \"pack expects a nonnegative value\\n\"\ngak_pack_negative_msg_end:\ngak_pack_encoding_msg: .ascii \"pack encoding must be u8, u16le/be, u32le/be, or u64le/be\\n\"\ngak_pack_encoding_msg_end:\n");
        for format in ["u8", "u16le", "u16be", "u32le", "u32be"] {
            writeln!(out, "gak_pack_range_{format}_msg: .ascii \"pack value out of range for {format}\\n\"\ngak_pack_range_{format}_msg_end:").unwrap();
        }
        out.push_str("gak_result_limit_msg: .ascii \"result memory exceeds 64 MiB\\n\"\ngak_result_limit_msg_end:\ngak_result_invalid_msg: .ascii \"result.fail needs a nonempty message of at most 4096 bytes\\n\"\ngak_result_invalid_msg_end:\ngak_result_message_success_msg: .ascii \"result.message requires a failed Result\\n\"\ngak_result_message_success_msg_end:\ngak_result_untyped_success_msg: .ascii \"untyped Result cannot contain success\\n\"\ngak_result_untyped_success_msg_end:\n");
        out.push_str("gak_cli_index_msg: .ascii \"argument index out of range\\n\"\ngak_cli_index_msg_end:\ngak_cli_invalid_msg: .ascii \"CLI argument is not an i64\\n\"\ngak_cli_invalid_msg_end:\ngak_cli_utf8_msg: .ascii \"cannot encode CLI argument as UTF-8\\n\"\ngak_cli_utf8_msg_end:\n");
        out.push_str(&self.data);
        out.push_str("gak_memory_box: .quad 6\n    .ascii \"memory\"\n.bss\n.align 8\ngak_steps: .quad 0\ngak_call_depth: .quad 0\ngak_main_rbp: .quad 0\ngak_native_call_mode: .byte 0\ngak_native_call_dispatch_active: .byte 0\n.align 8\ngak_record_bytes: .quad 0\n.globl gak_list_bytes\ngak_list_bytes: .quad 0\n.globl gak_bytes_allocated\ngak_bytes_allocated: .quad 0\ngak_source_bytes: .quad 0\n.globl gak_source_backing_bytes\ngak_source_backing_bytes: .quad 0\ngak_observation_bytes: .quad 0\ngak_diff_bytes: .quad 0\n.globl gak_str_bytes\ngak_str_bytes: .quad 0\ngak_result_bytes: .quad 0\n.globl gak_argc\n.globl gak_argv\ngak_argc: .quad 0\ngak_argv: .quad 0\ngak_cli_cache: .quad 0\n");
        out.push_str(".text\n.globl main\nmain:\n    push rbp\n    mov rbp, rsp\n    mov QWORD PTR [rip+gak_main_rbp], rbp\n");
        writeln!(out, "    sub rsp, {reserve}").unwrap();
        if self.windows {
            out.push_str("    call GetCommandLineW\n    mov rcx, rax\n    lea rdx, [rip+gak_argc]\n    call CommandLineToArgvW\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rip+gak_argv], rax\n");
            if self.uses_file_read || self.uses_python || self.uses_process || self.uses_net {
                out.push_str(
                    "    call gak_native_init\n    test eax, eax\n    jnz gak_native_init_error\n",
                );
                out.push_str("    mov DWORD PTR [rip+gak_native_call_grants_processed], 1\n");
            }
            out.push_str(
                "    call gak_native_call_begin\n    mov BYTE PTR [rip+gak_native_call_mode], al\n",
            );
            out.push_str("    mov ecx, DWORD PTR [rip+gak_argc]\n    mov edx, 8\n    call calloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rip+gak_cli_cache], rax\n");
            out.push_str("    mov ecx, 1\n    mov edx, 0x8000\n    call _setmode\n    mov ecx, 2\n    mov edx, 0x8000\n    call _setmode\n");
        } else {
            out.push_str("    mov eax, edi\n    mov QWORD PTR [rip+gak_argc], rax\n    mov QWORD PTR [rip+gak_argv], rsi\n");
            if self.uses_file_read || self.uses_python || self.uses_process || self.uses_net {
                out.push_str(
                    "    call gak_native_init\n    test eax, eax\n    jnz gak_native_init_error\n",
                );
                out.push_str("    mov DWORD PTR [rip+gak_native_call_grants_processed], 1\n");
            }
            out.push_str(
                "    call gak_native_call_begin\n    mov BYTE PTR [rip+gak_native_call_mode], al\n",
            );
        }
        out.push_str(&self.code);
        out.push_str("    xor eax, eax\n    mov rsp, rbp\n    pop rbp\n    ret\n");
        out.push_str("gak_alloc_list:\n    push rbx\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    cmp rbx, 100000\n    ja gak_list_limit\n    lea r11, [rbx+1]\n    shl r11, 3\n    mov r10, QWORD PTR [rip+gak_list_bytes]\n    add r10, r11\n    cmp r10, 67108864\n    ja gak_list_limit\n    mov QWORD PTR [rip+gak_list_bytes], r10\n");
        writeln!(out, "    mov {}, r11\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rax], rbx", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rbx\n    ret\n");
        out.push_str("gak_alloc_source_backing:\n    push rbx\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    cmp rbx, 536870912\n    ja gak_source_backing_limit\n    lea r11, [rbx+8]\n    mov r10, QWORD PTR [rip+gak_source_backing_bytes]\n    add r10, r11\n    jc gak_source_backing_limit\n    cmp r10, 536870920\n    ja gak_source_backing_limit\n    mov QWORD PTR [rip+gak_source_backing_bytes], r10\n");
        writeln!(out, "    mov {}, r11\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rax], rbx", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rbx\n    ret\n");
        out.push_str("gak_parse_i64:\n    mov r10, rax\n    xor r11, r11\n    xor ecx, ecx\n    movzx edx, BYTE PTR [r10]\n    cmp dl, 45\n    jne gak_parse_plus\n    mov ecx, 1\n    inc r10\n    jmp gak_parse_first\ngak_parse_plus:\n    cmp dl, 43\n    jne gak_parse_first\n    inc r10\ngak_parse_first:\n    movzx edx, BYTE PTR [r10]\n    cmp dl, 48\n    jb gak_cli_invalid\n    cmp dl, 57\n    ja gak_cli_invalid\ngak_parse_loop:\n    movzx edx, BYTE PTR [r10]\n    test dl, dl\n    jz gak_parse_done\n    cmp dl, 48\n    jb gak_cli_invalid\n    cmp dl, 57\n    ja gak_cli_invalid\n    sub edx, 48\n    imul r11, r11, 10\n    jo gak_cli_invalid\n    sub r11, rdx\n    jo gak_cli_invalid\n    inc r10\n    jmp gak_parse_loop\ngak_parse_done:\n    test ecx, ecx\n    jnz gak_parse_negative\n    neg r11\n    jo gak_cli_invalid\ngak_parse_negative:\n    mov rax, r11\n    ret\n");
        out.push_str("gak_str_eq:\n    push rbx\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        writeln!(out, "    mov rbx, {}\n    mov r10, {}\n    mov r11, QWORD PTR [rbx]\n    cmp r11, QWORD PTR [r10]\n    jne gak_str_eq_false\n    lea {}, [rbx+8]\n    lea {}, [r10+8]\n    mov {}, r11\n    call memcmp\n    test eax, eax\n    sete al\n    movzx eax, al\n    jmp gak_str_eq_done\ngak_str_eq_false:\n    xor eax, eax\ngak_str_eq_done:", self.arg0(), self.arg1(), self.arg0(), self.arg1(), self.arg2()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rbx\n    ret\n");
        out.push_str("gak_box_c_string:\n    push rbx\n    push r12\n    push r13\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        writeln!(out, "    mov rbx, rax\n    mov {}, rbx\n    call strlen\n    mov r12, rax\n    lea r11, [r12+8]\n    mov r10, QWORD PTR [rip+gak_str_bytes]\n    add r10, r11\n    cmp r10, 67108864\n    ja gak_str_limit\n    mov QWORD PTR [rip+gak_str_bytes], r10\n    mov {}, r11\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov r13, rax\n    mov QWORD PTR [r13], r12\n    lea {}, [r13+8]\n    mov {}, rbx\n    mov {}, r12\n    call memcpy\n    mov rax, r13", self.arg0(), self.arg0(), self.arg0(), self.arg1(), self.arg2()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_write_span:\n    push rbx\n    push r12\n    push r13\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        writeln!(out, "    mov r12, rax\n    mov r13, rdx\n    xor {}, {}\n    call fflush\n    test eax, eax\n    jnz gak_output_failure\ngak_write_span_loop:\n    test r13, r13\n    jz gak_write_span_done\n    mov {}, 1\n    mov {}, r12\n    mov {}, r13\n    call {}\n    cmp eax, 0\n    jle gak_output_failure\n    movsxd rax, eax\n    add r12, rax\n    sub r13, rax\n    jmp gak_write_span_loop\ngak_write_span_done:", self.arg0(), self.arg0(), self.arg0(), self.arg1(), self.arg2(), if self.windows { "_write" } else { "write" }).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_alloc_result:\n    push rbx\n    push r12\n");
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov r11, QWORD PTR [rip+gak_result_bytes]\n    add r11, 16\n    cmp r11, 67108864\n    ja gak_result_limit\n    mov QWORD PTR [rip+gak_result_bytes], r11\n");
        writeln!(out, "    mov {}, 16\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rax], r12\n    mov QWORD PTR [rax+8], rbx", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_alloc_bytes:\n    push rbx\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    cmp rbx, 1048576\n    ja gak_bytes_limit\n    lea r11, [rbx+8]\n    mov r10, QWORD PTR [rip+gak_bytes_allocated]\n    add r10, r11\n    jc gak_bytes_limit\n    cmp r10, 67108864\n    ja gak_bytes_limit\n    mov QWORD PTR [rip+gak_bytes_allocated], r10\n");
        writeln!(out, "    mov {}, r11\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rax], rbx", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rbx\n    ret\n");
        out.push_str("gak_alloc_source:\n    push rbx\n    push r12\n    push r13\n    push r14\n    push r15\n    push rsi\n");
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov r13, r10\n    mov r14, r11\n    mov r15, r8\n    mov r10, QWORD PTR [rip+gak_source_bytes]\n    add r10, 112\n    jc gak_source_limit\n    cmp r10, 67108864\n    ja gak_source_limit\n    mov QWORD PTR [rip+gak_source_bytes], r10\n");
        writeln!(out, "    mov {}, 112\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov rsi, rax\n    mov QWORD PTR [rsi], rbx\n    mov QWORD PTR [rsi+8], r12\n    mov QWORD PTR [rsi+16], r13\n    mov QWORD PTR [rsi+24], r14\n    mov QWORD PTR [rsi+32], r15\n    mov QWORD PTR [rsi+48], 0\n    mov QWORD PTR [rsi+56], 0\n    mov QWORD PTR [rsi+64], r14\n    mov QWORD PTR [rsi+72], 0\n    lea r10, [rip+gak_memory_box]\n    mov QWORD PTR [rsi+80], r10\n    mov QWORD PTR [rsi+88], r10\n    mov QWORD PTR [rsi+96], 0\n    mov QWORD PTR [rsi+104], 0\n    test r12, r12\n    jz gak_source_metadata_done\n    mov QWORD PTR [rsi+48], 1\n    mov r10, r13\n    sub r10, QWORD PTR [r12+16]\n    mov QWORD PTR [rsi+56], r10\n    mov r10, r14\n    sub r10, QWORD PTR [r12+16]\n    mov QWORD PTR [rsi+64], r10\ngak_source_metadata_done:\n    mov rdx, r14\n    sub rdx, r13\n    lea rax, [rbx+r13+8]\n    call gak_sha256\n    mov QWORD PTR [rsi+40], rax\n    mov rax, rsi", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop rsi\n    pop r15\n    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_alloc_observation:\n    push rbx\n    push r12\n    push r13\n    push r14\n    push r15\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov r13, r10\n    mov r14, r11\n    mov r15, r8\n    mov r10, QWORD PTR [rip+gak_observation_bytes]\n    add r10, 40\n    jc gak_observation_limit\n    cmp r10, 67108864\n    ja gak_observation_limit\n    mov QWORD PTR [rip+gak_observation_bytes], r10\n");
        writeln!(out, "    mov {}, 40\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rax], rbx\n    mov QWORD PTR [rax+8], r12\n    mov QWORD PTR [rax+16], r13\n    mov QWORD PTR [rax+24], r14\n    mov QWORD PTR [rax+32], r15", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop r15\n    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_alloc_str:\n    push rbx\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    cmp rbx, 67108856\n    ja gak_str_limit\n    lea r11, [rbx+8]\n    mov r10, QWORD PTR [rip+gak_str_bytes]\n    add r10, r11\n    jc gak_str_limit\n    cmp r10, 67108864\n    ja gak_str_limit\n    mov QWORD PTR [rip+gak_str_bytes], r10\n");
        writeln!(out, "    mov {}, r11\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov QWORD PTR [rax], rbx", self.arg0()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rbx\n    ret\n");
        out.push_str("gak_str_concat:\n    push rbx\n    push r12\n    push r13\n    push r14\n");
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        writeln!(out, "    mov rbx, {}\n    mov r12, {}\n    mov rax, QWORD PTR [rbx]\n    add rax, QWORD PTR [r12]\n    jc gak_str_limit\n    call gak_alloc_str\n    mov r13, rax\n    lea {}, [r13+8]\n    lea {}, [rbx+8]\n    mov {}, QWORD PTR [rbx]\n    call memcpy\n    mov r14, QWORD PTR [rbx]\n    lea {}, [r13+r14+8]\n    lea {}, [r12+8]\n    mov {}, QWORD PTR [r12]\n    call memcpy\n    mov rax, r13", self.arg0(), self.arg1(), self.arg0(), self.arg1(), self.arg2(), self.arg0(), self.arg1(), self.arg2()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str(
            r#"gak_hexdump:
    push rbx
    push r12
    push r13
    push r14
    push r15
"#,
        );
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str(
            r#"    mov rbx, rax
    mov r12, rdx
    mov r13, r10
    test r12, r12
    jz gak_hexdump_empty
    lea rax, [r12+15]
    shr rax, 4
    imul rax, rax, 62
    add rax, r12
    dec rax
    jmp gak_hexdump_alloc
gak_hexdump_empty:
    xor eax, eax
gak_hexdump_alloc:
    call gak_alloc_str
    mov r14, rax
    xor r15d, r15d
    xor r10d, r10d
    lea r9, [rip+gak_hex_digits]
gak_hexdump_row:
    cmp r10, r12
    jae gak_hexdump_done
    test r10, r10
    jz gak_hexdump_row_offset
    mov al, 10
    call gak_hexdump_put
gak_hexdump_row_offset:
    lea r8, [r13+r10]
    mov ecx, 8
gak_hexdump_offset_digit:
    mov rax, r8
    shr rax, 28
    and eax, 15
    mov al, BYTE PTR [r9+rax]
    call gak_hexdump_put
    shl r8, 4
    dec ecx
    jnz gak_hexdump_offset_digit
    mov al, 32
    call gak_hexdump_put
    mov al, 32
    call gak_hexdump_put
    xor r11d, r11d
gak_hexdump_hex_column:
    cmp r11, 16
    jae gak_hexdump_hex_done
    lea r8, [r10+r11]
    cmp r8, r12
    jae gak_hexdump_blank
    movzx edx, BYTE PTR [rbx+r8]
    mov eax, edx
    shr eax, 4
    mov al, BYTE PTR [r9+rax]
    call gak_hexdump_put
    mov eax, edx
    and eax, 15
    mov al, BYTE PTR [r9+rax]
    call gak_hexdump_put
    mov al, 32
    call gak_hexdump_put
    jmp gak_hexdump_extra_space
gak_hexdump_blank:
    mov al, 32
    call gak_hexdump_put
    mov al, 32
    call gak_hexdump_put
    mov al, 32
    call gak_hexdump_put
gak_hexdump_extra_space:
    cmp r11, 7
    jne gak_hexdump_next_column
    mov al, 32
    call gak_hexdump_put
gak_hexdump_next_column:
    inc r11
    jmp gak_hexdump_hex_column
gak_hexdump_hex_done:
    mov al, 124
    call gak_hexdump_put
    xor r11d, r11d
gak_hexdump_ascii_column:
    cmp r11, 16
    jae gak_hexdump_ascii_done
    lea r8, [r10+r11]
    cmp r8, r12
    jae gak_hexdump_ascii_done
    mov al, BYTE PTR [rbx+r8]
    cmp al, 32
    jb gak_hexdump_dot
    cmp al, 126
    jbe gak_hexdump_ascii_put
gak_hexdump_dot:
    mov al, 46
gak_hexdump_ascii_put:
    call gak_hexdump_put
    inc r11
    jmp gak_hexdump_ascii_column
gak_hexdump_ascii_done:
    mov al, 124
    call gak_hexdump_put
    add r10, 16
    jmp gak_hexdump_row
gak_hexdump_done:
    mov rax, r14
"#,
        );
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str(
            r#"    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
gak_hexdump_put:
    mov BYTE PTR [r14+r15+8], al
    inc r15
    ret
"#,
        );
        out.push_str(
            r#"gak_read_text:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
"#,
        );
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str(
            r#"    mov rbx, rax
    mov r12, rdx
    mov r13, r10
    mov r14, r11
    mov r15, r8
    mov rdi, r8
    cmp rdi, 3
    jne gak_read_text_width_ready
    mov edi, 2
gak_read_text_width_ready:
    xor esi, esi
gak_read_text_scan:
    cmp r13, r12
    jae gak_read_text_scanned
    cmp r15, 3
    jne gak_read_text_low_byte
    lea r10, [r13+1]
    cmp r10, r12
    jae gak_read_text_scanned
    cmp BYTE PTR [rbx+r13], 0
    jne gak_read_text_scanned
    mov al, BYTE PTR [rbx+r10]
    jmp gak_read_text_range
gak_read_text_low_byte:
    mov al, BYTE PTR [rbx+r13]
    cmp r15, 2
    jne gak_read_text_range
    lea r10, [r13+1]
    cmp r10, r12
    jae gak_read_text_scanned
    cmp BYTE PTR [rbx+r10], 0
    jne gak_read_text_scanned
gak_read_text_range:
    cmp al, 32
    jb gak_read_text_scanned
    cmp al, 126
    ja gak_read_text_scanned
gak_read_text_printable:
    cmp rsi, r14
    jae gak_read_text_limit
    inc rsi
    add r13, rdi
    jmp gak_read_text_scan
gak_read_text_scanned:
    test rsi, rsi
    jz gak_read_text_none
    mov r14, rsi
    mov rax, r14
    call gak_alloc_str
    mov rdi, r15
    cmp rdi, 3
    jne gak_read_text_copy_width_ready
    mov edi, 2
gak_read_text_copy_width_ready:
    mov r12, rax
    mov r10, r14
    imul r10, rdi
    sub r13, r10
    xor ecx, ecx
gak_read_text_copy:
    cmp rcx, r14
    jae gak_read_text_done
    mov al, BYTE PTR [rbx+r13]
    cmp r15, 3
    jne gak_read_text_copy_byte
    mov al, BYTE PTR [rbx+r13+1]
gak_read_text_copy_byte:
    mov BYTE PTR [r12+rcx+8], al
    add r13, rdi
    inc rcx
    jmp gak_read_text_copy
gak_read_text_done:
    mov rax, r12
    jmp gak_read_text_return
gak_read_text_none:
    xor eax, eax
    jmp gak_read_text_return
gak_read_text_limit:
    mov rax, -1
gak_read_text_return:
"#,
        );
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str(
            r#"    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
gak_text_limit_message:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
"#,
        );
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str(
            r#"    mov r12, rax
    xor r13d, r13d
    mov ecx, 10
gak_text_count_digits:
    xor edx, edx
    div rcx
    inc r13
    test rax, rax
    jnz gak_text_count_digits
    mov rax, r13
    add rax, gak_text_limit_prefix_end-gak_text_limit_prefix
    add rax, gak_text_limit_suffix_end-gak_text_limit_suffix
    call gak_alloc_str
    mov r14, rax
    lea rdi, [r14+8]
    lea rsi, [rip+gak_text_limit_prefix]
    mov ecx, gak_text_limit_prefix_end-gak_text_limit_prefix
    rep movsb
    lea rdi, [r14+8]
    add rdi, gak_text_limit_prefix_end-gak_text_limit_prefix
    add rdi, r13
    mov rax, r12
    mov ecx, 10
gak_text_write_digits:
    xor edx, edx
    div rcx
    dec rdi
    add dl, 48
    mov BYTE PTR [rdi], dl
    test rax, rax
    jnz gak_text_write_digits
    lea rdi, [r14+8]
    add rdi, gak_text_limit_prefix_end-gak_text_limit_prefix
    add rdi, r13
    lea rsi, [rip+gak_text_limit_suffix]
    mov ecx, gak_text_limit_suffix_end-gak_text_limit_suffix
    rep movsb
    mov rax, r14
"#,
        );
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str(
            r#"    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
"#,
        );
        out.push_str(
            r#"gak_find_strings:
    push rbx
    push r12
    push r13
    push r14
    push r15
"#,
        );
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str(
            r#"    mov rbx, rax
    mov r12, rdx
    mov r13, r10
    mov r14, r11
    xor r15d, r15d
    call gak_strings_scan
    cmp rax, -1
    je gak_find_strings_return
    call gak_alloc_list
    mov r15, rax
    call gak_strings_scan
    mov rax, r15
gak_find_strings_return:
"#,
        );
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str(
            r#"    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
gak_strings_scan:
    xor r8d, r8d
    xor r9d, r9d
gak_strings_outer:
    cmp r8, r12
    jae gak_strings_done
    cmp r14, 3
    jne gak_strings_outer_low_byte
    lea rcx, [r8+1]
    cmp rcx, r12
    jae gak_strings_skip
    cmp BYTE PTR [rbx+r8], 0
    jne gak_strings_skip
    movzx edx, BYTE PTR [rbx+rcx]
    jmp gak_strings_outer_range
gak_strings_outer_low_byte:
    movzx edx, BYTE PTR [rbx+r8]
    cmp r14, 2
    jne gak_strings_outer_range
    lea rcx, [r8+1]
    cmp rcx, r12
    jae gak_strings_skip
    cmp BYTE PTR [rbx+rcx], 0
    jne gak_strings_skip
gak_strings_outer_range:
    cmp dl, 32
    jb gak_strings_skip
    cmp dl, 126
    ja gak_strings_skip
gak_strings_start:
    mov r10, r8
    xor r11d, r11d
gak_strings_inner:
    cmp r8, r12
    jae gak_strings_run_done
    cmp r14, 3
    jne gak_strings_inner_low_byte
    lea rcx, [r8+1]
    cmp rcx, r12
    jae gak_strings_run_done
    cmp BYTE PTR [rbx+r8], 0
    jne gak_strings_run_done
    movzx edx, BYTE PTR [rbx+rcx]
    jmp gak_strings_inner_range
gak_strings_inner_low_byte:
    movzx edx, BYTE PTR [rbx+r8]
    cmp r14, 2
    jne gak_strings_inner_range
    lea rcx, [r8+1]
    cmp rcx, r12
    jae gak_strings_run_done
    cmp BYTE PTR [rbx+rcx], 0
    jne gak_strings_run_done
gak_strings_inner_range:
    cmp dl, 32
    jb gak_strings_run_done
    cmp dl, 126
    ja gak_strings_run_done
gak_strings_printable:
    inc r11
    cmp r14, 3
    je gak_strings_advance_be
    add r8, r14
    jmp gak_strings_inner
gak_strings_advance_be:
    add r8, 2
    jmp gak_strings_inner
gak_strings_run_done:
    cmp r11, r13
    jb gak_strings_outer
    cmp r9, 10000
    jae gak_strings_too_many
    test r15, r15
    jz gak_strings_count_hit
    mov QWORD PTR [r15+r9*8+8], r10
gak_strings_count_hit:
    inc r9
    jmp gak_strings_outer
gak_strings_skip:
    inc r8
    jmp gak_strings_outer
gak_strings_done:
    mov rax, r9
    ret
gak_strings_too_many:
    mov rax, -1
    ret
"#,
        );
        out.push_str(
            r#"gak_bytes_at:
    test rdx, rdx
    js gak_bytes_index
    cmp rdx, QWORD PTR [rax]
    jae gak_bytes_index
    movzx eax, BYTE PTR [rax+rdx+8]
    ret
gak_to_hex:
    push rbx
    push r12
    push r13
    push r14
"#,
        );
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        out.push_str(
            r#"    mov rbx, rax
    mov r12, rdx
    cmp r12, QWORD PTR [rbx]
    ja gak_bytes_index
    cmp r12, 1048576
    ja gak_bytes_limit
    mov rax, r12
    shl rax, 1
    call gak_alloc_str
    mov r13, rax
    xor r14d, r14d
gak_to_hex_loop:
    cmp r14, r12
    jae gak_to_hex_done
    movzx eax, BYTE PTR [rbx+r14+8]
    mov r10, rax
    shr r10, 4
    lea r11, [rip+gak_hex_digits]
    mov r10b, BYTE PTR [r11+r10]
    mov BYTE PTR [r13+r14*2+8], r10b
    and eax, 15
    mov al, BYTE PTR [r11+rax]
    mov BYTE PTR [r13+r14*2+9], al
    inc r14
    jmp gak_to_hex_loop
gak_to_hex_done:
    mov rax, r13
"#,
        );
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str(
            r#"gak_from_hex:
    push rbx
    push r12
    push r13
    push r14
    push r15
"#,
        );
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str(
            r#"    mov rbx, rax
    xor r12d, r12d
    mov r13, QWORD PTR [rbx]
    xor r14d, r14d
gak_from_hex_count:
    cmp r12, r13
    jae gak_from_hex_count_done
    movzx eax, BYTE PTR [rbx+r12+8]
    cmp al, 32
    je gak_from_hex_count_next
    cmp al, 9
    jb gak_from_hex_count_digit
    cmp al, 13
    jbe gak_from_hex_count_next
gak_from_hex_count_digit:
    cmp al, '0'
    jb gak_from_hex_fail_invalid
    cmp al, '9'
    jbe gak_from_hex_count_valid
    cmp al, 'A'
    jb gak_from_hex_fail_invalid
    cmp al, 'F'
    jbe gak_from_hex_count_valid
    cmp al, 'a'
    jb gak_from_hex_fail_invalid
    cmp al, 'f'
    ja gak_from_hex_fail_invalid
gak_from_hex_count_valid:
    inc r14
gak_from_hex_count_next:
    inc r12
    jmp gak_from_hex_count
gak_from_hex_count_done:
    test r14, 1
    jnz gak_from_hex_fail_odd
    shr r14, 1
    cmp r14, 1048576
    ja gak_from_hex_fail_limit
    mov rax, r14
    call gak_alloc_bytes
    mov r15, rax
    xor r12d, r12d
    xor r14d, r14d
    mov r10d, -1
gak_from_hex_write:
    cmp r12, r13
    jae gak_from_hex_done
    movzx eax, BYTE PTR [rbx+r12+8]
    cmp al, 32
    je gak_from_hex_next
    cmp al, 9
    jb gak_from_hex_digit
    cmp al, 13
    jbe gak_from_hex_next
gak_from_hex_digit:
    cmp al, '9'
    jbe gak_from_hex_numeric
    cmp al, 'F'
    jbe gak_from_hex_upper
    sub eax, 87
    jmp gak_from_hex_nibble
gak_from_hex_upper:
    sub eax, 55
    jmp gak_from_hex_nibble
gak_from_hex_numeric:
    sub eax, 48
gak_from_hex_nibble:
    cmp r10d, -1
    jne gak_from_hex_low
    shl eax, 4
    mov r10d, eax
    jmp gak_from_hex_next
gak_from_hex_low:
    or eax, r10d
    mov BYTE PTR [r15+r14+8], al
    inc r14
    mov r10d, -1
gak_from_hex_next:
    inc r12
    jmp gak_from_hex_write
gak_from_hex_done:
    mov rax, r15
    xor edx, edx
    jmp gak_from_hex_exit
gak_from_hex_fail_invalid:
    mov edx, 1
    jmp gak_from_hex_failed
gak_from_hex_fail_odd:
    mov edx, 2
    jmp gak_from_hex_failed
gak_from_hex_fail_limit:
    mov edx, 3
gak_from_hex_failed:
    xor eax, eax
gak_from_hex_exit:
"#,
        );
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop r15\n    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str(SHA256_RUNTIME);
        out.push_str(".globl gak_native_call_hash\ngak_native_call_hash:\n");
        writeln!(
            out,
            "    mov rax, {}\n    mov rdx, {}\n    jmp gak_sha256",
            self.arg0(),
            self.arg1()
        )
        .unwrap();
        out.push_str(
            "gak_bytes_extract:\n    push rbx\n    push r12\n    push r13\n    push r14\n",
        );
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov r13, r10\n    mov rax, r13\n    call gak_alloc_bytes\n    mov r14, rax\n    test r13, r13\n    jz gak_bytes_extract_done\n");
        writeln!(out, "    lea {}, [r14+8]\n    lea {}, [rbx+r12+8]\n    mov {}, r13\n    call memcpy\ngak_bytes_extract_done:\n    mov rax, r14", self.arg0(), self.arg1(), self.arg2()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_bytes_concat:\n    push rbx\n    push r12\n    push r13\n    push rsi\n    push rdi\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov rax, QWORD PTR [rbx]\n    add rax, QWORD PTR [r12]\n    call gak_alloc_bytes\n    mov r13, rax\n    lea rdi, [r13+8]\n    lea rsi, [rbx+8]\n    mov rcx, QWORD PTR [rbx]\n    rep movsb\n    lea rsi, [r12+8]\n    mov rcx, QWORD PTR [r12]\n    rep movsb\n    mov rax, r13\n");
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rdi\n    pop rsi\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_bytes_repeat:\n    push rbx\n    push r12\n    push r13\n    push r14\n    push rsi\n    push rdi\n");
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov rax, QWORD PTR [rbx]\n    imul rax, r12\n    call gak_alloc_bytes\n    mov r13, rax\n    lea rdi, [r13+8]\n    xor r14d, r14d\n    cmp QWORD PTR [rbx], 0\n    je gak_bytes_repeat_done\ngak_bytes_repeat_loop:\n    cmp r14, r12\n    jae gak_bytes_repeat_done\n    lea rsi, [rbx+8]\n    mov rcx, QWORD PTR [rbx]\n    rep movsb\n    inc r14\n    jmp gak_bytes_repeat_loop\ngak_bytes_repeat_done:\n    mov rax, r13\n");
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop rdi\n    pop rsi\n    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_bytes_xor:\n    push rbx\n    push r12\n    push r13\n    push r14\n    push r15\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, rdx\n    mov rax, QWORD PTR [rbx]\n    call gak_alloc_bytes\n    mov r13, rax\n    xor r14d, r14d\n    xor r15d, r15d\ngak_bytes_xor_loop:\n    cmp r14, QWORD PTR [rbx]\n    jae gak_bytes_xor_done\n    mov al, BYTE PTR [rbx+r14+8]\n    xor al, BYTE PTR [r12+r15+8]\n    mov BYTE PTR [r13+r14+8], al\n    inc r14\n    inc r15\n    cmp r15, QWORD PTR [r12]\n    jb gak_bytes_xor_loop\n    xor r15d, r15d\n    jmp gak_bytes_xor_loop\ngak_bytes_xor_done:\n    mov rax, r13\n");
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop r15\n    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        out.push_str("gak_check_result_message:\n    push rbx\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n");
        }
        writeln!(out, "    mov rbx, rax\n    mov r11, QWORD PTR [rbx]\n    test r11, r11\n    jz gak_check_result_message_invalid\n    cmp r11, 4096\n    ja gak_check_result_message_invalid\n    lea {}, [rbx+8]\n    xor {}, {}\n    mov {}, r11\n    call memchr\n    test rax, rax\n    jnz gak_check_result_message_invalid\n    mov rax, rbx\n    jmp gak_check_result_message_done\ngak_check_result_message_invalid:\n    xor eax, eax\ngak_check_result_message_done:", self.arg0(), self.arg1(), self.arg1(), self.arg2()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 32\n");
        }
        out.push_str("    pop rbx\n    ret\n");
        out.push_str(
            "gak_prefix_result:\n    push rbx\n    push r12\n    push r13\n    push r14\n",
        );
        if self.windows {
            out.push_str("    sub rsp, 40\n");
        } else {
            out.push_str("    sub rsp, 8\n");
        }
        out.push_str("    mov rbx, rax\n    mov r12, r10\n    mov r13, QWORD PTR [rbx+8]\n    mov r11, QWORD PTR [r12]\n    add r11, QWORD PTR [r13]\n    jc gak_prefix_result_skip\n    mov r10, r11\n    add r10, 8\n    jc gak_prefix_result_skip\n    mov r9, QWORD PTR [rip+gak_str_bytes]\n    add r9, r10\n    jc gak_prefix_result_skip\n    cmp r9, 67108864\n    ja gak_prefix_result_skip\n    mov QWORD PTR [rip+gak_str_bytes], r9\n");
        writeln!(out, "    mov {}, r10\n    call malloc\n    test rax, rax\n    jz gak_alloc_failure\n    mov r14, rax\n    mov r11, QWORD PTR [r12]\n    add r11, QWORD PTR [r13]\n    mov QWORD PTR [r14], r11\n    lea {}, [r14+8]\n    lea {}, [r12+8]\n    mov {}, QWORD PTR [r12]\n    call memcpy\n    mov r10, QWORD PTR [r12]\n    lea {}, [r14+r10+8]\n    lea {}, [r13+8]\n    mov {}, QWORD PTR [r13]\n    call memcpy\n    mov rax, r14\n    mov edx, 1\n    call gak_alloc_result\n    jmp gak_prefix_result_done\ngak_prefix_result_skip:\n    mov rax, rbx\ngak_prefix_result_done:", self.arg0(), self.arg0(), self.arg1(), self.arg2(), self.arg0(), self.arg1(), self.arg2()).unwrap();
        if self.windows {
            out.push_str("    add rsp, 40\n");
        } else {
            out.push_str("    add rsp, 8\n");
        }
        out.push_str("    pop r14\n    pop r13\n    pop r12\n    pop rbx\n    ret\n");
        if self.windows {
            out.push_str(
                r#"gak_cli_utf8_arg:
    push rbx
    sub rsp, 80
    mov rbx, rax
    mov r10, QWORD PTR [rip+gak_cli_cache]
    mov rax, QWORD PTR [r10+rbx*8]
    test rax, rax
    jnz gak_cli_utf8_done
    mov r10, QWORD PTR [rip+gak_argv]
    mov r10, QWORD PTR [r10+rbx*8]
    mov QWORD PTR [rsp+64], r10
    mov ecx, 65001
    xor edx, edx
    mov r8, r10
    mov r9d, -1
    mov QWORD PTR [rsp+32], 0
    mov QWORD PTR [rsp+40], 0
    mov QWORD PTR [rsp+48], 0
    mov QWORD PTR [rsp+56], 0
    call WideCharToMultiByte
    test eax, eax
    jz gak_cli_utf8_failure
    mov QWORD PTR [rsp+72], rax
    mov ecx, eax
    call malloc
    test rax, rax
    jz gak_alloc_failure
    mov r10, QWORD PTR [rip+gak_cli_cache]
    mov QWORD PTR [r10+rbx*8], rax
    mov ecx, 65001
    xor edx, edx
    mov r8, QWORD PTR [rsp+64]
    mov r9d, -1
    mov r10, QWORD PTR [rip+gak_cli_cache]
    mov r10, QWORD PTR [r10+rbx*8]
    mov QWORD PTR [rsp+32], r10
    mov r10, QWORD PTR [rsp+72]
    mov QWORD PTR [rsp+40], r10
    mov QWORD PTR [rsp+48], 0
    mov QWORD PTR [rsp+56], 0
    call WideCharToMultiByte
    test eax, eax
    jz gak_cli_utf8_failure
    mov r10, QWORD PTR [rip+gak_cli_cache]
    mov rax, QWORD PTR [r10+rbx*8]
gak_cli_utf8_done:
    add rsp, 80
    pop rbx
    ret
"#,
            );
        }
        let hunt_runtime = include_str!("native_hunt.S")
            .replace(
                "__SHADOW_ENTER__",
                if self.windows { "    sub rsp, 32" } else { "" },
            )
            .replace(
                "__SHADOW_LEAVE__",
                if self.windows { "    add rsp, 32" } else { "" },
            )
            .replace("__MALLOC_ARG__", self.arg0())
            .replace("__FREE_ARG__", self.arg0());
        out.push_str(&hunt_runtime);
        let entropy_runtime = include_str!("native_entropy.S")
            .replace(
                "__STACK_BYTES__",
                if self.windows { "2080" } else { "2048" },
            )
            .replace("__COUNTS_OFFSET__", if self.windows { "32" } else { "0" });
        out.push_str(&entropy_runtime);
        let patch_runtime = include_str!("native_patch.S")
            .replace(
                "__SHADOW_ENTER__",
                if self.windows { "    sub rsp, 32" } else { "" },
            )
            .replace(
                "__SHADOW_LEAVE__",
                if self.windows { "    add rsp, 32" } else { "" },
            );
        out.push_str(&patch_runtime);
        let splice_runtime = include_str!("native_splice.S")
            .replace(
                "__SHADOW_ENTER__",
                if self.windows { "    sub rsp, 32" } else { "" },
            )
            .replace(
                "__SHADOW_LEAVE__",
                if self.windows { "    add rsp, 32" } else { "" },
            );
        out.push_str(&splice_runtime);
        let diff_runtime = include_str!("native_diff.S")
            .replace(
                "__FRAME_ENTER__",
                if self.windows {
                    "    sub rsp, 40"
                } else {
                    "    sub rsp, 8"
                },
            )
            .replace(
                "__FRAME_LEAVE__",
                if self.windows {
                    "    add rsp, 40"
                } else {
                    "    add rsp, 8"
                },
            )
            .replace("__MALLOC_ARG__", self.arg0());
        out.push_str(&diff_runtime);
        for (label, message) in [
            ("gak_call_depth_error", "gak_call_depth_error_msg"),
            ("gak_call_stack_error", "gak_call_stack_error_msg"),
            ("gak_overflow", "gak_overflow_msg"),
            ("gak_divzero", "gak_divzero_msg"),
            ("gak_shift_range", "gak_shift_range_msg"),
            ("gak_limit", "gak_limit_msg"),
            ("gak_range_start", "gak_range_start_msg"),
            ("gak_range_end", "gak_range_end_msg"),
            ("gak_range_limit", "gak_range_limit_msg"),
            ("gak_record_limit", "gak_record_limit_msg"),
            ("gak_alloc_failure", "gak_alloc_failure_msg"),
            ("gak_list_limit", "gak_list_limit_msg"),
            ("gak_list_index", "gak_list_index_msg"),
            ("gak_cli_index", "gak_cli_index_msg"),
            ("gak_cli_invalid", "gak_cli_invalid_msg"),
            ("gak_cli_utf8_failure", "gak_cli_utf8_msg"),
            ("gak_str_limit", "gak_str_limit_msg"),
            ("gak_text_slice_range", "gak_text_slice_range_msg"),
            ("gak_text_search_alloc", "gak_text_search_alloc_msg"),
            ("gak_output_failure", "gak_output_failure_msg"),
            ("gak_result_limit", "gak_result_limit_msg"),
            ("gak_hex_invalid", "gak_hex_invalid_msg"),
            ("gak_hex_odd", "gak_hex_odd_msg"),
            ("gak_hex_limit", "gak_hex_limit_msg"),
            ("gak_bytes_limit", "gak_bytes_limit_msg"),
            ("gak_bytes_index", "gak_bytes_index_msg"),
            (
                "gak_binary_offset_negative",
                "gak_binary_offset_negative_msg",
            ),
            (
                "gak_binary_length_negative",
                "gak_binary_length_negative_msg",
            ),
            ("gak_binary_range_overflow", "gak_binary_range_overflow_msg"),
            ("gak_binary_out_of_bounds", "gak_binary_out_of_bounds_msg"),
            ("gak_analyze_max", "gak_analyze_max_msg"),
            (
                "gak_binary_unknown_decoder",
                "gak_binary_unknown_decoder_msg",
            ),
            ("gak_hexdump_limit", "gak_hexdump_limit_msg"),
            ("gak_text_offset_negative", "gak_text_offset_negative_msg"),
            ("gak_max_chars_range", "gak_max_chars_range_msg"),
            ("gak_max_chars_limit", "gak_max_chars_limit_msg"),
            ("gak_text_encoding", "gak_text_encoding_msg"),
            ("gak_text_offset_bounds", "gak_text_offset_bounds_msg"),
            ("gak_text_not_printable", "gak_text_not_printable_msg"),
            ("gak_strings_minimum_range", "gak_strings_minimum_range_msg"),
            ("gak_strings_minimum_limit", "gak_strings_minimum_limit_msg"),
            ("gak_strings_many", "gak_strings_many_msg"),
            ("gak_hunt_invalid_hex", "gak_hunt_invalid_hex_msg"),
            ("gak_hunt_hex_limit", "gak_hunt_hex_limit_msg"),
            ("gak_hunt_odd_hex", "gak_hunt_odd_hex_msg"),
            ("gak_hunt_mask_limit", "gak_hunt_mask_limit_msg"),
            ("gak_hunt_empty", "gak_hunt_empty_msg"),
            ("gak_hunt_many", "gak_hunt_many_msg"),
            ("gak_diff_limit_negative", "gak_diff_limit_negative_msg"),
            ("gak_diff_limit", "gak_diff_limit_msg"),
            ("gak_diff_many", "gak_diff_many_msg"),
            ("gak_diff_memory", "gak_diff_memory_msg"),
            ("gak_patch_empty", "gak_patch_empty_msg"),
            ("gak_patch_limit", "gak_patch_limit_msg"),
            ("gak_splice_insert_limit", "gak_splice_insert_limit_msg"),
            ("gak_splice_empty", "gak_splice_empty_msg"),
            ("gak_splice_size_overflow", "gak_splice_size_overflow_msg"),
            ("gak_splice_size_limit", "gak_splice_size_limit_msg"),
            (
                "gak_observation_value_range",
                "gak_observation_value_range_msg",
            ),
            ("gak_observation_limit", "gak_observation_limit_msg"),
            ("gak_source_depth", "gak_source_depth_msg"),
            ("gak_source_limit", "gak_source_limit_msg"),
            ("gak_source_backing_limit", "gak_source_backing_limit_msg"),
            ("gak_repeat_negative", "gak_repeat_negative_msg"),
            ("gak_repeat_count_limit", "gak_repeat_count_limit_msg"),
            ("gak_xor_empty_key", "gak_xor_empty_key_msg"),
            ("gak_pack_negative", "gak_pack_negative_msg"),
            ("gak_pack_encoding", "gak_pack_encoding_msg"),
            ("gak_pack_range_u8", "gak_pack_range_u8_msg"),
            ("gak_pack_range_u16le", "gak_pack_range_u16le_msg"),
            ("gak_pack_range_u16be", "gak_pack_range_u16be_msg"),
            ("gak_pack_range_u32le", "gak_pack_range_u32le_msg"),
            ("gak_pack_range_u32be", "gak_pack_range_u32be_msg"),
            ("gak_result_invalid", "gak_result_invalid_msg"),
            (
                "gak_result_message_success",
                "gak_result_message_success_msg",
            ),
            (
                "gak_result_untyped_success",
                "gak_result_untyped_success_msg",
            ),
        ] {
            writeln!(out, "{label}:\n    lea rax, [rip+{message}]\n    mov r11, {message}_end-{message}\n    jmp gak_error").unwrap();
        }
        if self.uses_file_read || self.uses_python || self.uses_process || self.uses_net {
            out.push_str("gak_native_init_error:\n    mov rax, QWORD PTR [rip+gak_file_error]\n    mov edx, 1\n    call gak_alloc_result\n    jmp gak_uncaught_result\n");
        }
        if self.uses_file_read || self.uses_process || self.uses_net || self.uses_formats {
            out.push_str("gak_analyze_error_dynamic:\n    mov edx, 1\n    call gak_alloc_result\n    jmp gak_uncaught_result\n");
        }
        if self.uses_python {
            out.push_str("gak_python_error_dynamic:\n    mov edx, 1\n    call gak_alloc_result\n    jmp gak_uncaught_result\n");
        }
        out.push_str("gak_text_limit_dynamic:\n    mov edx, 1\n    call gak_alloc_result\n    jmp gak_uncaught_result\ngak_uncaught_result:\n    mov rax, QWORD PTR [rax+8]\n    mov r11, QWORD PTR [rax]\n    lea rax, [rax+8]\n    mov rbp, QWORD PTR [rip+gak_main_rbp]\n    mov rsp, rbp\n    cmp BYTE PTR [rip+gak_native_call_dispatch_active], 0\n    je gak_uncaught_result_print\n    cmp DWORD PTR [rip+gak_native_call_serve_mode], 0\n    jne gak_native_call_recover\ngak_uncaught_result_print:\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n    mov ecx, 2\n    mov rdx, rax\n    mov r8, r11\n    call _write\n    mov ecx, 2\n    lea rdx, [rip+gak_newline]\n    mov r8d, 1\n    call _write\n");
        } else {
            out.push_str("    mov edi, 2\n    mov rsi, rax\n    mov rdx, r11\n    call write\n    mov edi, 2\n    lea rsi, [rip+gak_newline]\n    mov edx, 1\n    call write\n");
        }
        out.push_str("    mov eax, 1\n    mov rsp, rbp\n    pop rbp\n    ret\n");
        out.push_str("gak_error:\n    mov rbp, QWORD PTR [rip+gak_main_rbp]\n    mov rsp, rbp\n    cmp BYTE PTR [rip+gak_native_call_dispatch_active], 0\n    je gak_error_print\n    cmp DWORD PTR [rip+gak_native_call_serve_mode], 0\n    jne gak_native_call_recover\ngak_error_print:\n");
        if self.windows {
            out.push_str("    sub rsp, 32\n    mov ecx, 2\n    mov rdx, rax\n    mov r8, r11\n    call _write\n");
        } else {
            out.push_str("    mov edi, 2\n    mov rsi, rax\n    mov rdx, r11\n    call write\n");
        }
        out.push_str("    mov eax, 1\n    mov rsp, rbp\n    pop rbp\n    ret\n");
        writeln!(out, "gak_native_call_recover:\n    mov QWORD PTR [rip+gak_call_depth], 0\n    sub rsp, {reserve}\n    mov {}, rax\n    mov {}, r11\n    call gak_native_call_error\n    call gak_native_call_next\n    test eax, eax\n    jnz gak_native_call_dispatch\n    xor eax, eax\n    mov rsp, rbp\n    pop rbp\n    ret", self.arg0(), self.arg1()).unwrap();
        if !self.windows {
            out.push_str(".section .note.GNU-stack,\"\",@progbits\n");
        }
        Ok(out)
    }
}

#[cfg(test)]
mod source_validation_tests {
    use super::*;

    #[test]
    fn native_collection_rejects_sources_changed_after_validation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "galeikan-native-source-validation-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let root = directory.join("main.gak");
        let child = directory.join("child.gak");
        fs::write(&root, "import child\nprint child.value\n").unwrap();
        fs::write(&child, "let value: i64 = 1\n").unwrap();
        let hashes = runtime::checked_source_hashes(&root).unwrap();
        let path = root.canonicalize().unwrap();
        let project = project::resolve(&path).unwrap();

        fs::write(&child, "let value: i64 = 2\n").unwrap();
        let error = collect_module(
            path.clone(),
            &project,
            &hashes,
            &mut HashSet::new(),
            &mut HashMap::new(),
            &mut Vec::new(),
        )
        .err()
        .unwrap();
        assert!(error.contains("source changed after validation"), "{error}");

        fs::write(&child, "let value: i64 = 1\n").unwrap();
        fs::write(&root, "import child\nprint child.value + 1\n").unwrap();
        let error = collect_module(
            path,
            &project,
            &hashes,
            &mut HashSet::new(),
            &mut HashMap::new(),
            &mut Vec::new(),
        )
        .err()
        .unwrap();
        assert!(error.contains("source changed after validation"), "{error}");
        fs::remove_dir_all(directory).unwrap();
    }
}
