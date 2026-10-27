use crate::asm;
use crate::bytecode::{Instruction, Program};
use crate::bytes::{self, hex_bytes, parse_hex};
use crate::case;
use crate::file_access;
use crate::formats::{self, FormatReport, SectionInfo};
use crate::net;
use crate::process;
use crate::project;
use crate::python_bridge;
use crate::syntax::{
    self, BlockStmt, BlockStmtKind, Expr, ExprKind, FunctionBody, MatchPattern, Op, StmtKind,
};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

const MAX_SNAPSHOT: usize = 512 * 1024 * 1024;
const MAX_SCRIPT: usize = 8 * 1024 * 1024;
const MAX_HITS: usize = 10_000;
const MAX_TEXT_CHARS: usize = 4096;
const MAX_STRING_BYTES: usize = 64 * 1024 * 1024 - 8;
const MAX_HEXDUMP_BYTES: usize = 4096;
const DEFAULT_HEXDUMP_BYTES: usize = 256;
const MAX_CALL_DEPTH: usize = 128;
const MAX_DISASSEMBLY: usize = 10_000;
const MAX_NET_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_NET_REQUEST: usize = 1024 * 1024;
const MAX_UDP_DATAGRAM: usize = 65_507;
const MAX_PATCH_BYTES: usize = 1024 * 1024;
const MAX_MUTATION_CASES: usize = 256;
const MAX_MUTATION_INPUT: usize = 1024 * 1024;
const MAX_MUTATION_MATERIALIZED: usize = 64 * 1024 * 1024;
const MAX_SOURCE_DEPTH: usize = 64;
const MAX_IMPORT_DEPTH: usize = 64;
const MAX_NET_TIMEOUT_MS: i64 = 30_000;
const MAX_PYTHON_BYTES: usize = 500_000;
const BUNDLE_MAGIC: &[u8; 8] = b"GAKB\x0a\x00\x00\x00";
const MAX_LOOP_ITEMS: usize = 100_000;
const MAX_ACTION_STEPS: usize = 1_000_000;
const MAX_BUNDLE: usize = 64 * 1024 * 1024;
const MAX_CASE_EVENTS: usize = 10_000;
const MAX_CASE_ARTIFACTS: usize = 4096;
const MAX_CASE_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_AUDIT_PATTERN: usize = 4096;
pub const MAX_CALL_MESSAGE: usize = 1024 * 1024;

#[derive(Clone)]
enum Value {
    Int(i64),
    UInt(u64),
    Bool(bool),
    Str(String),
    List(Arc<Vec<Value>>, Option<ResultKind>),
    Bytes(Arc<Vec<u8>>),
    Source(Arc<Source>),
    HttpResponse(Arc<HttpResponseValue>),
    Observation(Arc<Observation>),
    Format(Arc<Source>, Arc<FormatReport>),
    Section(Arc<Source>, SectionInfo),
    Offsets(Vec<usize>),
    Diff(Arc<Diff>),
    Finding(Arc<Finding>),
    Instruction(Arc<AsmInstruction>),
    Disassembly(Arc<Disassembly>),
    Regions(Arc<Vec<Arc<process::Region>>>),
    Region(Arc<process::Region>),
    Result(Arc<Result<Value, String>>),
    Record(Arc<RecordValue>),
}

struct RecordValue {
    id: u64,
    name: String,
    fields: Vec<(String, Value)>,
}

struct AsmInstruction {
    source: Arc<Source>,
    offset: usize,
    decoded: asm::Decoded,
}

struct Disassembly {
    source: Arc<Source>,
    start: usize,
    range_start: usize,
    range_end: usize,
    instructions: Vec<Arc<AsmInstruction>>,
    blocks: Vec<asm::Block>,
    overlaps: Vec<bool>,
}

impl Disassembly {
    fn new(
        source: Arc<Source>,
        start: usize,
        instructions: Vec<Arc<AsmInstruction>>,
    ) -> Result<Self, String> {
        let decoded = instructions
            .iter()
            .map(|instruction| &instruction.decoded)
            .collect::<Vec<_>>();
        let blocks = asm::blocks(&decoded)?;
        let overlaps = asm::overlaps(&decoded)?;
        let range_start = instructions
            .iter()
            .map(|instruction| instruction.offset)
            .min()
            .ok_or("empty disassembly")?;
        let range_end = instructions.iter().try_fold(0_usize, |end, instruction| {
            let next = instruction
                .offset
                .checked_add(instruction.decoded.size)
                .ok_or("instruction range overflow")?;
            Ok::<usize, String>(end.max(next))
        })?;
        Ok(Self {
            source,
            start,
            range_start,
            range_end,
            instructions,
            blocks,
            overlaps,
        })
    }
}

struct HttpResponseValue {
    status: u16,
    request: Arc<Source>,
    body: Arc<Source>,
    headers: Vec<(String, String)>,
}

struct Source {
    origin: String,
    label: String,
    sha256: String,
    backing: Arc<[u8]>,
    start: usize,
    end: usize,
    parent: Option<SourceParent>,
    address: Option<SourceAddress>,
    depth: usize,
}
enum SourceParent {
    View(Arc<Source>, usize, usize),
    Patch(Arc<Source>, usize, usize),
    Splice(Arc<Source>, usize, usize, usize),
}
#[derive(Clone, Copy)]
enum SourceAddress {
    PeRva(u64),
    ElfVa(u64),
}
impl SourceAddress {
    fn display(self) -> String {
        match self {
            Self::PeRva(value) => format!("PE RVA 0x{value:x}"),
            Self::ElfVa(value) => format!("ELF VA 0x{value:x}"),
        }
    }

    fn as_json(self) -> JsonValue {
        match self {
            Self::PeRva(value) => json!({ "space": "pe.rva", "value": format!("0x{value:x}") }),
            Self::ElfVa(value) => json!({ "space": "elf.va", "value": format!("0x{value:x}") }),
        }
    }
}
impl Source {
    fn new(origin: String, label: String, bytes: Vec<u8>) -> Self {
        let digest = Sha256::digest(&bytes);
        let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
        let end = bytes.len();
        Self {
            origin,
            label,
            sha256,
            backing: bytes.into(),
            start: 0,
            end,
            parent: None,
            address: None,
            depth: 0,
        }
    }
    fn view(parent: Arc<Self>, start: usize, end: usize) -> Result<Self, String> {
        if parent.depth >= MAX_SOURCE_DEPTH {
            return Err(format!(
                "LimitExceeded: Source derivation depth exceeds {MAX_SOURCE_DEPTH}"
            ));
        }
        let absolute_start = parent.start + start;
        let absolute_end = parent.start + end;
        let digest = Sha256::digest(&parent.backing[absolute_start..absolute_end]);
        let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
        let label = format!("{}[{start}..{end})", parent.label);
        Ok(Self {
            origin: parent.origin.clone(),
            label,
            sha256,
            backing: parent.backing.clone(),
            start: absolute_start,
            end: absolute_end,
            depth: parent.depth + 1,
            parent: Some(SourceParent::View(parent, start, end)),
            address: None,
        })
    }
    fn patch(
        parent: Arc<Self>,
        start: usize,
        end: usize,
        replacement: &[u8],
    ) -> Result<Self, String> {
        if parent.depth >= MAX_SOURCE_DEPTH {
            return Err(format!(
                "LimitExceeded: Source derivation depth exceeds {MAX_SOURCE_DEPTH}"
            ));
        }
        let mut bytes = parent.bytes().to_vec();
        bytes[start..end].copy_from_slice(replacement);
        let mut patched = Self::new(
            parent.origin.clone(),
            format!("{} patched[{start}..{end})", parent.label),
            bytes,
        );
        patched.depth = parent.depth + 1;
        patched.parent = Some(SourceParent::Patch(parent, start, end));
        Ok(patched)
    }
    fn splice(
        parent: Arc<Self>,
        start: usize,
        end: usize,
        replacement: &[u8],
    ) -> Result<Self, String> {
        if parent.depth >= MAX_SOURCE_DEPTH {
            return Err(format!(
                "LimitExceeded: Source derivation depth exceeds {MAX_SOURCE_DEPTH}"
            ));
        }
        let new_size = parent
            .bytes()
            .len()
            .checked_sub(end - start)
            .and_then(|size| size.checked_add(replacement.len()))
            .ok_or("splice size overflow")?;
        if new_size > MAX_SNAPSHOT {
            return Err(format!(
                "LimitExceeded: Source exceeds {MAX_SNAPSHOT} bytes"
            ));
        }
        let mut bytes = Vec::with_capacity(new_size);
        bytes.extend_from_slice(&parent.bytes()[..start]);
        bytes.extend_from_slice(replacement);
        bytes.extend_from_slice(&parent.bytes()[end..]);
        let mut spliced = Self::new(
            parent.origin.clone(),
            format!(
                "{} spliced[{start}..{end})->{}",
                parent.label,
                replacement.len()
            ),
            bytes,
        );
        spliced.depth = parent.depth + 1;
        spliced.parent = Some(SourceParent::Splice(parent, start, end, replacement.len()));
        Ok(spliced)
    }
    fn rva_view(parent: Arc<Self>, start: usize, end: usize, rva: u64) -> Result<Self, String> {
        let mut view = Self::view(parent, start, end)?;
        view.label = format!("{} @ PE RVA 0x{rva:x}", view.label);
        view.address = Some(SourceAddress::PeRva(rva));
        Ok(view)
    }
    fn va_view(parent: Arc<Self>, start: usize, end: usize, va: u64) -> Result<Self, String> {
        let mut view = Self::view(parent, start, end)?;
        view.label = format!("{} @ ELF VA 0x{va:x}", view.label);
        view.address = Some(SourceAddress::ElfVa(va));
        Ok(view)
    }
    fn bytes(&self) -> &[u8] {
        &self.backing[self.start..self.end]
    }
    fn provenance(&self) -> String {
        let base = match &self.parent {
            Some(SourceParent::View(parent, start, end)) => {
                format!("view of sha256:{} [{start}..{end})", parent.sha256)
            }
            Some(SourceParent::Patch(parent, start, end)) => {
                format!("patch of sha256:{} [{start}..{end})", parent.sha256)
            }
            Some(SourceParent::Splice(parent, start, end, inserted_size)) => {
                format!(
                    "splice of sha256:{} [{start}..{end}) -> {inserted_size} bytes",
                    parent.sha256
                )
            }
            None => self.origin.clone(),
        };
        if let Some(address) = self.address {
            format!("{}; {base}", address.display())
        } else {
            base
        }
    }

    fn lineage(&self) -> Vec<JsonValue> {
        let mut sources = Vec::with_capacity(self.depth + 1);
        let mut cursor = Some(self);
        while let Some(source) = cursor {
            sources.push(source);
            cursor = match &source.parent {
                Some(
                    SourceParent::View(parent, ..)
                    | SourceParent::Patch(parent, ..)
                    | SourceParent::Splice(parent, ..),
                ) => Some(parent),
                None => None,
            };
        }
        sources
            .into_iter()
            .rev()
            .map(|source| match &source.parent {
                None => json!({
                    "operation": "capture", "origin": source.origin,
                    "label": source.label, "sha256": source.sha256,
                    "size": source.bytes().len()
                }),
                Some(SourceParent::View(parent, start, end)) => json!({
                    "operation": "view", "parent_sha256": parent.sha256,
                    "start": start, "end": end, "sha256": source.sha256,
                    "size": source.bytes().len(),
                    "address": source.address.map(SourceAddress::as_json)
                }),
                Some(SourceParent::Patch(parent, start, end)) => json!({
                    "operation": "patch", "parent_sha256": parent.sha256,
                    "start": start, "end": end,
                    "replacement_sha256": hex_bytes(&Sha256::digest(&source.bytes()[*start..*end])),
                    "sha256": source.sha256, "size": source.bytes().len()
                }),
                Some(SourceParent::Splice(parent, start, end, inserted_size)) => json!({
                    "operation": "splice", "parent_sha256": parent.sha256,
                    "start": start, "end": end, "inserted_size": inserted_size,
                    "replacement_sha256": hex_bytes(&Sha256::digest(&source.bytes()[*start..*start + *inserted_size])),
                    "sha256": source.sha256, "size": source.bytes().len()
                }),
            })
            .collect()
    }
}

fn case_value_sources(value: &Value, out: &mut Vec<Arc<Source>>) {
    match value {
        Value::Source(source) | Value::Format(source, _) | Value::Section(source, _) => {
            out.push(source.clone())
        }
        Value::HttpResponse(response) => {
            out.push(response.request.clone());
            out.push(response.body.clone());
        }
        Value::Observation(observation) => out.push(observation.source.clone()),
        Value::Diff(diff) => {
            out.push(diff.left.clone());
            out.push(diff.right.clone());
        }
        Value::Finding(finding) => match &finding.evidence {
            FindingEvidence::Numeric { observation, .. } => out.push(observation.source.clone()),
            FindingEvidence::Pattern { source, .. } | FindingEvidence::Signal { source, .. } => {
                out.push(source.clone());
            }
        },
        Value::Instruction(instruction) => out.push(instruction.source.clone()),
        Value::Disassembly(disassembly) => out.push(disassembly.source.clone()),
        Value::Result(result) => {
            if let Ok(value) = result.as_ref() {
                case_value_sources(value, out);
            }
        }
        Value::List(items, _) => {
            for item in items.iter() {
                case_value_sources(item, out);
            }
        }
        Value::Record(record) => {
            for (_, value) in &record.fields {
                case_value_sources(value, out);
            }
        }
        Value::Int(_)
        | Value::UInt(_)
        | Value::Bool(_)
        | Value::Str(_)
        | Value::Bytes(_)
        | Value::Offsets(_)
        | Value::Regions(_)
        | Value::Region(_) => {}
    }
}
struct Observation {
    source: Arc<Source>,
    offset: usize,
    width: usize,
    decoder: &'static str,
    value: u64,
}
struct Diff {
    left: Arc<Source>,
    right: Arc<Source>,
    offsets: Vec<usize>,
}
struct Finding {
    rule: String,
    evidence: FindingEvidence,
    passed: bool,
}
enum FindingEvidence {
    Numeric {
        observation: Arc<Observation>,
        constraint: Constraint,
    },
    Pattern {
        source: Arc<Source>,
        pattern_kind: &'static str,
        pattern_width: usize,
        pattern_sha256: String,
        offsets: Vec<usize>,
    },
    Signal {
        source: Arc<Source>,
        name: String,
        expected: String,
        actual: &'static str,
        field: Option<formats::NumericField>,
    },
}
enum Constraint {
    Equal(u64),
    Bound(u64, u64),
}
impl Constraint {
    fn display(&self) -> String {
        match self {
            Self::Equal(value) => format!("equal {value}"),
            Self::Bound(min, max) => format!("between {min} and {max}"),
        }
    }
}

impl Value {
    fn display(&self) -> String {
        match self {
            Value::Int(n) => n.to_string(),
            Value::UInt(n) => n.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Str(s) => s.clone(),
            Value::Record(record) => format!(
                "{}({})",
                record.name,
                record
                    .fields
                    .iter()
                    .map(|(name, value)| format!("{name}: {}", value.display()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Value::List(items, _) => {
                let sample = items.iter().take(16).map(Value::display).collect::<Vec<_>>().join(", ");
                if items.len() > 16 { format!("[{sample}, ...] ({} items)", items.len()) }
                else { format!("[{sample}]") }
            }
            Value::Bytes(bytes) => {
                let sample: String = bytes.iter().take(64).map(|b| format!("{b:02x}")).collect();
                let suffix = if bytes.len() > 64 { "..." } else { "" };
                format!("bytes({} bytes, hex:{sample}{suffix})", bytes.len())
            }
            Value::Source(s) => format!(
                "source({:?}, origin: {:?}, sha256: {}, {} bytes)",
                s.label,
                s.provenance(),
                s.sha256,
                s.bytes().len()
            ),
            Value::HttpResponse(response) => format!(
                "http_response(status: {}, request_sha256: {}, body_sha256: {}, {} bytes, {} headers)",
                response.status,
                response.request.sha256,
                response.body.sha256,
                response.body.bytes().len(),
                response.headers.len()
            ),
            Value::Observation(o) => format!(
                "{} @ [{}..{}) {} = {} [sha256:{}]",
                o.source.label,
                o.offset,
                o.offset + o.width,
                o.decoder,
                o.value,
                o.source.sha256
            ),
            Value::Format(source, report) => format!(
                "{} [sha256:{}] {}",
                source.label,
                source.sha256,
                report.summary()
            ),
            Value::Section(source, section) => format!(
                "section({:?}, file=[{}..{}), va=0x{:x}, virtual_size={}, flags=0x{:x}, writable={}, executable={}, source_sha256:{})",
                section.name.as_deref().unwrap_or("<name unavailable>"),
                section.file_offset,
                section.file_offset.saturating_add(section.file_size),
                section.virtual_address,
                section.virtual_size,
                section.flags,
                section.writable,
                section.executable,
                source.sha256,
            ),
            Value::Offsets(v) => format!("{v:?}"),
            Value::Diff(diff) => format!(
                "diff({:?} [sha256:{}; {} bytes], {:?} [sha256:{}; {} bytes], offsets: {:?})",
                diff.left.label,
                diff.left.sha256,
                diff.left.bytes().len(),
                diff.right.label,
                diff.right.sha256,
                diff.right.bytes().len(),
                diff.offsets
            ),
            Value::Finding(finding) => match &finding.evidence {
                FindingEvidence::Numeric { observation, constraint } => format!(
                    "finding(rule: {:?}, status: {}, expected: {}, actual: {}, source: {:?}, sha256: {}, range: [{}..{}))",
                    finding.rule,
                    if finding.passed { "pass" } else { "fail" },
                    constraint.display(),
                    observation.value,
                    observation.source.label,
                    observation.source.sha256,
                    observation.offset,
                    observation.offset + observation.width
                ),
                FindingEvidence::Pattern { source, pattern_kind, pattern_width, pattern_sha256, offsets } => format!(
                    "finding(rule: {:?}, status: {}, pattern: {} {} bytes [{}], source: {:?}, sha256: {}, offsets: {:?})",
                    finding.rule,
                    if finding.passed { "pass" } else { "fail" },
                    pattern_kind,
                    pattern_width,
                    pattern_sha256,
                    source.label,
                    source.sha256,
                    offsets
                ),
                FindingEvidence::Signal { source, name, expected, actual, field } => format!(
                    "finding(rule: {:?}, status: {}, signal: {:?}, expected: {:?}, actual: {}, source: {:?}, sha256: {}, field: {})",
                    finding.rule,
                    if finding.passed { "pass" } else { "fail" },
                    name,
                    expected,
                    actual,
                    source.label,
                    source.sha256,
                    field.map_or_else(|| "unavailable".into(), |field| format!("[{}..{}) {} = {}", field.offset, field.offset + field.width, field.decoder, field.value))
                ),
            },
            Value::Instruction(instruction) => format!(
                "instruction(0x{:x}: {}, source_sha256:{})",
                instruction.decoded.ip, instruction.decoded.text, instruction.source.sha256
            ),
            Value::Disassembly(disassembly) => format!(
                "disassembly(count: {}, blocks: {}, source: {:?}, sha256: {})",
                disassembly.instructions.len(), disassembly.blocks.len(), disassembly.source.label, disassembly.source.sha256
            ),
            Value::Regions(regions) => format!("regions(count: {})", regions.len()),
            Value::Region(region) => format!(
                "region(pid: {}, start: 0x{:x}, size: {}, access: {}, label: {:?}, image_backed: {})",
                region.pid, region.start, region.size, region.access, region.label,
                region.image_backed
            ),
            Value::Result(result) => match result.as_ref() {
                Ok(value) => format!("ok({})", value.display()),
                Err(error) => format!("error({error})"),
            },
        }
    }
    fn as_int(&self) -> Result<i64, String> {
        match self {
            Value::Int(n) => Ok(*n),
            _ => Err("integer expected".into()),
        }
    }
    fn as_uint(&self) -> Result<u64, String> {
        match self {
            Value::UInt(n) => Ok(*n),
            _ => Err("u64 expected".into()),
        }
    }
    fn as_bool(&self) -> Result<bool, String> {
        match self {
            Value::Bool(value) => Ok(*value),
            _ => Err("boolean expected".into()),
        }
    }
    fn as_str(&self) -> Result<&str, String> {
        match self {
            Value::Str(s) => Ok(s),
            _ => Err("string expected".into()),
        }
    }
    fn as_request_bytes(&self) -> Result<&[u8], String> {
        match self {
            Value::Str(s) => Ok(s.as_bytes()),
            Value::Bytes(bytes) => Ok(bytes.as_slice()),
            _ => Err("string or bytes expected".into()),
        }
    }
    fn as_source(&self) -> Result<Arc<Source>, String> {
        match self {
            Value::Source(s) => Ok(s.clone()),
            _ => Err("Source expected".into()),
        }
    }
    fn as_binary_bytes(&self) -> Result<&[u8], String> {
        match self {
            Value::Source(source) => Ok(source.bytes()),
            Value::Bytes(bytes) => Ok(bytes.as_slice()),
            _ => Err("Source or bytes expected".into()),
        }
    }
}

#[derive(Clone)]
enum Import {
    Binary,
    Bytes,
    Text,
    Formats,
    Cli,
    Net,
    Process,
    ResultOps,
    Audit,
    Iter,
    ListOps,
    Lab,
    Asm,
    Python(PathBuf),
    Local(Rc<Module>),
}

fn import_has_symbol(import: &Import, symbol: &str) -> bool {
    let module = match import {
        Import::Binary => "binary",
        Import::Bytes => "bytes",
        Import::Text => "text",
        Import::Formats => "formats",
        Import::Cli => "cli",
        Import::Net => "net",
        Import::Process => "process",
        Import::ResultOps => "result",
        Import::Audit => "audit",
        Import::Iter => "iter",
        Import::ListOps => "list",
        Import::Lab => "lab",
        Import::Asm => "asm",
        // Python can define functions dynamically; validation stays at call time.
        Import::Python(_) => return true,
        Import::Local(child) => {
            return child.functions.contains_key(symbol)
                || child.records.contains_key(symbol)
                || child.lets.iter().any(|binding| binding.name == symbol)
        }
    };
    if module == "iter" {
        return symbol == "range";
    }
    !matches!(
        standard_call(module, symbol, &[]),
        Err(message) if message.starts_with("unknown standard function ")
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Type {
    Any,
    Int,
    UInt,
    Bool,
    Str,
    Bytes,
    Source,
    HttpResponse,
    Observation,
    Format,
    Section,
    Offsets,
    Diff,
    Finding,
    Instruction,
    Disassembly,
    Regions,
    Region,
    List(Option<ResultKind>),
    Result(Option<ResultKind>),
    Record(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum ResultKind {
    Int,
    UInt,
    Bool,
    Str,
    Bytes,
    Source,
    HttpResponse,
    Observation,
    Format,
    Section,
    Offsets,
    Diff,
    Finding,
    Instruction,
    Disassembly,
    Regions,
    Region,
    Record(u64),
}

impl ResultKind {
    fn from_value(value: &Value) -> Option<Self> {
        Some(match value {
            Value::Int(_) => Self::Int,
            Value::UInt(_) => Self::UInt,
            Value::Bool(_) => Self::Bool,
            Value::Str(_) => Self::Str,
            Value::Bytes(_) => Self::Bytes,
            Value::Source(_) => Self::Source,
            Value::HttpResponse(_) => Self::HttpResponse,
            Value::Observation(_) => Self::Observation,
            Value::Format(_, _) => Self::Format,
            Value::Section(_, _) => Self::Section,
            Value::Offsets(_) => Self::Offsets,
            Value::Diff(_) => Self::Diff,
            Value::Finding(_) => Self::Finding,
            Value::Instruction(_) => Self::Instruction,
            Value::Disassembly(_) => Self::Disassembly,
            Value::Regions(_) => Self::Regions,
            Value::Region(_) => Self::Region,
            Value::Record(record) => Self::Record(record.id),
            Value::Result(_) | Value::List(_, _) => return None,
        })
    }
    fn as_type(self) -> Type {
        match self {
            Self::Int => Type::Int,
            Self::UInt => Type::UInt,
            Self::Bool => Type::Bool,
            Self::Str => Type::Str,
            Self::Bytes => Type::Bytes,
            Self::Source => Type::Source,
            Self::HttpResponse => Type::HttpResponse,
            Self::Observation => Type::Observation,
            Self::Format => Type::Format,
            Self::Section => Type::Section,
            Self::Offsets => Type::Offsets,
            Self::Diff => Type::Diff,
            Self::Finding => Type::Finding,
            Self::Instruction => Type::Instruction,
            Self::Disassembly => Type::Disassembly,
            Self::Regions => Type::Regions,
            Self::Region => Type::Region,
            Self::Record(id) => Type::Record(id),
        }
    }
    fn from_type(value: Type) -> Option<Self> {
        Some(match value {
            Type::Int => Self::Int,
            Type::UInt => Self::UInt,
            Type::Bool => Self::Bool,
            Type::Str => Self::Str,
            Type::Bytes => Self::Bytes,
            Type::Source => Self::Source,
            Type::HttpResponse => Self::HttpResponse,
            Type::Observation => Self::Observation,
            Type::Format => Self::Format,
            Type::Section => Self::Section,
            Type::Offsets => Self::Offsets,
            Type::Diff => Self::Diff,
            Type::Finding => Self::Finding,
            Type::Instruction => Self::Instruction,
            Type::Disassembly => Self::Disassembly,
            Type::Regions => Self::Regions,
            Type::Region => Self::Region,
            Type::Record(id) => Self::Record(id),
            _ => return None,
        })
    }
}

impl Type {
    fn from_name(name: &str) -> Result<Self, String> {
        if let Some(inner) = name.strip_prefix("List<").and_then(|s| s.strip_suffix('>')) {
            let inner = Self::from_name(inner)?;
            let kind = ResultKind::from_type(inner)
                .ok_or_else(|| format!("unsupported List type {name}"))?;
            return Ok(Self::List(Some(kind)));
        }
        if let Some(inner) = name
            .strip_prefix("Result<")
            .and_then(|s| s.strip_suffix('>'))
        {
            let inner = Self::from_name(inner)?;
            let kind = ResultKind::from_type(inner)
                .ok_or_else(|| format!("unsupported Result type {name}"))?;
            return Ok(Self::Result(Some(kind)));
        }
        match name {
            "i64" => Ok(Self::Int),
            "u64" => Ok(Self::UInt),
            "bool" => Ok(Self::Bool),
            "str" => Ok(Self::Str),
            "bytes" => Ok(Self::Bytes),
            "Source" => Ok(Self::Source),
            "HttpResponse" => Ok(Self::HttpResponse),
            "Observation" => Ok(Self::Observation),
            "Format" => Ok(Self::Format),
            "Section" => Ok(Self::Section),
            "Offsets" => Ok(Self::Offsets),
            "Diff" => Ok(Self::Diff),
            "Finding" => Ok(Self::Finding),
            "Instruction" => Ok(Self::Instruction),
            "Disassembly" => Ok(Self::Disassembly),
            "Regions" => Ok(Self::Regions),
            "Region" => Ok(Self::Region),
            _ => Err(format!("unknown type {name}")),
        }
    }

    fn accepts(self, value: &Value) -> bool {
        if let (Self::Record(expected), Value::Record(record)) = (self, value) {
            return expected == record.id;
        }
        if let (Self::List(expected), Value::List(items, actual)) = (self, value) {
            return items.len() <= MAX_LOOP_ITEMS
                && (expected.is_none() || actual.is_none() || expected == *actual);
        }
        if let (Self::Result(expected), Value::Result(result)) = (self, value) {
            return match result.as_ref() {
                Ok(inner) => expected.is_none_or(|kind| kind.as_type().accepts(inner)),
                Err(_) => true,
            };
        }
        matches!(
            (self, value),
            (Self::Any, _)
                | (Self::Int, Value::Int(_))
                | (Self::UInt, Value::UInt(_))
                | (Self::Bool, Value::Bool(_))
                | (Self::Str, Value::Str(_))
                | (Self::Bytes, Value::Bytes(_))
                | (Self::Source, Value::Source(_))
                | (Self::HttpResponse, Value::HttpResponse(_))
                | (Self::Observation, Value::Observation(_))
                | (Self::Format, Value::Format(_, _))
                | (Self::Section, Value::Section(_, _))
                | (Self::Offsets, Value::Offsets(_))
                | (Self::Diff, Value::Diff(_))
                | (Self::Finding, Value::Finding(_))
                | (Self::Instruction, Value::Instruction(_))
                | (Self::Disassembly, Value::Disassembly(_))
                | (Self::Regions, Value::Regions(_))
                | (Self::Region, Value::Region(_))
        )
    }

    fn compatible(self, actual: Self) -> bool {
        self == Self::Any
            || actual == Self::Any
            || self == actual
            || matches!(
                (self, actual),
                (Self::List(None), Self::List(_))
                    | (Self::List(_), Self::List(None))
                    | (Self::Result(None), Self::Result(_))
                    | (Self::Result(_), Self::Result(None))
            )
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Result(inner) = self {
            return match inner {
                Some(kind) => write!(f, "Result<{}>", kind.as_type()),
                None => f.write_str("Result<dynamic>"),
            };
        }
        if let Self::List(inner) = self {
            return match inner {
                Some(kind) => write!(f, "List<{}>", kind.as_type()),
                None => f.write_str("List<dynamic>"),
            };
        }
        f.write_str(match self {
            Self::Any => "dynamic",
            Self::Int => "i64",
            Self::UInt => "u64",
            Self::Bool => "bool",
            Self::Str => "str",
            Self::Bytes => "bytes",
            Self::Source => "Source",
            Self::HttpResponse => "HttpResponse",
            Self::Observation => "Observation",
            Self::Format => "Format",
            Self::Section => "Section",
            Self::Offsets => "Offsets",
            Self::Diff => "Diff",
            Self::Finding => "Finding",
            Self::Instruction => "Instruction",
            Self::Disassembly => "Disassembly",
            Self::Regions => "Regions",
            Self::Region => "Region",
            Self::Record(_) => "record",
            Self::List(_) => unreachable!(),
            Self::Result(_) => unreachable!(),
        })
    }
}

struct Function {
    params: Vec<(String, Type)>,
    result_type: Option<Type>,
    body: Option<FunctionBody>,
    steps: Vec<Action>,
    result_code: Option<Program>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDef {
    id: u64,
    name: String,
    fields: Vec<(String, Type)>,
}
struct Binding {
    name: String,
    mutable: bool,
    annotation: Option<Type>,
    expr: Option<Expr>,
    code: Program,
    line: usize,
}
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
enum ActionKind {
    Let,
    Var,
    Assign,
    Print,
    Impact,
    Return,
    Break,
    Continue,
    For,
    While,
    If,
}
struct ReturnCheck {
    allowed: bool,
    inferred: Vec<Type>,
}
struct Action {
    kind: ActionKind,
    name: Option<String>,
    annotation: Option<Type>,
    expr: Option<Expr>,
    code: Program,
    body: Vec<Action>,
    else_body: Vec<Action>,
    line: usize,
    col: usize,
}

enum ActionFlow {
    Next,
    Return(Value),
    Break,
    Continue,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    root_depth: u16,
    entry: String,
    effects: Vec<String>,
    modules: Vec<BundleModule>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleModule {
    path: String,
    effects: Vec<String>,
    imports: Vec<BundleImport>,
    functions: Vec<BundleFunction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    records: Vec<RecordDef>,
    lets: Vec<BundleBinding>,
    actions: Vec<BundleAction>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleImport {
    alias: String,
    target: BundleTarget,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum BundleTarget {
    Binary,
    Bytes,
    Text,
    Formats,
    Cli,
    Net,
    Process,
    ResultOps,
    Audit,
    Iter,
    ListOps,
    Lab,
    Asm,
    Python(String),
    Local(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFunction {
    name: String,
    params: Vec<(String, Type)>,
    result_type: Option<Type>,
    steps: Vec<BundleAction>,
    result: Option<Program>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleBinding {
    name: String,
    mutable: bool,
    annotation: Option<Type>,
    code: Program,
    line: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleAction {
    kind: ActionKind,
    name: Option<String>,
    annotation: Option<Type>,
    code: Program,
    body: Vec<BundleAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    else_body: Vec<BundleAction>,
    line: usize,
    col: usize,
}
struct Module {
    path: PathBuf,
    effects: HashSet<String>,
    imports: HashMap<String, Import>,
    functions: HashMap<String, Function>,
    records: HashMap<String, RecordDef>,
    lets: Vec<Binding>,
    mutable_globals: HashSet<String>,
    types: RefCell<HashMap<String, Type>>,
    globals: RefCell<HashMap<String, Value>>,
    actions: Vec<Action>,
}

struct CaseArtifact {
    kind: &'static str,
    path: String,
    sha256: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Ast,
    Vm,
}

struct Runtime {
    engine: Engine,
    project_root: PathBuf,
    packages: BTreeMap<String, PathBuf>,
    read_roots: Vec<PathBuf>,
    allowed_connections: HashSet<String>,
    allowed_processes: HashSet<u32>,
    python_executable: Option<PathBuf>,
    python_session: RefCell<Option<python_bridge::Session>>,
    script_args: Vec<String>,
    declared_effects: HashSet<String>,
    loading: HashSet<PathBuf>,
    cache: HashMap<PathBuf, Rc<Module>>,
    loaded_source_hashes: HashMap<PathBuf, [u8; 32]>,
    records: HashMap<u64, RecordDef>,
    record_modules: HashMap<u64, Rc<Module>>,
    checked_modules: HashSet<PathBuf>,
    initialized_modules: HashSet<PathBuf>,
    action_steps: Cell<usize>,
    machine_output: bool,
    case_output: Option<PathBuf>,
    case_events: RefCell<Vec<JsonValue>>,
    case_event_bytes: Cell<usize>,
    case_sources: RefCell<BTreeMap<String, Arc<Source>>>,
    case_source_bytes: Cell<usize>,
    case_artifacts: RefCell<BTreeMap<(String, String), CaseArtifact>>,
    case_artifact_bytes: Cell<usize>,
}

#[derive(Default)]
struct Permissions {
    read_roots: Vec<PathBuf>,
    allowed_connections: Vec<String>,
    allowed_processes: Vec<u32>,
    python_executable: Option<PathBuf>,
    case_output: Option<PathBuf>,
}

fn safe_bundle_path(root: &Path, value: &str, extension: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.len() > 4096 || value.contains('\\') || value.contains(':') {
        return Err("invalid bundle path".into());
    }
    let mut path = root.to_path_buf();
    for part in value.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err("invalid bundle path".into());
        }
        path.push(part);
    }
    if !(extension == "gak" && project::is_source_path(&path))
        && path.extension().and_then(|s| s.to_str()) != Some(extension)
    {
        return Err("invalid bundle path extension".into());
    }
    Ok(path)
}

fn bundle_action(action: &Action) -> BundleAction {
    BundleAction {
        kind: action.kind,
        name: action.name.clone(),
        annotation: action.annotation,
        code: action.code.clone(),
        body: action.body.iter().map(bundle_action).collect(),
        else_body: action.else_body.iter().map(bundle_action).collect(),
        line: action.line,
        col: action.col,
    }
}

fn load_bundle_action(
    raw: BundleAction,
    depth: usize,
    loop_depth: usize,
) -> Result<Action, String> {
    if depth > 32 {
        return Err("bundle block nesting too deep".into());
    }
    raw.code.verify()?;
    match raw.kind {
        ActionKind::Let | ActionKind::Var | ActionKind::Assign | ActionKind::For
            if raw.name.as_ref().is_none_or(String::is_empty) =>
        {
            return Err("bundle binding name missing".into());
        }
        ActionKind::Print
        | ActionKind::Impact
        | ActionKind::Return
        | ActionKind::Break
        | ActionKind::Continue
        | ActionKind::While
        | ActionKind::If
            if raw.name.is_some() =>
        {
            return Err("unexpected bundle binding name".into());
        }
        _ => {}
    }
    if !matches!(
        raw.kind,
        ActionKind::For | ActionKind::While | ActionKind::If
    ) && !raw.body.is_empty()
    {
        return Err("unexpected bundle action body".into());
    }
    if !matches!(raw.kind, ActionKind::If) && !raw.else_body.is_empty() {
        return Err("unexpected bundle else body".into());
    }
    if !matches!(raw.kind, ActionKind::Let | ActionKind::Var) && raw.annotation.is_some() {
        return Err("unexpected bundle type annotation".into());
    }
    if raw.annotation == Some(Type::Any) {
        return Err("invalid bundle type annotation".into());
    }
    if matches!(raw.kind, ActionKind::Break | ActionKind::Continue)
        && !matches!(raw.code.instructions.as_slice(), [Instruction::Bool(true)])
    {
        return Err("invalid bundle loop control".into());
    }
    if matches!(raw.kind, ActionKind::Break | ActionKind::Continue) && loop_depth == 0 {
        return Err("bundle loop control outside loop".into());
    }
    let body_loop_depth =
        loop_depth + usize::from(matches!(raw.kind, ActionKind::For | ActionKind::While));
    let body = raw
        .body
        .into_iter()
        .map(|item| load_bundle_action(item, depth + 1, body_loop_depth))
        .collect::<Result<Vec<_>, _>>()?;
    let else_body = raw
        .else_body
        .into_iter()
        .map(|item| load_bundle_action(item, depth + 1, loop_depth))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Action {
        kind: raw.kind,
        name: raw.name,
        annotation: raw.annotation,
        expr: None,
        code: raw.code,
        body,
        else_body,
        line: raw.line,
        col: raw.col,
    })
}

fn actions_have_return(actions: &[Action]) -> bool {
    actions.iter().any(|action| {
        matches!(action.kind, ActionKind::Return)
            || actions_have_return(&action.body)
            || actions_have_return(&action.else_body)
    })
}

fn actions_always_return(actions: &[Action]) -> bool {
    actions.iter().any(|action| match action.kind {
        ActionKind::Return => true,
        ActionKind::If => {
            !action.else_body.is_empty()
                && actions_always_return(&action.body)
                && actions_always_return(&action.else_body)
        }
        _ => false,
    })
}

fn resolve_type(
    name: &str,
    records: &HashMap<String, RecordDef>,
    imports: &HashMap<String, Import>,
) -> Result<Type, String> {
    if let Some(inner) = name.strip_prefix("List<").and_then(|s| s.strip_suffix('>')) {
        return ResultKind::from_type(resolve_type(inner, records, imports)?)
            .map(|kind| Type::List(Some(kind)))
            .ok_or_else(|| format!("unsupported List type {name}"));
    }
    if let Some(inner) = name
        .strip_prefix("Result<")
        .and_then(|s| s.strip_suffix('>'))
    {
        return ResultKind::from_type(resolve_type(inner, records, imports)?)
            .map(|kind| Type::Result(Some(kind)))
            .ok_or_else(|| format!("unsupported Result type {name}"));
    }
    if let Some(record) = records.get(name) {
        return Ok(Type::Record(record.id));
    }
    if let Some((alias, record)) = name.split_once('.') {
        if let Some(Import::Local(module)) = imports.get(alias) {
            return module
                .records
                .get(record)
                .map(|record| Type::Record(record.id))
                .ok_or_else(|| format!("unknown type {name}"));
        }
    }
    Type::from_name(name)
}

fn record_id(path: &Path, name: &str) -> u64 {
    let mut hash = Sha256::new();
    hash.update(path.to_string_lossy().as_bytes());
    hash.update([0]);
    hash.update(name.as_bytes());
    u64::from_le_bytes(hash.finalize()[..8].try_into().unwrap())
}

fn compile_steps(
    steps: &[BlockStmt],
    records: &HashMap<String, RecordDef>,
    imports: &HashMap<String, Import>,
) -> Result<Vec<Action>, String> {
    steps
        .iter()
        .map(|step| {
            if matches!(step.kind, BlockStmtKind::Break | BlockStmtKind::Continue) {
                return Ok(Action {
                    kind: if matches!(step.kind, BlockStmtKind::Break) {
                        ActionKind::Break
                    } else {
                        ActionKind::Continue
                    },
                    name: None,
                    annotation: None,
                    expr: None,
                    code: Program {
                        instructions: vec![Instruction::Bool(true)],
                    },
                    body: Vec::new(),
                    else_body: Vec::new(),
                    line: step.line,
                    col: step.col,
                });
            }
            let annotation = match &step.kind {
                BlockStmtKind::Let(_, annotation, _) | BlockStmtKind::Var(_, annotation, _) => {
                    annotation
                        .as_deref()
                        .map(|name| resolve_type(name, records, imports))
                        .transpose()
                        .map_err(|e| format!("{}:{}: {e}", step.line, step.col))?
                }
                _ => None,
            };
            let (kind, name, expr, body, else_body) = match &step.kind {
                BlockStmtKind::Let(name, _, expr) => (
                    ActionKind::Let,
                    Some(name.clone()),
                    expr,
                    Vec::new(),
                    Vec::new(),
                ),
                BlockStmtKind::Var(name, _, expr) => (
                    ActionKind::Var,
                    Some(name.clone()),
                    expr,
                    Vec::new(),
                    Vec::new(),
                ),
                BlockStmtKind::Assign(name, expr) => (
                    ActionKind::Assign,
                    Some(name.clone()),
                    expr,
                    Vec::new(),
                    Vec::new(),
                ),
                BlockStmtKind::Print(expr) => {
                    (ActionKind::Print, None, expr, Vec::new(), Vec::new())
                }
                BlockStmtKind::Impact(expr) => {
                    (ActionKind::Impact, None, expr, Vec::new(), Vec::new())
                }
                BlockStmtKind::Return(expr) => {
                    (ActionKind::Return, None, expr, Vec::new(), Vec::new())
                }
                BlockStmtKind::For(name, expr, body) => (
                    ActionKind::For,
                    Some(name.clone()),
                    expr,
                    compile_steps(body, records, imports)?,
                    Vec::new(),
                ),
                BlockStmtKind::While(expr, body) => (
                    ActionKind::While,
                    None,
                    expr,
                    compile_steps(body, records, imports)?,
                    Vec::new(),
                ),
                BlockStmtKind::If(expr, yes, no) => (
                    ActionKind::If,
                    None,
                    expr,
                    compile_steps(yes, records, imports)?,
                    compile_steps(no, records, imports)?,
                ),
                BlockStmtKind::Break | BlockStmtKind::Continue => unreachable!(),
            };
            Ok(Action {
                kind,
                name,
                annotation,
                expr: Some(expr.clone()),
                code: Program::compile(expr)?,
                body,
                else_body,
                line: step.line,
                col: step.col,
            })
        })
        .collect()
}

pub struct RunOptions {
    pub read_roots: Vec<PathBuf>,
    pub allowed_connections: Vec<String>,
    pub allowed_processes: Vec<u32>,
    pub python_executable: Option<PathBuf>,
    pub script_args: Vec<String>,
    pub engine: Engine,
    pub case_output: Option<PathBuf>,
}

pub fn run(script: &Path, options: RunOptions) -> Result<(), String> {
    start(
        script,
        Permissions {
            read_roots: options.read_roots,
            allowed_connections: options.allowed_connections,
            allowed_processes: options.allowed_processes,
            python_executable: options.python_executable,
            case_output: options.case_output,
        },
        options.script_args,
        true,
        options.engine,
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CallRequest {
    version: u8,
    args: Vec<JsonValue>,
}

fn decode_call_arg(value: JsonValue) -> Result<Value, String> {
    match value {
        JsonValue::Array(items) => {
            if items.len() > MAX_LOOP_ITEMS {
                return Err(format!("call list exceeds {MAX_LOOP_ITEMS} items"));
            }
            make_list(
                items
                    .into_iter()
                    .map(decode_call_scalar)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        other => decode_call_scalar(other),
    }
}

fn decode_call_scalar(value: JsonValue) -> Result<Value, String> {
    match value {
        JsonValue::Bool(value) => Ok(Value::Bool(value)),
        JsonValue::String(value) => Ok(Value::Str(value)),
        JsonValue::Number(value) => value
            .as_i64()
            .map(Value::Int)
            .ok_or_else(|| "call integer is outside i64 range".into()),
        JsonValue::Object(mut fields)
            if fields.len() == 2
                && fields.get("$galeikan").and_then(JsonValue::as_str) == Some("u64") =>
        {
            let value = fields
                .remove("value")
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or("call u64 argument needs a decimal string")?;
            Ok(Value::UInt(
                value.parse::<u64>().map_err(|_| "call u64 out of range")?,
            ))
        }
        JsonValue::Object(mut fields)
            if fields.len() == 2
                && fields.get("$galeikan").and_then(JsonValue::as_str) == Some("bytes") =>
        {
            let hex = fields
                .remove("hex")
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or("call bytes argument needs hex data")?;
            if hex.len() > MAX_PYTHON_BYTES * 2 {
                return Err(format!(
                    "call bytes argument exceeds {MAX_PYTHON_BYTES} bytes"
                ));
            }
            Ok(Value::Bytes(Arc::new(parse_hex(&hex)?)))
        }
        _ => Err(
            "call accepts i64, u64, bool, str, bytes, or a homogeneous list of those values".into(),
        ),
    }
}

fn encode_call_value(value: Value) -> Result<JsonValue, String> {
    Ok(match value {
        Value::Int(value) => json!(value),
        Value::UInt(value) => json!({ "$galeikan": "u64", "value": value.to_string() }),
        Value::Bool(value) => json!(value),
        Value::Str(value) => json!(value),
        Value::List(items, _) => {
            if items.len() > MAX_LOOP_ITEMS {
                return Err(format!("call list exceeds {MAX_LOOP_ITEMS} items"));
            }
            JsonValue::Array(
                items
                    .iter()
                    .cloned()
                    .map(encode_call_value)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        Value::Bytes(bytes) if bytes.len() <= MAX_PYTHON_BYTES => {
            json!({ "$galeikan": "bytes", "hex": hex_bytes(&bytes) })
        }
        Value::Bytes(_) => {
            return Err(format!(
                "call bytes result exceeds {MAX_PYTHON_BYTES} bytes"
            ));
        }
        Value::Source(source) => json!({
            "$galeikan": "Source", "label": source.label, "origin": source.provenance(),
            "sha256": source.sha256, "size": source.bytes().len(),
            "lineage": source.lineage()
        }),
        Value::HttpResponse(response) => json!({
            "$galeikan": "HttpResponse", "status": response.status,
            "headers": response.headers,
            "request": encode_call_value(Value::Source(response.request.clone()))?,
            "body": encode_call_value(Value::Source(response.body.clone()))?
        }),
        Value::Observation(observation) => json!({
            "$galeikan": "Observation", "value": observation.value,
            "offset": observation.offset, "width": observation.width,
            "decoder": observation.decoder, "source": observation.source.label,
            "origin": observation.source.provenance(), "sha256": observation.source.sha256,
            "source_lineage": observation.source.lineage()
        }),
        Value::Format(source, report) => json!({
            "$galeikan": "Format", "summary": report.summary(),
            "source": source.label, "origin": source.provenance(), "sha256": source.sha256,
            "source_lineage": source.lineage()
        }),
        Value::Section(source, section) => json!({
            "$galeikan": "Section", "name": section.name, "file_offset": section.file_offset,
            "file_size": section.file_size, "virtual_address": section.virtual_address,
            "virtual_size": section.virtual_size, "flags": section.flags,
            "writable": section.writable, "executable": section.executable,
            "source": source.label, "origin": source.provenance(), "sha256": source.sha256,
            "source_lineage": source.lineage()
        }),
        Value::Offsets(offsets) => json!({ "$galeikan": "Offsets", "values": offsets }),
        Value::Diff(diff) => json!({
            "$galeikan": "Diff", "offsets": diff.offsets,
            "left_sha256": diff.left.sha256, "right_sha256": diff.right.sha256,
            "left_size": diff.left.bytes().len(), "right_size": diff.right.bytes().len(),
            "left_lineage": diff.left.lineage(), "right_lineage": diff.right.lineage()
        }),
        Value::Finding(finding) => match &finding.evidence {
            FindingEvidence::Numeric {
                observation,
                constraint,
            } => json!({
                "$galeikan": "Finding", "kind": "numeric",
                "rule": finding.rule, "passed": finding.passed,
                "expected": constraint.display(), "actual": observation.value,
                "offset": observation.offset, "width": observation.width,
                "decoder": observation.decoder,
                "source": observation.source.label,
                "origin": observation.source.provenance(),
                "sha256": observation.source.sha256,
                "source_lineage": observation.source.lineage()
            }),
            FindingEvidence::Pattern {
                source,
                pattern_kind,
                pattern_width,
                pattern_sha256,
                offsets,
            } => json!({
                "$galeikan": "Finding", "kind": "pattern",
                "rule": finding.rule, "passed": finding.passed,
                "pattern_kind": pattern_kind, "pattern_width": pattern_width,
                "pattern_sha256": pattern_sha256,
                "count": offsets.len(), "offsets": offsets,
                "source": source.label, "origin": source.provenance(),
                "sha256": source.sha256, "source_lineage": source.lineage()
            }),
            FindingEvidence::Signal {
                source,
                name,
                expected,
                actual,
                field,
            } => json!({
                "$galeikan": "Finding", "kind": "signal",
                "rule": finding.rule, "passed": finding.passed,
                "signal": name, "expected": expected, "actual": actual,
                "field": field.map(|field| json!({
                    "offset": field.offset, "width": field.width,
                    "decoder": field.decoder, "raw_value": field.value
                })),
                "source": source.label, "origin": source.provenance(),
                "sha256": source.sha256, "source_lineage": source.lineage()
            }),
        },
        Value::Record(record) => {
            let fields = record
                .fields
                .iter()
                .map(|(name, value)| Ok((name.clone(), encode_call_value(value.clone())?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            json!({ "$galeikan": "Record", "type": record.name, "fields": fields })
        }
        Value::Instruction(instruction) => json!({
            "$galeikan": "Instruction", "text": instruction.decoded.text,
            "mnemonic": instruction.decoded.mnemonic, "flow": instruction.decoded.flow,
            "size": instruction.decoded.size, "offset": instruction.offset,
            "address": format!("0x{:x}", instruction.decoded.ip),
            "target": instruction.decoded.target.map(|target| format!("0x{target:x}")),
            "source": instruction.source.label, "origin": instruction.source.provenance(),
            "sha256": instruction.source.sha256,
            "source_lineage": instruction.source.lineage()
        }),
        Value::Disassembly(disassembly) => json!({
            "$galeikan": "Disassembly", "count": disassembly.instructions.len(),
            "block_count": disassembly.blocks.len(),
            "offset": disassembly.start,
            "range": [disassembly.range_start, disassembly.range_end],
            "address": disassembly.instructions.first().map(|i| format!("0x{:x}", i.decoded.ip)),
            "source": disassembly.source.label,
            "origin": disassembly.source.provenance(),
            "sha256": disassembly.source.sha256,
            "source_lineage": disassembly.source.lineage()
        }),
        Value::Regions(regions) => json!({ "$galeikan": "Regions", "count": regions.len() }),
        Value::Region(region) => json!({
            "$galeikan": "Region", "pid": region.pid,
            "start": format!("0x{:x}", region.start), "size": region.size,
            "access": region.access, "label": region.label,
            "image_backed": region.image_backed
        }),
        Value::Result(result) => match result.as_ref() {
            Ok(value) => {
                json!({ "$galeikan": "Result", "ok": true, "value": encode_call_value(value.clone())? })
            }
            Err(error) => json!({ "$galeikan": "Result", "ok": false, "error": error }),
        },
    })
}

pub struct CallOptions {
    pub read_roots: Vec<PathBuf>,
    pub allowed_connections: Vec<String>,
    pub allowed_processes: Vec<u32>,
    pub python_executable: Option<PathBuf>,
    pub script_args: Vec<String>,
    pub engine: Engine,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServeRequest {
    version: u8,
    function: String,
    args: Vec<JsonValue>,
}

pub struct CallSession {
    runtime: Runtime,
    root: Rc<Module>,
}

impl CallSession {
    pub fn new(script: &Path, options: CallOptions) -> Result<Self, String> {
        let path = script
            .canonicalize()
            .map_err(|e| format!("cannot read script: {}: {e}", script.display()))?;
        let is_bundle = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("gakb"));
        let (mut runtime, root) = if is_bundle {
            if options.engine != Engine::Vm {
                return Err(".gakb calls require the VM engine".into());
            }
            let (project_root, _, bundle, _) = read_bundle(&path)?;
            let mut runtime = Runtime::new(
                project_root,
                BTreeMap::new(),
                Permissions {
                    read_roots: options.read_roots,
                    allowed_connections: options.allowed_connections,
                    allowed_processes: options.allowed_processes,
                    python_executable: options.python_executable,
                    case_output: None,
                },
                options.script_args,
                Engine::Vm,
            );
            runtime.machine_output = true;
            let root = runtime.load_bundle(bundle)?;
            (runtime, root)
        } else {
            let project = project::resolve(&path)?;
            let mut runtime = Runtime::new(
                project.root,
                project.packages,
                Permissions {
                    read_roots: options.read_roots,
                    allowed_connections: options.allowed_connections,
                    allowed_processes: options.allowed_processes,
                    python_executable: options.python_executable,
                    case_output: None,
                },
                options.script_args,
                options.engine,
            );
            runtime.machine_output = true;
            let root = runtime.load_module(&path, true)?;
            runtime.check_module(&root)?;
            (runtime, root)
        };
        runtime.initialize_module(&root)?;
        Ok(Self { runtime, root })
    }

    fn invoke(&mut self, function: &str, args: Vec<JsonValue>) -> Result<JsonValue, String> {
        if args.len() > 64 {
            return Err("call has too many arguments".into());
        }
        let args = args
            .into_iter()
            .map(decode_call_arg)
            .collect::<Result<Vec<_>, _>>()?;
        self.invoke_decoded(function, args)
    }

    fn invoke_decoded(&mut self, function: &str, args: Vec<Value>) -> Result<JsonValue, String> {
        let value = self.runtime.call(&self.root, function, args, 0)?;
        encode_call_value(value)
    }

    pub fn serve_request(&mut self, request: &[u8]) -> String {
        let result = (|| {
            if request.len() > MAX_CALL_MESSAGE {
                return Err("call request exceeds 1 MiB".into());
            }
            let request: ServeRequest = serde_json::from_slice(request)
                .map_err(|e| format!("invalid call request: {e}"))?;
            if request.version != 1 {
                return Err("unsupported call version".into());
            }
            self.invoke(&request.function, request.args)
        })();
        let response = match result {
            Ok(value) => json!({ "version": 1, "ok": true, "value": value }),
            Err(error) => json!({ "version": 1, "ok": false, "error": error }),
        };
        let encoded = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"version":1,"ok":false,"error":"cannot encode call response"}"#.into()
        });
        if encoded.len() + 1 > MAX_CALL_MESSAGE {
            return r#"{"version":1,"ok":false,"error":"call result exceeds 1 MiB"}"#.into();
        }
        encoded
    }
}

pub fn call(
    script: &Path,
    function: &str,
    request: &[u8],
    options: CallOptions,
) -> Result<String, String> {
    if request.len() > MAX_CALL_MESSAGE {
        return Err("call request exceeds 1 MiB".into());
    }
    let request: CallRequest =
        serde_json::from_slice(request).map_err(|e| format!("invalid call request: {e}"))?;
    if request.version != 1 {
        return Err("unsupported call version".into());
    }
    if request.args.len() > 64 {
        return Err("call has too many arguments".into());
    }
    let args = request
        .args
        .into_iter()
        .map(decode_call_arg)
        .collect::<Result<Vec<_>, _>>()?;
    let mut session = CallSession::new(script, options)?;
    let value = session.invoke_decoded(function, args)?;
    let response = serde_json::to_string(&json!({ "version": 1, "value": value }))
        .map_err(|e| format!("cannot encode call result: {e}"))?;
    if response.len() > MAX_CALL_MESSAGE {
        return Err("call result exceeds 1 MiB".into());
    }
    Ok(response)
}

pub fn check(script: &Path) -> Result<(), String> {
    start(
        script,
        Permissions::default(),
        Vec::new(),
        false,
        Engine::Ast,
    )
}

pub fn checked_source_hashes(script: &Path) -> Result<HashMap<PathBuf, [u8; 32]>, String> {
    let path = script
        .canonicalize()
        .map_err(|e| format!("cannot read script: {}: {e}", script.display()))?;
    let project = project::resolve(&path)?;
    let mut runtime = Runtime::new(
        project.root,
        project.packages,
        Permissions::default(),
        Vec::new(),
        Engine::Ast,
    );
    let root = runtime.load_module(&path, true)?;
    runtime.check_module(&root)?;
    Ok(runtime.loaded_source_hashes)
}

pub fn build(script: &Path) -> Result<PathBuf, String> {
    let path = script
        .canonicalize()
        .map_err(|e| format!("cannot read script: {}: {e}", script.display()))?;
    let project = project::resolve(&path)?;
    let mut runtime = Runtime::new(
        project.root,
        project.packages,
        Permissions::default(),
        Vec::new(),
        Engine::Vm,
    );
    let root = runtime.load_module(&path, true)?;
    runtime.check_module(&root)?;
    let bundle = runtime.make_bundle(&root)?;
    let payload = serde_json::to_vec(&bundle).map_err(|e| format!("cannot encode bundle: {e}"))?;
    if payload.len() > MAX_BUNDLE {
        return Err("compiled bundle exceeds size limit".into());
    }
    let mut bytes = Vec::with_capacity(48 + payload.len());
    bytes.extend_from_slice(BUNDLE_MAGIC);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(&payload));
    bytes.extend_from_slice(&payload);
    let output = path.with_extension("gakb");
    fs::write(&output, bytes).map_err(|e| format!("cannot write {}: {e}", output.display()))?;
    Ok(output)
}

pub fn exec(artifact: &Path, options: RunOptions) -> Result<(), String> {
    let (project_root, bundle_path, bundle, bundle_bytes) = read_bundle(artifact)?;
    let mut runtime = Runtime::new(
        project_root,
        BTreeMap::new(),
        Permissions {
            read_roots: options.read_roots,
            allowed_connections: options.allowed_connections,
            allowed_processes: options.allowed_processes,
            python_executable: options.python_executable,
            case_output: options.case_output,
        },
        options.script_args,
        Engine::Vm,
    );
    runtime.record_case_artifact("galeikan.bundle", &bundle_path, &bundle_bytes)?;
    let root = runtime.load_bundle(bundle)?;
    runtime.run_root(&root)
}

fn read_bundle(artifact: &Path) -> Result<(PathBuf, PathBuf, Bundle, Vec<u8>), String> {
    let path = artifact
        .canonicalize()
        .map_err(|e| format!("cannot read bundle: {}: {e}", artifact.display()))?;
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .take((MAX_BUNDLE + 49) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let bundle = decode_bundle(&bytes)?;
    let project_root = path
        .parent()
        .and_then(|parent| parent.ancestors().nth(bundle.root_depth as usize))
        .ok_or("bundle project directory is unavailable")?
        .to_path_buf();
    Ok((project_root, path, bundle, bytes))
}

fn decode_bundle(bytes: &[u8]) -> Result<Bundle, String> {
    if bytes.len() < 48 || bytes.len() > MAX_BUNDLE + 48 || &bytes[..8] != BUNDLE_MAGIC {
        return Err("invalid or unsupported GAKB bundle".into());
    }
    let size = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| "invalid GAKB length field")?,
    );
    let payload = &bytes[48..];
    if size != payload.len() as u64 || Sha256::digest(payload).as_slice() != &bytes[16..48] {
        return Err("GAKB bundle length or checksum mismatch".into());
    }
    let bundle: Bundle =
        serde_json::from_slice(payload).map_err(|e| format!("invalid GAKB payload: {e}"))?;
    if bundle.root_depth > 32 {
        return Err("invalid bundle project depth".into());
    }
    Ok(bundle)
}

fn start(
    script: &Path,
    permissions: Permissions,
    script_args: Vec<String>,
    execute: bool,
    engine: Engine,
) -> Result<(), String> {
    let path = script
        .canonicalize()
        .map_err(|e| format!("cannot read script: {}: {e}", script.display()))?;
    let project = project::resolve(&path)?;
    let mut runtime = Runtime::new(
        project.root,
        project.packages,
        permissions,
        script_args,
        engine,
    );
    let root = runtime.load_module(&path, true)?;
    runtime.check_module(&root)?;
    if !execute {
        return Ok(());
    }
    runtime.run_root(&root)
}

impl Runtime {
    fn new(
        project_root: PathBuf,
        packages: BTreeMap<String, PathBuf>,
        permissions: Permissions,
        script_args: Vec<String>,
        engine: Engine,
    ) -> Self {
        Self {
            engine,
            project_root,
            packages,
            read_roots: permissions.read_roots,
            allowed_connections: permissions.allowed_connections.into_iter().collect(),
            allowed_processes: permissions.allowed_processes.into_iter().collect(),
            python_executable: permissions.python_executable,
            python_session: RefCell::new(None),
            script_args,
            declared_effects: HashSet::new(),
            loading: HashSet::new(),
            cache: HashMap::new(),
            loaded_source_hashes: HashMap::new(),
            records: HashMap::new(),
            record_modules: HashMap::new(),
            checked_modules: HashSet::new(),
            initialized_modules: HashSet::new(),
            action_steps: Cell::new(0),
            machine_output: false,
            case_output: permissions.case_output,
            case_events: RefCell::new(Vec::new()),
            case_event_bytes: Cell::new(0),
            case_sources: RefCell::new(BTreeMap::new()),
            case_source_bytes: Cell::new(0),
            case_artifacts: RefCell::new(BTreeMap::new()),
            case_artifact_bytes: Cell::new(0),
        }
    }

    fn emit_line(&self, line: &str) {
        if self.machine_output {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }

    fn run_root(&mut self, root: &Rc<Module>) -> Result<(), String> {
        if actions_have_return(&root.actions) {
            return Err("return outside function".into());
        }
        if let Some(path) = &self.case_output {
            if !self.declared_effects.contains("case.write") {
                return Err("case export requires { case.write } in the root module".into());
            }
            if path.exists() {
                return Err(format!("case output already exists: {}", path.display()));
            }
            let archive = case::archive_dir(path);
            if archive.exists() {
                return Err(format!(
                    "case archive already exists: {}",
                    archive.display()
                ));
            }
        }
        self.action_steps.set(0);
        self.initialize_module(root)?;
        match self.execute_actions(
            root,
            &root.actions,
            &mut HashMap::new(),
            &mut HashSet::new(),
            0,
        )? {
            ActionFlow::Next => {}
            ActionFlow::Return(_) => return Err("return outside function".into()),
            ActionFlow::Break | ActionFlow::Continue => {
                return Err("loop control outside loop".into())
            }
        }
        if let Some(path) = &self.case_output {
            self.write_case(root, path)?;
        }
        Ok(())
    }

    fn write_case(&self, root: &Rc<Module>, path: &Path) -> Result<(), String> {
        let bundle = self.make_bundle(root)?;
        let program = serde_json::to_vec(&bundle)
            .map_err(|e| format!("cannot encode case program identity: {e}"))?;
        let program_sha256 = hex_bytes(&Sha256::digest(&program));
        let sources = self.case_sources.borrow();
        let artifacts = self.case_artifacts.borrow();
        let mut blobs: BTreeMap<String, &[u8]> = BTreeMap::new();
        for (sha256, source) in sources.iter() {
            blobs.insert(sha256.clone(), source.bytes());
        }
        for artifact in artifacts.values() {
            if let Some(previous) = blobs.insert(artifact.sha256.clone(), &artifact.bytes) {
                if previous != artifact.bytes {
                    return Err("case artifact SHA-256 collision".into());
                }
            }
        }
        if let Some(previous) = blobs.insert(program_sha256.clone(), &program) {
            if previous != program {
                return Err("case program SHA-256 collision".into());
            }
        }
        if blobs.len() > case::MAX_BLOBS {
            return Err(format!("case exceeds {} unique blobs", case::MAX_BLOBS));
        }
        let total = blobs.values().try_fold(0_usize, |sum, bytes| {
            sum.checked_add(bytes.len())
                .ok_or("case blob size overflow")
        })?;
        if total > case::MAX_BLOB_BYTES {
            return Err(format!("case blobs exceed {} bytes", case::MAX_BLOB_BYTES));
        }
        let document = json!({
            "format": "galeikan.case",
            "version": 3,
            "entry": bundle.entry,
            "program_sha256": program_sha256,
            "program_blob_sha256": program_sha256,
            "engine": if self.engine == Engine::Ast { "ast" } else { "vm" },
            "effects": bundle.effects,
            "arguments": self.script_args,
            "program_mode": if artifacts.values().any(|artifact| artifact.kind == "galeikan.bundle") { "bundle" } else { "source" },
            "artifacts": artifacts.values().map(|artifact| json!({
                "kind": artifact.kind,
                "path": artifact.path,
                "sha256": artifact.sha256,
                "size": artifact.bytes.len()
            })).collect::<Vec<_>>(),
            "events": self.case_events.borrow().as_slice(),
            "blobs": blobs.iter().map(|(sha256, bytes)| json!({
                "sha256": sha256,
                "size": bytes.len()
            })).collect::<Vec<_>>(),
        });
        let payload =
            serde_json::to_vec_pretty(&document).map_err(|e| format!("cannot encode case: {e}"))?;
        if payload.len() > case::MAX_DOCUMENT {
            return Err(format!("case exceeds {} bytes", case::MAX_DOCUMENT));
        }
        case::write_archive(
            path,
            &payload,
            blobs.iter().map(|(hash, bytes)| (hash.as_str(), *bytes)),
        )
    }

    fn track_case_sources(&self, value: &Value) -> Result<(), String> {
        let mut roots = Vec::new();
        case_value_sources(value, &mut roots);
        let mut sources = self.case_sources.borrow_mut();
        let mut total = self.case_source_bytes.get();
        for source in roots {
            let mut cursor = Some(source);
            while let Some(current) = cursor {
                cursor = match &current.parent {
                    Some(
                        SourceParent::View(parent, ..)
                        | SourceParent::Patch(parent, ..)
                        | SourceParent::Splice(parent, ..),
                    ) => Some(parent.clone()),
                    None => None,
                };
                if let Some(existing) = sources.get(&current.sha256) {
                    if existing.bytes() != current.bytes() {
                        return Err("case Source hash collision".into());
                    }
                    continue;
                }
                if sources.len() >= case::MAX_BLOBS {
                    return Err(format!("case exceeds {} unique Sources", case::MAX_BLOBS));
                }
                total = total
                    .checked_add(current.bytes().len())
                    .ok_or("case Source byte count overflow")?;
                if total > case::MAX_BLOB_BYTES {
                    return Err(format!(
                        "case Sources exceed {} bytes",
                        case::MAX_BLOB_BYTES
                    ));
                }
                sources.insert(current.sha256.clone(), current);
            }
        }
        self.case_source_bytes.set(total);
        Ok(())
    }

    fn tick_action(&self) -> Result<(), String> {
        let count = self
            .action_steps
            .get()
            .checked_add(1)
            .ok_or("action step counter overflow")?;
        if count > MAX_ACTION_STEPS {
            return Err(format!("execution exceeds {MAX_ACTION_STEPS} action steps"));
        }
        self.action_steps.set(count);
        Ok(())
    }

    fn execute_actions(
        &self,
        module: &Rc<Module>,
        actions: &[Action],
        locals: &mut HashMap<String, Value>,
        mutable_locals: &mut HashSet<String>,
        depth: usize,
    ) -> Result<ActionFlow, String> {
        if depth > 32 {
            return Err("block nesting too deep".into());
        }
        for action in actions {
            let at = |e: String| {
                format!(
                    "{}:{}:{}: {e}",
                    module.path.display(),
                    action.line,
                    action.col
                )
            };
            self.tick_action().map_err(&at)?;
            if matches!(action.kind, ActionKind::Break) {
                return Ok(ActionFlow::Break);
            }
            if matches!(action.kind, ActionKind::Continue) {
                return Ok(ActionFlow::Continue);
            }
            if matches!(action.kind, ActionKind::If) {
                let condition = self
                    .execute_expr(module, locals, action.expr.as_ref(), &action.code, depth)
                    .map_err(&at)?
                    .as_bool()
                    .map_err(&at)?;
                let mut inner = locals.clone();
                let mut inner_mutable = mutable_locals.clone();
                let branch = if condition {
                    &action.body
                } else {
                    &action.else_body
                };
                let flow = self.execute_actions(
                    module,
                    branch,
                    &mut inner,
                    &mut inner_mutable,
                    depth + 1,
                )?;
                if let ActionFlow::Return(_) = flow {
                    return Ok(flow);
                }
                for outer_name in mutable_locals.iter() {
                    if let Some(updated) = inner.get(outer_name) {
                        locals.insert(outer_name.clone(), updated.clone());
                    }
                }
                if !matches!(flow, ActionFlow::Next) {
                    return Ok(flow);
                }
                continue;
            }
            if matches!(action.kind, ActionKind::While) {
                loop {
                    self.tick_action().map_err(&at)?;
                    let condition = self
                        .execute_expr(module, locals, action.expr.as_ref(), &action.code, depth)
                        .map_err(&at)?
                        .as_bool()
                        .map_err(&at)?;
                    if !condition {
                        break;
                    }
                    let mut inner = locals.clone();
                    let mut inner_mutable = mutable_locals.clone();
                    let flow = self.execute_actions(
                        module,
                        &action.body,
                        &mut inner,
                        &mut inner_mutable,
                        depth + 1,
                    )?;
                    if let ActionFlow::Return(_) = flow {
                        return Ok(flow);
                    }
                    for outer_name in mutable_locals.iter() {
                        if let Some(updated) = inner.get(outer_name) {
                            locals.insert(outer_name.clone(), updated.clone());
                        }
                    }
                    match flow {
                        ActionFlow::Break => break,
                        ActionFlow::Continue => continue,
                        ActionFlow::Next => {}
                        ActionFlow::Return(_) => unreachable!(),
                    }
                }
                continue;
            }
            let mut value = self
                .execute_expr(module, locals, action.expr.as_ref(), &action.code, depth)
                .map_err(&at)?;
            match action.kind {
                ActionKind::Let | ActionKind::Var => {
                    let name = action
                        .name
                        .as_ref()
                        .ok_or_else(|| at("local name missing".into()))?;
                    if let Some(expected) = action.annotation {
                        if !expected.accepts(&value) {
                            return Err(at(format!("binding {name} expects {expected}")));
                        }
                        value = specialize_list(value, expected);
                    }
                    if locals.insert(name.clone(), value).is_some() {
                        return Err(at(format!("duplicate local binding {name}")));
                    }
                    if matches!(action.kind, ActionKind::Var) {
                        mutable_locals.insert(name.clone());
                    }
                }
                ActionKind::Assign => {
                    let name = action
                        .name
                        .as_ref()
                        .ok_or_else(|| at("assignment name missing".into()))?;
                    if locals.contains_key(name) {
                        if !mutable_locals.contains(name) {
                            return Err(at(format!("cannot assign to immutable binding {name}")));
                        }
                        if !same_runtime_type(locals.get(name).unwrap(), &value) {
                            return Err(at(format!("assignment to {name} changes runtime type")));
                        }
                        let expected = match locals.get(name).unwrap() {
                            Value::List(_, Some(kind)) => Type::List(Some(*kind)),
                            _ => Type::Any,
                        };
                        locals.insert(name.clone(), specialize_list(value, expected));
                    } else if module.mutable_globals.contains(name) {
                        let mut globals = module.globals.borrow_mut();
                        let previous = globals
                            .get(name)
                            .ok_or_else(|| at(format!("uninitialized global {name}")))?;
                        if !same_runtime_type(previous, &value) {
                            return Err(at(format!("assignment to {name} changes runtime type")));
                        }
                        let expected = match previous {
                            Value::List(_, Some(kind)) => Type::List(Some(*kind)),
                            _ => Type::Any,
                        };
                        globals.insert(name.clone(), specialize_list(value, expected));
                    } else if module.globals.borrow().contains_key(name) {
                        return Err(at(format!("cannot assign to immutable binding {name}")));
                    } else {
                        return Err(at(format!("unknown assignment target {name}")));
                    }
                }
                ActionKind::For => {
                    let name = action
                        .name
                        .as_ref()
                        .ok_or_else(|| at("loop name missing".into()))?;
                    if locals.contains_key(name) {
                        return Err(at(format!("duplicate loop binding {name}")));
                    }
                    let values = match value {
                        Value::List(items, _) if items.len() <= MAX_LOOP_ITEMS => {
                            items.as_ref().clone()
                        }
                        Value::Offsets(offsets) if offsets.len() <= MAX_LOOP_ITEMS => offsets
                            .into_iter()
                            .map(|n| {
                                i64::try_from(n)
                                    .map(Value::Int)
                                    .map_err(|_| "loop offset outside i64 range".to_string())
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(&at)?,
                        Value::Bytes(bytes) if bytes.len() <= MAX_LOOP_ITEMS => {
                            bytes.iter().map(|b| Value::Int(i64::from(*b))).collect()
                        }
                        Value::Disassembly(disassembly)
                            if disassembly.instructions.len() <= MAX_LOOP_ITEMS =>
                        {
                            disassembly
                                .instructions
                                .iter()
                                .cloned()
                                .map(Value::Instruction)
                                .collect()
                        }
                        Value::Regions(regions) if regions.len() <= MAX_LOOP_ITEMS => {
                            regions.iter().cloned().map(Value::Region).collect()
                        }
                        Value::Offsets(_)
                        | Value::Bytes(_)
                        | Value::Disassembly(_)
                        | Value::Regions(_) => {
                            return Err(at(format!("loop exceeds {MAX_LOOP_ITEMS} items")))
                        }
                        Value::List(_, _) => {
                            return Err(at(format!("loop exceeds {MAX_LOOP_ITEMS} items")))
                        }
                        _ => {
                            return Err(at(
                                "for expects a List, Offsets, bytes, Disassembly, or Regions"
                                    .into(),
                            ))
                        }
                    };
                    for item in values {
                        self.tick_action().map_err(&at)?;
                        let mut inner = locals.clone();
                        let mut inner_mutable = mutable_locals.clone();
                        inner.insert(name.clone(), item);
                        let flow = self.execute_actions(
                            module,
                            &action.body,
                            &mut inner,
                            &mut inner_mutable,
                            depth + 1,
                        )?;
                        if let ActionFlow::Return(_) = flow {
                            return Ok(flow);
                        }
                        for outer_name in mutable_locals.iter() {
                            if let Some(updated) = inner.get(outer_name) {
                                locals.insert(outer_name.clone(), updated.clone());
                            }
                        }
                        match flow {
                            ActionFlow::Break => break,
                            ActionFlow::Continue => continue,
                            ActionFlow::Next => {}
                            ActionFlow::Return(_) => unreachable!(),
                        }
                    }
                }
                ActionKind::While | ActionKind::If | ActionKind::Break | ActionKind::Continue => {
                    unreachable!()
                }
                ActionKind::Return => return Ok(ActionFlow::Return(value)),
                ActionKind::Print => self.emit_line(&value.display()),
                ActionKind::Impact => {
                    let line = format_impact(value.clone()).map_err(&at)?;
                    if self.case_output.is_some() {
                        let mut events = self.case_events.borrow_mut();
                        if events.len() >= MAX_CASE_EVENTS {
                            return Err(at(format!("case exceeds {MAX_CASE_EVENTS} events")));
                        }
                        self.track_case_sources(&value).map_err(&at)?;
                        let event = json!({
                            "module": self.relative_path(&module.path).map_err(&at)?,
                            "line": action.line,
                            "column": action.col,
                            "value": encode_call_value(value).map_err(&at)?,
                        });
                        let length = serde_json::to_vec(&event)
                            .map_err(|e| at(format!("cannot encode case event: {e}")))?
                            .len();
                        let total = self.case_event_bytes.get().saturating_add(length);
                        if total > case::MAX_DOCUMENT / 2 {
                            return Err(at("case events exceed size limit".into()));
                        }
                        self.case_event_bytes.set(total);
                        events.push(event);
                    }
                    self.emit_line(&line);
                }
            }
        }
        Ok(ActionFlow::Next)
    }
}

fn format_impact(value: Value) -> Result<String, String> {
    let line = match value {
                Value::HttpResponse(response) => format!(
                    "impact {{ http_status: {}, request_sha256: {}, source: {:?}, origin: {:?}, sha256: {}, body_size: {}, headers: {} }}",
                    response.status, response.request.sha256, response.body.label, response.body.provenance(),
                    response.body.sha256, response.body.bytes().len(), response.headers.len()
                ),
                Value::Observation(o) => format!(
                    "impact {{ source: {:?}, origin: {:?}, sha256: {}, range: [{}..{}), decoder: {}, value: {} }}",
                    o.source.label, o.source.provenance(), o.source.sha256, o.offset, o.offset + o.width, o.decoder, o.value
                ),
                Value::Format(source, report) => format!(
                    "impact {{ source: {:?}, origin: {:?}, sha256: {}, {} }}",
                    source.label,
                    source.provenance(),
                    source.sha256,
                    report.summary()
                ),
                Value::Section(source, section) => format!(
                    "impact {{ section: {:?}, source: {:?}, origin: {:?}, sha256: {}, file: [{}..{}), address: 0x{:x}, virtual_size: {}, flags: 0x{:x}, writable: {}, executable: {} }}",
                    section.name.as_deref().unwrap_or("<name unavailable>"), source.label, source.provenance(), source.sha256,
                    section.file_offset, section.file_offset.saturating_add(section.file_size), section.virtual_address,
                    section.virtual_size, section.flags, section.writable, section.executable,
                ),
                Value::Diff(diff) => format!(
                    "impact {{ left: {:?}, left_origin: {:?}, left_sha256: {}, left_size: {}, right: {:?}, right_origin: {:?}, right_sha256: {}, right_size: {}, offsets: {:?} }}",
                    diff.left.label,
                    diff.left.provenance(),
                    diff.left.sha256,
                    diff.left.bytes().len(),
                    diff.right.label,
                    diff.right.provenance(),
                    diff.right.sha256,
                    diff.right.bytes().len(),
                    diff.offsets
                ),
                Value::Finding(finding) => match &finding.evidence {
                    FindingEvidence::Numeric { observation, constraint } => format!(
                        "impact {{ rule: {:?}, status: {}, expected: {:?}, actual: {}, source: {:?}, origin: {:?}, sha256: {}, range: [{}..{}), decoder: {} }}",
                        finding.rule,
                        if finding.passed { "pass" } else { "fail" },
                        constraint.display(),
                        observation.value,
                        observation.source.label,
                        observation.source.provenance(),
                        observation.source.sha256,
                        observation.offset,
                        observation.offset + observation.width,
                        observation.decoder
                    ),
                    FindingEvidence::Pattern { source, pattern_kind, pattern_width, pattern_sha256, offsets } => format!(
                        "impact {{ rule: {:?}, status: {}, pattern: {} {} bytes, pattern_sha256: {}, matches: {}, offsets: {:?}, source: {:?}, origin: {:?}, sha256: {} }}",
                        finding.rule,
                        if finding.passed { "pass" } else { "fail" },
                        pattern_kind,
                        pattern_width,
                        pattern_sha256,
                        offsets.len(),
                        offsets,
                        source.label,
                        source.provenance(),
                        source.sha256
                    ),
                    FindingEvidence::Signal { source, name, expected, actual, field } => format!(
                        "impact {{ rule: {:?}, status: {}, signal: {:?}, expected: {:?}, actual: {}, source: {:?}, origin: {:?}, sha256: {}, field: {} }}",
                        finding.rule,
                        if finding.passed { "pass" } else { "fail" },
                        name,
                        expected,
                        actual,
                        source.label,
                        source.provenance(),
                        source.sha256,
                        field.map_or_else(|| "unavailable".into(), |field| format!("[{}..{}) {} = {}", field.offset, field.offset + field.width, field.decoder, field.value))
                    ),
                },
                Value::Instruction(instruction) => format!(
                    "impact {{ source: {:?}, origin: {:?}, sha256: {}, range: [{}..{}), address: 0x{:x}, instruction: {:?}, flow: {} }}",
                    instruction.source.label, instruction.source.provenance(), instruction.source.sha256,
                    instruction.offset, instruction.offset + instruction.decoded.size,
                    instruction.decoded.ip, instruction.decoded.text, instruction.decoded.flow
                ),
                Value::Disassembly(disassembly) => format!(
                    "impact {{ source: {:?}, origin: {:?}, sha256: {}, range: [{}..{}), instructions: {}, blocks: {} }}",
                    disassembly.source.label, disassembly.source.provenance(), disassembly.source.sha256,
                    disassembly.range_start, disassembly.range_end,
                    disassembly.instructions.len(), disassembly.blocks.len()
                ),
                _ => {
                    return Err("impact expects an Observation, Format, Section, Diff, Finding, Instruction, Disassembly, or HttpResponse".into())
                }
            };
    Ok(line)
}

impl Runtime {
    fn relative_path(&self, path: &Path) -> Result<String, String> {
        let relative = path
            .strip_prefix(&self.project_root)
            .map_err(|_| format!("path outside project: {}", path.display()))?;
        let parts = relative
            .components()
            .map(|c| c.as_os_str().to_str().ok_or("non-UTF-8 project path"))
            .collect::<Result<Vec<_>, _>>()?;
        if parts.is_empty()
            || parts
                .iter()
                .any(|p| p.is_empty() || *p == "." || *p == "..")
        {
            return Err("invalid project path".into());
        }
        Ok(parts.join("/"))
    }

    fn record_case_artifact(
        &self,
        kind: &'static str,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), String> {
        if self.case_output.is_none() {
            return Ok(());
        }
        let relative = self.relative_path(path)?;
        let key = (kind.to_string(), relative.clone());
        let mut artifacts = self.case_artifacts.borrow_mut();
        if let Some(previous) = artifacts.get(&key) {
            return if previous.bytes == bytes {
                Ok(())
            } else {
                Err(format!("case artifact changed while loading: {relative}"))
            };
        }
        if artifacts.len() >= MAX_CASE_ARTIFACTS {
            return Err(format!("case exceeds {MAX_CASE_ARTIFACTS} artifacts"));
        }
        let total = self
            .case_artifact_bytes
            .get()
            .checked_add(bytes.len())
            .ok_or("case artifact size overflow")?;
        if total > MAX_CASE_ARTIFACT_BYTES {
            return Err(format!(
                "case artifacts exceed {MAX_CASE_ARTIFACT_BYTES} bytes"
            ));
        }
        let sha256 = hex_bytes(&Sha256::digest(bytes));
        artifacts.insert(
            key,
            CaseArtifact {
                kind,
                path: relative,
                sha256,
                bytes: bytes.to_vec(),
            },
        );
        self.case_artifact_bytes.set(total);
        Ok(())
    }

    fn expected_python_hash(&self, path: &Path) -> Result<Option<String>, String> {
        if self.case_output.is_none() {
            return Ok(None);
        }
        let key = ("python.module".to_string(), self.relative_path(path)?);
        self.case_artifacts
            .borrow()
            .get(&key)
            .map(|artifact| artifact.sha256.clone())
            .map(Some)
            .ok_or("Python module is missing from case artifacts".into())
    }

    fn capture_python_artifact(&self, path: &Path) -> Result<(), String> {
        if self.case_output.is_none() {
            return Ok(());
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|e| format!("cannot capture Python module {}: {e}", path.display()))?
            .take((MAX_SCRIPT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot capture Python module {}: {e}", path.display()))?;
        if bytes.len() > MAX_SCRIPT {
            return Err(format!("Python module exceeds {MAX_SCRIPT} case bytes"));
        }
        self.record_case_artifact("python.module", path, &bytes)
    }

    fn make_bundle(&self, root: &Rc<Module>) -> Result<Bundle, String> {
        let mut ordered = Vec::new();
        let mut seen = HashSet::new();
        fn visit(module: &Rc<Module>, seen: &mut HashSet<PathBuf>, ordered: &mut Vec<Rc<Module>>) {
            if !seen.insert(module.path.clone()) {
                return;
            }
            let mut children: Vec<_> = module
                .imports
                .values()
                .filter_map(|import| match import {
                    Import::Local(child) => Some(child.clone()),
                    _ => None,
                })
                .collect();
            children.sort_by(|a, b| a.path.cmp(&b.path));
            for child in children {
                visit(&child, seen, ordered);
            }
            ordered.push(module.clone());
        }
        visit(root, &mut seen, &mut ordered);
        let mut modules = Vec::new();
        for module in ordered {
            let mut imports = module
                .imports
                .iter()
                .map(|(alias, target)| {
                    let target = match target {
                        Import::Binary => BundleTarget::Binary,
                        Import::Bytes => BundleTarget::Bytes,
                        Import::Text => BundleTarget::Text,
                        Import::Formats => BundleTarget::Formats,
                        Import::Cli => BundleTarget::Cli,
                        Import::Net => BundleTarget::Net,
                        Import::Process => BundleTarget::Process,
                        Import::ResultOps => BundleTarget::ResultOps,
                        Import::Audit => BundleTarget::Audit,
                        Import::Iter => BundleTarget::Iter,
                        Import::ListOps => BundleTarget::ListOps,
                        Import::Lab => BundleTarget::Lab,
                        Import::Asm => BundleTarget::Asm,
                        Import::Python(path) => BundleTarget::Python(self.relative_path(path)?),
                        Import::Local(child) => {
                            BundleTarget::Local(self.relative_path(&child.path)?)
                        }
                    };
                    Ok(BundleImport {
                        alias: alias.clone(),
                        target,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            imports.sort_by(|a, b| a.alias.cmp(&b.alias));
            let mut functions = module
                .functions
                .iter()
                .map(|(name, function)| BundleFunction {
                    name: name.clone(),
                    params: function.params.clone(),
                    result_type: function.result_type,
                    steps: function.steps.iter().map(bundle_action).collect(),
                    result: function.result_code.clone(),
                })
                .collect::<Vec<_>>();
            functions.sort_by(|a, b| a.name.cmp(&b.name));
            let mut records = module.records.values().cloned().collect::<Vec<_>>();
            records.sort_by(|a, b| a.name.cmp(&b.name));
            let lets = module
                .lets
                .iter()
                .map(|b| BundleBinding {
                    name: b.name.clone(),
                    mutable: b.mutable,
                    annotation: b.annotation,
                    code: b.code.clone(),
                    line: b.line,
                })
                .collect();
            let actions = module.actions.iter().map(bundle_action).collect();
            let mut module_effects = module.effects.iter().cloned().collect::<Vec<_>>();
            module_effects.sort();
            modules.push(BundleModule {
                path: self.relative_path(&module.path)?,
                effects: module_effects,
                imports,
                functions,
                records,
                lets,
                actions,
            });
        }
        let mut effects = self.declared_effects.iter().cloned().collect::<Vec<_>>();
        effects.sort();
        let root_parent = root.path.parent().ok_or("script has no parent directory")?;
        let root_depth = root_parent
            .strip_prefix(&self.project_root)
            .map_err(|_| "script is outside project")?
            .components()
            .count();
        if root_depth > 32 {
            return Err("project nesting exceeds bundle limit".into());
        }
        Ok(Bundle {
            version: 23,
            root_depth: root_depth as u16,
            entry: self.relative_path(&root.path)?,
            effects,
            modules,
        })
    }

    fn load_bundle(&mut self, bundle: Bundle) -> Result<Rc<Module>, String> {
        if !(15..=23).contains(&bundle.version)
            || bundle.modules.is_empty()
            || bundle.modules.len() > 4096
        {
            return Err("unsupported or invalid GAKB bundle version/module count".into());
        }
        let bundle_version = bundle.version;
        for effect in bundle.effects {
            if !matches!(
                effect.as_str(),
                "file.read" | "net.connect" | "python.exec" | "process.inspect" | "case.write"
            ) || !self.declared_effects.insert(effect)
            {
                return Err("invalid or duplicate bundle effect".into());
            }
        }
        let module_count = bundle.modules.len();
        let mut built: HashMap<String, Rc<Module>> = HashMap::new();
        for (index, raw) in bundle.modules.into_iter().enumerate() {
            let path = safe_bundle_path(&self.project_root, &raw.path, "gak")?;
            if built.contains_key(&raw.path) {
                return Err("duplicate bundle module".into());
            }
            let is_root = raw.path == bundle.entry;
            if is_root && index + 1 != module_count {
                return Err("bundle entry must be last".into());
            }
            if !is_root && !raw.actions.is_empty() {
                return Err("imported bundle module has actions".into());
            }
            let mut effects = HashSet::new();
            for effect in raw.effects {
                if !matches!(
                    effect.as_str(),
                    "file.read" | "net.connect" | "python.exec" | "process.inspect" | "case.write"
                ) || !effects.insert(effect.clone())
                    || !self.declared_effects.contains(&effect)
                {
                    return Err("invalid or ungranted bundle module effect".into());
                }
            }
            if is_root && effects != self.declared_effects {
                return Err("bundle root effects do not match declared effects".into());
            }
            let mut names = HashSet::new();
            let mut imports = HashMap::new();
            for item in raw.imports {
                if !names.insert(item.alias.clone())
                    || item.alias.is_empty()
                    || item.alias.contains('.')
                {
                    return Err("invalid or duplicate bundle import alias".into());
                }
                let import = match item.target {
                    BundleTarget::Binary => Import::Binary,
                    BundleTarget::Bytes => Import::Bytes,
                    BundleTarget::Text => Import::Text,
                    BundleTarget::Formats => Import::Formats,
                    BundleTarget::Cli => Import::Cli,
                    BundleTarget::Net => Import::Net,
                    BundleTarget::Process => Import::Process,
                    BundleTarget::ResultOps => Import::ResultOps,
                    BundleTarget::Audit => Import::Audit,
                    BundleTarget::Iter => Import::Iter,
                    BundleTarget::ListOps => Import::ListOps,
                    BundleTarget::Lab => Import::Lab,
                    BundleTarget::Asm => Import::Asm,
                    BundleTarget::Local(key) => {
                        safe_bundle_path(&self.project_root, &key, "gak")?;
                        Import::Local(
                            built
                                .get(&key)
                                .ok_or("bundle module order or reference is invalid")?
                                .clone(),
                        )
                    }
                    BundleTarget::Python(key) => {
                        let candidate = safe_bundle_path(&self.project_root, &key, "py")?;
                        let canonical = candidate.canonicalize().map_err(|e| {
                            format!("cannot read Python module {}: {e}", candidate.display())
                        })?;
                        if !canonical.starts_with(&self.project_root) {
                            return Err("Python import outside project".into());
                        }
                        self.capture_python_artifact(&canonical)?;
                        Import::Python(canonical)
                    }
                };
                imports.insert(item.alias, import);
            }
            let mut records = HashMap::new();
            for record in raw.records {
                if record.name.is_empty()
                    || record.name.contains('.')
                    || !names.insert(record.name.clone())
                    || record.fields.len() > 64
                    || record.id == 0
                {
                    return Err("invalid or duplicate bundle struct".into());
                }
                let mut fields = HashSet::new();
                if record.fields.iter().any(|(name, kind)| {
                    name.is_empty() || !fields.insert(name) || *kind == Type::Any
                }) {
                    return Err("invalid bundle struct field".into());
                }
                if self.records.insert(record.id, record.clone()).is_some() {
                    return Err("duplicate bundle struct identifier".into());
                }
                records.insert(record.name.clone(), record);
            }
            let mut functions = HashMap::new();
            for function in raw.functions {
                if !names.insert(function.name.clone()) || function.name.is_empty() {
                    return Err("duplicate bundle function".into());
                }
                if let Some(result) = &function.result {
                    result.verify()?;
                }
                let mut local_names = HashSet::new();
                for (name, _) in &function.params {
                    if !local_names.insert(name.clone()) || name.is_empty() {
                        return Err("duplicate bundle parameter".into());
                    }
                }
                let steps = function
                    .steps
                    .into_iter()
                    .map(|step| load_bundle_action(step, 0, 0))
                    .collect::<Result<Vec<_>, _>>()?;
                if function.result.is_none()
                    && (bundle_version == 15 || !actions_always_return(&steps))
                {
                    return Err("bundle function has no guaranteed return".into());
                }
                functions.insert(
                    function.name,
                    Function {
                        params: function.params,
                        result_type: function.result_type,
                        body: None,
                        steps,
                        result_code: function.result,
                    },
                );
            }
            let mut lets = Vec::new();
            let mut mutable_globals = HashSet::new();
            for binding in raw.lets {
                if !names.insert(binding.name.clone()) || binding.name.is_empty() {
                    return Err("duplicate bundle binding".into());
                }
                if binding.annotation == Some(Type::Any) {
                    return Err("invalid bundle type annotation".into());
                }
                binding.code.verify()?;
                if binding.mutable {
                    mutable_globals.insert(binding.name.clone());
                }
                lets.push(Binding {
                    name: binding.name,
                    mutable: binding.mutable,
                    annotation: binding.annotation,
                    expr: None,
                    code: binding.code,
                    line: binding.line,
                });
            }
            let actions = raw
                .actions
                .into_iter()
                .map(|action| load_bundle_action(action, 0, 0))
                .collect::<Result<Vec<_>, _>>()?;
            let module = Rc::new(Module {
                path,
                effects,
                imports,
                functions,
                records,
                lets,
                mutable_globals,
                types: RefCell::new(HashMap::new()),
                globals: RefCell::new(HashMap::new()),
                actions,
            });
            for record in module.records.values() {
                self.record_modules.insert(record.id, module.clone());
            }
            built.insert(raw.path, module);
        }
        let root = built
            .get(&bundle.entry)
            .ok_or("bundle entry module missing")?
            .clone();
        let mut reachable = HashSet::new();
        fn mark(module: &Rc<Module>, seen: &mut HashSet<PathBuf>) {
            if !seen.insert(module.path.clone()) {
                return;
            }
            for import in module.imports.values() {
                if let Import::Local(child) = import {
                    mark(child, seen);
                }
            }
        }
        mark(&root, &mut reachable);
        if reachable.len() != module_count {
            return Err("bundle contains unreachable modules".into());
        }
        Ok(root)
    }

    fn load_module(&mut self, path: &Path, is_root: bool) -> Result<Rc<Module>, String> {
        let path = path
            .canonicalize()
            .map_err(|e| format!("cannot read module: {}: {e}", path.display()))?;
        if !path.starts_with(&self.project_root) {
            return Err(format!("import outside project: {}", path.display()));
        }
        if self.loading.contains(&path) {
            return Err(format!("cyclic import: {}", path.display()));
        }
        if let Some(module) = self.cache.get(&path) {
            return Ok(module.clone());
        }
        if self.loading.len() >= MAX_IMPORT_DEPTH {
            return Err(format!("module import depth exceeds {MAX_IMPORT_DEPTH}"));
        }
        self.loading.insert(path.clone());
        let mut source_bytes = Vec::new();
        fs::File::open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .take(MAX_SCRIPT as u64 + 1)
            .read_to_end(&mut source_bytes)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if source_bytes.len() > MAX_SCRIPT {
            return Err(format!(
                "{}: source exceeds {} Bytes",
                path.display(),
                MAX_SCRIPT
            ));
        }
        let source_hash: [u8; 32] = Sha256::digest(&source_bytes).into();
        let source = String::from_utf8(source_bytes)
            .map_err(|_| format!("{}: source is not UTF-8", path.display()))?;
        self.loaded_source_hashes.insert(path.clone(), source_hash);
        self.record_case_artifact("galeikan.source", &path, source.as_bytes())?;
        let tokens = syntax::lex(&source).map_err(|e| format!("{}:{e}", path.display()))?;
        let stmts = syntax::parse(tokens).map_err(|e| format!("{}:{e}", path.display()))?;
        let mut imports = HashMap::new();
        let mut functions = HashMap::new();
        let mut records = HashMap::new();
        let mut lets = Vec::new();
        let mut mutable_globals = HashSet::new();
        let mut actions = Vec::new();
        let mut saw_action = false;
        let mut saw_definition = false;
        let mut saw_requires = false;
        let mut module_effects = HashSet::new();
        let mut names = HashSet::new();
        for stmt in stmts {
            match stmt.kind {
                StmtKind::Requires(effects) => {
                    if saw_requires || saw_definition {
                        return Err(format!(
                            "{}:{}: requires must appear once at the start of the module",
                            path.display(),
                            stmt.line
                        ));
                    }
                    saw_requires = true;
                    for effect in effects {
                        if effect != "file.read"
                            && effect != "python.exec"
                            && effect != "net.connect"
                            && effect != "process.inspect"
                            && effect != "case.write"
                        {
                            return Err(format!(
                                "{}:{}: unknown effect {effect}",
                                path.display(),
                                stmt.line
                            ));
                        }
                        if !module_effects.insert(effect.clone()) {
                            return Err(format!(
                                "{}:{}: duplicate effect {effect}",
                                path.display(),
                                stmt.line
                            ));
                        }
                        if is_root {
                            self.declared_effects.insert(effect);
                        } else if !self.declared_effects.contains(&effect) {
                            return Err(format!(
                                "{}:{}: module requires {effect}, but the root script does not grant it",
                                path.display(),
                                stmt.line
                            ));
                        }
                    }
                }
                StmtKind::Import(target, alias, selected_functions) => {
                    saw_definition = true;
                    if saw_action || alias.contains('.') || !names.insert(alias.clone()) {
                        return Err(format!(
                            "{}:{}: invalid or duplicate import alias",
                            path.display(),
                            stmt.line
                        ));
                    }
                    let imported = self.resolve_import(
                        &path,
                        &target,
                        stmt.line,
                        stmt.col,
                        &selected_functions,
                    )?;
                    imports.insert(alias, imported);
                }
                StmtKind::Struct(name, fields) => {
                    saw_definition = true;
                    if saw_action || name.contains('.') || !names.insert(name.clone()) {
                        return Err(format!(
                            "{}:{}: invalid or duplicate struct name",
                            path.display(),
                            stmt.line
                        ));
                    }
                    let mut field_names = HashSet::new();
                    let fields = fields
                        .into_iter()
                        .map(|field| {
                            if !field_names.insert(field.name.clone()) {
                                return Err(format!("duplicate field {}", field.name));
                            }
                            let kind = resolve_type(
                                field.annotation.as_deref().ok_or("field type missing")?,
                                &records,
                                &imports,
                            )?;
                            Ok((field.name, kind))
                        })
                        .collect::<Result<Vec<_>, String>>()
                        .map_err(|e| format!("{}:{}: {e}", path.display(), stmt.line))?;
                    let definition = RecordDef {
                        id: record_id(&path, &name),
                        name: name.clone(),
                        fields,
                    };
                    if self
                        .records
                        .insert(definition.id, definition.clone())
                        .is_some()
                    {
                        return Err("struct type identifier collision".into());
                    }
                    records.insert(name, definition);
                }
                StmtKind::Function(name, params, result_type, body) => {
                    saw_definition = true;
                    if saw_action || name.contains('.') || !names.insert(name.clone()) {
                        return Err(format!(
                            "{}:{}: invalid or duplicate function name",
                            path.display(),
                            stmt.line
                        ));
                    }
                    let mut seen = HashSet::new();
                    if params
                        .iter()
                        .any(|p| p.name.contains('.') || !seen.insert(&p.name))
                    {
                        return Err(format!(
                            "{}:{}: invalid or duplicate parameter",
                            path.display(),
                            stmt.line
                        ));
                    }
                    let params = params
                        .into_iter()
                        .map(|p| {
                            Ok((
                                p.name,
                                p.annotation
                                    .as_deref()
                                    .map(|name| resolve_type(name, &records, &imports))
                                    .transpose()?
                                    .unwrap_or(Type::Any),
                            ))
                        })
                        .collect::<Result<Vec<_>, String>>()
                        .map_err(|e| format!("{}:{}: {e}", path.display(), stmt.line))?;
                    let result_type = result_type
                        .as_deref()
                        .map(|name| resolve_type(name, &records, &imports))
                        .transpose()
                        .map_err(|e| format!("{}:{}: {e}", path.display(), stmt.line))?;
                    let (steps, result_code) = match &body {
                        FunctionBody::Expression(expr) => {
                            (Vec::new(), Some(Program::compile(expr)?))
                        }
                        FunctionBody::Block(steps, result) => (
                            compile_steps(steps, &records, &imports)?,
                            result.as_ref().map(Program::compile).transpose()?,
                        ),
                    };
                    functions.insert(
                        name,
                        Function {
                            params,
                            result_type,
                            body: Some(body),
                            steps,
                            result_code,
                        },
                    );
                }
                StmtKind::Let(name, annotation, expr) => {
                    saw_definition = true;
                    if saw_action {
                        return Err(format!(
                            "{}:{}: top-level definitions must precede actions",
                            path.display(),
                            stmt.line
                        ));
                    }
                    if name.contains('.') || !names.insert(name.clone()) {
                        return Err(format!(
                            "{}:{}: invalid variable name",
                            path.display(),
                            stmt.line
                        ));
                    }
                    let annotation = annotation
                        .as_deref()
                        .map(|name| resolve_type(name, &records, &imports))
                        .transpose()
                        .map_err(|e| format!("{}:{}: {e}", path.display(), stmt.line))?;
                    let program = Program::compile(&expr)?;
                    lets.push(Binding {
                        name,
                        mutable: false,
                        annotation,
                        expr: Some(expr),
                        code: program,
                        line: stmt.line,
                    });
                }
                StmtKind::Var(name, annotation, expr) => {
                    saw_definition = true;
                    if saw_action {
                        return Err(format!(
                            "{}:{}: top-level definitions must precede actions",
                            path.display(),
                            stmt.line
                        ));
                    }
                    if name.contains('.') || !names.insert(name.clone()) {
                        return Err(format!(
                            "{}:{}: invalid variable name",
                            path.display(),
                            stmt.line
                        ));
                    }
                    let annotation = annotation
                        .as_deref()
                        .map(|name| resolve_type(name, &records, &imports))
                        .transpose()
                        .map_err(|e| format!("{}:{}: {e}", path.display(), stmt.line))?;
                    let program = Program::compile(&expr)?;
                    mutable_globals.insert(name.clone());
                    lets.push(Binding {
                        name,
                        mutable: true,
                        annotation,
                        expr: Some(expr),
                        code: program,
                        line: stmt.line,
                    });
                }
                StmtKind::Print(_)
                | StmtKind::Impact(_)
                | StmtKind::For(_, _, _)
                | StmtKind::While(_, _)
                | StmtKind::If(_, _, _)
                | StmtKind::Assign(_, _) => {
                    saw_definition = true;
                    if !is_root {
                        return Err(format!(
                            "{}:{}: imported module cannot execute top-level actions",
                            path.display(),
                            stmt.line
                        ));
                    }
                    saw_action = true;
                    let (kind, name, expr, body, else_body) = match &stmt.kind {
                        StmtKind::Print(expr) => {
                            (ActionKind::Print, None, expr, Vec::new(), Vec::new())
                        }
                        StmtKind::Impact(expr) => {
                            (ActionKind::Impact, None, expr, Vec::new(), Vec::new())
                        }
                        StmtKind::For(name, expr, body) => (
                            ActionKind::For,
                            Some(name.clone()),
                            expr,
                            compile_steps(body, &records, &imports)?,
                            Vec::new(),
                        ),
                        StmtKind::While(expr, body) => (
                            ActionKind::While,
                            None,
                            expr,
                            compile_steps(body, &records, &imports)?,
                            Vec::new(),
                        ),
                        StmtKind::If(expr, yes, no) => (
                            ActionKind::If,
                            None,
                            expr,
                            compile_steps(yes, &records, &imports)?,
                            compile_steps(no, &records, &imports)?,
                        ),
                        StmtKind::Assign(name, expr) => (
                            ActionKind::Assign,
                            Some(name.clone()),
                            expr,
                            Vec::new(),
                            Vec::new(),
                        ),
                        _ => unreachable!(),
                    };
                    let program = Program::compile(expr)?;
                    actions.push(Action {
                        kind,
                        name,
                        annotation: None,
                        expr: Some(expr.clone()),
                        code: program,
                        body,
                        else_body,
                        line: stmt.line,
                        col: stmt.col,
                    });
                }
            }
        }
        let module = Rc::new(Module {
            path: path.clone(),
            effects: module_effects,
            imports,
            functions,
            records,
            lets,
            mutable_globals,
            types: RefCell::new(HashMap::new()),
            globals: RefCell::new(HashMap::new()),
            actions,
        });
        for record in module.records.values() {
            self.record_modules.insert(record.id, module.clone());
        }
        self.loading.remove(&path);
        self.cache.insert(path, module.clone());
        Ok(module)
    }

    fn resolve_import(
        &mut self,
        path: &Path,
        target: &str,
        line: usize,
        col: usize,
        selected_functions: &[String],
    ) -> Result<Import, String> {
        let imported = if target == "std.binary" {
            Import::Binary
        } else if target == "std.bytes" {
            Import::Bytes
        } else if target == "std.text" {
            Import::Text
        } else if target == "std.formats" {
            Import::Formats
        } else if target == "std.cli" {
            Import::Cli
        } else if target == "std.net" {
            Import::Net
        } else if target == "std.process" {
            Import::Process
        } else if target == "std.result" {
            Import::ResultOps
        } else if target == "std.audit" {
            Import::Audit
        } else if target == "std.iter" {
            Import::Iter
        } else if target == "std.list" {
            Import::ListOps
        } else if target == "std.lab" {
            Import::Lab
        } else if target == "std.asm" {
            Import::Asm
        } else if let Some(package_target) = target.strip_prefix("pkg.") {
            let (package, module) = package_target
                .split_once('.')
                .unwrap_or((package_target, "main"));
            if package.is_empty()
                || module.split('.').any(|part| {
                    part.is_empty()
                        || !part
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                })
            {
                return Err(format!(
                    "{}:{line}: invalid package import {target}",
                    path.display()
                ));
            }
            let package_path = self.packages.get(package).ok_or_else(|| {
                format!(
                    "{}:{line}: unknown package {package}; declare it in galeikan.json",
                    path.display()
                )
            })?;
            let child = project::source_module_path(package_path, module)?;
            Import::Local(self.load_module(&child, false)?)
        } else if target.starts_with("py.") || target.starts_with("py:") {
            let filename = if let Some(module) = target.strip_prefix("py.") {
                format!("{}.py", module.replace('.', "/"))
            } else {
                let module = target.strip_prefix("py:").unwrap();
                if module.ends_with(".py") {
                    module.to_string()
                } else {
                    format!("{module}.py")
                }
            };
            let python_path = path.parent().unwrap().join(filename);
            let python_path = python_path.canonicalize().map_err(|e| {
                format!("{}:{line}: cannot read Python module: {e}", path.display())
            })?;
            if !python_path.starts_with(&self.project_root) {
                return Err(format!(
                    "{}:{line}: Python import outside project: {}",
                    path.display(),
                    python_path.display()
                ));
            }
            self.capture_python_artifact(&python_path)?;
            Import::Python(python_path)
        } else {
            if target.starts_with("std.") {
                return Err(format!(
                    "{}:{line}: unknown standard module {target}",
                    path.display()
                ));
            }
            let child = project::source_module_path(path.parent().unwrap(), target)?;
            Import::Local(self.load_module(&child, false)?)
        };
        for symbol in selected_functions {
            if !import_has_symbol(&imported, symbol) {
                return Err(format!(
                    "{}:{line}:{col}: unknown imported symbol {symbol} from {target}",
                    path.display()
                ));
            }
        }
        Ok(imported)
    }

    fn check_module(&mut self, module: &Rc<Module>) -> Result<(), String> {
        if self.checked_modules.contains(&module.path) {
            return Ok(());
        }
        for import in module.imports.values() {
            if let Import::Local(child) = import {
                self.check_module(child)?;
            }
        }
        let mut globals = HashMap::new();
        for binding in &module.lets {
            let expr = binding.expr.as_ref().ok_or("source expression missing")?;
            let kind = self
                .infer_expr(module, &HashMap::new(), &globals, expr)
                .map_err(|e| format!("{}:{e}", module.path.display()))?;
            if let Some(expected) = binding.annotation {
                require_type(expected, kind).map_err(|e| {
                    format!(
                        "{}:{}: binding {}: {e}",
                        module.path.display(),
                        binding.line,
                        binding.name
                    )
                })?;
            }
            globals.insert(binding.name.clone(), binding.annotation.unwrap_or(kind));
        }
        *module.types.borrow_mut() = globals.clone();
        for (name, function) in &module.functions {
            let mut locals: HashMap<String, Type> = function.params.iter().cloned().collect();
            let mut returns = ReturnCheck {
                allowed: true,
                inferred: Vec::new(),
            };
            let body = function
                .body
                .as_ref()
                .ok_or("source function body missing")?;
            let fallback = match body {
                FunctionBody::Expression(expr) => {
                    self.infer_expr(module, &locals, &globals, expr).map(Some)
                }
                FunctionBody::Block(_, result) => {
                    self.check_actions(
                        module,
                        &function.steps,
                        &mut locals,
                        &mut HashSet::new(),
                        &globals,
                        &mut returns,
                    )?;
                    result
                        .as_ref()
                        .map(|expr| self.infer_expr(module, &locals, &globals, expr))
                        .transpose()
                }
            }
            .map_err(|e| format!("{}:{e}", module.path.display()))?;
            let result = fallback
                .or(function.result_type)
                .or_else(|| returns.inferred.first().copied())
                .ok_or_else(|| {
                    format!(
                        "{}: function {name} has no return value",
                        module.path.display()
                    )
                })?;
            if let (Some(expected), Some(fallback)) = (function.result_type, fallback) {
                let compatible = match expected {
                    Type::Result(Some(inner)) => {
                        inner.as_type().compatible(fallback) || expected.compatible(fallback)
                    }
                    Type::Result(None) => expected.compatible(fallback),
                    _ => expected.compatible(fallback),
                };
                if !compatible {
                    return Err(format!(
                        "{}: function {name} returns {fallback}, expected {expected}",
                        module.path.display()
                    ));
                }
            }
            let expected = function.result_type.unwrap_or(result);
            for returned in returns.inferred {
                let compatible = match expected {
                    Type::Result(Some(inner)) => {
                        inner.as_type().compatible(returned) || expected.compatible(returned)
                    }
                    _ => expected.compatible(returned),
                };
                if !compatible {
                    return Err(format!(
                        "{}: function {name} early return has {returned}, expected {expected}",
                        module.path.display()
                    ));
                }
            }
        }
        self.check_actions(
            module,
            &module.actions,
            &mut HashMap::new(),
            &mut HashSet::new(),
            &globals,
            &mut ReturnCheck {
                allowed: false,
                inferred: Vec::new(),
            },
        )?;
        self.checked_modules.insert(module.path.clone());
        Ok(())
    }

    fn check_actions(
        &self,
        module: &Rc<Module>,
        actions: &[Action],
        locals: &mut HashMap<String, Type>,
        mutable_locals: &mut HashSet<String>,
        globals: &HashMap<String, Type>,
        returns: &mut ReturnCheck,
    ) -> Result<(), String> {
        for action in actions {
            if matches!(action.kind, ActionKind::Break | ActionKind::Continue) {
                continue;
            }
            let expr = action.expr.as_ref().ok_or("source action missing")?;
            let kind = self
                .infer_expr(module, locals, globals, expr)
                .map_err(|e| format!("{}:{e}", module.path.display()))?;
            match action.kind {
                ActionKind::Return => {
                    if !returns.allowed {
                        return Err(format!(
                            "{}:{}:{}: return outside function",
                            module.path.display(),
                            action.line,
                            action.col
                        ));
                    }
                    returns.inferred.push(kind);
                }
                ActionKind::Let | ActionKind::Var => {
                    let name = action.name.as_deref().ok_or("local name missing")?;
                    if let Some(expected) = action.annotation {
                        require_type(expected, kind).map_err(|e| {
                            format!(
                                "{}:{}:{}: binding {name}: {e}",
                                module.path.display(),
                                action.line,
                                action.col
                            )
                        })?;
                    }
                    if locals
                        .insert(name.to_string(), action.annotation.unwrap_or(kind))
                        .is_some()
                    {
                        return Err(format!(
                            "{}:{}:{}: duplicate local binding {name}",
                            module.path.display(),
                            action.line,
                            action.col
                        ));
                    }
                    if matches!(action.kind, ActionKind::Var) {
                        mutable_locals.insert(name.to_string());
                    }
                }
                ActionKind::Assign => {
                    let name = action.name.as_deref().ok_or("assignment name missing")?;
                    let expected = if let Some(expected) = locals.get(name) {
                        if !mutable_locals.contains(name) {
                            return Err(format!(
                                "{}:{}:{}: cannot assign to immutable binding {name}",
                                module.path.display(),
                                action.line,
                                action.col
                            ));
                        }
                        *expected
                    } else if let Some(expected) = globals.get(name) {
                        if !module.mutable_globals.contains(name) {
                            return Err(format!(
                                "{}:{}:{}: cannot assign to immutable binding {name}",
                                module.path.display(),
                                action.line,
                                action.col
                            ));
                        }
                        *expected
                    } else {
                        return Err(format!(
                            "{}:{}:{}: unknown assignment target {name}",
                            module.path.display(),
                            action.line,
                            action.col
                        ));
                    };
                    require_type(expected, kind).map_err(|e| {
                        format!(
                            "{}:{}:{}: assignment to {name}: {e}",
                            module.path.display(),
                            action.line,
                            action.col
                        )
                    })?;
                }
                ActionKind::For => {
                    if !matches!(
                        kind,
                        Type::Offsets
                            | Type::Bytes
                            | Type::Disassembly
                            | Type::Regions
                            | Type::List(_)
                            | Type::Any
                    ) {
                        return Err(format!(
                            "{}:{}:{}: for expects a List, Offsets, bytes, Disassembly, or Regions, got {kind}",
                            module.path.display(),
                            action.line,
                            action.col
                        ));
                    }
                    let name = action.name.as_deref().ok_or("loop name missing")?;
                    let mut inner = locals.clone();
                    let mut inner_mutable = mutable_locals.clone();
                    let item_type = match kind {
                        Type::Disassembly => Type::Instruction,
                        Type::Regions => Type::Region,
                        Type::List(Some(kind)) => kind.as_type(),
                        Type::List(None) => Type::Any,
                        Type::Any => Type::Any,
                        _ => Type::Int,
                    };
                    if inner.insert(name.to_string(), item_type).is_some() {
                        return Err(format!(
                            "{}:{}:{}: duplicate loop binding {name}",
                            module.path.display(),
                            action.line,
                            action.col
                        ));
                    }
                    self.check_actions(
                        module,
                        &action.body,
                        &mut inner,
                        &mut inner_mutable,
                        globals,
                        returns,
                    )?;
                }
                ActionKind::While => {
                    require_type(Type::Bool, kind).map_err(|e| {
                        format!(
                            "{}:{}:{}: while condition: {e}",
                            module.path.display(),
                            action.line,
                            action.col
                        )
                    })?;
                    let mut inner = locals.clone();
                    let mut inner_mutable = mutable_locals.clone();
                    self.check_actions(
                        module,
                        &action.body,
                        &mut inner,
                        &mut inner_mutable,
                        globals,
                        returns,
                    )?;
                }
                ActionKind::If => {
                    require_type(Type::Bool, kind).map_err(|e| {
                        format!(
                            "{}:{}:{}: if condition: {e}",
                            module.path.display(),
                            action.line,
                            action.col
                        )
                    })?;
                    for branch in [&action.body, &action.else_body] {
                        let mut inner = locals.clone();
                        let mut inner_mutable = mutable_locals.clone();
                        self.check_actions(
                            module,
                            branch,
                            &mut inner,
                            &mut inner_mutable,
                            globals,
                            returns,
                        )?;
                    }
                }
                ActionKind::Break | ActionKind::Continue => unreachable!(),
                ActionKind::Impact
                    if !matches!(
                        kind,
                        Type::Observation
                            | Type::Format
                            | Type::Section
                            | Type::Diff
                            | Type::Finding
                            | Type::Instruction
                            | Type::Disassembly
                            | Type::HttpResponse
                            | Type::Any
                    ) =>
                {
                    return Err(format!("{}:{}:{}: impact expects Observation, Format, Section, Diff, Finding, Instruction, Disassembly, or HttpResponse, got {kind}", module.path.display(), action.line, action.col));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn initialize_module(&mut self, module: &Rc<Module>) -> Result<(), String> {
        if self.initialized_modules.contains(&module.path) {
            return Ok(());
        }
        for import in module.imports.values() {
            if let Import::Local(child) = import {
                self.initialize_module(child)?;
            }
        }
        for binding in &module.lets {
            let mut value = self
                .execute_expr(
                    module,
                    &HashMap::new(),
                    binding.expr.as_ref(),
                    &binding.code,
                    0,
                )
                .map_err(|e| format!("{}:{}: {e}", module.path.display(), binding.line))?;
            if let Some(expected) = binding.annotation {
                if !expected.accepts(&value) {
                    return Err(format!(
                        "{}:{}: binding {} expects {expected}",
                        module.path.display(),
                        binding.line,
                        binding.name
                    ));
                }
                value = specialize_list(value, expected);
            }
            module
                .globals
                .borrow_mut()
                .insert(binding.name.clone(), value);
        }
        self.initialized_modules.insert(module.path.clone());
        Ok(())
    }

    fn infer_expr(
        &self,
        module: &Rc<Module>,
        locals: &HashMap<String, Type>,
        globals: &HashMap<String, Type>,
        expr: &Expr,
    ) -> Result<Type, String> {
        let error = |message: String| format!("{}:{}: {message}", expr.line, expr.col);
        let kind =
            match &expr.kind {
                ExprKind::Int(_) => Type::Int,
                ExprKind::UInt(_) => Type::UInt,
                ExprKind::Bool(_) => Type::Bool,
                ExprKind::Str(_) => Type::Str,
                ExprKind::List(items) => {
                    if items.len() > MAX_LOOP_ITEMS {
                        return Err(error(format!("list exceeds {MAX_LOOP_ITEMS} items")));
                    }
                    let mut element = Type::Any;
                    for item in items {
                        let next = self.infer_expr(module, locals, globals, item)?;
                        if ResultKind::from_type(next).is_none() && next != Type::Any {
                            return Err(error(format!("list element type {next} is unsupported")));
                        }
                        if element == Type::Any {
                            element = next;
                        } else if next != Type::Any && element != next {
                            return Err(error(format!(
                                "list elements must have one type, got {element} and {next}"
                            )));
                        }
                    }
                    Type::List(ResultKind::from_type(element))
                }
                ExprKind::Index(list, index) => {
                    let list_type = self.infer_expr(module, locals, globals, list)?;
                    require_type(Type::Int, self.infer_expr(module, locals, globals, index)?)
                        .map_err(&error)?;
                    match list_type {
                        Type::List(Some(kind)) => kind.as_type(),
                        Type::List(None) | Type::Any => Type::Any,
                        _ => return Err(error(format!("indexing expects List, got {list_type}"))),
                    }
                }
                ExprKind::Field(value, field) => {
                    let kind = self.infer_expr(module, locals, globals, value)?;
                    self.record_field_type(kind, field).map_err(&error)?
                }
                ExprKind::Var(name) => {
                    if let Some((alias, key)) = name.split_once('.') {
                        match module.imports.get(alias) {
                            Some(Import::Local(child)) => {
                                let (base, fields) = key.split_once('.').unwrap_or((key, ""));
                                let kind =
                                    child.types.borrow().get(base).copied().ok_or_else(|| {
                                        error(format!("unknown module value {name}"))
                                    })?;
                                self.record_field_type(kind, fields).map_err(&error)?
                            }
                            Some(Import::Python(_)) => {
                                self.check_effect(module, "python.exec").map_err(&error)?;
                                Type::Any
                            }
                            _ => {
                                let kind = locals
                                    .get(alias)
                                    .or_else(|| globals.get(alias))
                                    .copied()
                                    .ok_or_else(|| error(format!("unknown name {alias}")))?;
                                self.record_field_type(kind, key).map_err(&error)?
                            }
                        }
                    } else {
                        locals
                            .get(name)
                            .or_else(|| globals.get(name))
                            .copied()
                            .ok_or_else(|| error(format!("unknown name {name}")))?
                    }
                }
                ExprKind::Neg(inner) => {
                    let actual = self.infer_expr(module, locals, globals, inner)?;
                    require_type(Type::Int, actual).map_err(&error)?;
                    Type::Int
                }
                ExprKind::BitNot(inner) => {
                    let actual = self.infer_expr(module, locals, globals, inner)?;
                    if actual == Type::UInt {
                        Type::UInt
                    } else {
                        require_type(Type::Int, actual).map_err(&error)?;
                        Type::Int
                    }
                }
                ExprKind::Not(inner) => {
                    let actual = self.infer_expr(module, locals, globals, inner)?;
                    require_type(Type::Bool, actual).map_err(&error)?;
                    Type::Bool
                }
                ExprKind::Binary(left, op, right) => {
                    let a = self.infer_expr(module, locals, globals, left)?;
                    let b = self.infer_expr(module, locals, globals, right)?;
                    match op {
                        Op::And | Op::Or => {
                            require_type(Type::Bool, a).map_err(&error)?;
                            require_type(Type::Bool, b).map_err(&error)?;
                            Type::Bool
                        }
                        Op::Add if a == Type::Str || b == Type::Str => {
                            require_type(Type::Str, a).map_err(&error)?;
                            require_type(Type::Str, b).map_err(&error)?;
                            Type::Str
                        }
                        Op::Add
                        | Op::Sub
                        | Op::Mul
                        | Op::Div
                        | Op::BitAnd
                        | Op::BitOr
                        | Op::BitXor
                        | Op::Shl
                        | Op::Shr
                        | Op::Ushr
                        | Op::Lt
                        | Op::Le
                        | Op::Gt
                        | Op::Ge => {
                            let numeric = if a == Type::UInt || b == Type::UInt {
                                Type::UInt
                            } else {
                                Type::Int
                            };
                            require_type(numeric, a).map_err(&error)?;
                            require_type(numeric, b).map_err(&error)?;
                            if matches!(
                                op,
                                Op::Add
                                    | Op::Sub
                                    | Op::Mul
                                    | Op::Div
                                    | Op::BitAnd
                                    | Op::BitOr
                                    | Op::BitXor
                                    | Op::Shl
                                    | Op::Shr
                                    | Op::Ushr
                            ) {
                                numeric
                            } else {
                                Type::Bool
                            }
                        }
                        Op::Eq | Op::Ne => {
                            if !a.compatible(b)
                                || !matches!(
                                    a,
                                    Type::Int | Type::UInt | Type::Bool | Type::Str | Type::Any
                                )
                                || !matches!(
                                    b,
                                    Type::Int | Type::UInt | Type::Bool | Type::Str | Type::Any
                                )
                            {
                                return Err(error(
                                    "equality needs two values of the same scalar type".into(),
                                ));
                            }
                            Type::Bool
                        }
                    }
                }
                ExprKind::If(condition, when_true, when_false) => {
                    let condition = self.infer_expr(module, locals, globals, condition)?;
                    require_type(Type::Bool, condition).map_err(&error)?;
                    let a = self.infer_expr(module, locals, globals, when_true)?;
                    let b = self.infer_expr(module, locals, globals, when_false)?;
                    if !a.compatible(b) {
                        return Err(error(format!(
                            "if branches have different types: {a} and {b}"
                        )));
                    }
                    match (a, b) {
                        (Type::Any, _) | (_, Type::Any) => Type::Any,
                        (Type::Result(None), other) | (other, Type::Result(None)) => other,
                        (Type::List(None), other) | (other, Type::List(None)) => other,
                        _ => a,
                    }
                }
                ExprKind::Match(subject, arms, default) => {
                    let subject_type = self.infer_expr(module, locals, globals, subject)?;
                    if !matches!(
                        subject_type,
                        Type::Int | Type::UInt | Type::Bool | Type::Str
                    ) {
                        return Err(error(format!(
                            "match subject must be i64, u64, bool, or str, got {subject_type}"
                        )));
                    }
                    let mut result = self.infer_expr(module, locals, globals, default)?;
                    for (pattern, value) in arms {
                        let pattern_type = match pattern {
                            MatchPattern::Int(_) => Type::Int,
                            MatchPattern::UInt(_) => Type::UInt,
                            MatchPattern::Bool(_) => Type::Bool,
                            MatchPattern::Str(_) => Type::Str,
                        };
                        if subject_type != pattern_type {
                            return Err(error(format!(
                                "match pattern has type {pattern_type}, expected {subject_type}"
                            )));
                        }
                        let branch = self.infer_expr(module, locals, globals, value)?;
                        if !result.compatible(branch) {
                            return Err(error(format!(
                                "match branches have different types: {result} and {branch}"
                            )));
                        }
                        result = match (result, branch) {
                            (Type::Any, _) | (_, Type::Any) => Type::Any,
                            (Type::Result(None), other) | (other, Type::Result(None)) => other,
                            (Type::List(None), other) | (other, Type::List(None)) => other,
                            _ => result,
                        };
                    }
                    result
                }
                ExprKind::Try(inner) => {
                    let actual = self.infer_expr(module, locals, globals, inner)?;
                    match actual {
                        Type::Result(Some(kind)) => kind.as_type(),
                        Type::Result(None) => Type::Any,
                        Type::Any => Type::Any,
                        _ => return Err(error(format!("? expects Result<T>, got {actual}"))),
                    }
                }
                ExprKind::Call(name, args) => {
                    let args = args
                        .iter()
                        .map(|arg| self.infer_expr(module, locals, globals, arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    if let Some((receiver, method)) = name.rsplit_once('.') {
                        if is_value_method_receiver(module, receiver) {
                            let receiver_expr = Expr {
                                kind: ExprKind::Var(receiver.to_owned()),
                                line: expr.line,
                                col: expr.col,
                            };
                            let receiver_type =
                                self.infer_expr(module, locals, globals, &receiver_expr)?;
                            return self
                                .infer_method(receiver_type, method, &args)
                                .map_err(&error);
                        }
                    }
                    self.infer_call(module, name, &args).map_err(&error)?
                }
                ExprKind::MethodCall(receiver, method, args) => {
                    let receiver_type = self.infer_expr(module, locals, globals, receiver)?;
                    let args = args
                        .iter()
                        .map(|arg| self.infer_expr(module, locals, globals, arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.infer_method(receiver_type, method, &args)
                        .map_err(&error)?
                }
            };
        Ok(kind)
    }

    fn check_effect(&self, module: &Module, effect: &str) -> Result<(), String> {
        if !self.declared_effects.contains(effect) {
            return Err(format!("{effect} was not declared with requires"));
        }
        if !module.effects.contains(effect) {
            return Err(format!(
                "{effect} was not declared with requires in {}",
                module.path.display()
            ));
        }
        Ok(())
    }

    fn record_field_type(&self, mut kind: Type, fields: &str) -> Result<Type, String> {
        if fields.is_empty() {
            return Ok(kind);
        }
        for field in fields.split('.') {
            let Type::Record(id) = kind else {
                return Err(format!("field {field} needs a struct value, got {kind}"));
            };
            kind = self
                .records
                .get(&id)
                .and_then(|record| record.fields.iter().find(|(name, _)| name == field))
                .map(|(_, kind)| *kind)
                .ok_or_else(|| format!("unknown struct field {field}"))?;
        }
        Ok(kind)
    }

    fn infer_call(&self, module: &Rc<Module>, name: &str, args: &[Type]) -> Result<Type, String> {
        if let Some((alias, function)) = name.split_once('.') {
            return match module.imports.get(alias) {
                Some(Import::Binary) => {
                    if function == "analyze" {
                        self.check_effect(module, "file.read")?;
                    }
                    standard_call("binary", function, args)
                }
                Some(Import::Bytes) => standard_call("bytes", function, args),
                Some(Import::Text) => standard_call("text", function, args),
                Some(Import::Formats) => standard_call("formats", function, args),
                Some(Import::Cli) => standard_call("cli", function, args),
                Some(Import::Net) => {
                    if matches!(function, "exchange" | "datagram" | "fetch" | "request") {
                        self.check_effect(module, "net.connect")?;
                    }
                    standard_call("net", function, args)
                }
                Some(Import::Process) => {
                    if matches!(
                        function,
                        "snapshot"
                            | "snapshot_u64"
                            | "regions"
                            | "images"
                            | "modules"
                            | "thread_ids"
                            | "children"
                            | "executable"
                            | "parent_pid"
                            | "snapshot_region"
                            | "snapshot_ref"
                            | "snapshot_at"
                            | "snapshot_at_u64"
                    ) {
                        self.check_effect(module, "process.inspect")?;
                    }
                    standard_call("process", function, args)
                }
                Some(Import::ResultOps) => standard_call("result", function, args),
                Some(Import::Audit) => standard_call("audit", function, args),
                Some(Import::Iter) => standard_call("iter", function, args),
                Some(Import::ListOps) => standard_call("list", function, args),
                Some(Import::Lab) => standard_call("lab", function, args),
                Some(Import::Asm) => standard_call("asm", function, args),
                Some(Import::Python(_)) => {
                    self.check_effect(module, "python.exec")?;
                    for actual in args {
                        if !matches!(
                            actual,
                            Type::Int
                                | Type::UInt
                                | Type::Bool
                                | Type::Str
                                | Type::Bytes
                                | Type::List(None)
                                | Type::List(Some(
                                    ResultKind::Int
                                        | ResultKind::UInt
                                        | ResultKind::Bool
                                        | ResultKind::Str
                                        | ResultKind::Bytes
                                ))
                                | Type::Any
                        ) {
                            return Err(format!("Python bridge cannot send {actual}"));
                        }
                    }
                    Ok(Type::Any)
                }
                Some(Import::Local(child)) => check_function_call(child, function, args),
                None => Err(format!("unknown module {alias}")),
            };
        }
        check_function_call(module, name, args)
    }

    fn infer_method(&self, receiver: Type, method: &str, args: &[Type]) -> Result<Type, String> {
        let Type::Record(id) = receiver else {
            return Err(format!("method {method} needs a class value"));
        };
        let record = self.records.get(&id).ok_or("unknown class type")?;
        let owner = self
            .record_modules
            .get(&id)
            .ok_or("class module unavailable")?;
        let key = syntax::class_method_key(&record.name, method);
        if !owner.functions.contains_key(&key) {
            return Err(format!("unknown method {method} on {}", record.name));
        }
        let mut method_args = Vec::with_capacity(args.len() + 1);
        method_args.push(receiver);
        method_args.extend_from_slice(args);
        check_function_call(owner, &key, &method_args)
    }

    fn execute_expr(
        &self,
        module: &Rc<Module>,
        locals: &HashMap<String, Value>,
        expr: Option<&Expr>,
        program: &Program,
        depth: usize,
    ) -> Result<Value, String> {
        match self.engine {
            Engine::Ast => self.eval(module, locals, expr.ok_or("AST expression missing")?, depth),
            Engine::Vm => self.eval_bytecode(module, locals, program, depth),
        }
    }

    fn eval(
        &self,
        module: &Rc<Module>,
        locals: &HashMap<String, Value>,
        expr: &Expr,
        depth: usize,
    ) -> Result<Value, String> {
        if depth > MAX_CALL_DEPTH {
            return Err("call depth exceeded".into());
        }
        match &expr.kind {
            ExprKind::Int(n) => Ok(Value::Int(*n)),
            ExprKind::UInt(n) => Ok(Value::UInt(*n)),
            ExprKind::Bool(value) => Ok(Value::Bool(*value)),
            ExprKind::Str(s) => Ok(Value::Str(s.clone())),
            ExprKind::List(items) => make_list(
                items
                    .iter()
                    .map(|item| self.eval(module, locals, item, depth))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ExprKind::Index(list, index) => list_index(
                self.eval(module, locals, list, depth)?,
                self.eval(module, locals, index, depth)?,
            ),
            ExprKind::Field(value, field) => {
                record_field_value(self.eval(module, locals, value, depth)?, field)
            }
            ExprKind::Var(name) => self.load_value(module, locals, name),
            ExprKind::Neg(inner) => apply_neg(self.eval(module, locals, inner, depth)?),
            ExprKind::BitNot(inner) => match self.eval(module, locals, inner, depth)? {
                Value::Int(n) => Ok(Value::Int(!n)),
                Value::UInt(n) => Ok(Value::UInt(!n)),
                _ => Err("bitwise not expects i64 or u64".into()),
            },
            ExprKind::Not(inner) => Ok(Value::Bool(
                !self.eval(module, locals, inner, depth)?.as_bool()?,
            )),
            ExprKind::Binary(left, Op::And, right) => {
                if !self.eval(module, locals, left, depth)?.as_bool()? {
                    Ok(Value::Bool(false))
                } else {
                    Ok(Value::Bool(
                        self.eval(module, locals, right, depth)?.as_bool()?,
                    ))
                }
            }
            ExprKind::Binary(left, Op::Or, right) => {
                if self.eval(module, locals, left, depth)?.as_bool()? {
                    Ok(Value::Bool(true))
                } else {
                    Ok(Value::Bool(
                        self.eval(module, locals, right, depth)?.as_bool()?,
                    ))
                }
            }
            ExprKind::Binary(left, op, right) => {
                let a = self.eval(module, locals, left, depth)?;
                let b = self.eval(module, locals, right, depth)?;
                apply_binary(a, *op, b)
            }
            ExprKind::If(condition, when_true, when_false) => {
                if self.eval(module, locals, condition, depth)?.as_bool()? {
                    self.eval(module, locals, when_true, depth)
                } else {
                    self.eval(module, locals, when_false, depth)
                }
            }
            ExprKind::Match(subject, arms, default) => {
                let subject = self.eval(module, locals, subject, depth)?;
                for (pattern, value) in arms {
                    let matches = match (&subject, pattern) {
                        (Value::Int(a), MatchPattern::Int(b)) => a == b,
                        (Value::UInt(a), MatchPattern::UInt(b)) => a == b,
                        (Value::Bool(a), MatchPattern::Bool(b)) => a == b,
                        (Value::Str(a), MatchPattern::Str(b)) => a == b,
                        _ => false,
                    };
                    if matches {
                        return self.eval(module, locals, value, depth);
                    }
                }
                self.eval(module, locals, default, depth)
            }
            ExprKind::Try(inner) => apply_try(self.eval(module, locals, inner, depth)?),
            ExprKind::Call(name, args) => {
                let values: Vec<Value> = args
                    .iter()
                    .map(|e| self.eval(module, locals, e, depth))
                    .collect::<Result<_, _>>()?;
                self.invoke(module, locals, name, values, depth)
            }
            ExprKind::MethodCall(receiver, method, args) => {
                let receiver = self.eval(module, locals, receiver, depth)?;
                let values = args
                    .iter()
                    .map(|arg| self.eval(module, locals, arg, depth))
                    .collect::<Result<Vec<_>, _>>()?;
                self.invoke_method(receiver, method, values, depth)
            }
        }
    }

    fn eval_bytecode(
        &self,
        module: &Rc<Module>,
        locals: &HashMap<String, Value>,
        program: &Program,
        depth: usize,
    ) -> Result<Value, String> {
        if depth > MAX_CALL_DEPTH {
            return Err("call depth exceeded".into());
        }
        let code = &program.instructions;
        let mut stack = Vec::new();
        let mut pc = 0;
        while pc < code.len() {
            match &code[pc] {
                Instruction::Int(value) => stack.push(Value::Int(*value)),
                Instruction::UInt(value) => stack.push(Value::UInt(*value)),
                Instruction::Bool(value) => stack.push(Value::Bool(*value)),
                Instruction::Str(value) => stack.push(Value::Str(value.clone())),
                Instruction::Load(name) => stack.push(self.load_value(module, locals, name)?),
                Instruction::Dup => {
                    let value = stack.last().ok_or("invalid bytecode stack")?.clone();
                    stack.push(value);
                }
                Instruction::Pop => {
                    stack.pop().ok_or("invalid bytecode stack")?;
                }
                Instruction::MakeList(count) => {
                    let start = stack
                        .len()
                        .checked_sub(*count)
                        .ok_or("invalid bytecode stack")?;
                    let items = stack.split_off(start);
                    stack.push(make_list(items)?);
                }
                Instruction::Index => {
                    let index = stack.pop().ok_or("invalid bytecode stack")?;
                    let list = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(list_index(list, index)?);
                }
                Instruction::Field(field) => {
                    let value = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(record_field_value(value, field)?);
                }
                Instruction::Neg => {
                    let value = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(apply_neg(value)?);
                }
                Instruction::BitNot => {
                    let value = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(match value {
                        Value::Int(n) => Value::Int(!n),
                        Value::UInt(n) => Value::UInt(!n),
                        _ => return Err("bitwise not expects i64 or u64".into()),
                    });
                }
                Instruction::Not => {
                    let value = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(Value::Bool(!value.as_bool()?));
                }
                Instruction::EnsureBool => {
                    let value = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(Value::Bool(value.as_bool()?));
                }
                Instruction::Binary(op) => {
                    let right = stack.pop().ok_or("invalid bytecode stack")?;
                    let left = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(apply_binary(left, *op, right)?);
                }
                Instruction::Call(name, count) => {
                    let start = stack
                        .len()
                        .checked_sub(*count)
                        .ok_or("invalid bytecode stack")?;
                    let args = stack.split_off(start);
                    stack.push(self.invoke(module, locals, name, args, depth)?);
                }
                Instruction::MethodCall(method, count) => {
                    let start = stack
                        .len()
                        .checked_sub(*count)
                        .ok_or("invalid bytecode stack")?;
                    let args = stack.split_off(start);
                    let receiver = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(self.invoke_method(receiver, method, args, depth)?);
                }
                Instruction::JumpIfFalse(target) => {
                    let condition = stack.pop().ok_or("invalid bytecode stack")?.as_bool()?;
                    if !condition {
                        if *target > code.len() {
                            return Err("invalid bytecode jump".into());
                        }
                        pc = *target;
                        continue;
                    }
                }
                Instruction::Jump(target) => {
                    if *target > code.len() {
                        return Err("invalid bytecode jump".into());
                    }
                    pc = *target;
                    continue;
                }
                Instruction::Try => {
                    let value = stack.pop().ok_or("invalid bytecode stack")?;
                    stack.push(apply_try(value)?);
                }
            }
            pc += 1;
        }
        if stack.len() == 1 {
            Ok(stack.pop().unwrap())
        } else {
            Err("invalid bytecode stack".into())
        }
    }

    fn load_value(
        &self,
        module: &Rc<Module>,
        locals: &HashMap<String, Value>,
        name: &str,
    ) -> Result<Value, String> {
        if let Some((alias, key)) = name.split_once('.') {
            match module.imports.get(alias) {
                Some(Import::Local(imported)) => {
                    let (base, fields) = key.split_once('.').unwrap_or((key, ""));
                    let value = imported
                        .globals
                        .borrow()
                        .get(base)
                        .cloned()
                        .ok_or_else(|| format!("unknown module value {name}"))?;
                    record_field_value(value, fields)
                }
                Some(Import::Python(path)) => self.get_python(module, path, key),
                _ => {
                    let value = locals
                        .get(alias)
                        .cloned()
                        .or_else(|| module.globals.borrow().get(alias).cloned())
                        .ok_or_else(|| format!("unknown name {alias}"))?;
                    record_field_value(value, key)
                }
            }
        } else {
            locals
                .get(name)
                .cloned()
                .or_else(|| module.globals.borrow().get(name).cloned())
                .ok_or_else(|| format!("unknown name {name}"))
        }
    }

    fn invoke(
        &self,
        module: &Rc<Module>,
        locals: &HashMap<String, Value>,
        name: &str,
        args: Vec<Value>,
        depth: usize,
    ) -> Result<Value, String> {
        if let Some((receiver, method)) = name.rsplit_once('.') {
            if is_value_method_receiver(module, receiver) {
                let value = self.load_value(module, locals, receiver)?;
                return self.invoke_method(value, method, args, depth);
            }
        }
        if let Some((alias, function)) = name.split_once('.') {
            match module.imports.get(alias) {
                Some(Import::Binary) => self.binary(module, function, &args),
                Some(Import::Bytes) => self.bytes(function, &args),
                Some(Import::Text) => self.text(function, &args),
                Some(Import::Formats) => self.formats(function, &args),
                Some(Import::Cli) => self.cli(function, &args),
                Some(Import::Net) => self.net(module, function, &args),
                Some(Import::Process) => self.process(module, function, &args),
                Some(Import::ResultOps) => self.result_ops(function, &args),
                Some(Import::Audit) => self.audit(function, &args),
                Some(Import::Iter) => self.iter(function, &args),
                Some(Import::ListOps) => self.list_ops(function, &args),
                Some(Import::Lab) => self.lab(function, &args),
                Some(Import::Asm) => self.asm(function, &args),
                Some(Import::Python(path)) => self.call_python(module, path, function, &args),
                Some(Import::Local(imported)) => self.call(imported, function, args, depth + 1),
                None => Err(format!("unknown module {alias}")),
            }
        } else {
            self.call(module, name, args, depth + 1)
        }
    }

    fn invoke_method(
        &self,
        receiver: Value,
        method: &str,
        mut args: Vec<Value>,
        depth: usize,
    ) -> Result<Value, String> {
        let Value::Record(record) = &receiver else {
            return Err(format!("method {method} needs a class value"));
        };
        let owner = self
            .record_modules
            .get(&record.id)
            .ok_or("class module unavailable")?;
        let key = syntax::class_method_key(&record.name, method);
        if !owner.functions.contains_key(&key) {
            return Err(format!("unknown method {method} on {}", record.name));
        }
        args.insert(0, receiver);
        self.call(owner, &key, args, depth + 1)
    }

    fn call(
        &self,
        module: &Rc<Module>,
        name: &str,
        args: Vec<Value>,
        depth: usize,
    ) -> Result<Value, String> {
        if depth > MAX_CALL_DEPTH {
            return Err("call depth exceeded".into());
        }
        if let Some(record) = module.records.get(name) {
            if args.len() != record.fields.len() {
                return Err(format!("{name} expects {} arguments", record.fields.len()));
            }
            let mut fields = Vec::with_capacity(args.len());
            for ((field, kind), value) in record.fields.iter().zip(args) {
                if !kind.accepts(&value) {
                    return Err(format!("{name} field {field} expects {kind}"));
                }
                fields.push((field.clone(), value));
            }
            return Ok(Value::Record(Arc::new(RecordValue {
                id: record.id,
                name: record.name.clone(),
                fields,
            })));
        }
        let function = module
            .functions
            .get(name)
            .ok_or_else(|| format!("unknown function {name}"))?;
        if args.len() != function.params.len() {
            return Err(format!(
                "{name} expects {} arguments",
                function.params.len()
            ));
        }
        let mut locals = HashMap::new();
        for ((param, kind), value) in function.params.iter().zip(args) {
            if !kind.accepts(&value) {
                return Err(format!("{name}: parameter {param} expects {kind}"));
            }
            locals.insert(param.clone(), specialize_list(value, *kind));
        }
        let evaluated: Result<Value, String> = (|| {
            let early = self.execute_actions(
                module,
                &function.steps,
                &mut locals,
                &mut HashSet::new(),
                depth,
            )?;
            match early {
                ActionFlow::Return(value) => return Ok(value),
                ActionFlow::Next => {}
                ActionFlow::Break | ActionFlow::Continue => {
                    return Err("loop control outside loop".into())
                }
            }
            let result_expr = function.body.as_ref().and_then(|body| match body {
                FunctionBody::Expression(expr) => Some(expr),
                FunctionBody::Block(_, expr) => expr.as_ref(),
            });
            let result_code = function
                .result_code
                .as_ref()
                .ok_or("function fell through without return")?;
            self.execute_expr(module, &locals, result_expr, result_code, depth)
        })();
        let result = if matches!(function.result_type, Some(Type::Result(_))) {
            match evaluated {
                Ok(value @ Value::Result(_)) => value,
                Ok(value) => Value::Result(Arc::new(Ok(value))),
                Err(error) => Value::Result(Arc::new(Err(error))),
            }
        } else {
            evaluated?
        };
        if let Some(kind) = function.result_type {
            if !kind.accepts(&result) {
                return Err(format!("{name}: return value expects {kind}"));
            }
        }
        Ok(match function.result_type {
            Some(kind) => specialize_list(result, kind),
            None => result,
        })
    }

    fn bytes(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("from_hex", [text]) => Ok(Value::Bytes(Arc::new(parse_hex(text.as_str()?)?))),
            ("pack", [value @ Value::UInt(_), encoding]) => Ok(Value::Bytes(Arc::new(
                bytes::pack_unsigned(value.as_uint()?, encoding.as_str()?)?,
            ))),
            ("pack", [value, encoding]) => Ok(Value::Bytes(Arc::new(bytes::pack(
                value.as_int()?,
                encoding.as_str()?,
            )?))),
            ("to_hex", [Value::Bytes(data)]) => Ok(Value::Str(bytes::to_hex(data)?)),
            ("concat", [Value::Bytes(left), Value::Bytes(right)]) => {
                Ok(Value::Bytes(Arc::new(bytes::concat(left, right)?)))
            }
            ("repeat", [Value::Bytes(data), count]) => Ok(Value::Bytes(Arc::new(bytes::repeat(
                data,
                count.as_int()?,
            )?))),
            ("xor", [Value::Bytes(data), Value::Bytes(key)]) => {
                Ok(Value::Bytes(Arc::new(bytes::xor(data, key)?)))
            }
            ("at", [Value::Bytes(data), index]) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "byte index out of range")?;
                Ok(Value::Int(i64::from(
                    *data.get(index).ok_or("byte index out of range")?,
                )))
            }
            _ => Err(format!(
                "unknown bytes function or wrong argument count: {name}"
            )),
        }
    }

    fn text(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("length", [value]) => Ok(Value::Int(value.as_str()?.chars().count() as i64)),
            ("byte_length", [value]) => Ok(Value::Int(value.as_str()?.len() as i64)),
            ("find", [value, needle]) => {
                let value = value.as_str()?;
                let needle = needle.as_str()?;
                Ok(Value::Int(match value.find(needle) {
                    Some(offset) => value[..offset].chars().count() as i64,
                    None => -1,
                }))
            }
            ("contains", [value, needle]) => {
                Ok(Value::Bool(value.as_str()?.contains(needle.as_str()?)))
            }
            ("starts_with", [value, prefix]) => {
                Ok(Value::Bool(value.as_str()?.starts_with(prefix.as_str()?)))
            }
            ("ends_with", [value, suffix]) => {
                Ok(Value::Bool(value.as_str()?.ends_with(suffix.as_str()?)))
            }
            ("slice", [value, start, count]) => {
                let value = value.as_str()?;
                let start =
                    usize::try_from(start.as_int()?).map_err(|_| "text slice out of range")?;
                let count =
                    usize::try_from(count.as_int()?).map_err(|_| "text slice out of range")?;
                let end = start.checked_add(count).ok_or("text slice out of range")?;
                let boundary = |index| {
                    value
                        .char_indices()
                        .map(|(offset, _)| offset)
                        .chain(std::iter::once(value.len()))
                        .nth(index)
                        .ok_or("text slice out of range")
                };
                Ok(Value::Str(
                    value[boundary(start)?..boundary(end)?].to_owned(),
                ))
            }
            _ => Err(format!(
                "unknown text function or wrong argument count: {name}"
            )),
        }
    }

    fn binary(&self, module: &Rc<Module>, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("analyze", [path, max]) => {
                self.check_effect(module, "file.read")?;
                let max = max.as_int()?;
                if max < 0 || max as u64 > MAX_SNAPSHOT as u64 {
                    return Err(format!("max_bytes must be between 0 and {MAX_SNAPSHOT}"));
                }
                let label = path.as_str()?.to_string();
                let path = module.path.parent().unwrap().join(&label);
                let (file, opened) = file_access::open_authorized(&path, &self.read_roots)?;
                let mut bytes = Vec::new();
                file.take(max as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| format!("{}: {e}", opened.display()))?;
                if bytes.len() > max as usize {
                    return Err(format!(
                        "LimitExceeded: {} is larger than {max} bytes",
                        opened.display()
                    ));
                }
                Ok(Value::Source(Arc::new(Source::new(
                    format!("file:{}", opened.display()),
                    label,
                    bytes,
                ))))
            }
            ("deep", [source, offset, kind]) => {
                let source = source.as_source()?;
                let offset = offset.as_int()?;
                if offset < 0 {
                    return Err("offset must not be negative".into());
                }
                let (width, decoder): (usize, &'static str) = match kind.as_str()? {
                    "u8" => (1, "u8"),
                    "u16le" => (2, "u16le"),
                    "u16be" => (2, "u16be"),
                    "u32le" => (4, "u32le"),
                    "u32be" => (4, "u32be"),
                    "u64le" => (8, "u64le"),
                    "u64be" => (8, "u64be"),
                    _ => return Err("unknown decoder".into()),
                };
                let offset = usize::try_from(offset).map_err(|_| "offset too large")?;
                let end = offset.checked_add(width).ok_or("offset overflow")?;
                let bytes = source.bytes().get(offset..end).ok_or("out of bounds")?;
                let value = if decoder.ends_with("be") {
                    bytes.iter().fold(0_u64, |n, b| (n << 8) | u64::from(*b))
                } else {
                    bytes
                        .iter()
                        .enumerate()
                        .fold(0_u64, |n, (i, b)| n | (u64::from(*b) << (8 * i)))
                };
                Ok(Value::Observation(Arc::new(Observation {
                    source,
                    offset,
                    width,
                    decoder,
                    value,
                })))
            }
            ("view", [source, offset, length]) => {
                let source = source.as_source()?;
                let (start, end) = checked_span(offset, length, source.bytes().len())?;
                Ok(Value::Source(Arc::new(Source::view(source, start, end)?)))
            }
            ("extract", [source, offset, length]) => {
                let bytes = source.as_binary_bytes()?;
                let (start, end) = checked_span(offset, length, bytes.len())?;
                Ok(Value::Bytes(Arc::new(bytes[start..end].to_vec())))
            }
            ("hexdump", [source]) => {
                let source = source.as_source()?;
                let end = source.bytes().len().min(DEFAULT_HEXDUMP_BYTES);
                Ok(Value::Str(bytes::hex_dump(&source.bytes()[..end], 0)))
            }
            ("hexdump", [source, offset, length]) => {
                let source = source.as_source()?;
                let (start, end) = checked_span(offset, length, source.bytes().len())?;
                if end - start > MAX_HEXDUMP_BYTES {
                    return Err(format!("hexdump length exceeds {MAX_HEXDUMP_BYTES} bytes"));
                }
                Ok(Value::Str(bytes::hex_dump(
                    &source.bytes()[start..end],
                    start,
                )))
            }
            ("patch", [source, offset, Value::Bytes(replacement)]) => {
                let source = source.as_source()?;
                if replacement.is_empty() {
                    return Err("patch data must not be empty".into());
                }
                if replacement.len() > MAX_PATCH_BYTES {
                    return Err(format!(
                        "LimitExceeded: patch exceeds {MAX_PATCH_BYTES} bytes"
                    ));
                }
                let length = Value::Int(
                    i64::try_from(replacement.len()).map_err(|_| "patch length out of range")?,
                );
                let (start, end) = checked_span(offset, &length, source.bytes().len())?;
                Ok(Value::Source(Arc::new(Source::patch(
                    source,
                    start,
                    end,
                    replacement,
                )?)))
            }
            ("splice", [source, offset, removed, Value::Bytes(replacement)]) => {
                let source = source.as_source()?;
                if replacement.len() > MAX_PATCH_BYTES {
                    return Err(format!(
                        "LimitExceeded: splice insertion exceeds {MAX_PATCH_BYTES} bytes"
                    ));
                }
                let (start, end) = checked_span(offset, removed, source.bytes().len())?;
                if start == end && replacement.is_empty() {
                    return Err("splice must insert or remove at least one byte".into());
                }
                Ok(Value::Source(Arc::new(Source::splice(
                    source,
                    start,
                    end,
                    replacement,
                )?)))
            }
            ("value", [Value::Observation(observation)]) => Ok(Value::Int(
                i64::try_from(observation.value)
                    .map_err(|_| "Observation value does not fit i64")?,
            )),
            ("value_u64", [Value::Observation(observation)]) => Ok(Value::UInt(observation.value)),
            ("signed_value", [Value::Observation(observation)]) => {
                let width = match observation.decoder {
                    "u8" => 1,
                    "u16le" | "u16be" => 2,
                    "u32le" | "u32be" => 4,
                    "u64le" | "u64be" => 8,
                    _ => return Err("Observation is not an unsigned integer field".into()),
                };
                let shift = 64 - width * 8;
                Ok(Value::Int(((observation.value << shift) as i64) >> shift))
            }
            ("offset", [Value::Observation(observation)]) => Ok(Value::Int(
                i64::try_from(observation.offset).map_err(|_| "offset out of range")?,
            )),
            ("width", [Value::Observation(observation)]) => Ok(Value::Int(
                i64::try_from(observation.width).map_err(|_| "width out of range")?,
            )),
            ("diff", [left, right, limit]) => {
                let left = left.as_source()?;
                let right = right.as_source()?;
                let limit =
                    usize::try_from(limit.as_int()?).map_err(|_| "max_differences out of range")?;
                if limit > MAX_HITS {
                    return Err(format!("max_differences must be at most {MAX_HITS}"));
                }
                let offsets = diff_offsets(left.bytes(), right.bytes(), limit)?;
                Ok(Value::Diff(Arc::new(Diff {
                    left,
                    right,
                    offsets,
                })))
            }
            ("diff_offsets", [Value::Diff(diff)]) => Ok(Value::Offsets(diff.offsets.clone())),
            ("diff_count", [Value::Diff(diff)]) => Ok(Value::Int(
                i64::try_from(diff.offsets.len()).map_err(|_| "diff count out of range")?,
            )),
            ("from_hex", [text]) => {
                let bytes = parse_hex(text.as_str()?)?;
                Ok(Value::Bytes(Arc::new(bytes)))
            }
            ("snapshot", [Value::Bytes(bytes)]) => Ok(Value::Source(Arc::new(Source::new(
                "memory".into(),
                "memory".into(),
                bytes.as_ref().clone(),
            )))),
            ("snapshot", [_]) => Err("bytes expected".into()),
            ("size", [Value::Bytes(bytes)]) => Ok(Value::Int(
                i64::try_from(bytes.len()).map_err(|_| "size out of range")?,
            )),
            ("size", [Value::Source(source)]) => Ok(Value::Int(
                i64::try_from(source.bytes().len()).map_err(|_| "size out of range")?,
            )),
            ("entropy", [source]) => {
                let source = source.as_source()?;
                let width = source.bytes().len();
                Ok(Value::Observation(Arc::new(Observation {
                    value: shannon_entropy_milli(source.bytes()),
                    source,
                    offset: 0,
                    width,
                    decoder: "entropy_milli",
                })))
            }
            ("hunt", [source, pattern]) => {
                let source = source.as_source()?;
                let result = search_pattern(source.bytes(), pattern, usize::MAX)?;
                Ok(Value::Offsets(result.offsets))
            }
            ("strings", [source, minimum, encoding]) => {
                let source = source.as_source()?;
                let minimum = usize::try_from(minimum.as_int()?)
                    .map_err(|_| "minimum string length out of range")?;
                if !(1..=MAX_TEXT_CHARS).contains(&minimum) {
                    return Err(format!(
                        "minimum string length must be 1 to {MAX_TEXT_CHARS}"
                    ));
                }
                let encoding = TextEncoding::parse(encoding.as_str()?)?;
                Ok(Value::Offsets(find_strings(
                    source.bytes(),
                    minimum,
                    encoding,
                )?))
            }
            ("read_text", [source, offset, max_chars, encoding]) => {
                let source = source.as_source()?;
                let offset = usize::try_from(offset.as_int()?)
                    .map_err(|_| "text offset must not be negative")?;
                let max_chars =
                    usize::try_from(max_chars.as_int()?).map_err(|_| "max_chars out of range")?;
                if !(1..=MAX_TEXT_CHARS).contains(&max_chars) {
                    return Err(format!("max_chars must be 1 to {MAX_TEXT_CHARS}"));
                }
                let encoding = TextEncoding::parse(encoding.as_str()?)?;
                Ok(Value::Str(read_text(
                    source.bytes(),
                    offset,
                    max_chars,
                    encoding,
                )?))
            }
            ("sha256", [Value::Bytes(bytes)]) => {
                let digest = Sha256::digest(bytes.as_slice());
                Ok(Value::Str(
                    digest.iter().map(|b| format!("{b:02x}")).collect(),
                ))
            }
            ("sha256", [source]) => {
                let source = source.as_source()?;
                Ok(Value::Str(source.sha256.clone()))
            }
            _ => Err(format!(
                "unknown binary function or wrong argument count: {name}"
            )),
        }
    }

    fn process(&self, module: &Rc<Module>, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("self_pid", []) => Ok(Value::Int(i64::from(std::process::id()))),
            ("modules", [pid]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                make_list(process::modules(pid)?.into_iter().map(Value::Str).collect())
            }
            ("thread_ids", [pid]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                make_list(
                    process::thread_ids(pid)?
                        .into_iter()
                        .map(|id| Value::Int(i64::from(id)))
                        .collect(),
                )
            }
            ("children", [pid]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                make_list(
                    process::children(pid)?
                        .into_iter()
                        .map(|id| Value::Int(i64::from(id)))
                        .collect(),
                )
            }
            ("executable", [pid]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                Ok(Value::Str(process::executable(pid)?))
            }
            ("parent_pid", [pid]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                Ok(Value::Int(i64::from(process::parent_pid(pid)?)))
            }
            ("regions" | "images", [pid]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                let regions = if name == "images" {
                    process::images(pid)?
                } else {
                    process::regions(pid)?
                }
                .into_iter()
                .map(Arc::new)
                .collect();
                Ok(Value::Regions(Arc::new(regions)))
            }
            ("count", [Value::Regions(regions)]) => Ok(Value::Int(
                i64::try_from(regions.len()).map_err(|_| "region count out of range")?,
            )),
            ("at", [Value::Regions(regions), index]) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "region index out of range")?;
                regions
                    .get(index)
                    .cloned()
                    .map(Value::Region)
                    .ok_or("region index out of range".into())
            }
            ("locate" | "locate_u64", [Value::Regions(regions), address]) => {
                let address = if name == "locate_u64" {
                    usize::try_from(address.as_uint()?)
                } else {
                    usize::try_from(address.as_int()?)
                }
                .map_err(|_| "process address out of range")?;
                Ok(Value::Region(locate_region(regions, address)?))
            }
            ("pid", [Value::Region(region)]) => Ok(Value::Int(i64::from(region.pid))),
            ("start_u64", [Value::Region(region)]) => Ok(Value::UInt(
                u64::try_from(region.start).map_err(|_| "region start outside u64 range")?,
            )),
            ("start", [Value::Region(region)]) => Ok(Value::Int(
                i64::try_from(region.start).map_err(|_| "region start outside i64 range")?,
            )),
            ("size", [Value::Region(region)]) => Ok(Value::Int(
                i64::try_from(region.size).map_err(|_| "region size outside i64 range")?,
            )),
            ("end", [Value::Region(region)]) => Ok(Value::Int(
                i64::try_from(
                    region
                        .start
                        .checked_add(region.size)
                        .ok_or("region end overflow")?,
                )
                .map_err(|_| "region end outside i64 range")?,
            )),
            ("end_u64", [Value::Region(region)]) => Ok(Value::UInt(
                u64::try_from(
                    region
                        .start
                        .checked_add(region.size)
                        .ok_or("region end overflow")?,
                )
                .map_err(|_| "region end outside u64 range")?,
            )),
            ("access", [Value::Region(region)]) => Ok(Value::Str(region.access.clone())),
            ("label", [Value::Region(region)]) => Ok(Value::Str(region.label.clone())),
            ("reference", [Value::Region(region), address]) => {
                let address = usize::try_from(address.as_uint()?)
                    .map_err(|_| "process address out of range")?;
                Ok(Value::Str(region.reference(address)?))
            }
            ("resolve", [Value::Region(region), reference]) => Ok(Value::UInt(
                u64::try_from(region.resolve_reference(reference.as_str()?)?)
                    .map_err(|_| "process address outside u64 range")?,
            )),
            ("image_backed", [Value::Region(region)]) => Ok(Value::Bool(region.image_backed)),
            ("offset" | "offset_u64", [Value::Region(region), address]) => {
                let address = if name == "offset_u64" {
                    usize::try_from(address.as_uint()?)
                } else {
                    usize::try_from(address.as_int()?)
                }
                .map_err(|_| "process address out of range")?;
                let offset = region.offset_of(address)?;
                Ok(Value::Int(
                    i64::try_from(offset).map_err(|_| "region offset outside i64 range")?,
                ))
            }
            ("address", [Value::Region(region), offset]) => {
                let offset =
                    usize::try_from(offset.as_int()?).map_err(|_| "region offset out of range")?;
                let address = region.address_of(offset)?;
                Ok(Value::Int(
                    i64::try_from(address).map_err(|_| "region address outside i64 range")?,
                ))
            }
            ("address_u64", [Value::Region(region), offset]) => {
                let offset =
                    usize::try_from(offset.as_int()?).map_err(|_| "region offset out of range")?;
                Ok(Value::UInt(
                    u64::try_from(region.address_of(offset)?)
                        .map_err(|_| "region address outside u64 range")?,
                ))
            }
            ("snapshot_at" | "snapshot_at_u64", [Value::Regions(regions), address, length]) => {
                self.check_effect(module, "process.inspect")?;
                let address = if name == "snapshot_at_u64" {
                    usize::try_from(address.as_uint()?)
                } else {
                    usize::try_from(address.as_int()?)
                }
                .map_err(|_| "process address out of range")?;
                let region = locate_region(regions, address)?;
                let offset = region.offset_of(address)?;
                let offset =
                    i64::try_from(offset).map_err(|_| "region offset outside i64 range")?;
                self.process(
                    module,
                    "snapshot_region",
                    &[Value::Region(region), Value::Int(offset), length.clone()],
                )
            }
            ("snapshot_region", [Value::Region(region), offset, length]) => {
                self.check_effect(module, "process.inspect")?;
                if !self.allowed_processes.contains(&region.pid) {
                    return Err(format!("process access not allowed: {}", region.pid));
                }
                if !region.access.starts_with('r') {
                    return Err("region is not marked readable".into());
                }
                let offset =
                    usize::try_from(offset.as_int()?).map_err(|_| "region offset out of range")?;
                let length =
                    usize::try_from(length.as_int()?).map_err(|_| "region length out of range")?;
                if offset
                    .checked_add(length)
                    .is_none_or(|end| end > region.size)
                {
                    return Err("snapshot exceeds region boundaries".into());
                }
                let address = region
                    .start
                    .checked_add(offset)
                    .ok_or("region address overflow")?;
                let bytes = process::snapshot(region.pid, address, length)?;
                let label = format!("process {} @ 0x{address:x}", region.pid);
                let origin = format!(
                    "{label} (region {:?}, access {}, {} bytes requested)",
                    region.label, region.access, length
                );
                Ok(Value::Source(Arc::new(Source::new(origin, label, bytes))))
            }
            ("snapshot_ref", [Value::Region(region), reference, length]) => {
                self.check_effect(module, "process.inspect")?;
                let address = region.resolve_reference(reference.as_str()?)?;
                let offset = i64::try_from(region.offset_of(address)?)
                    .map_err(|_| "region offset outside i64 range")?;
                self.process(
                    module,
                    "snapshot_region",
                    &[
                        Value::Region(region.clone()),
                        Value::Int(offset),
                        length.clone(),
                    ],
                )
            }
            ("snapshot" | "snapshot_u64", [pid, address, length]) => {
                self.check_effect(module, "process.inspect")?;
                let pid = u32::try_from(pid.as_int()?).map_err(|_| "pid out of range")?;
                let address = if name == "snapshot_u64" {
                    usize::try_from(address.as_uint()?)
                } else {
                    usize::try_from(address.as_int()?)
                }
                .map_err(|_| "process address out of range")?;
                let length =
                    usize::try_from(length.as_int()?).map_err(|_| "process length out of range")?;
                if !self.allowed_processes.contains(&pid) {
                    return Err(format!("process access not allowed: {pid}"));
                }
                let bytes = process::snapshot(pid, address, length)?;
                let label = format!("process {pid} @ 0x{address:x}");
                let origin = format!("{label} ({length} bytes requested)");
                Ok(Value::Source(Arc::new(Source::new(origin, label, bytes))))
            }
            _ => Err(format!(
                "unknown process function or wrong argument count: {name}"
            )),
        }
    }

    fn net(&self, module: &Rc<Module>, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("request", [method, url, headers, body, max_bytes, timeout_ms]) => {
                self.check_effect(module, "net.connect")?;
                let (url, authority) = net::http_url(url.as_str()?)?;
                if !self.allowed_connections.contains(&authority) {
                    return Err(format!("network access not allowed: {authority}"));
                }
                let headers = match headers {
                    Value::List(items, _) => items
                        .iter()
                        .map(|item| item.as_str().map(str::to_owned))
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("HTTP headers must be a List<str>".into()),
                };
                let body = body.as_request_bytes()?;
                if body.len() > MAX_NET_REQUEST {
                    return Err(format!("HTTP request body exceeds {MAX_NET_REQUEST} bytes"));
                }
                let max_bytes =
                    usize::try_from(max_bytes.as_int()?).map_err(|_| "max_bytes out of range")?;
                if max_bytes > MAX_NET_RESPONSE {
                    return Err(format!("max_bytes must be at most {MAX_NET_RESPONSE}"));
                }
                let timeout_ms = timeout_ms.as_int()?;
                if !(1..=MAX_NET_TIMEOUT_MS).contains(&timeout_ms) {
                    return Err(format!(
                        "timeout_ms must be between 1 and {MAX_NET_TIMEOUT_MS}"
                    ));
                }
                let method = method.as_str()?;
                let response = net::request(
                    url,
                    method,
                    &headers,
                    body,
                    max_bytes,
                    Duration::from_millis(timeout_ms as u64),
                )?;
                let origin = match response.peer {
                    Some(peer) => format!(
                        "HTTP {method} {} {} (peer {peer})",
                        response.status, response.url
                    ),
                    None => format!("HTTP {method} {} {}", response.status, response.url),
                };
                let request_source = Arc::new(Source::new(
                    format!("HTTP {method} request {}", response.url),
                    format!("HTTP {method} request"),
                    body.to_vec(),
                ));
                let source = Arc::new(Source::new(origin, response.url, response.bytes));
                Ok(Value::HttpResponse(Arc::new(HttpResponseValue {
                    status: response.status,
                    request: request_source,
                    body: source,
                    headers: response.headers,
                })))
            }
            ("status", [Value::HttpResponse(response)]) => {
                Ok(Value::Int(i64::from(response.status)))
            }
            ("body", [Value::HttpResponse(response)]) => Ok(Value::Source(response.body.clone())),
            ("headers", [Value::HttpResponse(response), name]) => {
                let name = name.as_str()?;
                let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| "invalid HTTP header name")?;
                make_list(
                    response
                        .headers
                        .iter()
                        .filter(|(field, _)| field == name.as_str())
                        .map(|(_, value)| Value::Str(value.clone()))
                        .collect(),
                )
            }
            ("fetch", [url, max_bytes, timeout_ms]) => {
                self.check_effect(module, "net.connect")?;
                let (url, authority) = net::http_url(url.as_str()?)?;
                if !self.allowed_connections.contains(&authority) {
                    return Err(format!("network access not allowed: {authority}"));
                }
                let max_bytes =
                    usize::try_from(max_bytes.as_int()?).map_err(|_| "max_bytes out of range")?;
                if max_bytes > MAX_NET_RESPONSE {
                    return Err(format!("max_bytes must be at most {MAX_NET_RESPONSE}"));
                }
                let timeout_ms = timeout_ms.as_int()?;
                if !(1..=MAX_NET_TIMEOUT_MS).contains(&timeout_ms) {
                    return Err(format!(
                        "timeout_ms must be between 1 and {MAX_NET_TIMEOUT_MS}"
                    ));
                }
                let response =
                    net::fetch(url, max_bytes, Duration::from_millis(timeout_ms as u64))?;
                let origin = match response.peer {
                    Some(peer) => {
                        format!("HTTP {} {} (peer {peer})", response.status, response.url)
                    }
                    None => format!("HTTP {} {}", response.status, response.url),
                };
                Ok(Value::Source(Arc::new(Source::new(
                    origin,
                    response.url,
                    response.bytes,
                ))))
            }
            ("exchange" | "datagram", [host, port, request, max_bytes, timeout_ms]) => {
                self.check_effect(module, "net.connect")?;
                let host = host.as_str()?;
                if host.is_empty() || host.len() > 255 {
                    return Err("host must contain 1 to 255 bytes".into());
                }
                let port = u16::try_from(port.as_int()?).map_err(|_| "port out of range")?;
                if port == 0 {
                    return Err("port out of range".into());
                }
                let authority = net::authority(host, port);
                if !self.allowed_connections.contains(&authority) {
                    return Err(format!("network access not allowed: {authority}"));
                }
                let request = request.as_request_bytes()?;
                let request_limit = if name == "datagram" {
                    MAX_UDP_DATAGRAM
                } else {
                    MAX_NET_REQUEST
                };
                if request.len() > request_limit {
                    return Err(format!("request exceeds {request_limit} bytes"));
                }
                let max_bytes =
                    usize::try_from(max_bytes.as_int()?).map_err(|_| "max_bytes out of range")?;
                let response_limit = if name == "datagram" {
                    MAX_UDP_DATAGRAM
                } else {
                    MAX_NET_RESPONSE
                };
                if max_bytes > response_limit {
                    return Err(format!("max_bytes must be at most {response_limit}"));
                }
                let timeout_ms = timeout_ms.as_int()?;
                if !(1..=MAX_NET_TIMEOUT_MS).contains(&timeout_ms) {
                    return Err(format!(
                        "timeout_ms must be between 1 and {MAX_NET_TIMEOUT_MS}"
                    ));
                }
                let (bytes, peer, scheme) = if name == "datagram" {
                    let response = net::datagram(
                        host,
                        port,
                        request,
                        max_bytes,
                        Duration::from_millis(timeout_ms as u64),
                    )?;
                    (response.bytes, response.peer, "udp")
                } else {
                    let response = net::exchange(
                        host,
                        port,
                        request,
                        max_bytes,
                        Duration::from_millis(timeout_ms as u64),
                    )?;
                    (response.bytes, response.peer, "tcp")
                };
                let label = format!("{scheme}://{authority}");
                let origin = format!("{label} (peer {peer})");
                Ok(Value::Source(Arc::new(Source::new(origin, label, bytes))))
            }
            _ => Err(format!(
                "unknown net function or wrong argument count: {name}"
            )),
        }
    }

    fn asm(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("linear", [Value::Format(source, report), count]) => {
                let count = usize::try_from(count.as_int()?).map_err(|_| {
                    format!("instruction count must be between 1 and {MAX_DISASSEMBLY}")
                })?;
                if !(1..=MAX_DISASSEMBLY).contains(&count) {
                    return Err(format!(
                        "instruction count must be between 1 and {MAX_DISASSEMBLY}"
                    ));
                }
                let (start, end, bitness) = report.x86_entry_region(source.bytes().len())?;
                let is_pe = report.name.starts_with("PE");
                let mut cursor = start;
                let mut ip = report.entry;
                let mut instructions = Vec::with_capacity(count);
                for _ in 0..count {
                    if cursor >= end {
                        return Err("linear disassembly exceeds executable entry region".into());
                    }
                    let decoded = asm::decode(&source.bytes()[cursor..end], 0, ip, bitness)?;
                    let next = cursor + decoded.size;
                    let mapped = if is_pe {
                        report.pe_rva_range(source.bytes().len(), ip, decoded.size)?
                    } else {
                        report.elf_va_range(source.bytes().len(), ip, decoded.size)?
                    };
                    if mapped != (cursor, next) {
                        return Err(
                            "instruction bytes do not map to the expected file range".into()
                        );
                    }
                    let view = if is_pe {
                        Source::rva_view(source.clone(), cursor, next, ip)?
                    } else {
                        Source::va_view(source.clone(), cursor, next, ip)?
                    };
                    instructions.push(Arc::new(AsmInstruction {
                        source: Arc::new(view),
                        offset: cursor,
                        decoded,
                    }));
                    ip = ip
                        .checked_add((next - cursor) as u64)
                        .ok_or("instruction address overflow")?;
                    cursor = next;
                }
                let view = if is_pe {
                    Source::rva_view(source.clone(), start, cursor, report.entry)?
                } else {
                    Source::va_view(source.clone(), start, cursor, report.entry)?
                };
                Ok(Value::Disassembly(Arc::new(Disassembly::new(
                    Arc::new(view),
                    start,
                    instructions,
                )?)))
            }
            ("reachable_entry", [Value::Format(source, report), count]) => {
                let count = usize::try_from(count.as_int()?).map_err(|_| {
                    format!("instruction count must be between 1 and {MAX_DISASSEMBLY}")
                })?;
                if !(1..=MAX_DISASSEMBLY).contains(&count) {
                    return Err(format!(
                        "instruction count must be between 1 and {MAX_DISASSEMBLY}"
                    ));
                }
                let (start, end, bitness) = report.x86_entry_region(source.bytes().len())?;
                let is_pe = report.name.starts_with("PE");
                let found =
                    asm::reachable(&source.bytes()[start..end], 0, report.entry, bitness, count)?;
                let mut instructions = Vec::with_capacity(found.len());
                for (relative, decoded) in found {
                    let offset = start + relative;
                    let next = offset + decoded.size;
                    let mapped = if is_pe {
                        report.pe_rva_range(source.bytes().len(), decoded.ip, decoded.size)?
                    } else {
                        report.elf_va_range(source.bytes().len(), decoded.ip, decoded.size)?
                    };
                    if mapped != (offset, next) {
                        return Err(
                            "instruction bytes do not map to the expected file range".into()
                        );
                    }
                    let view = if is_pe {
                        Source::rva_view(source.clone(), offset, next, decoded.ip)?
                    } else {
                        Source::va_view(source.clone(), offset, next, decoded.ip)?
                    };
                    instructions.push(Arc::new(AsmInstruction {
                        source: Arc::new(view),
                        offset,
                        decoded,
                    }));
                }
                Ok(Value::Disassembly(Arc::new(Disassembly::new(
                    source.clone(),
                    start,
                    instructions,
                )?)))
            }
            ("entry", [Value::Format(source, report)]) => {
                let (start, end, bitness) = report.x86_entry_window(source.bytes().len())?;
                let decoded = asm::decode(&source.bytes()[start..end], 0, report.entry, bitness)?;
                let view = if report.name.starts_with("PE") {
                    Source::rva_view(source.clone(), start, start + decoded.size, report.entry)?
                } else {
                    Source::va_view(source.clone(), start, start + decoded.size, report.entry)?
                };
                Ok(Value::Instruction(Arc::new(AsmInstruction {
                    source: Arc::new(view),
                    offset: start,
                    decoded,
                })))
            }
            ("decode", [source, offset, bitness])
            | ("decode", [source, offset, _, bitness])
            | ("decode_u64", [source, offset, _, bitness]) => {
                let source = source.as_source()?;
                let offset = usize::try_from(offset.as_int()?)
                    .map_err(|_| "instruction offset must be nonnegative")?;
                let ip = if name == "decode_u64" {
                    args[2].as_uint()?
                } else if args.len() == 4 {
                    u64::try_from(args[2].as_int()?)
                        .map_err(|_| "instruction address must be nonnegative")?
                } else {
                    u64::try_from(offset).map_err(|_| "instruction address is too large")?
                };
                let bitness = u32::try_from(bitness.as_int()?)
                    .map_err(|_| "x86 bitness must be 16, 32, or 64")?;
                let decoded = asm::decode(source.bytes(), offset, ip, bitness)?;
                let view = Arc::new(Source::view(source, offset, offset + decoded.size)?);
                Ok(Value::Instruction(Arc::new(AsmInstruction {
                    source: view,
                    offset,
                    decoded,
                })))
            }
            ("reachable", [source, offset, base_ip, bitness, count]) => {
                let source = source.as_source()?;
                let offset = usize::try_from(offset.as_int()?)
                    .map_err(|_| "reachable entry offset must be nonnegative")?;
                let base_ip = base_ip.as_uint()?;
                let bitness = u32::try_from(bitness.as_int()?)
                    .map_err(|_| "x86 bitness must be 16, 32, or 64")?;
                let count = usize::try_from(count.as_int()?).map_err(|_| {
                    format!("instruction count must be between 1 and {MAX_DISASSEMBLY}")
                })?;
                if !(1..=MAX_DISASSEMBLY).contains(&count) {
                    return Err(format!(
                        "instruction count must be between 1 and {MAX_DISASSEMBLY}"
                    ));
                }
                let found = asm::reachable(source.bytes(), offset, base_ip, bitness, count)?;
                let mut instructions = Vec::with_capacity(found.len());
                for (instruction_offset, decoded) in found {
                    let view = Source::view(
                        source.clone(),
                        instruction_offset,
                        instruction_offset + decoded.size,
                    )?;
                    instructions.push(Arc::new(AsmInstruction {
                        source: Arc::new(view),
                        offset: instruction_offset,
                        decoded,
                    }));
                }
                Ok(Value::Disassembly(Arc::new(Disassembly::new(
                    source,
                    offset,
                    instructions,
                )?)))
            }
            ("text", [Value::Instruction(i)]) => Ok(Value::Str(i.decoded.text.clone())),
            ("mnemonic", [Value::Instruction(i)]) => Ok(Value::Str(i.decoded.mnemonic.clone())),
            ("flow", [Value::Instruction(i)]) => Ok(Value::Str(i.decoded.flow.into())),
            ("address", [Value::Instruction(i)]) => Ok(Value::Str(format!("0x{:x}", i.decoded.ip))),
            ("target", [Value::Instruction(i)]) => i
                .decoded
                .target
                .map(|target| Value::Str(format!("0x{target:x}")))
                .ok_or_else(|| "instruction has no direct branch target".into()),
            ("address_u64", [Value::Instruction(i)]) => Ok(Value::UInt(i.decoded.ip)),
            ("target_u64", [Value::Instruction(i)]) => i
                .decoded
                .target
                .map(Value::UInt)
                .ok_or_else(|| "instruction has no direct branch target".into()),
            ("successors", [Value::Instruction(i)]) => Ok(Value::List(
                Arc::new(
                    i.decoded
                        .successors()?
                        .into_iter()
                        .map(Value::UInt)
                        .collect(),
                ),
                Some(ResultKind::UInt),
            )),
            ("size", [Value::Instruction(i)]) => Ok(Value::Int(i.decoded.size as i64)),
            ("offset", [Value::Instruction(i)]) => Ok(Value::Int(i.offset as i64)),
            ("next", [Value::Instruction(i)]) => Ok(Value::Int((i.offset + i.decoded.size) as i64)),
            ("source", [Value::Instruction(i)]) => Ok(Value::Source(i.source.clone())),
            ("bytes", [Value::Instruction(i)]) => {
                Ok(Value::Bytes(Arc::new(i.source.bytes().to_vec())))
            }
            ("count", [Value::Disassembly(disassembly)]) => {
                Ok(Value::Int(disassembly.instructions.len() as i64))
            }
            ("call_targets", [Value::Disassembly(disassembly)]) => Ok(Value::List(
                Arc::new(
                    asm::call_targets(
                        &disassembly
                            .instructions
                            .iter()
                            .map(|instruction| &instruction.decoded)
                            .collect::<Vec<_>>(),
                    )
                    .into_iter()
                    .map(Value::UInt)
                    .collect(),
                ),
                Some(ResultKind::UInt),
            )),
            ("xrefs", [Value::Disassembly(disassembly), address]) => Ok(Value::List(
                Arc::new(
                    asm::xrefs(
                        &disassembly
                            .instructions
                            .iter()
                            .map(|instruction| &instruction.decoded)
                            .collect::<Vec<_>>(),
                        address.as_uint()?,
                    )
                    .into_iter()
                    .map(Value::UInt)
                    .collect(),
                ),
                Some(ResultKind::UInt),
            )),
            ("overlap_count", [Value::Disassembly(disassembly)]) => Ok(Value::Int(
                disassembly
                    .overlaps
                    .iter()
                    .filter(|overlap| **overlap)
                    .count() as i64,
            )),
            ("overlap_at", [Value::Disassembly(disassembly), index]) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "instruction index out of range")?;
                Ok(Value::Bool(
                    *disassembly
                        .overlaps
                        .get(index)
                        .ok_or("instruction index out of range")?,
                ))
            }
            ("at", [Value::Disassembly(disassembly), index]) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "instruction index out of range")?;
                Ok(Value::Instruction(
                    disassembly
                        .instructions
                        .get(index)
                        .ok_or("instruction index out of range")?
                        .clone(),
                ))
            }
            ("block_count", [Value::Disassembly(disassembly)]) => {
                Ok(Value::Int(disassembly.blocks.len() as i64))
            }
            ("block_instruction", [Value::Disassembly(disassembly), block, within]) => {
                let block =
                    usize::try_from(block.as_int()?).map_err(|_| "block index out of range")?;
                let within = usize::try_from(within.as_int()?)
                    .map_err(|_| "block instruction index out of range")?;
                let block = disassembly
                    .blocks
                    .get(block)
                    .ok_or("block index out of range")?;
                if within >= block.instruction_count {
                    return Err("block instruction index out of range".into());
                }
                Ok(Value::Instruction(
                    disassembly.instructions[block.first_index + within].clone(),
                ))
            }
            (
                "block_start"
                | "block_end"
                | "block_instruction_count"
                | "block_successors"
                | "block_unresolved",
                [Value::Disassembly(disassembly), index],
            ) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "block index out of range")?;
                let block = disassembly
                    .blocks
                    .get(index)
                    .ok_or("block index out of range")?;
                match name {
                    "block_start" => Ok(Value::UInt(block.start)),
                    "block_end" => Ok(Value::UInt(block.end)),
                    "block_instruction_count" => Ok(Value::Int(block.instruction_count as i64)),
                    "block_unresolved" => Ok(Value::Bool(block.unresolved)),
                    "block_successors" => Ok(Value::List(
                        Arc::new(block.successors.iter().copied().map(Value::UInt).collect()),
                        Some(ResultKind::UInt),
                    )),
                    _ => unreachable!(),
                }
            }
            _ => Err(format!(
                "unknown asm function or wrong argument count: {name}"
            )),
        }
    }

    fn formats(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("kind", [Value::Format(_, report)]) => Ok(Value::Str(report.kind().into())),
            ("bits", [Value::Format(_, report)]) => Ok(Value::Int(report.bits())),
            ("endian", [Value::Format(_, report)]) => Ok(Value::Str(report.endian().into())),
            ("arch", [Value::Format(_, report)]) => Ok(Value::Str(report.arch().into())),
            ("build_id", [Value::Format(source, report)]) => {
                Ok(Value::Str(report.build_id(source.bytes())?))
            }
            ("probe", [source]) => {
                let source = source.as_source()?;
                let report = formats::probe(source.bytes())?;
                Ok(Value::Format(source, Arc::new(report)))
            }
            ("signal", [Value::Format(_, report), name]) => {
                Ok(Value::Str(report.signal(name.as_str()?)?.into()))
            }
            ("count", [Value::Format(_, report)]) => Ok(Value::Int(
                i64::try_from(report.section_info.len())
                    .map_err(|_| "section count outside i64 range")?,
            )),
            ("import_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.imports(source.bytes())?.len())
                    .map_err(|_| "import count outside i64 range")?,
            )),
            ("delay_import_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.delay_imports(source.bytes())?.len())
                    .map_err(|_| "delay import count outside i64 range")?,
            )),
            ("export_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.exports(source.bytes())?.len())
                    .map_err(|_| "export count outside i64 range")?,
            )),
            ("certificate_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.certificates(source.bytes())?.len())
                    .map_err(|_| "certificate count outside i64 range")?,
            )),
            ("debug_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.debug_entries(source.bytes())?.len())
                    .map_err(|_| "debug count outside i64 range")?,
            )),
            (
                "debug_data" | "debug_size" | "debug_timestamp" | "debug_kind" | "debug_type"
                | "debug_pdb_path" | "debug_pdb_guid" | "debug_pdb_age",
                [Value::Format(source, report), index],
            ) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "debug index out of range")?;
                let entry = report
                    .debug_entries(source.bytes())?
                    .get(index)
                    .ok_or("debug index out of range")?;
                match name {
                    "debug_data" => {
                        if entry.size == 0 {
                            return Err("PE debug entry has no data".into());
                        }
                        Ok(Value::Source(Arc::new(Source::view(
                            source.clone(),
                            entry.offset,
                            entry.offset + entry.size,
                        )?)))
                    }
                    "debug_size" => Ok(Value::Int(entry.size as i64)),
                    "debug_timestamp" => Ok(Value::Int(i64::from(entry.timestamp))),
                    "debug_kind" => Ok(Value::Int(i64::from(entry.kind))),
                    "debug_type" => Ok(Value::Str(entry.type_name().into())),
                    "debug_pdb_path" => Ok(Value::Str(
                        entry
                            .pdb_path
                            .as_ref()
                            .ok_or("PE debug entry has no RSDS PDB data")?
                            .clone(),
                    )),
                    "debug_pdb_guid" => Ok(Value::Str(
                        entry
                            .pdb_guid
                            .as_ref()
                            .ok_or("PE debug entry has no RSDS PDB data")?
                            .clone(),
                    )),
                    _ => Ok(Value::Int(i64::from(
                        entry.pdb_age.ok_or("PE debug entry has no RSDS PDB data")?,
                    ))),
                }
            }
            (
                "certificate_data"
                | "certificate_offset"
                | "certificate_size"
                | "certificate_revision"
                | "certificate_type",
                [Value::Format(source, report), index],
            ) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "certificate index out of range")?;
                let certificate = report
                    .certificates(source.bytes())?
                    .get(index)
                    .ok_or("certificate index out of range")?;
                match name {
                    "certificate_data" => Ok(Value::Source(Arc::new(Source::view(
                        source.clone(),
                        certificate.offset,
                        certificate.offset + certificate.size,
                    )?))),
                    "certificate_offset" => Ok(Value::Int(
                        i64::try_from(certificate.offset)
                            .map_err(|_| "certificate offset outside i64 range")?,
                    )),
                    "certificate_size" => Ok(Value::Int(
                        i64::try_from(certificate.size)
                            .map_err(|_| "certificate size outside i64 range")?,
                    )),
                    "certificate_revision" => Ok(Value::Int(i64::from(certificate.revision))),
                    _ => Ok(Value::Int(i64::from(certificate.kind))),
                }
            }
            ("symbol_count" | "static_symbol_count", [Value::Format(source, report)]) => {
                let static_table = name == "static_symbol_count";
                let symbols = if static_table {
                    report.static_symbols(source.bytes())?
                } else {
                    report.dynamic_symbols(source.bytes())?
                };
                Ok(Value::Int(
                    i64::try_from(symbols.len()).map_err(|_| "symbol count outside i64 range")?,
                ))
            }
            ("relocation_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.relocations(source.bytes())?.len())
                    .map_err(|_| "relocation count outside i64 range")?,
            )),
            ("relocation_location", [Value::Format(_, report)]) => {
                Ok(Value::Str(report.relocation_location().into()))
            }
            ("needed_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.needed_libraries(source.bytes())?.len())
                    .map_err(|_| "needed library count outside i64 range")?,
            )),
            ("dependency_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.dependencies(source.bytes())?.len())
                    .map_err(|_| "dependency count outside i64 range")?,
            )),
            ("delay_dependency_count", [Value::Format(source, report)]) => Ok(Value::Int(
                i64::try_from(report.delay_dependencies(source.bytes())?.len())
                    .map_err(|_| "delay dependency count outside i64 range")?,
            )),
            ("delay_dependency_name", [Value::Format(source, report), index]) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "delay dependency index out of range")?;
                Ok(Value::Str(
                    report
                        .delay_dependencies(source.bytes())?
                        .get(index)
                        .ok_or("delay dependency index out of range")?
                        .clone(),
                ))
            }
            ("dependency_name", [Value::Format(source, report), index]) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "dependency index out of range")?;
                Ok(Value::Str(
                    report
                        .dependencies(source.bytes())?
                        .get(index)
                        .ok_or("dependency index out of range")?
                        .clone(),
                ))
            }
            ("needed_name", [Value::Format(source, report), index]) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "needed library index out of range")?;
                Ok(Value::Str(
                    report
                        .needed_libraries(source.bytes())?
                        .get(index)
                        .ok_or("needed library index out of range")?
                        .clone(),
                ))
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
                [Value::Format(source, report), index],
            ) => {
                let static_table = name.starts_with("static_");
                let property = name.strip_prefix("static_").unwrap_or(name);
                let label = if static_table { "static" } else { "dynamic" };
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| format!("{label} symbol index out of range"))?;
                let symbols = if static_table {
                    report.static_symbols(source.bytes())?
                } else {
                    report.dynamic_symbols(source.bytes())?
                };
                let symbol = symbols
                    .get(index)
                    .ok_or_else(|| format!("{label} symbol index out of range"))?;
                match property {
                    "symbol_name" => Ok(Value::Str(symbol.name.clone())),
                    "symbol_binding" => Ok(Value::Str(symbol.binding_name().into())),
                    "symbol_type" => Ok(Value::Str(symbol.type_name().into())),
                    "symbol_visibility" => Ok(Value::Str(symbol.visibility_name().into())),
                    "symbol_role" => Ok(Value::Str(symbol.role().into())),
                    "symbol_address" => Ok(Value::Str(format!("0x{:x}", symbol.address))),
                    "symbol_size" => {
                        Ok(Value::Int(i64::try_from(symbol.size).map_err(|_| {
                            format!("{label} symbol size outside i64 range")
                        })?))
                    }
                    "symbol_section" => Ok(Value::Int(i64::from(symbol.section_index))),
                    "symbol_defined" => Ok(Value::Bool(symbol.section_index != 0)),
                    _ => Ok(Value::Str(format!(
                        "{} [{} {}] @ 0x{:x}",
                        if symbol.name.is_empty() {
                            "(unnamed)"
                        } else {
                            &symbol.name
                        },
                        symbol.role(),
                        symbol.type_name(),
                        symbol.address
                    ))),
                }
            }
            (
                "relocation_rva" | "relocation_address" | "relocation_type" | "relocation_kind"
                | "relocation_summary" | "relocation_symbol" | "relocation_addend",
                [Value::Format(source, report), index],
            ) => {
                let index = usize::try_from(index.as_int()?)
                    .map_err(|_| "relocation index out of range")?;
                let relocation = report
                    .relocations(source.bytes())?
                    .get(index)
                    .ok_or("relocation index out of range")?;
                let kind = report.relocation_label(relocation);
                match name {
                    "relocation_rva" if report.name.starts_with("PE") => Ok(Value::Int(
                        i64::try_from(relocation.address)
                            .map_err(|_| "relocation RVA outside i64 range")?,
                    )),
                    "relocation_rva" => Err("relocation_rva requires a PE image".into()),
                    "relocation_address" => Ok(Value::Str(format!("0x{:x}", relocation.address))),
                    "relocation_type" if relocation.relr => {
                        Err("RELR relocation has no raw type code".into())
                    }
                    "relocation_type" => Ok(Value::Int(i64::from(relocation.kind))),
                    "relocation_kind" => Ok(Value::Str(kind.into())),
                    "relocation_symbol" if relocation.relr => {
                        Err("RELR relocation has no symbol index".into())
                    }
                    "relocation_symbol" => Ok(Value::Int(i64::from(
                        relocation.symbol.ok_or("ELF relocation expected")?,
                    ))),
                    "relocation_addend" => Ok(Value::Int(
                        relocation
                            .addend
                            .ok_or("relocation has no explicit addend")?,
                    )),
                    _ if report.name.starts_with("PE") => {
                        Ok(Value::Str(format!("{kind} @ 0x{:x}", relocation.address)))
                    }
                    _ => Ok(Value::Str(format!(
                        "{kind} @ {} 0x{:x}",
                        report.relocation_location(),
                        relocation.address
                    ))),
                }
            }
            (
                "export_name" | "export_ordinal" | "export_address" | "export_target"
                | "export_kind" | "export_summary",
                [Value::Format(source, report), index],
            ) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "export index out of range")?;
                let export = report
                    .exports(source.bytes())?
                    .get(index)
                    .ok_or("export index out of range")?;
                match name {
                    "export_ordinal" => Ok(Value::Int(
                        i64::try_from(export.ordinal)
                            .map_err(|_| "export ordinal outside i64 range")?,
                    )),
                    "export_address" if export.kind == "rva" => Ok(Value::Int(
                        i64::try_from(export.rva)
                            .map_err(|_| "export address outside i64 range")?,
                    )),
                    "export_address" => Err("forwarded export has no direct address".into()),
                    "export_name" => Ok(Value::Str(export.name.clone())),
                    "export_target" => Ok(Value::Str(export.target.clone())),
                    "export_kind" => Ok(Value::Str(export.kind.into())),
                    _ => {
                        let label = if export.named {
                            format!("{} (#{})", export.name, export.ordinal)
                        } else {
                            export.name.clone()
                        };
                        let connector = if export.kind == "forwarder" {
                            "->"
                        } else {
                            "@"
                        };
                        Ok(Value::Str(format!("{label} {connector} {}", export.target)))
                    }
                }
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
                [Value::Format(source, report), index],
            ) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "import index out of range")?;
                let delayed = name.starts_with("delay_");
                let imports = if delayed {
                    report.delay_imports(source.bytes())?
                } else {
                    report.imports(source.bytes())?
                };
                let import = imports.get(index).ok_or("import index out of range")?;
                let result = match name {
                    "import_library" | "delay_import_library" => import.library.clone(),
                    "import_symbol" | "delay_import_symbol" => import.symbol.clone(),
                    "import_kind" | "delay_import_kind" => import.kind.to_string(),
                    _ => format!("{}!{}", import.library, import.symbol),
                };
                Ok(Value::Str(result))
            }
            ("field", [Value::Format(source, report), field_name]) => {
                let field_name = field_name.as_str()?;
                let field = report
                    .field(field_name)
                    .ok_or_else(|| format!("unknown format field {field_name}"))?;
                Ok(Value::Observation(Arc::new(Observation {
                    source: source.clone(),
                    offset: field.offset,
                    width: field.width,
                    decoder: field.decoder,
                    value: field.value,
                })))
            }
            ("section", [Value::Format(source, report), index]) => {
                let index =
                    usize::try_from(index.as_int()?).map_err(|_| "section index out of range")?;
                let info = report.section(index).ok_or("section index out of range")?;
                Ok(Value::Section(source.clone(), info.clone()))
            }
            ("overlay", [Value::Format(source, report)]) => {
                let (start, end) = report.overlay_range(source.bytes().len())?;
                Ok(Value::Source(Arc::new(Source::view(
                    source.clone(),
                    start,
                    end,
                )?)))
            }
            ("rva", [Value::Format(source, report), rva, count]) => {
                let rva = u64::try_from(rva.as_int()?).map_err(|_| "RVA must not be negative")?;
                let count = usize::try_from(count.as_int()?)
                    .map_err(|_| "RVA view length must not be negative")?;
                let (start, end) = report.pe_rva_range(source.bytes().len(), rva, count)?;
                Ok(Value::Source(Arc::new(Source::rva_view(
                    source.clone(),
                    start,
                    end,
                    rva,
                )?)))
            }
            ("va", [Value::Format(source, report), va, count]) => {
                let va = u64::try_from(va.as_int()?).map_err(|_| "VA must not be negative")?;
                let count = usize::try_from(count.as_int()?)
                    .map_err(|_| "VA view length must not be negative")?;
                let (start, end) = report.elf_va_range(source.bytes().len(), va, count)?;
                Ok(Value::Source(Arc::new(Source::va_view(
                    source.clone(),
                    start,
                    end,
                    va,
                )?)))
            }
            ("entry_view", [Value::Format(source, report), count]) => {
                let count = usize::try_from(count.as_int()?)
                    .map_err(|_| "entry view length must not be negative")?;
                let address = report.entry;
                if report.name.starts_with("PE") {
                    let (start, end) = report.pe_rva_range(source.bytes().len(), address, count)?;
                    Ok(Value::Source(Arc::new(Source::rva_view(
                        source.clone(),
                        start,
                        end,
                        address,
                    )?)))
                } else {
                    let (start, end) = report.elf_va_range(source.bytes().len(), address, count)?;
                    Ok(Value::Source(Arc::new(Source::va_view(
                        source.clone(),
                        start,
                        end,
                        address,
                    )?)))
                }
            }
            ("name", [Value::Section(_, info)]) => Ok(Value::Str(
                info.name
                    .clone()
                    .ok_or("section name unavailable in captured Source")?,
            )),
            ("data", [Value::Section(source, info)]) => {
                if !info.file_backed {
                    return Err("section has no file-backed bytes".into());
                }
                let end = info
                    .file_offset
                    .checked_add(info.file_size)
                    .ok_or("section range overflow")?;
                if end > source.bytes().len() {
                    return Err("section data outside captured Source".into());
                }
                Ok(Value::Source(Arc::new(Source::view(
                    source.clone(),
                    info.file_offset,
                    end,
                )?)))
            }
            ("offset", [Value::Section(_, info)]) => Ok(Value::Int(
                i64::try_from(info.file_offset).map_err(|_| "section offset outside i64 range")?,
            )),
            ("size", [Value::Section(_, info)]) => Ok(Value::Int(
                i64::try_from(info.file_size).map_err(|_| "section size outside i64 range")?,
            )),
            ("virtual_size", [Value::Section(_, info)]) => Ok(Value::Int(
                i64::try_from(info.virtual_size)
                    .map_err(|_| "virtual section size outside i64 range")?,
            )),
            ("address", [Value::Section(_, info)]) => {
                Ok(Value::Str(format!("0x{:x}", info.virtual_address)))
            }
            ("flags", [Value::Section(_, info)]) => Ok(Value::Str(format!("0x{:x}", info.flags))),
            ("writable", [Value::Section(_, info)]) => Ok(Value::Bool(info.writable)),
            ("executable", [Value::Section(_, info)]) => Ok(Value::Bool(info.executable)),
            ("field", [_, _]) => Err("format report expected".into()),
            _ => Err(format!(
                "unknown formats function or wrong argument count: {name}"
            )),
        }
    }

    fn lab(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        if name != "mutate" {
            return Err(format!("unknown lab function {name}"));
        }
        let (source, span, mode, count) = match args {
            [source, mode, count] => {
                let source = source.as_source()?;
                let len = source.bytes().len();
                (source, (0, len), mode.as_str()?, count.as_int()?)
            }
            [source, offset, length, mode, count] => {
                let source = source.as_source()?;
                let span = checked_span(offset, length, source.bytes().len())?;
                (source, span, mode.as_str()?, count.as_int()?)
            }
            _ => return Err("lab.mutate expects 3 or 5 arguments".into()),
        };
        if source.bytes().len() > MAX_MUTATION_INPUT {
            return Err(format!(
                "lab.mutate source exceeds {MAX_MUTATION_INPUT} bytes"
            ));
        }
        let count = usize::try_from(count).map_err(|_| "mutation count must not be negative")?;
        if count > MAX_MUTATION_CASES {
            return Err(format!("mutation count exceeds {MAX_MUTATION_CASES}"));
        }
        let integer_width = match mode {
            "integer-boundary:u16le" | "integer-boundary:u16be" => Some(2),
            "integer-boundary:u32le" | "integer-boundary:u32be" => Some(4),
            "integer-boundary:u64le" | "integer-boundary:u64be" => Some(8),
            _ => None,
        };
        if !matches!(
            mode,
            "bitflip" | "byte-boundary" | "truncate" | "insert-boundary" | "delete-byte"
        ) && integer_width.is_none()
        {
            return Err(format!("unknown mutation strategy {mode}"));
        }
        if mode == "truncate" && span != (0, source.bytes().len()) {
            return Err("truncate strategy requires the whole Source".into());
        }
        if mode != "truncate" {
            let available = if let Some(width) = integer_width {
                if span.1 - span.0 < width {
                    return Err(format!(
                        "integer-boundary strategy needs at least {width} bytes in the selected span"
                    ));
                }
                let little_endian = mode.ends_with("le");
                let boundaries = integer_boundaries(width);
                let mut available = 0;
                if count > 0 {
                    'positions: for offset in span.0..=span.1 - width {
                        for boundary in boundaries {
                            if integer_boundary_bytes(boundary, width, little_endian)[..width]
                                != source.bytes()[offset..offset + width]
                            {
                                available += 1;
                                if available == count {
                                    break 'positions;
                                }
                            }
                        }
                    }
                }
                available
            } else if mode == "bitflip" {
                (span.1 - span.0) * 8
            } else if mode == "insert-boundary" {
                (span.1 - span.0 + 1) * 4
            } else if mode == "delete-byte" {
                span.1 - span.0
            } else {
                source.bytes()[span.0..span.1]
                    .iter()
                    .map(|byte| 4 - usize::from([0x00, 0x7f, 0x80, 0xff].contains(byte)))
                    .sum()
            };
            let candidate_size = match mode {
                "insert-boundary" => source.bytes().len() + 1,
                "delete-byte" => source.bytes().len().saturating_sub(1),
                _ => source.bytes().len(),
            };
            let materialized = candidate_size * count.min(available);
            if materialized > MAX_MUTATION_MATERIALIZED {
                return Err(format!(
                    "mutation corpus exceeds {MAX_MUTATION_MATERIALIZED} materialized bytes"
                ));
            }
        }
        let mut variants = Vec::with_capacity(count);
        let mut materialized = 0_usize;
        if mode == "truncate" {
            for removed in 1..=count.min(source.bytes().len()) {
                let length = source.bytes().len() - removed;
                let mut variant = Source::view(source.clone(), 0, length)?;
                variant.label = format!("{} truncate to {length}", source.label);
                variants.push(Value::Source(Arc::new(variant)));
            }
        } else if mode == "insert-boundary" {
            'positions: for offset in span.0..=span.1 {
                for boundary in [0x00, 0x7f, 0x80, 0xff] {
                    if variants.len() >= count {
                        break 'positions;
                    }
                    materialized = materialized
                        .checked_add(source.bytes().len() + 1)
                        .ok_or("mutation corpus size overflow")?;
                    if materialized > MAX_MUTATION_MATERIALIZED {
                        return Err(format!(
                            "mutation corpus exceeds {MAX_MUTATION_MATERIALIZED} materialized bytes"
                        ));
                    }
                    let mut variant = Source::splice(source.clone(), offset, offset, &[boundary])?;
                    variant.label = format!(
                        "{} insert-boundary 0x{boundary:02x} at {offset}",
                        source.label
                    );
                    variants.push(Value::Source(Arc::new(variant)));
                }
            }
        } else if mode == "delete-byte" {
            for offset in span.0..span.1 {
                if variants.len() >= count {
                    break;
                }
                materialized = materialized
                    .checked_add(source.bytes().len() - 1)
                    .ok_or("mutation corpus size overflow")?;
                if materialized > MAX_MUTATION_MATERIALIZED {
                    return Err(format!(
                        "mutation corpus exceeds {MAX_MUTATION_MATERIALIZED} materialized bytes"
                    ));
                }
                let mut variant = Source::splice(source.clone(), offset, offset + 1, &[])?;
                variant.label = format!("{} delete-byte at {offset}", source.label);
                variants.push(Value::Source(Arc::new(variant)));
            }
        } else if let Some(width) = integer_width {
            let little_endian = mode.ends_with("le");
            'positions: for offset in span.0..=span.1 - width {
                for boundary in integer_boundaries(width) {
                    if variants.len() >= count {
                        break 'positions;
                    }
                    let replacement = integer_boundary_bytes(boundary, width, little_endian);
                    if replacement[..width] == source.bytes()[offset..offset + width] {
                        continue;
                    }
                    materialized = materialized
                        .checked_add(source.bytes().len())
                        .ok_or("mutation corpus size overflow")?;
                    if materialized > MAX_MUTATION_MATERIALIZED {
                        return Err(format!(
                            "mutation corpus exceeds {MAX_MUTATION_MATERIALIZED} materialized bytes"
                        ));
                    }
                    let mut variant = Source::patch(
                        source.clone(),
                        offset,
                        offset + width,
                        &replacement[..width],
                    )?;
                    variant.label = format!(
                        "{} integer-boundary {} 0x{boundary:x} at {offset}",
                        source.label,
                        &mode["integer-boundary:".len()..]
                    );
                    variants.push(Value::Source(Arc::new(variant)));
                }
            }
        } else {
            'positions: for offset in span.0..span.1 {
                let original = source.bytes()[offset];
                let mut replacements = Vec::with_capacity(8);
                if mode == "bitflip" {
                    for bit in 0..8 {
                        replacements.push((original ^ (1 << bit), format!("bitflip bit {bit}")));
                    }
                } else {
                    for boundary in [0x00, 0x7f, 0x80, 0xff] {
                        if boundary != original {
                            replacements
                                .push((boundary, format!("byte-boundary 0x{boundary:02x}")));
                        }
                    }
                }
                for (replacement, label) in replacements {
                    if variants.len() >= count {
                        break 'positions;
                    }
                    materialized = materialized
                        .checked_add(source.bytes().len())
                        .ok_or("mutation corpus size overflow")?;
                    if materialized > MAX_MUTATION_MATERIALIZED {
                        return Err(format!(
                            "mutation corpus exceeds {MAX_MUTATION_MATERIALIZED} materialized bytes"
                        ));
                    }
                    let mut variant =
                        Source::patch(source.clone(), offset, offset + 1, &[replacement])?;
                    variant.label = format!("{} {label} at {offset}", source.label);
                    variants.push(Value::Source(Arc::new(variant)));
                }
            }
        }
        Ok(Value::List(Arc::new(variants), Some(ResultKind::Source)))
    }

    fn list_ops(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("count", [Value::List(items, _)]) => Ok(Value::Int(items.len() as i64)),
            ("append", [Value::List(items, kind), value]) => {
                let next = ResultKind::from_value(value)
                    .ok_or("list.append cannot add nested List or Result")?;
                if kind.is_some() && *kind != Some(next) {
                    return Err("list.append element type mismatch".into());
                }
                if items.len() >= MAX_LOOP_ITEMS {
                    return Err(format!("list exceeds {MAX_LOOP_ITEMS} items"));
                }
                let mut result = items.as_ref().clone();
                result.push(value.clone());
                make_list(result)
            }
            ("concat", [Value::List(left, left_kind), Value::List(right, right_kind)]) => {
                if left_kind.is_some() && right_kind.is_some() && left_kind != right_kind {
                    return Err("list.concat element type mismatch".into());
                }
                if left
                    .len()
                    .checked_add(right.len())
                    .is_none_or(|n| n > MAX_LOOP_ITEMS)
                {
                    return Err(format!("list exceeds {MAX_LOOP_ITEMS} items"));
                }
                Ok(Value::List(
                    Arc::new(left.iter().chain(right.iter()).cloned().collect()),
                    left_kind.or(*right_kind),
                ))
            }
            _ => Err(format!(
                "unknown list function or wrong argument types: {name}"
            )),
        }
    }

    fn iter(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("range", [end]) | ("range", [_, end]) => {
                let start = if args.len() == 1 {
                    0
                } else {
                    args[0].as_int()?
                };
                let end = end.as_int()?;
                let start =
                    usize::try_from(start).map_err(|_| "range start must not be negative")?;
                let end = usize::try_from(end).map_err(|_| "range end must not be negative")?;
                let count = end.saturating_sub(start);
                if count > MAX_LOOP_ITEMS {
                    return Err(format!("range exceeds {MAX_LOOP_ITEMS} items"));
                }
                Ok(Value::Offsets((start..end).collect()))
            }
            _ => Err(format!(
                "unknown iter function or wrong argument count: {name}"
            )),
        }
    }

    fn cli(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("count", []) => Ok(Value::Int(
                i64::try_from(self.script_args.len()).map_err(|_| "too many script arguments")?,
            )),
            ("arg", [index]) => {
                let index = index.as_int()?;
                let index = usize::try_from(index).map_err(|_| "argument index out of range")?;
                let arg = self
                    .script_args
                    .get(index)
                    .ok_or("argument index out of range")?;
                Ok(Value::Str(arg.clone()))
            }
            ("int", [index]) => {
                let index = index.as_int()?;
                let index = usize::try_from(index).map_err(|_| "argument index out of range")?;
                let arg = self
                    .script_args
                    .get(index)
                    .ok_or("argument index out of range")?;
                let value = arg
                    .parse::<i64>()
                    .map_err(|_| format!("argument {index} is not an i64"))?;
                Ok(Value::Int(value))
            }
            _ => Err(format!(
                "unknown cli function or wrong argument count: {name}"
            )),
        }
    }

    fn result_ops(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("ok", [value]) => {
                if ResultKind::from_value(value).is_none() {
                    return Err("result.ok supports only scalar or research values".into());
                }
                Ok(Value::Result(Arc::new(Ok(value.clone()))))
            }
            ("fail", [message]) => {
                let message = message.as_str()?;
                if message.is_empty() || message.len() > 4096 || message.contains('\0') {
                    return Err("result.fail needs a nonempty message of at most 4096 bytes".into());
                }
                Ok(Value::Result(Arc::new(Err(message.to_owned()))))
            }
            ("is_ok", [Value::Result(value)]) => Ok(Value::Bool(value.is_ok())),
            ("is_error", [Value::Result(value)]) => Ok(Value::Bool(value.is_err())),
            ("message", [Value::Result(value)]) => match value.as_ref() {
                Ok(_) => Err("result.message requires a failed Result".into()),
                Err(message) => Ok(Value::Str(message.clone())),
            },
            ("recover", [Value::Result(value), fallback]) => match value.as_ref() {
                Ok(value) => Ok(value.clone()),
                Err(_) => Ok(fallback.clone()),
            },
            ("ok" | "fail" | "is_ok" | "is_error" | "message" | "recover", _) => {
                Err("result function has invalid arguments".into())
            }
            _ => Err(format!("unknown result function {name}")),
        }
    }

    fn audit(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (name, args) {
            ("bound", [Value::Observation(observation), min, max, rule]) => {
                let min =
                    u64::try_from(min.as_int()?).map_err(|_| "minimum must not be negative")?;
                let max =
                    u64::try_from(max.as_int()?).map_err(|_| "maximum must not be negative")?;
                if max < min {
                    return Err("maximum must be at least minimum".into());
                }
                let rule = checked_rule_id(rule)?;
                Ok(Value::Finding(Arc::new(Finding {
                    rule,
                    evidence: FindingEvidence::Numeric {
                        observation: observation.clone(),
                        constraint: Constraint::Bound(min, max),
                    },
                    passed: (min..=max).contains(&observation.value),
                })))
            }
            ("expect", [Value::Observation(observation), expected, rule]) => {
                let expected = u64::try_from(expected.as_int()?)
                    .map_err(|_| "expected value must not be negative")?;
                let rule = checked_rule_id(rule)?;
                Ok(Value::Finding(Arc::new(Finding {
                    rule,
                    evidence: FindingEvidence::Numeric {
                        observation: observation.clone(),
                        constraint: Constraint::Equal(expected),
                    },
                    passed: observation.value == expected,
                })))
            }
            ("hunt", [Value::Source(source), pattern, rule]) => {
                let rule = checked_rule_id(rule)?;
                let result = search_pattern(source.bytes(), pattern, MAX_AUDIT_PATTERN)?;
                Ok(Value::Finding(Arc::new(Finding {
                    rule,
                    passed: !result.offsets.is_empty(),
                    evidence: FindingEvidence::Pattern {
                        source: source.clone(),
                        pattern_kind: result.kind,
                        pattern_width: result.width,
                        pattern_sha256: result.sha256,
                        offsets: result.offsets,
                    },
                })))
            }
            ("signal", [Value::Format(source, report), name, expected, rule]) => {
                let name = name.as_str()?;
                let expected = expected.as_str()?;
                if !matches!(expected, "present" | "absent") {
                    return Err("signal expectation must be present or absent".into());
                }
                let rule = checked_rule_id(rule)?;
                let actual = report.signal(name)?;
                Ok(Value::Finding(Arc::new(Finding {
                    rule,
                    passed: actual == expected,
                    evidence: FindingEvidence::Signal {
                        source: source.clone(),
                        name: name.to_owned(),
                        expected: expected.to_owned(),
                        actual,
                        field: report.signal_field(name),
                    },
                })))
            }
            ("passed", [Value::Finding(finding)]) => Ok(Value::Bool(finding.passed)),
            ("failed", [Value::Finding(finding)]) => Ok(Value::Bool(!finding.passed)),
            ("bound" | "expect" | "hunt" | "signal" | "passed" | "failed", _) => {
                Err("invalid audit arguments".into())
            }
            _ => Err(format!("unknown audit function {name}")),
        }
    }

    fn call_python(
        &self,
        module: &Rc<Module>,
        path: &Path,
        function: &str,
        args: &[Value],
    ) -> Result<Value, String> {
        self.check_effect(module, "python.exec")?;
        let executable = self
            .python_executable
            .as_ref()
            .ok_or("Python execution not allowed; pass --allow-python")?;
        let args: Vec<JsonValue> = args
            .iter()
            .map(encode_python_arg)
            .collect::<Result<_, String>>()?;
        let expected = self.expected_python_hash(path)?;
        let mut session = self.python_session.borrow_mut();
        if session.is_none() {
            *session = Some(python_bridge::Session::start(executable)?);
        }
        let result = session
            .as_mut()
            .unwrap()
            .call(path, function, &args, expected.as_deref());
        if session.as_ref().is_some_and(python_bridge::Session::broken) {
            session.take();
        }
        let result = result?;
        Self::python_result(result)
    }

    fn get_python(&self, module: &Rc<Module>, path: &Path, name: &str) -> Result<Value, String> {
        self.check_effect(module, "python.exec")?;
        let executable = self
            .python_executable
            .as_ref()
            .ok_or("Python execution not allowed; pass --allow-python")?;
        let expected = self.expected_python_hash(path)?;
        let mut session = self.python_session.borrow_mut();
        if session.is_none() {
            *session = Some(python_bridge::Session::start(executable)?);
        }
        let result = session
            .as_mut()
            .unwrap()
            .get(path, name, expected.as_deref());
        if session.as_ref().is_some_and(python_bridge::Session::broken) {
            session.take();
        }
        Self::python_result(result?)
    }

    fn python_result(result: JsonValue) -> Result<Value, String> {
        match result {
            JsonValue::Array(items) => {
                if items.len() > MAX_LOOP_ITEMS {
                    return Err(format!("Python list exceeds {MAX_LOOP_ITEMS} items"));
                }
                make_list(
                    items
                        .into_iter()
                        .map(decode_call_scalar)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            JsonValue::String(s) => Ok(Value::Str(s)),
            JsonValue::Bool(value) => Ok(Value::Bool(value)),
            JsonValue::Number(n) => n
                .as_i64()
                .map(Value::Int)
                .ok_or_else(|| "Python integer is outside i64 range".into()),
            JsonValue::Object(map)
                if map.len() == 2
                    && map.get("$galeikan").and_then(JsonValue::as_str) == Some("u64") =>
            {
                let value = map
                    .get("value")
                    .and_then(JsonValue::as_str)
                    .ok_or("Python u64 response has no decimal value")?;
                Ok(Value::UInt(
                    value
                        .parse::<u64>()
                        .map_err(|_| "Python u64 out of range")?,
                ))
            }
            JsonValue::Object(map)
                if map.len() == 2
                    && map.get("$galeikan").and_then(JsonValue::as_str) == Some("bytes") =>
            {
                let hex = map
                    .get("hex")
                    .and_then(JsonValue::as_str)
                    .ok_or("Python bytes response has no hex payload")?;
                if hex.len() > MAX_PYTHON_BYTES * 2 {
                    return Err(format!(
                        "Python bytes response exceeds {MAX_PYTHON_BYTES} bytes"
                    ));
                }
                Ok(Value::Bytes(Arc::new(parse_hex(hex)?)))
            }
            _ => Err("Python bridge returned an unsupported value".into()),
        }
    }
}

fn encode_python_arg(value: &Value) -> Result<JsonValue, String> {
    match value {
        Value::Int(n) => Ok(json!(n)),
        Value::UInt(n) => Ok(json!({ "$galeikan": "u64", "value": n.to_string() })),
        Value::Bool(value) => Ok(json!(value)),
        Value::Str(s) => Ok(json!(s)),
        Value::Bytes(bytes) if bytes.len() <= MAX_PYTHON_BYTES => {
            Ok(json!({ "$galeikan": "bytes", "hex": hex_bytes(bytes) }))
        }
        Value::Bytes(_) => Err(format!(
            "Python bytes argument exceeds {MAX_PYTHON_BYTES} bytes"
        )),
        Value::List(items, _) if items.len() <= MAX_LOOP_ITEMS => Ok(JsonValue::Array(
            items
                .iter()
                .map(encode_python_arg)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::List(_, _) => Err(format!("Python list exceeds {MAX_LOOP_ITEMS} items")),
        _ => Err(
            "Python bridge accepts i64, u64, bool, str, bytes, or a homogeneous list of those values"
                .into(),
        ),
    }
}

fn apply_neg(value: Value) -> Result<Value, String> {
    value
        .as_int()?
        .checked_neg()
        .map(Value::Int)
        .ok_or_else(|| "integer overflow".into())
}

fn make_list(items: Vec<Value>) -> Result<Value, String> {
    if items.len() > MAX_LOOP_ITEMS {
        return Err(format!("list exceeds {MAX_LOOP_ITEMS} items"));
    }
    let mut kind: Option<ResultKind> = None;
    for item in &items {
        let next = ResultKind::from_value(item)
            .ok_or("nested lists and Result values are not supported as list elements")?;
        if let Some(existing) = kind {
            if existing != next {
                return Err(format!(
                    "list elements must have one type, got {} and {}",
                    existing.as_type(),
                    next.as_type()
                ));
            }
        } else {
            kind = Some(next);
        }
    }
    Ok(Value::List(Arc::new(items), kind))
}

fn locate_region(
    regions: &[Arc<process::Region>],
    address: usize,
) -> Result<Arc<process::Region>, String> {
    regions
        .iter()
        .find(|region| region.contains(address))
        .cloned()
        .ok_or_else(|| "no process region contains address".into())
}

fn list_index(list: Value, index: Value) -> Result<Value, String> {
    let Value::List(items, _) = list else {
        return Err("indexing expects List".into());
    };
    let index = usize::try_from(index.as_int()?).map_err(|_| "list index out of range")?;
    items
        .get(index)
        .cloned()
        .ok_or_else(|| "list index out of range".into())
}

fn same_runtime_type(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::List(_, a), Value::List(_, b)) => a.is_none() || b.is_none() || a == b,
        _ => std::mem::discriminant(left) == std::mem::discriminant(right),
    }
}

fn specialize_list(value: Value, expected: Type) -> Value {
    match (value, expected) {
        (Value::List(items, None), Type::List(Some(kind))) => Value::List(items, Some(kind)),
        (value, _) => value,
    }
}

fn apply_try(value: Value) -> Result<Value, String> {
    match value {
        Value::Result(result) => match result.as_ref() {
            Ok(value) => Ok(value.clone()),
            Err(error) => Err(error.clone()),
        },
        _ => Err("? expects Result<T>".into()),
    }
}

fn apply_binary(left: Value, op: Op, right: Value) -> Result<Value, String> {
    match op {
        Op::And | Op::Or => Err("logical operators require short-circuit evaluation".into()),
        Op::Add | Op::Sub | Op::Mul | Op::Div => match (left, right) {
            (Value::Str(a), Value::Str(b)) if matches!(op, Op::Add) => {
                let length = a
                    .len()
                    .checked_add(b.len())
                    .ok_or("string length overflow")?;
                if length > MAX_STRING_BYTES {
                    return Err("string memory exceeds 64 MiB".into());
                }
                let mut joined = String::new();
                joined
                    .try_reserve_exact(length)
                    .map_err(|_| "string allocation failed")?;
                joined.push_str(&a);
                joined.push_str(&b);
                Ok(Value::Str(joined))
            }
            (Value::Int(a), Value::Int(b)) => {
                let result = match op {
                    Op::Add => a.checked_add(b),
                    Op::Sub => a.checked_sub(b),
                    Op::Mul => a.checked_mul(b),
                    Op::Div => a.checked_div(b),
                    _ => unreachable!(),
                };
                result.map(Value::Int).ok_or_else(|| {
                    if matches!(op, Op::Div) && b == 0 {
                        "division by zero".into()
                    } else {
                        "integer overflow".into()
                    }
                })
            }
            (Value::UInt(a), Value::UInt(b)) => {
                let result = match op {
                    Op::Add => a.checked_add(b),
                    Op::Sub => a.checked_sub(b),
                    Op::Mul => a.checked_mul(b),
                    Op::Div => a.checked_div(b),
                    _ => unreachable!(),
                };
                result.map(Value::UInt).ok_or_else(|| {
                    if matches!(op, Op::Div) && b == 0 {
                        "division by zero".into()
                    } else {
                        "integer overflow".into()
                    }
                })
            }
            _ => Err("numeric operands must both be i64 or u64".into()),
        },
        Op::BitAnd | Op::BitOr | Op::BitXor => match (left, right) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(match op {
                Op::BitAnd => a & b,
                Op::BitOr => a | b,
                Op::BitXor => a ^ b,
                _ => unreachable!(),
            })),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::UInt(match op {
                Op::BitAnd => a & b,
                Op::BitOr => a | b,
                Op::BitXor => a ^ b,
                _ => unreachable!(),
            })),
            _ => Err("numeric operands must both be i64 or u64".into()),
        },
        Op::Shl | Op::Shr | Op::Ushr => match (left, right) {
            (Value::Int(a), Value::Int(b)) if (0..=63).contains(&b) => Ok(Value::Int(match op {
                Op::Shl => a.wrapping_shl(b as u32),
                Op::Shr => a >> b,
                Op::Ushr => ((a as u64) >> b) as i64,
                _ => unreachable!(),
            })),
            (Value::UInt(a), Value::UInt(b)) if b <= 63 => Ok(Value::UInt(match op {
                Op::Shl => a.wrapping_shl(b as u32),
                Op::Shr | Op::Ushr => a >> b,
                _ => unreachable!(),
            })),
            (Value::Int(_), Value::Int(_)) | (Value::UInt(_), Value::UInt(_)) => {
                Err("shift count must be in 0..63".into())
            }
            _ => Err("numeric operands must both be i64 or u64".into()),
        },
        Op::Eq | Op::Ne => {
            let equal = match (&left, &right) {
                (Value::Int(a), Value::Int(b)) => a == b,
                (Value::UInt(a), Value::UInt(b)) => a == b,
                (Value::Bool(a), Value::Bool(b)) => a == b,
                (Value::Str(a), Value::Str(b)) => a == b,
                _ => return Err("equality needs two values of the same scalar type".into()),
            };
            Ok(Value::Bool(if matches!(op, Op::Eq) {
                equal
            } else {
                !equal
            }))
        }
        Op::Lt | Op::Le | Op::Gt | Op::Ge => match (left, right) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(match op {
                Op::Lt => a < b,
                Op::Le => a <= b,
                Op::Gt => a > b,
                Op::Ge => a >= b,
                _ => unreachable!(),
            })),
            (Value::UInt(a), Value::UInt(b)) => Ok(Value::Bool(match op {
                Op::Lt => a < b,
                Op::Le => a <= b,
                Op::Gt => a > b,
                Op::Ge => a >= b,
                _ => unreachable!(),
            })),
            _ => Err("numeric operands must both be i64 or u64".into()),
        },
    }
}

fn checked_rule_id(value: &Value) -> Result<String, String> {
    let rule = value.as_str()?;
    if rule.is_empty()
        || rule.len() > 128
        || !rule
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err("rule id must be 1 to 128 ASCII letters, digits, '.', '_', ':', or '-'".into());
    }
    Ok(rule.to_string())
}

fn require_type(expected: Type, actual: Type) -> Result<(), String> {
    if expected.compatible(actual) {
        Ok(())
    } else {
        Err(format!("expected {expected}, got {actual}"))
    }
}

fn check_arguments(name: &str, args: &[Type], expected: &[Type]) -> Result<(), String> {
    if args.len() != expected.len() {
        return Err(format!("{name} expects {} arguments", expected.len()));
    }
    for (index, (&actual, &kind)) in args.iter().zip(expected).enumerate() {
        require_type(kind, actual).map_err(|e| format!("{name} argument {}: {e}", index + 1))?;
    }
    Ok(())
}

fn is_value_method_receiver(module: &Module, receiver: &str) -> bool {
    let first = receiver.split('.').next().unwrap_or(receiver);
    match module.imports.get(first) {
        None => true,
        Some(Import::Local(child)) => receiver.split_once('.').is_some_and(|(_, path)| {
            let base = path.split('.').next().unwrap_or(path);
            child.lets.iter().any(|binding| binding.name == base)
        }),
        _ => false,
    }
}

fn check_function_call(module: &Module, name: &str, args: &[Type]) -> Result<Type, String> {
    if let Some(record) = module.records.get(name) {
        check_arguments(
            name,
            args,
            &record
                .fields
                .iter()
                .map(|(_, kind)| *kind)
                .collect::<Vec<_>>(),
        )?;
        return Ok(Type::Record(record.id));
    }
    let function = module
        .functions
        .get(name)
        .ok_or_else(|| format!("unknown function {name}"))?;
    if args.len() != function.params.len() {
        return Err(format!(
            "{name} expects {} arguments",
            function.params.len()
        ));
    }
    for (actual, (param, kind)) in args.iter().zip(&function.params) {
        require_type(*kind, *actual).map_err(|e| format!("{name} parameter {param}: {e}"))?;
    }
    Ok(function.result_type.unwrap_or(Type::Any))
}

fn record_field_value(mut value: Value, fields: &str) -> Result<Value, String> {
    if fields.is_empty() {
        return Ok(value);
    }
    for field in fields.split('.') {
        let Value::Record(record) = value else {
            return Err(format!("field {field} needs a struct value"));
        };
        value = record
            .fields
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| format!("unknown struct field {field}"))?;
    }
    Ok(value)
}

fn standard_call(module: &str, name: &str, args: &[Type]) -> Result<Type, String> {
    use Type::{
        Bool, Bytes, Diff, Disassembly, Finding, Format, Instruction, Int, Observation, Offsets,
        Region, Regions, Source, Str, UInt,
    };
    let qualified = format!("{module}.{name}");
    if module == "bytes" && name == "pack" {
        match args {
            [Int | UInt | Type::Any, Str | Type::Any] => return Ok(Bytes),
            [value, encoding] => {
                if !matches!(value, Int | UInt | Type::Any) {
                    return Err(format!("{qualified} expects i64 or u64 value, got {value}"));
                }
                return Err(format!("{qualified} expects str encoding, got {encoding}"));
            }
            _ => return Err(format!("{qualified} expects 2 arguments")),
        }
    }
    if module == "binary" && name == "hexdump" {
        let expected: &[Type] = match args.len() {
            1 => &[Source],
            3 => &[Source, Int, Int],
            _ => return Err(format!("{qualified} expects 1 or 3 arguments")),
        };
        check_arguments(&qualified, args, expected)?;
        return Ok(Str);
    }
    if module == "lab" {
        if name != "mutate" {
            return Err(format!("unknown standard function {qualified}"));
        }
        match args {
            [source, strategy, count] => {
                require_type(Source, *source)?;
                require_type(Str, *strategy)?;
                require_type(Int, *count)?;
            }
            [source, offset, length, strategy, count] => {
                require_type(Source, *source)?;
                require_type(Int, *offset)?;
                require_type(Int, *length)?;
                require_type(Str, *strategy)?;
                require_type(Int, *count)?;
            }
            _ => return Err(format!("{qualified} expects 3 or 5 arguments")),
        }
        return Ok(Type::List(Some(ResultKind::Source)));
    }
    if module == "list" {
        return match (name, args) {
            ("count", [Type::List(_) | Type::Any]) => Ok(Int),
            ("append", [Type::List(kind), value]) => {
                if let Some(kind) = kind {
                    require_type(kind.as_type(), *value)?;
                    Ok(Type::List(Some(*kind)))
                } else if *value == Type::Any {
                    Ok(Type::List(None))
                } else {
                    ResultKind::from_type(*value)
                        .map(|kind| Type::List(Some(kind)))
                        .ok_or_else(|| format!("{qualified} cannot append {value}"))
                }
            }
            ("concat", [Type::List(a), Type::List(b)]) => {
                if a.is_some() && b.is_some() && a != b {
                    Err(format!("{qualified} list element types differ"))
                } else {
                    Ok(Type::List(a.or(*b)))
                }
            }
            ("append", [Type::Any, _])
            | ("concat", [Type::Any, _])
            | ("concat", [_, Type::Any]) => Ok(Type::Any),
            ("count" | "append" | "concat", _) => Err(format!("{qualified} has invalid arguments")),
            _ => Err(format!("unknown standard function {qualified}")),
        };
    }
    if module == "iter" {
        if name != "range" || !(args.len() == 1 || args.len() == 2) {
            return Err(format!("{qualified} expects 1 or 2 arguments"));
        }
        for actual in args {
            require_type(Int, *actual)?;
        }
        return Ok(Offsets);
    }
    if module == "result" {
        return match name {
            "ok" => {
                check_arguments(&qualified, args, &[Type::Any])?;
                match ResultKind::from_type(args[0]) {
                    Some(kind) => Ok(Type::Result(Some(kind))),
                    None if args[0] == Type::Any => Ok(Type::Result(None)),
                    None => Err(format!("{qualified} cannot wrap {}", args[0])),
                }
            }
            "fail" => {
                check_arguments(&qualified, args, &[Str])?;
                Ok(Type::Result(None))
            }
            "is_ok" | "is_error" | "message" => {
                if args.len() != 1 {
                    return Err(format!("{qualified} expects 1 argument"));
                }
                if !matches!(args[0], Type::Result(_) | Type::Any) {
                    return Err(format!("{qualified} expects Result<T>"));
                }
                Ok(if name == "message" { Str } else { Type::Bool })
            }
            "recover" => {
                if args.len() != 2 {
                    return Err(format!("{qualified} expects 2 arguments"));
                }
                match args[0] {
                    Type::Result(Some(kind)) => {
                        require_type(kind.as_type(), args[1])?;
                        Ok(kind.as_type())
                    }
                    Type::Result(None) => Ok(args[1]),
                    Type::Any => Ok(Type::Any),
                    _ => Err(format!("{qualified} expects Result<T>")),
                }
            }
            _ => Err(format!("unknown standard function {qualified}")),
        };
    }
    if module == "asm" {
        if matches!(name, "linear" | "reachable_entry") {
            check_arguments(&qualified, args, &[Format, Int])?;
            return Ok(Disassembly);
        }
        if name == "entry" {
            check_arguments(&qualified, args, &[Format])?;
            return Ok(Instruction);
        }
        if name == "decode" {
            let expected: &[Type] = match args.len() {
                3 => &[Source, Int, Int],
                4 => &[Source, Int, Int, Int],
                _ => return Err(format!("{qualified} expects 3 or 4 arguments")),
            };
            check_arguments(&qualified, args, expected)?;
            return Ok(Instruction);
        }
        if name == "decode_u64" {
            check_arguments(&qualified, args, &[Source, Int, UInt, Int])?;
            return Ok(Instruction);
        }
        if name == "reachable" {
            check_arguments(&qualified, args, &[Source, Int, UInt, Int, Int])?;
            return Ok(Disassembly);
        }
        if name == "count" {
            check_arguments(&qualified, args, &[Disassembly])?;
            return Ok(Int);
        }
        if name == "call_targets" || name == "overlap_count" {
            check_arguments(&qualified, args, &[Disassembly])?;
            return Ok(if name == "call_targets" {
                Type::List(Some(ResultKind::UInt))
            } else {
                Int
            });
        }
        if name == "xrefs" {
            check_arguments(&qualified, args, &[Disassembly, UInt])?;
            return Ok(Type::List(Some(ResultKind::UInt)));
        }
        if name == "overlap_at" {
            check_arguments(&qualified, args, &[Disassembly, Int])?;
            return Ok(Bool);
        }
        if name == "at" {
            check_arguments(&qualified, args, &[Disassembly, Int])?;
            return Ok(Instruction);
        }
        if name == "block_count" {
            check_arguments(&qualified, args, &[Disassembly])?;
            return Ok(Int);
        }
        if name == "block_instruction" {
            check_arguments(&qualified, args, &[Disassembly, Int, Int])?;
            return Ok(Instruction);
        }
        if matches!(
            name,
            "block_start"
                | "block_end"
                | "block_instruction_count"
                | "block_successors"
                | "block_unresolved"
        ) {
            check_arguments(&qualified, args, &[Disassembly, Int])?;
            return Ok(match name {
                "block_start" | "block_end" => UInt,
                "block_instruction_count" => Int,
                "block_successors" => Type::List(Some(ResultKind::UInt)),
                "block_unresolved" => Bool,
                _ => unreachable!(),
            });
        }
        if name == "successors" {
            check_arguments(&qualified, args, &[Instruction])?;
            return Ok(Type::List(Some(ResultKind::UInt)));
        }
        let result = match name {
            "text" | "mnemonic" | "flow" | "address" | "target" => Str,
            "address_u64" | "target_u64" => UInt,
            "size" | "offset" | "next" => Int,
            "source" => Source,
            "bytes" => Bytes,
            _ => return Err(format!("unknown standard function {qualified}")),
        };
        check_arguments(&qualified, args, &[Instruction])?;
        return Ok(result);
    }
    let (expected, result): (&[Type], Type) = match (module, name) {
        ("bytes", "from_hex") => (&[Str], Bytes),
        ("bytes", "pack") => (&[Type::Any, Str], Bytes),
        ("bytes", "to_hex") => (&[Bytes], Str),
        ("bytes", "concat" | "xor") => (&[Bytes, Bytes], Bytes),
        ("bytes", "repeat") => (&[Bytes, Int], Bytes),
        ("bytes", "at") => (&[Bytes, Int], Int),
        ("text", "length" | "byte_length") => (&[Str], Int),
        ("text", "find") => (&[Str, Str], Int),
        ("text", "contains" | "starts_with" | "ends_with") => (&[Str, Str], Bool),
        ("text", "slice") => (&[Str, Int, Int], Str),
        ("binary", "analyze") => (&[Str, Int], Source),
        ("binary", "from_hex") => (&[Str], Bytes),
        ("binary", "snapshot") => (&[Bytes], Source),
        ("binary", "deep") => (&[Source, Int, Str], Observation),
        ("binary", "entropy") => (&[Source], Observation),
        ("binary", "view") => (&[Source, Int, Int], Source),
        ("binary", "extract") => (&[Type::Any, Int, Int], Bytes),
        ("binary", "patch") => (&[Source, Int, Bytes], Source),
        ("binary", "splice") => (&[Source, Int, Int, Bytes], Source),
        ("binary", "value" | "offset" | "width") => (&[Observation], Int),
        ("binary", "value_u64") => (&[Observation], UInt),
        ("binary", "signed_value") => (&[Observation], Int),
        ("binary", "diff") => (&[Source, Source, Int], Diff),
        ("binary", "diff_offsets") => (&[Diff], Offsets),
        ("binary", "diff_count") => (&[Diff], Int),
        ("binary", "hunt") => (&[Source, Type::Any], Offsets),
        ("binary", "strings") => (&[Source, Int, Str], Offsets),
        ("binary", "read_text") => (&[Source, Int, Int, Str], Str),
        ("binary", "size") => (&[Type::Any], Int),
        ("binary", "sha256") => (&[Type::Any], Str),
        ("formats", "probe") => (&[Source], Format),
        ("formats", "kind" | "endian" | "arch" | "build_id") => (&[Format], Str),
        ("formats", "bits") => (&[Format], Int),
        ("formats", "signal") => (&[Format, Str], Str),
        ("formats", "count") => (&[Format], Int),
        ("formats", "import_count" | "delay_import_count") => (&[Format], Int),
        ("formats", "export_count") => (&[Format], Int),
        ("formats", "certificate_count") => (&[Format], Int),
        ("formats", "debug_count") => (&[Format], Int),
        ("formats", "symbol_count" | "static_symbol_count") => (&[Format], Int),
        ("formats", "relocation_count") => (&[Format], Int),
        ("formats", "relocation_location") => (&[Format], Str),
        ("formats", "needed_count") => (&[Format], Int),
        ("formats", "dependency_count" | "delay_dependency_count") => (&[Format], Int),
        ("formats", "needed_name") => (&[Format, Int], Str),
        (
            "formats",
            "symbol_size" | "symbol_section" | "static_symbol_size" | "static_symbol_section",
        ) => (&[Format, Int], Int),
        ("formats", "symbol_defined" | "static_symbol_defined") => (&[Format, Int], Bool),
        (
            "formats",
            "symbol_name"
            | "symbol_binding"
            | "symbol_type"
            | "symbol_visibility"
            | "symbol_role"
            | "symbol_address"
            | "symbol_summary"
            | "static_symbol_name"
            | "static_symbol_binding"
            | "static_symbol_type"
            | "static_symbol_visibility"
            | "static_symbol_role"
            | "static_symbol_address"
            | "static_symbol_summary",
        ) => (&[Format, Int], Str),
        ("formats", "dependency_name" | "delay_dependency_name") => (&[Format, Int], Str),
        ("formats", "export_ordinal" | "export_address") => (&[Format, Int], Int),
        (
            "formats",
            "certificate_offset" | "certificate_size" | "certificate_revision" | "certificate_type",
        ) => (&[Format, Int], Int),
        ("formats", "certificate_data") => (&[Format, Int], Source),
        ("formats", "debug_size" | "debug_timestamp" | "debug_kind" | "debug_pdb_age") => {
            (&[Format, Int], Int)
        }
        ("formats", "debug_type" | "debug_pdb_path" | "debug_pdb_guid") => (&[Format, Int], Str),
        ("formats", "debug_data") => (&[Format, Int], Source),
        (
            "formats",
            "relocation_rva" | "relocation_type" | "relocation_symbol" | "relocation_addend",
        ) => (&[Format, Int], Int),
        ("formats", "relocation_address" | "relocation_kind" | "relocation_summary") => {
            (&[Format, Int], Str)
        }
        ("formats", "export_name" | "export_target" | "export_kind" | "export_summary") => {
            (&[Format, Int], Str)
        }
        (
            "formats",
            "import_library"
            | "import_symbol"
            | "import_kind"
            | "import_summary"
            | "delay_import_library"
            | "delay_import_symbol"
            | "delay_import_kind"
            | "delay_import_summary",
        ) => (&[Format, Int], Str),
        ("formats", "field") => (&[Format, Str], Observation),
        ("formats", "section") => (&[Format, Int], Type::Section),
        ("formats", "overlay") => (&[Format], Source),
        ("formats", "rva" | "va") => (&[Format, Int, Int], Source),
        ("formats", "entry_view") => (&[Format, Int], Source),
        ("formats", "name" | "address" | "flags") => (&[Type::Section], Str),
        ("formats", "writable" | "executable") => (&[Type::Section], Bool),
        ("formats", "data") => (&[Type::Section], Source),
        ("formats", "offset" | "size" | "virtual_size") => (&[Type::Section], Int),
        ("audit", "bound") => (&[Observation, Int, Int, Str], Finding),
        ("audit", "expect") => (&[Observation, Int, Str], Finding),
        ("audit", "hunt") => (&[Source, Type::Any, Str], Finding),
        ("audit", "signal") => (&[Format, Str, Str, Str], Finding),
        ("audit", "passed" | "failed") => (&[Finding], Type::Bool),
        ("cli", "count") => (&[], Int),
        ("cli", "arg") => (&[Int], Str),
        ("cli", "int") => (&[Int], Int),
        ("net", "exchange" | "datagram") => (&[Str, Int, Type::Any, Int, Int], Source),
        ("net", "fetch") => (&[Str, Int, Int], Source),
        ("net", "request") => (
            &[
                Str,
                Str,
                Type::List(Some(ResultKind::Str)),
                Type::Any,
                Int,
                Int,
            ],
            Type::HttpResponse,
        ),
        ("net", "status") => (&[Type::HttpResponse], Int),
        ("net", "body") => (&[Type::HttpResponse], Source),
        ("net", "headers") => (
            &[Type::HttpResponse, Str],
            Type::List(Some(ResultKind::Str)),
        ),
        ("process", "snapshot") => (&[Int, Int, Int], Source),
        ("process", "self_pid") => (&[], Int),
        ("process", "snapshot_u64") => (&[Int, UInt, Int], Source),
        ("process", "regions" | "images") => (&[Int], Regions),
        ("process", "modules") => (&[Int], Type::List(Some(ResultKind::Str))),
        ("process", "thread_ids" | "children") => (&[Int], Type::List(Some(ResultKind::Int))),
        ("process", "executable") => (&[Int], Str),
        ("process", "parent_pid") => (&[Int], Int),
        ("process", "count") => (&[Regions], Int),
        ("process", "at") => (&[Regions, Int], Region),
        ("process", "locate") => (&[Regions, Int], Region),
        ("process", "locate_u64") => (&[Regions, UInt], Region),
        ("process", "pid" | "start" | "size" | "end") => (&[Region], Int),
        ("process", "start_u64" | "end_u64") => (&[Region], UInt),
        ("process", "offset" | "address") => (&[Region, Int], Int),
        ("process", "offset_u64") => (&[Region, UInt], Int),
        ("process", "address_u64") => (&[Region, Int], UInt),
        ("process", "reference") => (&[Region, UInt], Str),
        ("process", "resolve") => (&[Region, Str], UInt),
        ("process", "access" | "label") => (&[Region], Str),
        ("process", "image_backed") => (&[Region], Type::Bool),
        ("process", "snapshot_region") => (&[Region, Int, Int], Source),
        ("process", "snapshot_ref") => (&[Region, Str, Int], Source),
        ("process", "snapshot_at") => (&[Regions, Int, Int], Source),
        ("process", "snapshot_at_u64") => (&[Regions, UInt, Int], Source),
        _ => return Err(format!("unknown standard function {qualified}")),
    };
    check_arguments(&qualified, args, expected)?;
    match (module, name) {
        ("binary" | "audit", "hunt") | ("net", "exchange" | "datagram" | "request") => {
            let index = if module == "net" { 2 } else { 1 };
            let index = if name == "request" { 3 } else { index };
            if !matches!(args[index], Str | Bytes | Type::Any) {
                return Err(format!(
                    "{qualified} argument {} expects str or bytes",
                    index + 1
                ));
            }
        }
        ("binary", "size" | "sha256" | "extract")
            if !matches!(args[0], Source | Bytes | Type::Any) =>
        {
            return Err(format!("{qualified} expects Source or bytes"));
        }
        _ => {}
    }
    Ok(result)
}

fn integer_boundaries(width: usize) -> [u64; 5] {
    let sign_boundary = 1_u64 << (width * 8 - 1);
    let maximum = if width == 8 {
        u64::MAX
    } else {
        (1_u64 << (width * 8)) - 1
    };
    [0, 1, sign_boundary - 1, sign_boundary, maximum]
}

fn integer_boundary_bytes(value: u64, width: usize, little_endian: bool) -> [u8; 8] {
    let mut bytes = [0; 8];
    if little_endian {
        bytes[..width].copy_from_slice(&value.to_le_bytes()[..width]);
    } else {
        bytes[..width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
    }
    bytes
}

fn checked_span(offset: &Value, length: &Value, total: usize) -> Result<(usize, usize), String> {
    let offset = usize::try_from(offset.as_int()?).map_err(|_| "offset must not be negative")?;
    let length = usize::try_from(length.as_int()?).map_err(|_| "length must not be negative")?;
    let end = offset.checked_add(length).ok_or("range overflow")?;
    if end > total {
        return Err("out of bounds".into());
    }
    Ok((offset, end))
}

// Fixed-point logarithms avoid platform-dependent floating-point rounding in reports.
fn log2_q32(value: u64) -> u64 {
    debug_assert!(value > 0);
    let integer = 63 - value.leading_zeros();
    let mut normalized = u128::from(value) << (63 - integer);
    let mut fractional = 0_u64;
    for bit in (0_u32..32).rev() {
        normalized = (normalized * normalized) >> 63;
        if normalized >= (1_u128 << 64) {
            normalized >>= 1;
            fractional |= 1_u64 << bit;
        }
    }
    (u64::from(integer) << 32) | fractional
}

fn shannon_entropy_milli(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as u64;
    let log_total = log2_q32(total);
    let weighted = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| u128::from(*count) * u128::from(log_total - log2_q32(*count)))
        .sum::<u128>();
    let denominator = u128::from(total) << 32;
    ((weighted * 1000 + denominator / 2) / denominator) as u64
}

fn diff_offsets(left: &[u8], right: &[u8], limit: usize) -> Result<Vec<usize>, String> {
    let mut offsets = Vec::new();
    let common = left.len().min(right.len());
    for i in 0..common {
        if left[i] != right[i] {
            if offsets.len() == limit {
                return Err("LimitExceeded: too many differences".into());
            }
            offsets.push(i);
        }
    }
    for i in common..left.len().max(right.len()) {
        if offsets.len() == limit {
            return Err("LimitExceeded: too many differences".into());
        }
        offsets.push(i);
    }
    Ok(offsets)
}

#[derive(Clone, Copy)]
enum TextEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

impl TextEncoding {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "ascii" => Ok(Self::Ascii),
            "utf16le" => Ok(Self::Utf16Le),
            "utf16be" => Ok(Self::Utf16Be),
            _ => Err("text encoding must be ascii, utf16le, or utf16be".into()),
        }
    }

    fn width(self) -> usize {
        match self {
            Self::Ascii => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
        }
    }

    fn printable(self, bytes: &[u8], offset: usize) -> Option<u8> {
        let first = *bytes.get(offset)?;
        let character = match self {
            Self::Ascii => first,
            Self::Utf16Le if bytes.get(offset + 1) == Some(&0) => first,
            Self::Utf16Be if first == 0 => *bytes.get(offset + 1)?,
            _ => return None,
        };
        (0x20..=0x7e).contains(&character).then_some(character)
    }
}

fn find_strings(
    bytes: &[u8],
    minimum: usize,
    encoding: TextEncoding,
) -> Result<Vec<usize>, String> {
    let mut hits = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if encoding.printable(bytes, offset).is_none() {
            offset += 1;
            continue;
        }
        let start = offset;
        let mut count = 0;
        while encoding.printable(bytes, offset).is_some() {
            count += 1;
            offset += encoding.width();
        }
        if count >= minimum {
            hits.push(start);
            if hits.len() > MAX_HITS {
                return Err("too many strings".into());
            }
        }
    }
    Ok(hits)
}

fn read_text(
    bytes: &[u8],
    offset: usize,
    max_chars: usize,
    encoding: TextEncoding,
) -> Result<String, String> {
    if offset >= bytes.len() {
        return Err("text offset out of bounds".into());
    }
    let mut text = String::new();
    let mut cursor = offset;
    while let Some(byte) = encoding.printable(bytes, cursor) {
        if text.len() == max_chars {
            return Err(format!(
                "LimitExceeded: text exceeds {max_chars} characters"
            ));
        }
        text.push(char::from(byte));
        cursor += encoding.width();
    }
    if text.is_empty() {
        return Err("no printable text at offset".into());
    }
    Ok(text)
}

struct SearchResult {
    offsets: Vec<usize>,
    width: usize,
    kind: &'static str,
    sha256: String,
}

fn search_pattern(
    haystack: &[u8],
    pattern: &Value,
    max_width: usize,
) -> Result<SearchResult, String> {
    let (needle, masks, kind): (Cow<'_, [u8]>, Option<Vec<u8>>, &'static str) = match pattern {
        Value::Bytes(bytes) => (Cow::Borrowed(bytes), None, "bytes"),
        Value::Str(text) if text.starts_with("hex:") => {
            let (needle, masks) = parse_hunt_hex(&text[4..])?;
            (Cow::Owned(needle), Some(masks), "hex")
        }
        Value::Str(text) => (Cow::Borrowed(text.as_bytes()), None, "text"),
        _ => return Err("string or bytes expected".into()),
    };
    if needle.is_empty() {
        return Err("empty search pattern".into());
    }
    if needle.len() > max_width {
        return Err(format!("search pattern exceeds {max_width} bytes"));
    }
    let offsets = match &masks {
        Some(masks) if masks.iter().any(|mask| *mask != 0xff) => {
            find_masked(haystack, &needle, masks)?
        }
        _ => find_all(haystack, &needle)?,
    };
    let mut digest = Sha256::new();
    digest.update(b"galeikan.search.v1\0");
    digest.update(kind.as_bytes());
    digest.update((needle.len() as u64).to_le_bytes());
    digest.update(&needle);
    if let Some(masks) = &masks {
        digest.update(masks);
    }
    Ok(SearchResult {
        offsets,
        width: needle.len(),
        kind,
        sha256: hex_bytes(&digest.finalize()),
    })
}

fn parse_hunt_hex(text: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut bytes = Vec::new();
    let mut masks = Vec::new();
    let mut high = None;
    for ch in text.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let nibble = if ch == '?' {
            (0_u8, 0_u8)
        } else {
            (
                ch.to_digit(16)
                    .filter(|_| ch.is_ascii())
                    .ok_or("invalid hex pattern")? as u8,
                0x0f,
            )
        };
        if let Some((first, first_mask)) = high.take() {
            if bytes.len() >= MAX_NET_REQUEST {
                return Err(format!("hex pattern exceeds {MAX_NET_REQUEST} bytes"));
            }
            bytes.push((first << 4) | nibble.0);
            masks.push((first_mask << 4) | nibble.1);
        } else {
            high = Some(nibble);
        }
    }
    if high.is_some() {
        return Err("hex pattern needs an even number of nibbles".into());
    }
    if masks.iter().any(|mask| *mask != 0xff) && bytes.len() > 64 {
        return Err("masked hex pattern exceeds 64 bytes".into());
    }
    Ok((bytes, masks))
}

// Shift-And matches up to 64 bytes in one state word, including overlaps and nibble wildcards.
fn find_masked(haystack: &[u8], needle: &[u8], masks: &[u8]) -> Result<Vec<usize>, String> {
    debug_assert!(!needle.is_empty() && needle.len() <= 64 && needle.len() == masks.len());
    let mut accept = [0_u64; 256];
    for (position, (&value, &mask)) in needle.iter().zip(masks).enumerate() {
        let bit = 1_u64 << position;
        for (byte, entry) in accept.iter_mut().enumerate() {
            if (byte as u8 & mask) == value {
                *entry |= bit;
            }
        }
    }
    let final_bit = 1_u64 << (needle.len() - 1);
    let mut state = 0_u64;
    let mut hits = Vec::new();
    for (position, byte) in haystack.iter().enumerate() {
        state = ((state << 1) | 1) & accept[*byte as usize];
        if state & final_bit != 0 {
            hits.push(position + 1 - needle.len());
            if hits.len() > MAX_HITS {
                return Err("too many matches".into());
            }
        }
    }
    Ok(hits)
}

// KMP keeps the search linear and reports overlapping matches as well.
fn find_all(haystack: &[u8], needle: &[u8]) -> Result<Vec<usize>, String> {
    debug_assert!(!needle.is_empty());
    let mut prefix = vec![0; needle.len()];
    for i in 1..needle.len() {
        let mut j = prefix[i - 1];
        while j > 0 && needle[i] != needle[j] {
            j = prefix[j - 1];
        }
        if needle[i] == needle[j] {
            j += 1;
        }
        prefix[i] = j;
    }
    let mut hits = Vec::new();
    let mut j = 0;
    for (i, byte) in haystack.iter().enumerate() {
        while j > 0 && *byte != needle[j] {
            j = prefix[j - 1];
        }
        if *byte == needle[j] {
            j += 1;
        }
        if j == needle.len() {
            hits.push(i + 1 - needle.len());
            if hits.len() > MAX_HITS {
                return Err("too many matches".into());
            }
            j = prefix[j - 1];
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod binary_tests {
    use super::{
        find_masked, find_strings, parse_hunt_hex, shannon_entropy_milli, Source, TextEncoding,
    };
    use std::sync::Arc;

    #[test]
    fn mapped_views_keep_structured_address_provenance() {
        let root = Arc::new(Source::new(
            "fixture".into(),
            "fixture".into(),
            vec![1, 2, 3],
        ));
        let rva = Source::rva_view(root.clone(), 1, 3, 0x1000).unwrap();
        let va = Source::va_view(root, 0, 2, 0x400000).unwrap();
        assert_eq!(rva.lineage()[1]["address"]["space"], "pe.rva");
        assert_eq!(rva.lineage()[1]["address"]["value"], "0x1000");
        assert_eq!(va.lineage()[1]["address"]["space"], "elf.va");
        assert_eq!(va.lineage()[1]["address"]["value"], "0x400000");
        assert!(rva.provenance().starts_with("PE RVA 0x1000;"));
    }

    #[test]
    fn full_word_pattern_keeps_overlaps_and_match_limit() {
        let (needle, masks) = parse_hunt_hex(&format!("{}a?", "??".repeat(63))).unwrap();
        let mut data = vec![0; 65];
        data[63] = 0xa7;
        data[64] = 0xa8;
        assert_eq!(find_masked(&data, &needle, &masks).unwrap(), vec![0, 1]);

        let (needle, masks) = parse_hunt_hex("??").unwrap();
        assert_eq!(
            find_masked(&vec![0; 10_001], &needle, &masks),
            Err("too many matches".into())
        );
    }

    #[test]
    fn text_scan_rejects_excessive_matches_and_truncated_wide_units() {
        let bytes = [b'A', 0].repeat(10_001);
        assert_eq!(
            find_strings(&bytes, 1, TextEncoding::Ascii),
            Err("too many strings".into())
        );
        assert_eq!(
            find_strings(&[b'X', 0, b'Y'], 2, TextEncoding::Utf16Le).unwrap(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn entropy_is_deterministic_in_millibits_per_byte() {
        assert_eq!(shannon_entropy_milli(&[]), 0);
        assert_eq!(shannon_entropy_milli(b"AAAA"), 0);
        assert_eq!(shannon_entropy_milli(b"ABAB"), 1000);
        assert_eq!(shannon_entropy_milli(b"AAAB"), 811);
        assert_eq!(
            shannon_entropy_milli(&(0_u8..=255).collect::<Vec<_>>()),
            8000
        );
    }
}

#[cfg(test)]
mod bundle_mutation_tests {
    use super::{
        decode_bundle, load_bundle_action, ActionKind, Bundle, BundleAction, BundleBinding,
        BundleFunction, BundleModule, Engine, Permissions, Runtime, BUNDLE_MAGIC,
    };
    use crate::bytecode::{Instruction, Program};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::PathBuf;

    fn wrap(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48 + payload.len());
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&Sha256::digest(payload));
        bytes.extend_from_slice(payload);
        bytes
    }

    fn exercise(bytes: &[u8]) {
        if let Ok(bundle) = decode_bundle(bytes) {
            let mut runtime = Runtime::new(
                PathBuf::from("bundle-mutation-root"),
                BTreeMap::new(),
                Permissions::default(),
                Vec::new(),
                Engine::Vm,
            );
            let _ = runtime.load_bundle(bundle);
        }
    }

    #[test]
    fn bundle_rejects_else_branch_on_non_conditional_action() {
        let nested = BundleAction {
            kind: ActionKind::Print,
            name: None,
            annotation: None,
            code: Program {
                instructions: vec![Instruction::Int(1)],
            },
            body: Vec::new(),
            else_body: Vec::new(),
            line: 1,
            col: 1,
        };
        let action = BundleAction {
            kind: ActionKind::Print,
            name: None,
            annotation: None,
            code: Program {
                instructions: vec![Instruction::Int(2)],
            },
            body: Vec::new(),
            else_body: vec![nested],
            line: 1,
            col: 1,
        };
        assert_eq!(
            load_bundle_action(action, 0, 0).err().as_deref(),
            Some("unexpected bundle else body")
        );
    }

    #[test]
    fn bundle_rejects_loop_control_outside_a_loop() {
        let control = BundleAction {
            kind: ActionKind::Break,
            name: None,
            annotation: None,
            code: Program {
                instructions: vec![Instruction::Bool(true)],
            },
            body: Vec::new(),
            else_body: Vec::new(),
            line: 1,
            col: 1,
        };
        assert_eq!(
            load_bundle_action(control, 0, 0).err().as_deref(),
            Some("bundle loop control outside loop")
        );
    }

    #[test]
    fn version_15_function_results_remain_readable_and_version_16_requires_return() {
        let legacy = Bundle {
            version: 15,
            root_depth: 0,
            entry: "main.gak".into(),
            effects: Vec::new(),
            modules: vec![BundleModule {
                path: "main.gak".into(),
                effects: Vec::new(),
                imports: Vec::new(),
                functions: vec![BundleFunction {
                    name: "answer".into(),
                    params: Vec::new(),
                    result_type: None,
                    steps: Vec::new(),
                    result: Some(Program {
                        instructions: vec![Instruction::Int(42)],
                    }),
                }],
                records: Vec::new(),
                lets: Vec::new(),
                actions: Vec::new(),
            }],
        };
        let bytes = wrap(&serde_json::to_vec(&legacy).unwrap());
        let mut runtime = Runtime::new(
            PathBuf::from("bundle-mutation-root"),
            BTreeMap::new(),
            Permissions::default(),
            Vec::new(),
            Engine::Vm,
        );
        let root = runtime.load_bundle(decode_bundle(&bytes).unwrap()).unwrap();
        assert_eq!(
            runtime
                .call(&root, "answer", Vec::new(), 0)
                .unwrap()
                .as_int()
                .unwrap(),
            42
        );

        let invalid = Bundle {
            version: 16,
            root_depth: 0,
            entry: "main.gak".into(),
            effects: Vec::new(),
            modules: vec![BundleModule {
                path: "main.gak".into(),
                effects: Vec::new(),
                imports: Vec::new(),
                functions: vec![BundleFunction {
                    name: "missing".into(),
                    params: Vec::new(),
                    result_type: None,
                    steps: Vec::new(),
                    result: None,
                }],
                records: Vec::new(),
                lets: Vec::new(),
                actions: Vec::new(),
            }],
        };
        let mut runtime = Runtime::new(
            PathBuf::from("bundle-mutation-root"),
            BTreeMap::new(),
            Permissions::default(),
            Vec::new(),
            Engine::Vm,
        );
        assert_eq!(
            runtime.load_bundle(invalid).err().as_deref(),
            Some("bundle function has no guaranteed return")
        );
    }

    #[test]
    fn truncated_and_mutated_bundle_payloads_do_not_panic() {
        let bundle = Bundle {
            version: 15,
            root_depth: 0,
            entry: "main.gak".into(),
            effects: Vec::new(),
            modules: vec![BundleModule {
                path: "main.gak".into(),
                effects: Vec::new(),
                imports: Vec::new(),
                functions: Vec::new(),
                records: Vec::new(),
                lets: vec![BundleBinding {
                    name: "value".into(),
                    mutable: false,
                    annotation: None,
                    code: Program {
                        instructions: vec![Instruction::Int(42)],
                    },
                    line: 1,
                }],
                actions: vec![BundleAction {
                    kind: ActionKind::Print,
                    name: None,
                    annotation: None,
                    code: Program {
                        instructions: vec![Instruction::Load("value".into())],
                    },
                    body: Vec::new(),
                    else_body: Vec::new(),
                    line: 2,
                    col: 1,
                }],
            }],
        };
        let payload = serde_json::to_vec(&bundle).unwrap();
        let encoded = wrap(&payload);
        assert!(decode_bundle(&encoded).is_ok());
        let mut older = encoded.clone();
        older[4] = 6;
        assert!(decode_bundle(&older).is_err());
        for length in 0..encoded.len() {
            assert!(
                catch_unwind(AssertUnwindSafe(|| exercise(&encoded[..length]))).is_ok(),
                "bundle truncated at {length} panicked"
            );
        }
        for offset in 0..48 {
            for replacement in [0, 1, 0x7f, 0xff] {
                let mut changed = encoded.clone();
                changed[offset] = replacement;
                assert!(
                    catch_unwind(AssertUnwindSafe(|| exercise(&changed))).is_ok(),
                    "bundle header byte {offset} value {replacement:#04x} panicked"
                );
            }
        }
        for offset in 0..payload.len() {
            for replacement in [0, b'[', b']', b'"', b'0', 0xff] {
                let mut changed = payload.clone();
                changed[offset] = replacement;
                let bytes = wrap(&changed);
                assert!(
                    catch_unwind(AssertUnwindSafe(|| exercise(&bytes))).is_ok(),
                    "payload byte {offset} value {replacement:#04x} panicked"
                );
            }
        }
        let rounds = std::env::var("GALEIKAN_BUNDLE_MUTATIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4096)
            .min(1_000_000);
        let mut state = 0x1748_c2ad_6f3b_905e_u64;
        for case in 0..rounds {
            let mut changed = payload.clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for _ in 0..1 + (state as usize % 8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let offset = state as usize % changed.len();
                changed[offset] ^= (state >> 24) as u8;
            }
            let bytes = wrap(&changed);
            assert!(
                catch_unwind(AssertUnwindSafe(|| exercise(&bytes))).is_ok(),
                "payload mutation {case} panicked"
            );
        }
    }
}
