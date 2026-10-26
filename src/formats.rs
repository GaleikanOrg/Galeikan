use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Copy)]
pub struct NumericField {
    pub offset: usize,
    pub width: usize,
    pub value: u64,
    pub decoder: &'static str,
}

#[derive(Clone, Copy)]
enum ElfBindNow {
    Unknown,
    Absent(Option<NumericField>),
    Present(NumericField),
}

impl ElfBindNow {
    fn status(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Absent(_) => "absent",
            Self::Present(_) => "present",
        }
    }

    fn field(self) -> Option<NumericField> {
        match self {
            Self::Unknown => None,
            Self::Absent(field) => field,
            Self::Present(field) => Some(field),
        }
    }
}

#[derive(Clone)]
pub struct SectionInfo {
    pub name: Option<String>,
    pub file_offset: usize,
    pub file_size: usize,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub flags: u64,
    pub flags_field: NumericField,
    pub writable: bool,
    pub executable: bool,
    pub file_backed: bool,
}

#[derive(Clone, Debug)]
pub struct ImportInfo {
    pub library: String,
    pub symbol: String,
    pub kind: &'static str,
}

#[derive(Clone, Debug)]
pub struct ExportInfo {
    pub name: String,
    pub named: bool,
    pub ordinal: u64,
    pub rva: u64,
    pub target: String,
    pub kind: &'static str,
}

#[derive(Clone, Debug)]
pub struct CertificateInfo {
    pub offset: usize,
    pub size: usize,
    pub revision: u16,
    pub kind: u16,
}

#[derive(Clone, Debug)]
pub struct DebugInfo {
    pub offset: usize,
    pub size: usize,
    pub timestamp: u32,
    pub kind: u32,
    pub pdb_path: Option<String>,
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
}

impl DebugInfo {
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            0 => "unknown",
            1 => "coff",
            2 => "codeview",
            16 => "repro",
            _ => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DynamicSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub binding: u8,
    pub symbol_type: u8,
    pub visibility: u8,
    pub section_index: u16,
}

impl DynamicSymbol {
    pub fn binding_name(&self) -> &'static str {
        match self.binding {
            0 => "local",
            1 => "global",
            2 => "weak",
            10 => "gnu_unique",
            _ => "unknown",
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self.symbol_type {
            0 => "notype",
            1 => "object",
            2 => "function",
            3 => "section",
            4 => "file",
            5 => "common",
            6 => "tls",
            10 => "gnu_ifunc",
            _ => "unknown",
        }
    }

    pub fn visibility_name(&self) -> &'static str {
        match self.visibility {
            0 => "default",
            1 => "internal",
            2 => "hidden",
            _ => "protected",
        }
    }

    pub fn role(&self) -> &'static str {
        if self.section_index == 0 {
            "undefined"
        } else if matches!(self.binding, 1 | 2 | 10) && matches!(self.visibility, 0 | 3) {
            "exported"
        } else {
            "local"
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocationInfo {
    pub address: u64,
    pub kind: u32,
    pub symbol: Option<u32>,
    pub addend: Option<i64>,
    pub relr: bool,
}

#[derive(Clone)]
struct RelocationTable {
    file_offset: usize,
    size: usize,
    entry_size: usize,
    encoding: RelocationEncoding,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelocationEncoding {
    Rel,
    Rela,
    Relr,
}

#[derive(Clone)]
struct LoadSegment {
    file_offset: usize,
    file_size: u64,
    virtual_address: u64,
    memory_size: u64,
    flags: u32,
}

const MAX_SECTIONS: usize = 100_000;
const MAX_SEGMENTS: usize = 10_000;
const MAX_DYNAMIC_BYTES: usize = 1024 * 1024;
const MAX_DYNAMIC_STRING_BYTES: usize = 16 * 1024 * 1024;
const MAX_NEEDED_LIBRARIES: usize = 10_000;
const MAX_NEEDED_NAME_BYTES: usize = 4096;
const MAX_IMPORT_DESCRIPTORS: usize = 4096;
const MAX_IMPORT_SYMBOLS: usize = 10_000;
const MAX_IMPORT_LIBRARY_BYTES: usize = 1024;
const MAX_IMPORT_SYMBOL_BYTES: usize = 4096;
const MAX_EXPORT_ADDRESSES: usize = 10_000;
const MAX_EXPORT_NAMES: usize = 10_000;
const MAX_EXPORT_TEXT_BYTES: usize = 4096;
const MAX_RELOCATION_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RELOCATION_BLOCKS: usize = 65_536;
const MAX_RELOCATION_SLOTS: usize = 100_000;
const MAX_DYNAMIC_SYMBOLS: usize = 100_000;
const MAX_DYNAMIC_SYMBOL_NAME_BYTES: usize = 4096;
const MAX_DYNAMIC_SYMBOL_NAMES_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_HASH_WORDS: usize = 100_000;
const MAX_CERTIFICATE_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CERTIFICATES: usize = 4096;
const MAX_DEBUG_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEBUG_ENTRIES: usize = 4096;
const MAX_DEBUG_DATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_PDB_PATH_BYTES: usize = 4096;

#[derive(Clone)]
pub struct FormatReport {
    pub name: &'static str,
    pub byte_order: &'static str,
    pub machine: u16,
    pub entry: u64,
    pub entry_kind: &'static str,
    pub sections: Option<u64>,
    pub header_span: (usize, usize),
    declared_file_end: u64,
    pub machine_field: NumericField,
    pub entry_field: NumericField,
    pub sections_field: NumericField,
    pub section_info: Vec<SectionInfo>,
    pe_dll_characteristics_field: Option<NumericField>,
    elf_stack_flags_field: Option<NumericField>,
    elf_bind_now: ElfBindNow,
    elf_relro_segment: bool,
    elf_program_headers_present: bool,
    elf_load_segments: Vec<LoadSegment>,
    elf_dynamic: Option<(usize, u64)>,
    elf_file_type: u16,
    elf_section_types: Vec<u32>,
    elf_dynsym_sections: Vec<(usize, usize, usize)>,
    elf_symbols: Arc<OnceLock<Result<Vec<DynamicSymbol>, String>>>,
    elf_symtab_sections: Vec<(usize, usize, usize)>,
    elf_static_symbols: Arc<OnceLock<Result<Vec<DynamicSymbol>, String>>>,
    elf_relocation_sections: Vec<RelocationTable>,
    elf_relocations: Arc<OnceLock<Result<Vec<RelocationInfo>, String>>>,
    elf_needed: Arc<OnceLock<Result<Vec<String>, String>>>,
    pe_headers_size: Option<usize>,
    pe_image_base_field: Option<NumericField>,
    pe_import_directory: Result<Option<(u64, u64)>, String>,
    pe_delay_import_directory: Result<Option<(u64, u64)>, String>,
    pe_export_directory: Result<Option<(u64, u64)>, String>,
    pe_relocation_directory: Result<Option<(u64, u64)>, String>,
    pe_certificate_directory: Result<Option<(u64, u64)>, String>,
    pe_debug_directory: Result<Option<(u64, u64)>, String>,
    pe_thunk_width: usize,
    pe_dependencies: Arc<OnceLock<Result<Vec<String>, String>>>,
    pe_imports: Arc<OnceLock<Result<Vec<ImportInfo>, String>>>,
    pe_delay_imports: Arc<OnceLock<Result<Vec<ImportInfo>, String>>>,
    pe_delay_dependencies: Arc<OnceLock<Result<Vec<String>, String>>>,
    pe_exports: Arc<OnceLock<Result<Vec<ExportInfo>, String>>>,
    pe_relocations: Arc<OnceLock<Result<Vec<RelocationInfo>, String>>>,
    pe_certificates: Arc<OnceLock<Result<Vec<CertificateInfo>, String>>>,
    pe_debug_entries: Arc<OnceLock<Result<Vec<DebugInfo>, String>>>,
}

impl FormatReport {
    pub fn kind(&self) -> &'static str {
        if self.name.starts_with("PE") {
            "pe"
        } else {
            "elf"
        }
    }

    pub fn bits(&self) -> i64 {
        if matches!(self.name, "PE32" | "ELF32") {
            32
        } else {
            64
        }
    }

    pub fn endian(&self) -> &'static str {
        if self.byte_order == "big-endian" {
            "big"
        } else {
            "little"
        }
    }

    pub fn arch(&self) -> &'static str {
        match (self.kind(), self.machine) {
            ("pe", 0x014c) | ("elf", 3) => "x86",
            ("pe", 0x8664) | ("elf", 62) => "x86_64",
            ("pe", 0x01c0 | 0x01c2 | 0x01c4) | ("elf", 40) => "arm",
            ("pe", 0xaa64 | 0xa641 | 0xa64e) | ("elf", 183) => "aarch64",
            ("pe", 0x5032 | 0x5064 | 0x5128) | ("elf", 243) => "riscv",
            _ => "unknown",
        }
    }

    pub fn overlay_range(&self, captured_size: usize) -> Result<(usize, usize), String> {
        let start = usize::try_from(self.declared_file_end)
            .map_err(|_| "declared binary extent outside address space")?;
        if start > captured_size {
            return Err("declared binary extent outside captured Source".into());
        }
        Ok((start, captured_size))
    }

    pub fn field(&self, name: &str) -> Option<NumericField> {
        match name {
            "machine" => Some(self.machine_field),
            "entry" => Some(self.entry_field),
            "sections" => Some(self.sections_field),
            "dll_characteristics" => self.pe_dll_characteristics_field,
            "image_base" => self.pe_image_base_field,
            "file_type" if self.name.starts_with("ELF") => Some(NumericField {
                offset: 16,
                width: 2,
                value: u64::from(self.elf_file_type),
                decoder: if self.byte_order == "big-endian" {
                    "u16be"
                } else {
                    "u16le"
                },
            }),
            "gnu_stack_flags" => self.elf_stack_flags_field,
            _ => None,
        }
    }

    pub fn signal(&self, name: &str) -> Result<&'static str, String> {
        let pe = self.name.starts_with("PE");
        let pe_flag = |mask| {
            if pe {
                flag_status(
                    self.pe_dll_characteristics_field.map(|field| field.value),
                    mask,
                )
            } else {
                "not_applicable"
            }
        };
        Ok(match name {
            "pe.high_entropy_va" if self.name == "PE32" => "not_applicable",
            "pe.high_entropy_va" => pe_flag(0x0020),
            "pe.dynamic_base" => pe_flag(0x0040),
            "pe.nx_compat" => pe_flag(0x0100),
            "pe.guard_cf" => pe_flag(0x4000),
            "pe.section_wx" => {
                if !pe {
                    "not_applicable"
                } else if self
                    .section_info
                    .iter()
                    .any(|section| section.writable && section.executable)
                {
                    "present"
                } else {
                    "absent"
                }
            }
            "elf.et_dyn" => {
                if pe {
                    "not_applicable"
                } else if self.elf_file_type == 3 {
                    "present"
                } else if self.elf_file_type == 2 {
                    "absent"
                } else {
                    "unknown"
                }
            }
            "elf.gnu_stack_nx" => {
                if pe {
                    "not_applicable"
                } else {
                    self.elf_stack_flags_field.map_or("unknown", |field| {
                        if field.value & 1 == 0 {
                            "present"
                        } else {
                            "absent"
                        }
                    })
                }
            }
            "elf.gnu_relro" => {
                if pe {
                    "not_applicable"
                } else if !self.elf_program_headers_present {
                    "unknown"
                } else if self.elf_relro_segment {
                    "present"
                } else {
                    "absent"
                }
            }
            "elf.bind_now" => {
                if pe {
                    "not_applicable"
                } else {
                    self.elf_bind_now.status()
                }
            }
            "elf.relro_now" => {
                if pe {
                    "not_applicable"
                } else if !self.elf_program_headers_present {
                    "unknown"
                } else if !self.elf_relro_segment {
                    "absent"
                } else {
                    self.elf_bind_now.status()
                }
            }
            "elf.load_rwx" => {
                if pe {
                    "not_applicable"
                } else if !self.elf_program_headers_present || self.elf_load_segments.is_empty() {
                    "unknown"
                } else if self
                    .elf_load_segments
                    .iter()
                    .any(|segment| segment.flags & 7 == 7)
                {
                    "present"
                } else {
                    "absent"
                }
            }
            _ => return Err(format!("unknown format signal {name}")),
        })
    }

    pub fn signal_field(&self, name: &str) -> Option<NumericField> {
        match name {
            "pe.high_entropy_va" | "pe.dynamic_base" | "pe.nx_compat" | "pe.guard_cf" => {
                self.field("dll_characteristics")
            }
            "pe.section_wx" if self.kind() == "pe" => self
                .section_info
                .iter()
                .find(|section| section.writable && section.executable)
                .map(|section| section.flags_field),
            "elf.et_dyn" => self.field("file_type"),
            "elf.gnu_stack_nx" => self.field("gnu_stack_flags"),
            "elf.bind_now" => self.elf_bind_now.field(),
            _ => None,
        }
    }

    pub fn summary(&self) -> String {
        let sections = self
            .sections
            .map_or_else(|| "extended".to_string(), |n| n.to_string());
        format!(
            "{} {} machine=0x{:04x} entry_{}=0x{:x} sections={} header=[{}..{})",
            self.name,
            self.byte_order,
            self.machine,
            self.entry_kind,
            self.entry,
            sections,
            self.header_span.0,
            self.header_span.1,
        )
    }

    pub fn section(&self, index: usize) -> Option<&SectionInfo> {
        self.section_info.get(index)
    }

    pub fn relocation_location(&self) -> &'static str {
        if self.name.starts_with("PE") {
            "rva"
        } else if self.elf_file_type == 1 {
            "section_offset"
        } else if matches!(self.elf_file_type, 2 | 3) {
            "va"
        } else {
            "unknown"
        }
    }

    pub fn relocation_kind(&self, kind: u32) -> &'static str {
        if self.name.starts_with("PE") {
            return match kind {
                1 => "HIGH",
                2 => "LOW",
                3 => "HIGHLOW",
                4 => "HIGHADJ",
                10 => "DIR64",
                _ => "unknown",
            };
        }
        if self.machine == 62 {
            match kind {
                1 => "R_X86_64_64",
                2 => "R_X86_64_PC32",
                3 => "R_X86_64_GOT32",
                4 => "R_X86_64_PLT32",
                5 => "R_X86_64_COPY",
                6 => "R_X86_64_GLOB_DAT",
                7 => "R_X86_64_JUMP_SLOT",
                8 => "R_X86_64_RELATIVE",
                9 => "R_X86_64_GOTPCREL",
                10 => "R_X86_64_32",
                11 => "R_X86_64_32S",
                _ => "unknown",
            }
        } else {
            "unknown"
        }
    }

    pub fn relocation_label(&self, relocation: &RelocationInfo) -> &'static str {
        if relocation.relr {
            "RELR_RELATIVE"
        } else {
            self.relocation_kind(relocation.kind)
        }
    }

    pub fn imports(&self, bytes: &[u8]) -> Result<&[ImportInfo], String> {
        if !self.name.starts_with("PE") {
            return Err("PE imports require a PE image".into());
        }
        match self.pe_imports.get_or_init(|| self.parse_pe_imports(bytes)) {
            Ok(imports) => Ok(imports),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn delay_imports(&self, bytes: &[u8]) -> Result<&[ImportInfo], String> {
        if !self.name.starts_with("PE") {
            return Err("PE delay imports require a PE image".into());
        }
        match self
            .pe_delay_imports
            .get_or_init(|| self.parse_pe_delay_imports(bytes))
        {
            Ok(imports) => Ok(imports),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn certificates(&self, bytes: &[u8]) -> Result<&[CertificateInfo], String> {
        if !self.name.starts_with("PE") {
            return Err("PE certificates require a PE image".into());
        }
        match self
            .pe_certificates
            .get_or_init(|| self.parse_pe_certificates(bytes))
        {
            Ok(certificates) => Ok(certificates),
            Err(error) => Err(error.clone()),
        }
    }

    fn parse_pe_certificates(&self, bytes: &[u8]) -> Result<Vec<CertificateInfo>, String> {
        let (offset, size) = match &self.pe_certificate_directory {
            Ok(Some(directory)) => *directory,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => return Err(error.clone()),
        };
        if size > MAX_CERTIFICATE_DIRECTORY_BYTES {
            return Err(format!(
                "PE certificate table exceeds {MAX_CERTIFICATE_DIRECTORY_BYTES} bytes"
            ));
        }
        let start = usize::try_from(offset).map_err(|_| "PE certificate offset out of range")?;
        let size = usize::try_from(size).map_err(|_| "PE certificate size out of range")?;
        if start % 8 != 0 {
            return Err("PE certificate table is not 8-byte aligned".into());
        }
        if offset < self.declared_file_end {
            return Err("PE certificate table overlaps headers or sections".into());
        }
        let end = start
            .checked_add(size)
            .ok_or("PE certificate table range overflow")?;
        if end > bytes.len() {
            return Err("PE certificate table outside captured Source".into());
        }
        let mut entries = Vec::new();
        let mut current = start;
        while current < end {
            if entries.len() >= MAX_CERTIFICATES {
                return Err(format!("PE certificate count exceeds {MAX_CERTIFICATES}"));
            }
            if end - current < 8 {
                return Err("truncated PE certificate entry".into());
            }
            let length = usize::try_from(number(bytes, current, 4, false)?)
                .map_err(|_| "PE certificate length out of range")?;
            if length < 8 {
                return Err("PE certificate entry is shorter than its header".into());
            }
            let aligned = length
                .checked_add(7)
                .ok_or("PE certificate length overflow")?
                & !7;
            let next = current
                .checked_add(aligned)
                .ok_or("PE certificate table range overflow")?;
            if next > end {
                return Err("PE certificate entries exceed directory size".into());
            }
            entries.push(CertificateInfo {
                offset: current + 8,
                size: length - 8,
                revision: number(bytes, current + 4, 2, false)? as u16,
                kind: number(bytes, current + 6, 2, false)? as u16,
            });
            current = next;
        }
        Ok(entries)
    }

    pub fn debug_entries(&self, bytes: &[u8]) -> Result<&[DebugInfo], String> {
        if !self.name.starts_with("PE") {
            return Err("PE debug entries require a PE image".into());
        }
        match self
            .pe_debug_entries
            .get_or_init(|| self.parse_pe_debug_entries(bytes))
        {
            Ok(entries) => Ok(entries),
            Err(error) => Err(error.clone()),
        }
    }

    fn parse_pe_debug_entries(&self, bytes: &[u8]) -> Result<Vec<DebugInfo>, String> {
        let (rva, size) = match &self.pe_debug_directory {
            Ok(Some(directory)) => *directory,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => return Err(error.clone()),
        };
        if size > MAX_DEBUG_DIRECTORY_BYTES {
            return Err("PE debug directory exceeds 16 MiB".into());
        }
        let size = usize::try_from(size).map_err(|_| "PE debug directory size out of range")?;
        if !size.is_multiple_of(28) {
            return Err("PE debug directory has a partial entry".into());
        }
        if size / 28 > MAX_DEBUG_ENTRIES {
            return Err("PE debug directory exceeds 4096 entries".into());
        }
        let (start, _) = self.pe_rva_range(bytes.len(), rva, size)?;
        let mut entries = Vec::with_capacity(size / 28);
        for index in 0..size / 28 {
            let at = start + index * 28;
            let timestamp = number(bytes, at + 4, 4, false)? as u32;
            let kind = number(bytes, at + 12, 4, false)? as u32;
            let data_size = number(bytes, at + 16, 4, false)? as usize;
            if data_size > MAX_DEBUG_DATA_BYTES {
                return Err("PE debug data exceeds 16 MiB".into());
            }
            let data_rva = number(bytes, at + 20, 4, false)?;
            let file_pointer = number(bytes, at + 24, 4, false)?;
            let offset = if data_size == 0 {
                0
            } else if file_pointer != 0 {
                let offset = usize::try_from(file_pointer)
                    .map_err(|_| "PE debug data offset out of range")?;
                span(bytes, offset, data_size)
                    .map_err(|_| "PE debug data outside captured Source")?;
                offset
            } else if data_rva != 0 {
                self.pe_rva_range(bytes.len(), data_rva, data_size)?.0
            } else {
                return Err("PE debug entry has no data address".into());
            };
            let mut pdb_path = None;
            let mut pdb_guid = None;
            let mut pdb_age = None;
            if kind == 2 && data_size >= 4 && &bytes[offset..offset + 4] == b"RSDS" {
                if data_size < 25 {
                    return Err("truncated PE CodeView RSDS data".into());
                }
                let guid = &bytes[offset + 4..offset + 20];
                let path_data = &bytes[offset + 24..offset + data_size];
                let limit = path_data.len().min(MAX_PDB_PATH_BYTES + 1);
                let path_end = path_data[..limit]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(if path_data.len() > MAX_PDB_PATH_BYTES {
                        "PE PDB path exceeds 4096 bytes"
                    } else {
                        "unterminated PE PDB path"
                    })?;
                if path_end == 0 {
                    return Err("empty PE PDB path".into());
                }
                if path_end > MAX_PDB_PATH_BYTES {
                    return Err("PE PDB path exceeds 4096 bytes".into());
                }
                pdb_guid = Some(format!(
                    "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    number(guid, 0, 4, false)?,
                    number(guid, 4, 2, false)?,
                    number(guid, 6, 2, false)?,
                    guid[8],
                    guid[9],
                    guid[10],
                    guid[11],
                    guid[12],
                    guid[13],
                    guid[14],
                    guid[15]
                ));
                pdb_age = Some(number(bytes, offset + 20, 4, false)? as u32);
                pdb_path = Some(section_name(&path_data[..path_end]));
            }
            entries.push(DebugInfo {
                offset,
                size: data_size,
                timestamp,
                kind,
                pdb_path,
                pdb_guid,
                pdb_age,
            });
        }
        Ok(entries)
    }

    pub fn delay_dependencies(&self, bytes: &[u8]) -> Result<&[String], String> {
        if !self.name.starts_with("PE") {
            return Err("PE delay dependencies require a PE image".into());
        }
        match self.pe_delay_dependencies.get_or_init(|| {
            self.pe_delay_import_descriptors(bytes)
                .map(|descriptors| descriptors.into_iter().map(|(_, name, _)| name).collect())
        }) {
            Ok(names) => Ok(names),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn exports(&self, bytes: &[u8]) -> Result<&[ExportInfo], String> {
        if !self.name.starts_with("PE") {
            return Err("PE exports require a PE image".into());
        }
        match self.pe_exports.get_or_init(|| self.parse_pe_exports(bytes)) {
            Ok(exports) => Ok(exports),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn relocations(&self, bytes: &[u8]) -> Result<&[RelocationInfo], String> {
        let parsed = if self.name.starts_with("PE") {
            self.pe_relocations
                .get_or_init(|| self.parse_pe_relocations(bytes))
        } else {
            self.elf_relocations
                .get_or_init(|| self.parse_elf_relocations(bytes))
        };
        match parsed {
            Ok(relocations) => Ok(relocations),
            Err(error) => Err(error.clone()),
        }
    }

    fn parse_pe_relocations(&self, bytes: &[u8]) -> Result<Vec<RelocationInfo>, String> {
        let (directory_rva, directory_size) = match &self.pe_relocation_directory {
            Ok(Some(directory)) => *directory,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => return Err(error.clone()),
        };
        if directory_size > MAX_RELOCATION_DIRECTORY_BYTES {
            return Err("PE base relocation directory exceeds 16 MiB".into());
        }
        let end = directory_rva
            .checked_add(directory_size)
            .ok_or("PE base relocation directory overflow")?;
        if end > u64::from(u32::MAX) + 1 {
            return Err("PE base relocation directory outside RVA space".into());
        }
        let mut cursor = directory_rva;
        let mut blocks = 0_usize;
        let mut slots = 0_usize;
        let mut relocations = Vec::new();
        while cursor < end {
            if blocks == MAX_RELOCATION_BLOCKS {
                return Err("PE base relocation block limit exceeded".into());
            }
            if end - cursor < 8 {
                return Err("truncated PE base relocation block header".into());
            }
            let (header, _) = self.pe_rva_range(bytes.len(), cursor, 8)?;
            let page_rva = number(bytes, header, 4, false)?;
            let block_size = number(bytes, header + 4, 4, false)?;
            if block_size < 8 || block_size % 2 != 0 || block_size > end - cursor {
                return Err("invalid PE base relocation block size".into());
            }
            let body_size = usize::try_from(block_size - 8)
                .map_err(|_| "PE base relocation block outside host address space")?;
            let count = body_size / 2;
            slots = slots
                .checked_add(count)
                .ok_or("PE base relocation slot count overflow")?;
            if slots > MAX_RELOCATION_SLOTS {
                return Err("PE base relocation slot limit exceeded".into());
            }
            let mut index = 0;
            if body_size > 0 {
                let (body, _) = self.pe_rva_range(bytes.len(), cursor + 8, body_size)?;
                while index < count {
                    let entry = number(bytes, body + index * 2, 2, false)? as u16;
                    let kind = (entry >> 12) as u8;
                    let address = page_rva
                        .checked_add(u64::from(entry & 0x0fff))
                        .ok_or("PE base relocation RVA overflow")?;
                    if address > u64::from(u32::MAX) {
                        return Err("PE base relocation RVA outside address space".into());
                    }
                    if kind != 0 {
                        relocations.push(RelocationInfo {
                            address,
                            kind: u32::from(kind),
                            symbol: None,
                            addend: None,
                            relr: false,
                        });
                    }
                    if kind == 4 {
                        if index + 1 >= count {
                            return Err("PE HIGHADJ relocation lacks its pair".into());
                        }
                        index += 1;
                    }
                    index += 1;
                }
            }
            cursor += block_size;
            blocks += 1;
        }
        Ok(relocations)
    }

    fn parse_elf_relocations(&self, bytes: &[u8]) -> Result<Vec<RelocationInfo>, String> {
        let mut tables = self.elf_relocation_sections.clone();
        tables.extend(self.elf_dynamic_relocation_tables(bytes)?);
        tables.retain(|table| table.size > 0);
        tables.sort_by_key(|table| table.file_offset);
        tables.dedup_by(|left, right| {
            left.file_offset == right.file_offset
                && left.size == right.size
                && left.entry_size == right.entry_size
                && left.encoding == right.encoding
        });
        for pair in tables.windows(2) {
            let first_end = pair[0]
                .file_offset
                .checked_add(pair[0].size)
                .ok_or("ELF relocation table range overflow")?;
            if first_end > pair[1].file_offset {
                return Err("overlapping ELF relocation tables".into());
            }
        }
        let width = if self.name == "ELF32" { 4 } else { 8 };
        let big = self.byte_order == "big-endian";
        let mut total_bytes = 0_usize;
        let mut total_entries = 0_usize;
        let mut relocations = Vec::new();
        for table in tables {
            let expected = if table.encoding == RelocationEncoding::Relr {
                width
            } else {
                width
                    * if table.encoding == RelocationEncoding::Rela {
                        3
                    } else {
                        2
                    }
            };
            if table.entry_size != expected || table.size % expected != 0 {
                return Err("invalid ELF relocation entry size".into());
            }
            total_bytes = total_bytes
                .checked_add(table.size)
                .ok_or("ELF relocation bytes overflow")?;
            total_entries = total_entries
                .checked_add(table.size / expected)
                .ok_or("ELF relocation count overflow")?;
            if total_bytes as u64 > MAX_RELOCATION_DIRECTORY_BYTES
                || total_entries > MAX_RELOCATION_SLOTS
            {
                return Err("ELF relocation limit exceeded".into());
            }
            span(bytes, table.file_offset, table.size)?;
            if table.encoding == RelocationEncoding::Relr {
                if !matches!(self.elf_file_type, 2 | 3) {
                    return Err("ELF RELR requires ET_EXEC or ET_DYN".into());
                }
                let mut next = None;
                for index in 0..table.size / width {
                    let entry = number(bytes, table.file_offset + index * width, width, big)?;
                    if entry & 1 == 0 {
                        if entry % width as u64 != 0 {
                            return Err("unaligned ELF RELR address".into());
                        }
                        next = Some(
                            entry
                                .checked_add(width as u64)
                                .ok_or("ELF RELR address overflow")?,
                        );
                        relocations.push(RelocationInfo {
                            address: entry,
                            kind: 0,
                            symbol: None,
                            addend: None,
                            relr: true,
                        });
                    } else {
                        let base = next.ok_or("ELF RELR bitmap without address")?;
                        for bit in 1..width * 8 {
                            if entry & (1_u64 << bit) != 0 {
                                let address = base
                                    .checked_add(((bit - 1) * width) as u64)
                                    .ok_or("ELF RELR address overflow")?;
                                if width == 4 && address > u32::MAX as u64 {
                                    return Err("ELF RELR address outside ELF32 space".into());
                                }
                                relocations.push(RelocationInfo {
                                    address,
                                    kind: 0,
                                    symbol: None,
                                    addend: None,
                                    relr: true,
                                });
                            }
                        }
                        next = Some(
                            base.checked_add(((width * 8 - 1) * width) as u64)
                                .ok_or("ELF RELR address overflow")?,
                        );
                    }
                    if relocations.len() > MAX_RELOCATION_SLOTS {
                        return Err("ELF relocation limit exceeded".into());
                    }
                }
                continue;
            }
            for index in 0..table.size / expected {
                let offset = table.file_offset + index * expected;
                let address = number(bytes, offset, width, big)?;
                let info = number(bytes, offset + width, width, big)?;
                let (kind, symbol) = if width == 4 {
                    ((info & 0xff) as u32, (info >> 8) as u32)
                } else {
                    (info as u32, (info >> 32) as u32)
                };
                let addend = if table.encoding == RelocationEncoding::Rela {
                    let raw = number(bytes, offset + 2 * width, width, big)?;
                    Some(if width == 4 {
                        (raw as u32 as i32) as i64
                    } else {
                        raw as i64
                    })
                } else {
                    None
                };
                if kind != 0 {
                    relocations.push(RelocationInfo {
                        address,
                        kind,
                        symbol: Some(symbol),
                        addend,
                        relr: false,
                    });
                }
            }
        }
        Ok(relocations)
    }

    fn elf_dynamic_relocation_tables(&self, bytes: &[u8]) -> Result<Vec<RelocationTable>, String> {
        let (dynamic_offset, dynamic_size) = match self.elf_dynamic {
            Some(dynamic) => dynamic,
            None => return Ok(Vec::new()),
        };
        let width = if self.name == "ELF32" { 4 } else { 8 };
        let big = self.byte_order == "big-endian";
        let size = usize::try_from(dynamic_size)
            .map_err(|_| "ELF dynamic table outside host address space")?;
        if size == 0 || dynamic_size > MAX_DYNAMIC_BYTES as u64 || size % (2 * width) != 0 {
            return Err("invalid ELF dynamic table size".into());
        }
        span(bytes, dynamic_offset, size)?;
        let mut tags = BTreeMap::new();
        let mut terminated = false;
        for index in 0..size / (2 * width) {
            let offset = dynamic_offset + index * 2 * width;
            let tag = number(bytes, offset, width, big)?;
            if tag == 0 {
                terminated = true;
                break;
            }
            if matches!(tag, 2 | 7 | 8 | 9 | 17 | 18 | 19 | 20 | 23 | 35 | 36 | 37) {
                let value = number(bytes, offset + width, width, big)?;
                if tags.insert(tag, value).is_some() {
                    return Err("duplicate ELF relocation dynamic tag".into());
                }
            }
        }
        if !terminated {
            return Err("ELF dynamic table has no DT_NULL terminator".into());
        }
        let mut tables = Vec::new();
        for (address_tag, size_tag, entry_tag, encoding) in [
            (7, 8, 9, RelocationEncoding::Rela),
            (17, 18, 19, RelocationEncoding::Rel),
        ] {
            let (Some(address), Some(table_size), Some(entry_size)) = (
                tags.get(&address_tag),
                tags.get(&size_tag),
                tags.get(&entry_tag),
            ) else {
                if [address_tag, size_tag, entry_tag]
                    .iter()
                    .any(|tag| tags.contains_key(tag))
                {
                    return Err("incomplete ELF dynamic relocation table".into());
                }
                continue;
            };
            self.push_dynamic_relocation_table(
                bytes.len(),
                *address,
                *table_size,
                *entry_size,
                encoding,
                &mut tables,
            )?;
        }
        let plt_tags = [23, 2, 20];
        if plt_tags.iter().any(|tag| tags.contains_key(tag)) {
            let address = *tags.get(&23).ok_or("incomplete ELF PLT relocation table")?;
            let size = *tags.get(&2).ok_or("incomplete ELF PLT relocation table")?;
            let kind = *tags.get(&20).ok_or("incomplete ELF PLT relocation table")?;
            let encoding = match kind {
                7 => RelocationEncoding::Rela,
                17 => RelocationEncoding::Rel,
                _ => return Err("invalid ELF DT_PLTREL type".into()),
            };
            self.push_dynamic_relocation_table(
                bytes.len(),
                address,
                size,
                (width
                    * if encoding == RelocationEncoding::Rela {
                        3
                    } else {
                        2
                    }) as u64,
                encoding,
                &mut tables,
            )?;
        }
        let relr_tags = [36, 35, 37];
        if relr_tags.iter().any(|tag| tags.contains_key(tag)) {
            let address = *tags.get(&36).ok_or("incomplete ELF RELR dynamic table")?;
            let size = *tags.get(&35).ok_or("incomplete ELF RELR dynamic table")?;
            let entry = *tags.get(&37).ok_or("incomplete ELF RELR dynamic table")?;
            self.push_dynamic_relocation_table(
                bytes.len(),
                address,
                size,
                entry,
                RelocationEncoding::Relr,
                &mut tables,
            )?;
        }
        Ok(tables)
    }

    fn push_dynamic_relocation_table(
        &self,
        captured_len: usize,
        address: u64,
        size: u64,
        entry_size: u64,
        encoding: RelocationEncoding,
        tables: &mut Vec<RelocationTable>,
    ) -> Result<(), String> {
        if size == 0 {
            return Ok(());
        }
        if size > MAX_RELOCATION_DIRECTORY_BYTES {
            return Err("ELF relocation table exceeds 16 MiB".into());
        }
        let size = usize::try_from(size).map_err(|_| "ELF relocation size out of range")?;
        let entry_size =
            usize::try_from(entry_size).map_err(|_| "ELF relocation entry size out of range")?;
        let (file_offset, _) = self.elf_va_range(captured_len, address, size)?;
        tables.push(RelocationTable {
            file_offset,
            size,
            entry_size,
            encoding,
        });
        Ok(())
    }

    pub fn needed_libraries(&self, bytes: &[u8]) -> Result<&[String], String> {
        if !self.name.starts_with("ELF") {
            return Err("ELF needed libraries require an ELF image".into());
        }
        match self.elf_needed.get_or_init(|| self.parse_elf_needed(bytes)) {
            Ok(names) => Ok(names),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn dynamic_symbols(&self, bytes: &[u8]) -> Result<&[DynamicSymbol], String> {
        if !self.name.starts_with("ELF") {
            return Err("ELF dynamic symbols require an ELF image".into());
        }
        match self
            .elf_symbols
            .get_or_init(|| self.parse_elf_symbols(bytes, false))
        {
            Ok(symbols) => Ok(symbols),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn static_symbols(&self, bytes: &[u8]) -> Result<&[DynamicSymbol], String> {
        if !self.name.starts_with("ELF") {
            return Err("ELF static symbols require an ELF image".into());
        }
        match self
            .elf_static_symbols
            .get_or_init(|| self.parse_elf_symbols(bytes, true))
        {
            Ok(symbols) => Ok(symbols),
            Err(error) => Err(error.clone()),
        }
    }

    fn parse_elf_symbols(
        &self,
        bytes: &[u8],
        static_table: bool,
    ) -> Result<Vec<DynamicSymbol>, String> {
        let width = if self.name == "ELF32" { 4 } else { 8 };
        let entry_size = if width == 4 { 16 } else { 24 };
        let big = self.byte_order == "big-endian";
        let label = if static_table { "static" } else { "dynamic" };
        let sections = if static_table {
            &self.elf_symtab_sections
        } else {
            &self.elf_dynsym_sections
        };
        let table = match sections.as_slice() {
            [] if static_table => None,
            [] => self.elf_dynamic_symbol_table(bytes)?,
            [(section_index, string_index, actual_entry_size)] => {
                if *actual_entry_size != entry_size {
                    return Err(format!("invalid ELF {label} symbol entry size"));
                }
                if *string_index == 0 || self.elf_section_types.get(*string_index) != Some(&3) {
                    return Err(format!("ELF {label} symbols need a linked SHT_STRTAB"));
                }
                let symbols = &self.section_info[*section_index];
                let strings = &self.section_info[*string_index];
                if symbols.flags & 0x800 != 0 || strings.flags & 0x800 != 0 {
                    return Err(format!(
                        "compressed ELF {label} symbol tables are unsupported"
                    ));
                }
                if !symbols.file_size.is_multiple_of(entry_size) {
                    return Err(format!("ELF {label} symbol table has a partial entry"));
                }
                Some((
                    symbols.file_offset,
                    symbols.file_size / entry_size,
                    strings.file_offset,
                    strings.file_size,
                ))
            }
            _ => return Err(format!("multiple ELF {label} symbol sections")),
        };
        let Some((symbol_start, count, string_start, string_size)) = table else {
            return Ok(Vec::new());
        };
        if count > MAX_DYNAMIC_SYMBOLS {
            return Err(format!("ELF {label} symbols exceed {MAX_DYNAMIC_SYMBOLS}"));
        }
        if string_size > MAX_DYNAMIC_STRING_BYTES {
            return Err("ELF dynamic string table exceeds 16 MiB".into());
        }
        span(bytes, symbol_start, count * entry_size)?;
        let strings = span(bytes, string_start, string_size)?;
        let mut symbols = Vec::with_capacity(count);
        let mut name_bytes_total = 0_usize;
        for index in 0..count {
            let base = symbol_start + index * entry_size;
            let name_offset = number(bytes, base, 4, big)? as usize;
            let (info, other, section_index, address, size) = if width == 4 {
                (
                    bytes[base + 12],
                    bytes[base + 13],
                    number(bytes, base + 14, 2, big)? as u16,
                    number(bytes, base + 4, 4, big)?,
                    number(bytes, base + 8, 4, big)?,
                )
            } else {
                (
                    bytes[base + 4],
                    bytes[base + 5],
                    number(bytes, base + 6, 2, big)? as u16,
                    number(bytes, base + 8, 8, big)?,
                    number(bytes, base + 16, 8, big)?,
                )
            };
            let name = if name_offset == 0 {
                String::new()
            } else {
                let tail = strings
                    .get(name_offset..)
                    .ok_or_else(|| format!("ELF {label} symbol name offset out of range"))?;
                let end = tail
                    .iter()
                    .take(MAX_DYNAMIC_SYMBOL_NAME_BYTES + 1)
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| format!("unterminated or oversized ELF {label} symbol name"))?;
                if end == 0 || end > MAX_DYNAMIC_SYMBOL_NAME_BYTES {
                    return Err(format!("empty or oversized ELF {label} symbol name"));
                }
                name_bytes_total = name_bytes_total
                    .checked_add(end)
                    .ok_or_else(|| format!("ELF {label} symbol names exceed size limit"))?;
                if name_bytes_total > MAX_DYNAMIC_SYMBOL_NAMES_TOTAL_BYTES {
                    return Err(format!("ELF {label} symbol names exceed 16 MiB"));
                }
                section_name(&tail[..end])
            };
            symbols.push(DynamicSymbol {
                name,
                address,
                size,
                binding: info >> 4,
                symbol_type: info & 0x0f,
                visibility: other & 0x03,
                section_index,
            });
        }
        Ok(symbols)
    }

    fn elf_dynamic_symbol_table(
        &self,
        bytes: &[u8],
    ) -> Result<Option<(usize, usize, usize, usize)>, String> {
        let Some((dynamic_offset, dynamic_size)) = self.elf_dynamic else {
            return Ok(None);
        };
        let width = if self.name == "ELF32" { 4 } else { 8 };
        let big = self.byte_order == "big-endian";
        let entry_size = width * 2;
        let dynamic_size = usize::try_from(dynamic_size)
            .map_err(|_| "ELF dynamic table outside host address space")?;
        if dynamic_size == 0 || dynamic_size > MAX_DYNAMIC_BYTES || dynamic_size % entry_size != 0 {
            return Err("invalid ELF dynamic table size".into());
        }
        span(bytes, dynamic_offset, dynamic_size)?;
        let mut symtab = None;
        let mut syment = None;
        let mut strtab = None;
        let mut strsz = None;
        let mut sysv_hash = None;
        let mut gnu_hash = None;
        let mut terminated = false;
        for index in 0..dynamic_size / entry_size {
            let offset = dynamic_offset + index * entry_size;
            let tag = number(bytes, offset, width, big)?;
            let value = number(bytes, offset + width, width, big)?;
            if tag == 0 {
                terminated = true;
                break;
            }
            let slot = match tag {
                4 => &mut sysv_hash,
                5 => &mut strtab,
                6 => &mut symtab,
                10 => &mut strsz,
                11 => &mut syment,
                0x6fff_fef5 => &mut gnu_hash,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(format!("duplicate ELF dynamic tag 0x{tag:x}"));
            }
        }
        if !terminated {
            return Err("ELF dynamic table has no DT_NULL terminator".into());
        }
        let Some(symtab) = symtab else {
            return Ok(None);
        };
        let symbol_entry_size = if width == 4 { 16 } else { 24 };
        if syment != Some(symbol_entry_size as u64) {
            return Err("invalid ELF DT_SYMENT".into());
        }
        let string_va = strtab.ok_or("ELF dynamic symbols lack DT_STRTAB")?;
        let string_size = usize::try_from(strsz.ok_or("ELF dynamic symbols lack DT_STRSZ")?)
            .map_err(|_| "ELF dynamic string table outside host address space")?;
        if string_size > MAX_DYNAMIC_STRING_BYTES {
            return Err("ELF dynamic string table exceeds 16 MiB".into());
        }
        let count = if let Some(hash_va) = sysv_hash {
            self.elf_sysv_hash_count(bytes, hash_va)?
        } else if let Some(hash_va) = gnu_hash {
            self.elf_gnu_hash_count(bytes, hash_va)?
        } else {
            return Err("ELF dynamic symbol count needs DT_HASH or DT_GNU_HASH".into());
        };
        if count > MAX_DYNAMIC_SYMBOLS {
            return Err(format!("ELF dynamic symbols exceed {MAX_DYNAMIC_SYMBOLS}"));
        }
        let symbol_start = if count == 0 {
            0
        } else {
            self.elf_va_range(bytes.len(), symtab, count * symbol_entry_size)?
                .0
        };
        let string_start = if string_size == 0 {
            0
        } else {
            self.elf_va_range(bytes.len(), string_va, string_size)?.0
        };
        Ok(Some((symbol_start, count, string_start, string_size)))
    }

    fn elf_sysv_hash_count(&self, bytes: &[u8], hash_va: u64) -> Result<usize, String> {
        let (start, _) = self.elf_va_range(bytes.len(), hash_va, 8)?;
        let big = self.byte_order == "big-endian";
        let buckets = usize::try_from(number(bytes, start, 4, big)?)
            .map_err(|_| "ELF hash bucket count out of range")?;
        let chains = usize::try_from(number(bytes, start + 4, 4, big)?)
            .map_err(|_| "ELF hash chain count out of range")?;
        if buckets > MAX_HASH_WORDS || chains > MAX_DYNAMIC_SYMBOLS {
            return Err("ELF hash table exceeds symbol limits".into());
        }
        let bytes_needed = (2 + buckets + chains) * 4;
        self.elf_va_range(bytes.len(), hash_va, bytes_needed)?;
        Ok(chains)
    }

    fn elf_gnu_hash_count(&self, bytes: &[u8], hash_va: u64) -> Result<usize, String> {
        let (start, _) = self.elf_va_range(bytes.len(), hash_va, 16)?;
        let big = self.byte_order == "big-endian";
        let buckets = usize::try_from(number(bytes, start, 4, big)?)
            .map_err(|_| "ELF GNU hash bucket count out of range")?;
        let first_symbol = usize::try_from(number(bytes, start + 4, 4, big)?)
            .map_err(|_| "ELF GNU hash first symbol out of range")?;
        let bloom_words = usize::try_from(number(bytes, start + 8, 4, big)?)
            .map_err(|_| "ELF GNU hash bloom count out of range")?;
        if buckets == 0
            || bloom_words == 0
            || buckets > MAX_HASH_WORDS
            || bloom_words > MAX_HASH_WORDS
            || first_symbol > MAX_DYNAMIC_SYMBOLS
        {
            return Err("ELF GNU hash table exceeds symbol limits".into());
        }
        let width = if self.name == "ELF32" { 4 } else { 8 };
        let bucket_va = hash_va
            .checked_add(16 + (bloom_words * width) as u64)
            .ok_or("ELF GNU hash address overflow")?;
        let (bucket_start, _) = self.elf_va_range(bytes.len(), bucket_va, buckets * 4)?;
        let mut last_bucket = 0_usize;
        for index in 0..buckets {
            let symbol = usize::try_from(number(bytes, bucket_start + index * 4, 4, big)?)
                .map_err(|_| "ELF GNU hash bucket out of range")?;
            if symbol != 0 && (symbol < first_symbol || symbol >= MAX_DYNAMIC_SYMBOLS) {
                return Err("ELF GNU hash bucket refers outside dynamic symbols".into());
            }
            if symbol != 0 && symbol < last_bucket {
                return Err("ELF GNU hash buckets are out of order".into());
            }
            last_bucket = last_bucket.max(symbol);
        }
        if last_bucket == 0 {
            return Ok(first_symbol);
        }
        let chain_va = bucket_va
            .checked_add((buckets * 4 + (last_bucket - first_symbol) * 4) as u64)
            .ok_or("ELF GNU hash address overflow")?;
        let (chain_start, _) = self.elf_va_range(bytes.len(), chain_va, 4)?;
        for symbol in last_bucket..MAX_DYNAMIC_SYMBOLS {
            let offset = chain_start
                .checked_add((symbol - last_bucket) * 4)
                .ok_or("ELF GNU hash chain offset overflow")?;
            let chain = number(bytes, offset, 4, big)?;
            if chain & 1 != 0 {
                let used = (symbol - last_bucket + 1) * 4;
                self.elf_va_range(bytes.len(), chain_va, used)?;
                return Ok(symbol + 1);
            }
        }
        Err("ELF GNU hash chain has no terminator within symbol limit".into())
    }

    pub fn dependencies(&self, bytes: &[u8]) -> Result<&[String], String> {
        if self.name.starts_with("ELF") {
            return self.needed_libraries(bytes);
        }
        match self.pe_dependencies.get_or_init(|| {
            self.pe_import_descriptors(bytes)
                .map(|descriptors| descriptors.into_iter().map(|(_, name)| name).collect())
        }) {
            Ok(names) => Ok(names),
            Err(error) => Err(error.clone()),
        }
    }

    fn parse_elf_needed(&self, bytes: &[u8]) -> Result<Vec<String>, String> {
        let (dynamic_offset, dynamic_size) = match self.elf_dynamic {
            Some(table) => table,
            None => return Ok(Vec::new()),
        };
        let width = if self.name == "ELF32" { 4 } else { 8 };
        let big = self.byte_order == "big-endian";
        let entry_size = width * 2;
        let dynamic_size = usize::try_from(dynamic_size)
            .map_err(|_| "ELF dynamic table outside host address space")?;
        if dynamic_size == 0 || dynamic_size > MAX_DYNAMIC_BYTES || dynamic_size % entry_size != 0 {
            return Err("invalid ELF dynamic table size".into());
        }
        span(bytes, dynamic_offset, dynamic_size)?;
        let mut string_va = None;
        let mut string_size = None;
        let mut needed_offsets = Vec::new();
        let mut terminated = false;
        for index in 0..dynamic_size / entry_size {
            let offset = dynamic_offset + index * entry_size;
            let tag = number(bytes, offset, width, big)?;
            let value = number(bytes, offset + width, width, big)?;
            match tag {
                0 => {
                    terminated = true;
                    break;
                }
                1 => {
                    if needed_offsets.len() >= MAX_NEEDED_LIBRARIES {
                        return Err(format!(
                            "ELF needed libraries exceed {MAX_NEEDED_LIBRARIES}"
                        ));
                    }
                    needed_offsets.push(value);
                }
                5 => match string_va {
                    None => string_va = Some(value),
                    Some(_) => return Err("duplicate ELF DT_STRTAB".into()),
                },
                10 => match string_size {
                    None => string_size = Some(value),
                    Some(_) => return Err("duplicate ELF DT_STRSZ".into()),
                },
                _ => {}
            }
        }
        if !terminated {
            return Err("ELF dynamic table has no DT_NULL terminator".into());
        }
        if needed_offsets.is_empty() {
            return Ok(Vec::new());
        }
        let string_va = string_va.ok_or("ELF needed libraries lack DT_STRTAB")?;
        let string_size = string_size.ok_or("ELF needed libraries lack DT_STRSZ")?;
        let string_size = usize::try_from(string_size)
            .map_err(|_| "ELF dynamic string table outside host address space")?;
        if string_size == 0 || string_size > MAX_DYNAMIC_STRING_BYTES {
            return Err("invalid ELF dynamic string table size".into());
        }
        let (string_start, string_end) = self.elf_va_range(bytes.len(), string_va, string_size)?;
        let string_table = &bytes[string_start..string_end];
        let mut names = Vec::with_capacity(needed_offsets.len());
        for offset in needed_offsets {
            let offset =
                usize::try_from(offset).map_err(|_| "ELF needed name offset out of range")?;
            let tail = string_table
                .get(offset..)
                .ok_or("ELF needed name offset out of range")?;
            let end = tail
                .iter()
                .take(MAX_NEEDED_NAME_BYTES + 1)
                .position(|byte| *byte == 0)
                .ok_or("unterminated or oversized ELF needed name")?;
            if end == 0 || end > MAX_NEEDED_NAME_BYTES {
                return Err("empty or oversized ELF needed name".into());
            }
            names.push(section_name(&tail[..end]));
        }
        Ok(names)
    }

    fn parse_pe_exports(&self, bytes: &[u8]) -> Result<Vec<ExportInfo>, String> {
        let (directory_rva, directory_size) = match &self.pe_export_directory {
            Ok(Some(directory)) => *directory,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => return Err(error.clone()),
        };
        if directory_size < 40 {
            return Err("PE export directory is shorter than its header".into());
        }
        let directory_end = directory_rva
            .checked_add(directory_size)
            .ok_or("PE export directory RVA overflow")?;
        if directory_end > u64::from(u32::MAX) + 1 {
            return Err("PE export directory outside PE address space".into());
        }
        let (header, _) = self.pe_rva_range(bytes.len(), directory_rva, 40)?;
        let base = number(bytes, header + 16, 4, false)?;
        let address_count = number(bytes, header + 20, 4, false)? as usize;
        let name_count = number(bytes, header + 24, 4, false)? as usize;
        if address_count > MAX_EXPORT_ADDRESSES || name_count > MAX_EXPORT_NAMES {
            return Err("PE export table exceeds symbol limits".into());
        }
        if name_count > 0 && address_count == 0 {
            return Err("PE export names have no address table".into());
        }
        let address_rva = number(bytes, header + 28, 4, false)?;
        let name_rva = number(bytes, header + 32, 4, false)?;
        let ordinal_rva = number(bytes, header + 36, 4, false)?;
        let mut names = vec![Vec::<String>::new(); address_count];
        let address_table = if address_count == 0 {
            None
        } else {
            Some(
                self.pe_rva_range(bytes.len(), address_rva, address_count * 4)?
                    .0,
            )
        };
        if name_count > 0 {
            let (name_table, _) = self.pe_rva_range(bytes.len(), name_rva, name_count * 4)?;
            let (ordinal_table, _) = self.pe_rva_range(bytes.len(), ordinal_rva, name_count * 2)?;
            for index in 0..name_count {
                let name_address = number(bytes, name_table + index * 4, 4, false)?;
                let ordinal_index = number(bytes, ordinal_table + index * 2, 2, false)? as usize;
                let names_for_ordinal = names
                    .get_mut(ordinal_index)
                    .ok_or("PE export name ordinal index out of range")?;
                names_for_ordinal.push(self.pe_text(bytes, name_address, MAX_EXPORT_TEXT_BYTES)?);
            }
        }
        let mut exports = Vec::with_capacity(address_count.max(name_count));
        if let Some(address_table) = address_table {
            for (index, names_for_ordinal) in names.into_iter().enumerate() {
                let target_rva = number(bytes, address_table + index * 4, 4, false)?;
                if target_rva == 0 {
                    if !names_for_ordinal.is_empty() {
                        return Err("PE export name points to an empty address".into());
                    }
                    continue;
                }
                let ordinal = base
                    .checked_add(index as u64)
                    .ok_or("PE export ordinal overflow")?;
                if ordinal > u64::from(u32::MAX) {
                    return Err("PE export ordinal outside u32 range".into());
                }
                let (target, kind) = if (directory_rva..directory_end).contains(&target_rva) {
                    let available = usize::try_from(directory_end - target_rva)
                        .unwrap_or(usize::MAX)
                        .min(MAX_EXPORT_TEXT_BYTES);
                    (self.pe_text(bytes, target_rva, available)?, "forwarder")
                } else {
                    (format!("0x{target_rva:x}"), "rva")
                };
                if names_for_ordinal.is_empty() {
                    exports.push(ExportInfo {
                        name: format!("#{ordinal}"),
                        named: false,
                        ordinal,
                        rva: target_rva,
                        target,
                        kind,
                    });
                } else {
                    for name in names_for_ordinal {
                        exports.push(ExportInfo {
                            name,
                            named: true,
                            ordinal,
                            rva: target_rva,
                            target: target.clone(),
                            kind,
                        });
                    }
                }
            }
        }
        Ok(exports)
    }

    fn pe_import_descriptors(&self, bytes: &[u8]) -> Result<Vec<(u64, String)>, String> {
        let (directory_rva, directory_size) = match &self.pe_import_directory {
            Ok(Some(directory)) => *directory,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => return Err(error.clone()),
        };
        let directory_size = usize::try_from(directory_size)
            .map_err(|_| "PE import directory outside host address space")?;
        let mut descriptors = Vec::new();
        for descriptor_index in 0..=MAX_IMPORT_DESCRIPTORS {
            let relative = descriptor_index
                .checked_mul(20)
                .ok_or("PE import descriptor offset overflow")?;
            if relative + 20 > directory_size {
                return Err("PE import directory has no null descriptor".into());
            }
            let rva = directory_rva
                .checked_add(relative as u64)
                .ok_or("PE import descriptor RVA overflow")?;
            let (offset, _) = self.pe_rva_range(bytes.len(), rva, 20)?;
            let descriptor = &bytes[offset..offset + 20];
            if descriptor.iter().all(|byte| *byte == 0) {
                return Ok(descriptors);
            }
            if descriptor_index == MAX_IMPORT_DESCRIPTORS {
                return Err(format!(
                    "PE import directory exceeds {MAX_IMPORT_DESCRIPTORS} descriptors"
                ));
            }
            let lookup_rva = number(bytes, offset, 4, false)?;
            let library_rva = number(bytes, offset + 12, 4, false)?;
            let iat_rva = number(bytes, offset + 16, 4, false)?;
            if library_rva == 0 || (lookup_rva == 0 && iat_rva == 0) {
                return Err("PE import descriptor lacks a library or lookup table".into());
            }
            let library = self.pe_text(bytes, library_rva, MAX_IMPORT_LIBRARY_BYTES)?;
            let lookup_rva = if lookup_rva == 0 { iat_rva } else { lookup_rva };
            descriptors.push((lookup_rva, library));
        }
        Err(format!(
            "PE import directory exceeds {MAX_IMPORT_DESCRIPTORS} descriptors"
        ))
    }

    fn pe_delay_import_descriptors(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<(u64, String, bool)>, String> {
        let (directory_rva, directory_size) = match &self.pe_delay_import_directory {
            Ok(Some(directory)) => *directory,
            Ok(None) => return Ok(Vec::new()),
            Err(error) => return Err(error.clone()),
        };
        let directory_size = usize::try_from(directory_size)
            .map_err(|_| "PE delay import directory outside host address space")?;
        let mut descriptors = Vec::new();
        for index in 0..=MAX_IMPORT_DESCRIPTORS {
            let relative = index
                .checked_mul(32)
                .ok_or("PE delay import descriptor offset overflow")?;
            if relative + 32 > directory_size {
                return Err("PE delay import directory has no null descriptor".into());
            }
            let rva = directory_rva
                .checked_add(relative as u64)
                .ok_or("PE delay import descriptor RVA overflow")?;
            let (offset, _) = self.pe_rva_range(bytes.len(), rva, 32)?;
            let descriptor = &bytes[offset..offset + 32];
            if descriptor.iter().all(|byte| *byte == 0) {
                return Ok(descriptors);
            }
            if index == MAX_IMPORT_DESCRIPTORS {
                return Err(format!(
                    "PE delay import directory exceeds {MAX_IMPORT_DESCRIPTORS} descriptors"
                ));
            }
            let attributes = number(bytes, offset, 4, false)?;
            if attributes & !1 != 0 {
                return Err("PE delay import descriptor has reserved attribute bits".into());
            }
            let library_address = number(bytes, offset + 4, 4, false)?;
            let lookup_address = number(bytes, offset + 16, 4, false)?;
            if library_address == 0 || lookup_address == 0 {
                return Err("PE delay import descriptor lacks a library or name table".into());
            }
            let va_based = attributes == 0;
            let library_rva = self.pe_delay_rva(library_address, va_based)?;
            let lookup_rva = self.pe_delay_rva(lookup_address, va_based)?;
            let library = self.pe_text(bytes, library_rva, MAX_IMPORT_LIBRARY_BYTES)?;
            descriptors.push((lookup_rva, library, va_based));
        }
        Err(format!(
            "PE delay import directory exceeds {MAX_IMPORT_DESCRIPTORS} descriptors"
        ))
    }

    fn parse_pe_imports(&self, bytes: &[u8]) -> Result<Vec<ImportInfo>, String> {
        let descriptors = self
            .pe_import_descriptors(bytes)?
            .into_iter()
            .map(|(lookup_rva, library)| (lookup_rva, library, false))
            .collect();
        self.parse_pe_import_symbols(bytes, descriptors)
    }

    fn parse_pe_delay_imports(&self, bytes: &[u8]) -> Result<Vec<ImportInfo>, String> {
        self.parse_pe_import_symbols(bytes, self.pe_delay_import_descriptors(bytes)?)
    }

    fn parse_pe_import_symbols(
        &self,
        bytes: &[u8],
        descriptors: Vec<(u64, String, bool)>,
    ) -> Result<Vec<ImportInfo>, String> {
        let mut imports = Vec::new();
        for (lookup_rva, library, va_based) in descriptors {
            let ordinal_flag = 1_u64 << (self.pe_thunk_width * 8 - 1);
            for symbol_index in 0..=MAX_IMPORT_SYMBOLS {
                let delta = symbol_index
                    .checked_mul(self.pe_thunk_width)
                    .ok_or("PE import lookup offset overflow")?;
                let rva = lookup_rva
                    .checked_add(delta as u64)
                    .ok_or("PE import lookup RVA overflow")?;
                let (offset, _) = self.pe_rva_range(bytes.len(), rva, self.pe_thunk_width)?;
                let raw = number(bytes, offset, self.pe_thunk_width, false)?;
                if raw == 0 {
                    break;
                }
                if imports.len() >= MAX_IMPORT_SYMBOLS {
                    return Err(format!("PE imports exceed {MAX_IMPORT_SYMBOLS} symbols"));
                }
                let (symbol, kind) = if raw & ordinal_flag != 0 {
                    if raw & !(ordinal_flag | 0xffff) != 0 {
                        return Err("PE import ordinal has reserved bits set".into());
                    }
                    (format!("#{}", raw & 0xffff), "ordinal")
                } else {
                    let name_rva = self.pe_delay_rva(raw, va_based)?;
                    let name_rva = u32::try_from(name_rva)
                        .map_err(|_| "PE import name RVA outside PE address space")?;
                    self.pe_rva_range(bytes.len(), u64::from(name_rva), 2)?;
                    let symbol =
                        self.pe_text(bytes, u64::from(name_rva) + 2, MAX_IMPORT_SYMBOL_BYTES)?;
                    (symbol, "name")
                };
                imports.push(ImportInfo {
                    library: library.clone(),
                    symbol,
                    kind,
                });
                if symbol_index == MAX_IMPORT_SYMBOLS {
                    return Err("PE import lookup table has no null entry".into());
                }
            }
        }
        Ok(imports)
    }

    fn pe_delay_rva(&self, address: u64, va_based: bool) -> Result<u64, String> {
        if va_based {
            let image_base = self
                .pe_image_base_field
                .ok_or("PE image base is unavailable")?
                .value;
            address
                .checked_sub(image_base)
                .ok_or_else(|| "PE delay import VA is below image base".into())
        } else {
            Ok(address)
        }
    }

    fn pe_text(&self, bytes: &[u8], rva: u64, max_len: usize) -> Result<String, String> {
        let (start, _) = self.pe_rva_range(bytes.len(), rva, 1)?;
        let available =
            if let Some(headers_size) = self.pe_headers_size.filter(|size| rva < *size as u64) {
                headers_size as u64 - rva
            } else {
                let section = self.section_info.iter().find(|section| {
                    rva >= section.virtual_address
                        && rva - section.virtual_address < section.file_size as u64
                });
                let section = section.ok_or("PE text has no file-backed bytes")?;
                section.file_size as u64 - (rva - section.virtual_address)
            };
        let limit = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(max_len)
            .min(bytes.len() - start);
        let tail = &bytes[start..start + limit];
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("unterminated PE text")?;
        if end == 0 {
            return Err("empty PE text".into());
        }
        Ok(section_name(&tail[..end]))
    }

    pub fn pe_rva_range(
        &self,
        captured_len: usize,
        rva: u64,
        count: usize,
    ) -> Result<(usize, usize), String> {
        if !self.name.starts_with("PE") {
            return Err("formats.rva requires a PE image".into());
        }
        if count == 0 {
            return Err("RVA view length must be positive".into());
        }
        let count_u64 = u64::try_from(count).map_err(|_| "RVA length outside address space")?;
        let end = rva.checked_add(count_u64).ok_or("RVA range overflow")?;
        if end > u64::from(u32::MAX) + 1 {
            return Err("RVA range outside PE address space".into());
        }
        let mut mapped = None;
        if let Some(headers_size) = self.pe_headers_size {
            if rva < headers_size as u64 {
                if end > headers_size as u64 {
                    return Err("RVA range crosses PE header boundary".into());
                }
                mapped = Some((
                    usize::try_from(rva).map_err(|_| "RVA outside host address space")?,
                    usize::try_from(end).map_err(|_| "RVA outside host address space")?,
                ));
            }
        }
        for section in &self.section_info {
            let start = section.virtual_address;
            let size = section.virtual_size.max(section.file_size as u64);
            let section_end = start.checked_add(size).ok_or("PE section RVA overflow")?;
            if rva < start || rva >= section_end {
                continue;
            }
            if end > section_end {
                return Err("RVA range crosses PE section boundary".into());
            }
            let within = rva - start;
            if within + count_u64 > section.file_size as u64 {
                return Err("RVA range has no file-backed bytes".into());
            }
            let file_start = section
                .file_offset
                .checked_add(usize::try_from(within).map_err(|_| "RVA outside host address space")?)
                .ok_or("PE file offset overflow")?;
            let file_end = file_start
                .checked_add(count)
                .ok_or("PE file range overflow")?;
            if mapped.replace((file_start, file_end)).is_some() {
                return Err("RVA maps to multiple PE regions".into());
            }
        }
        let (file_start, file_end) = mapped.ok_or("RVA is not mapped to PE file bytes")?;
        if file_end > captured_len {
            return Err("RVA data outside captured Source".into());
        }
        Ok((file_start, file_end))
    }

    pub fn x86_entry_window(&self, captured_len: usize) -> Result<(usize, usize, u32), String> {
        let (start, end, bitness) = self.x86_entry_region(captured_len)?;
        let count = (end - start).min(15);
        let range = if self.name.starts_with("PE") {
            self.pe_rva_range(captured_len, self.entry, count)?
        } else {
            self.elf_va_range(captured_len, self.entry, count)?
        };
        Ok((range.0, range.1, bitness))
    }

    pub fn x86_entry_region(&self, captured_len: usize) -> Result<(usize, usize, u32), String> {
        let bitness = match (self.name, self.machine, self.byte_order) {
            ("PE32", 0x014c, _) | ("ELF32", 3, "little-endian") => 32,
            ("PE32+", 0x8664, _) | ("ELF64", 62, "little-endian") => 64,
            _ => {
                return Err(
                    "asm.entry supports only matching little-endian x86 PE/ELF images".into(),
                )
            }
        };
        let address = self.entry;
        let count = if self.name.starts_with("PE") {
            let (start, _) = self.pe_rva_range(captured_len, address, 1)?;
            let section = self
                .section_info
                .iter()
                .find(|section| {
                    let end = section
                        .virtual_address
                        .saturating_add(section.virtual_size.max(section.file_size as u64));
                    address >= section.virtual_address && address < end
                })
                .ok_or("PE entry is not in an executable section")?;
            if section.flags & 0x2000_0000 == 0 {
                return Err("PE entry section is not executable".into());
            }
            let within = address - section.virtual_address;
            let remaining = section.file_size as u64 - within;
            usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(captured_len - start)
        } else {
            let (start, _) = self.elf_va_range(captured_len, address, 1)?;
            let segment = self
                .elf_load_segments
                .iter()
                .find(|segment| {
                    let end = segment.virtual_address.saturating_add(segment.memory_size);
                    address >= segment.virtual_address && address < end
                })
                .ok_or("ELF entry is not in an executable load segment")?;
            if segment.flags & 1 == 0 {
                return Err("ELF entry load segment is not executable".into());
            }
            let within = address - segment.virtual_address;
            let remaining = segment.file_size - within;
            usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(captured_len - start)
        };
        let (start, _) = if self.name.starts_with("PE") {
            self.pe_rva_range(captured_len, address, 1)?
        } else {
            self.elf_va_range(captured_len, address, 1)?
        };
        let end = start
            .checked_add(count)
            .ok_or("entry file range overflow")?;
        Ok((start, end, bitness))
    }

    pub fn elf_va_range(
        &self,
        captured_len: usize,
        va: u64,
        count: usize,
    ) -> Result<(usize, usize), String> {
        if !self.name.starts_with("ELF") {
            return Err("formats.va requires an ELF image".into());
        }
        if count == 0 {
            return Err("VA view length must be positive".into());
        }
        let count_u64 = u64::try_from(count).map_err(|_| "VA length outside address space")?;
        let end = va.checked_add(count_u64).ok_or("VA range overflow")?;
        if self.name == "ELF32" && end > u64::from(u32::MAX) + 1 {
            return Err("VA range outside ELF32 address space".into());
        }
        let mut mapped = None;
        for segment in &self.elf_load_segments {
            let segment_end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .ok_or("ELF segment VA overflow")?;
            if va < segment.virtual_address || va >= segment_end {
                continue;
            }
            if end > segment_end {
                return Err("VA range crosses ELF load segment boundary".into());
            }
            let within = va - segment.virtual_address;
            if within.checked_add(count_u64).ok_or("VA range overflow")? > segment.file_size {
                return Err("VA range has no file-backed bytes".into());
            }
            let file_start = segment
                .file_offset
                .checked_add(usize::try_from(within).map_err(|_| "VA outside host address space")?)
                .ok_or("ELF file offset overflow")?;
            let file_end = file_start
                .checked_add(count)
                .ok_or("ELF file range overflow")?;
            if mapped.replace((file_start, file_end)).is_some() {
                return Err("VA maps to multiple ELF load segments".into());
            }
        }
        let (file_start, file_end) = mapped.ok_or("VA is not mapped to ELF file bytes")?;
        if file_end > captured_len {
            return Err("VA data outside captured Source".into());
        }
        Ok((file_start, file_end))
    }
}

fn flag_status(flags: Option<u64>, mask: u64) -> &'static str {
    match flags {
        Some(flags) if flags & mask != 0 => "present",
        Some(_) => "absent",
        None => "unknown",
    }
}

fn section_name(bytes: &[u8]) -> String {
    let mut name = String::new();
    for byte in bytes {
        if (0x20..=0x7e).contains(byte) {
            name.push(*byte as char);
        } else {
            name.push_str(&format!("\\x{byte:02x}"));
        }
    }
    name
}

pub fn probe(bytes: &[u8]) -> Result<FormatReport, String> {
    if bytes.starts_with(b"MZ") {
        probe_pe(bytes)
    } else if bytes.starts_with(b"\x7fELF") {
        probe_elf(bytes)
    } else {
        Err("unknown binary format".into())
    }
}

fn span(bytes: &[u8], offset: usize, width: usize) -> Result<&[u8], String> {
    let end = offset.checked_add(width).ok_or("format offset overflow")?;
    bytes
        .get(offset..end)
        .ok_or_else(|| format!("truncated binary header at offset {offset}"))
}

fn number(bytes: &[u8], offset: usize, width: usize, big: bool) -> Result<u64, String> {
    let data = span(bytes, offset, width)?;
    Ok(if big {
        data.iter().fold(0_u64, |n, b| (n << 8) | u64::from(*b))
    } else {
        data.iter()
            .enumerate()
            .fold(0_u64, |n, (i, b)| n | (u64::from(*b) << (8 * i)))
    })
}

fn parse_elf_bind_now(
    bytes: &[u8],
    dynamic: Option<(usize, u64)>,
    width: usize,
    big: bool,
) -> ElfBindNow {
    let Some((start, raw_size)) = dynamic else {
        return ElfBindNow::Unknown;
    };
    let Ok(size) = usize::try_from(raw_size) else {
        return ElfBindNow::Unknown;
    };
    let entry_size = width * 2;
    if size == 0
        || size > MAX_DYNAMIC_BYTES
        || !size.is_multiple_of(entry_size)
        || span(bytes, start, size).is_err()
    {
        return ElfBindNow::Unknown;
    }
    let decoder = match (width, big) {
        (4, false) => "u32le",
        (4, true) => "u32be",
        (8, false) => "u64le",
        _ => "u64be",
    };
    let mut marker = None;
    let mut flags = None;
    let mut flags_1 = None;
    let mut terminated = false;
    for index in 0..size / entry_size {
        let offset = start + index * entry_size;
        let Ok(tag) = number(bytes, offset, width, big) else {
            return ElfBindNow::Unknown;
        };
        if tag == 0 {
            terminated = true;
            break;
        }
        if !matches!(tag, 24 | 30 | 0x6fff_fffb) {
            continue;
        }
        let Ok(value) = number(bytes, offset + width, width, big) else {
            return ElfBindNow::Unknown;
        };
        let field = NumericField {
            offset: if tag == 24 { offset } else { offset + width },
            width,
            value: if tag == 24 { tag } else { value },
            decoder,
        };
        let slot = match tag {
            24 => &mut marker,
            30 => &mut flags,
            _ => &mut flags_1,
        };
        if slot.replace(field).is_some() {
            return ElfBindNow::Unknown;
        }
    }
    if !terminated {
        return ElfBindNow::Unknown;
    }
    if let Some(field) = marker
        .or_else(|| flags.filter(|field| field.value & 8 != 0))
        .or_else(|| flags_1.filter(|field| field.value & 1 != 0))
    {
        ElfBindNow::Present(field)
    } else {
        ElfBindNow::Absent(flags_1.or(flags))
    }
}

fn probe_pe(bytes: &[u8]) -> Result<FormatReport, String> {
    span(bytes, 0, 64)?;
    let pe_offset = usize::try_from(number(bytes, 0x3c, 4, false)?)
        .map_err(|_| "PE offset outside address space")?;
    if pe_offset < 64 {
        return Err("PE offset overlaps DOS header".into());
    }
    if span(bytes, pe_offset, 4)? != b"PE\0\0" {
        return Err("missing PE signature".into());
    }
    let coff = pe_offset.checked_add(4).ok_or("PE offset overflow")?;
    span(bytes, coff, 20)?;
    let machine = number(bytes, coff, 2, false)? as u16;
    let sections = number(bytes, coff + 2, 2, false)? as u16;
    let optional_size = number(bytes, coff + 16, 2, false)? as usize;
    let optional = coff.checked_add(20).ok_or("PE offset overflow")?;
    let section_table = optional
        .checked_add(optional_size)
        .ok_or("PE offset overflow")?;
    span(bytes, optional, optional_size)?;
    if optional_size < 20 {
        return Err("PE optional header too short".into());
    }
    let name = match number(bytes, optional, 2, false)? {
        0x10b => "PE32",
        0x20b => "PE32+",
        _ => return Err("unknown PE optional header magic".into()),
    };
    let pe_dll_characteristics_field = if optional_size >= 72 {
        Some(NumericField {
            offset: optional + 70,
            width: 2,
            value: number(bytes, optional + 70, 2, false)?,
            decoder: "u16le",
        })
    } else {
        None
    };
    let pe_headers_size = if optional_size >= 64 {
        Some(number(bytes, optional + 60, 4, false)? as usize)
    } else {
        None
    };
    let image_base_offset = if name == "PE32" { 28 } else { 24 };
    let image_base_width = if name == "PE32" { 4 } else { 8 };
    let pe_image_base_field = if optional_size >= image_base_offset + image_base_width {
        Some(NumericField {
            offset: optional + image_base_offset,
            width: image_base_width,
            value: number(bytes, optional + image_base_offset, image_base_width, false)?,
            decoder: if name == "PE32" { "u32le" } else { "u64le" },
        })
    } else {
        None
    };
    let (directory_count_offset, export_directory_offset, import_directory_offset, pe_thunk_width) =
        if name == "PE32" {
            (92, 96, 104, 4)
        } else {
            (108, 112, 120, 8)
        };
    let pe_export_directory = (|| -> Result<Option<(u64, u64)>, String> {
        if optional_size < directory_count_offset + 4 {
            return Err("PE optional header has no data-directory count".into());
        }
        if number(bytes, optional + directory_count_offset, 4, false)? < 1 {
            return Ok(None);
        }
        if optional_size < export_directory_offset + 8 {
            return Err("PE export directory lies outside optional header".into());
        }
        let rva = number(bytes, optional + export_directory_offset, 4, false)?;
        let size = number(bytes, optional + export_directory_offset + 4, 4, false)?;
        match (rva, size) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err("incomplete PE export directory".into()),
            _ => Ok(Some((rva, size))),
        }
    })();
    let pe_import_directory = (|| -> Result<Option<(u64, u64)>, String> {
        if optional_size < directory_count_offset + 4 {
            return Err("PE optional header has no data-directory count".into());
        }
        if number(bytes, optional + directory_count_offset, 4, false)? < 2 {
            return Ok(None);
        }
        if optional_size < import_directory_offset + 8 {
            return Err("PE import directory lies outside optional header".into());
        }
        let rva = number(bytes, optional + import_directory_offset, 4, false)?;
        let size = number(bytes, optional + import_directory_offset + 4, 4, false)?;
        match (rva, size) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err("incomplete PE import directory".into()),
            _ => Ok(Some((rva, size))),
        }
    })();
    let pe_delay_import_directory = (|| -> Result<Option<(u64, u64)>, String> {
        if optional_size < directory_count_offset + 4 {
            return Err("PE optional header has no data-directory count".into());
        }
        if number(bytes, optional + directory_count_offset, 4, false)? < 14 {
            return Ok(None);
        }
        let directory_offset = export_directory_offset + 13 * 8;
        if optional_size < directory_offset + 8 {
            return Err("PE delay import directory lies outside optional header".into());
        }
        let rva = number(bytes, optional + directory_offset, 4, false)?;
        let size = number(bytes, optional + directory_offset + 4, 4, false)?;
        match (rva, size) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err("incomplete PE delay import directory".into()),
            _ => Ok(Some((rva, size))),
        }
    })();
    let pe_relocation_directory = (|| -> Result<Option<(u64, u64)>, String> {
        if optional_size < directory_count_offset + 4 {
            return Err("PE optional header has no data-directory count".into());
        }
        if number(bytes, optional + directory_count_offset, 4, false)? < 6 {
            return Ok(None);
        }
        let relocation_offset = export_directory_offset + 5 * 8;
        if optional_size < relocation_offset + 8 {
            return Err("PE base relocation directory lies outside optional header".into());
        }
        let rva = number(bytes, optional + relocation_offset, 4, false)?;
        let size = number(bytes, optional + relocation_offset + 4, 4, false)?;
        match (rva, size) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err("incomplete PE base relocation directory".into()),
            _ => Ok(Some((rva, size))),
        }
    })();
    let pe_certificate_directory = (|| -> Result<Option<(u64, u64)>, String> {
        if optional_size < directory_count_offset + 4 {
            return Err("PE optional header has no data-directory count".into());
        }
        if number(bytes, optional + directory_count_offset, 4, false)? < 5 {
            return Ok(None);
        }
        let directory_offset = export_directory_offset + 4 * 8;
        if optional_size < directory_offset + 8 {
            return Err("PE certificate directory lies outside optional header".into());
        }
        let file_offset = number(bytes, optional + directory_offset, 4, false)?;
        let size = number(bytes, optional + directory_offset + 4, 4, false)?;
        match (file_offset, size) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err("incomplete PE certificate directory".into()),
            _ => Ok(Some((file_offset, size))),
        }
    })();
    let pe_debug_directory = (|| -> Result<Option<(u64, u64)>, String> {
        if optional_size < directory_count_offset + 4 {
            return Err("PE optional header has no data-directory count".into());
        }
        if number(bytes, optional + directory_count_offset, 4, false)? < 7 {
            return Ok(None);
        }
        let directory_offset = export_directory_offset + 6 * 8;
        if optional_size < directory_offset + 8 {
            return Err("PE debug directory lies outside optional header".into());
        }
        let rva = number(bytes, optional + directory_offset, 4, false)?;
        let size = number(bytes, optional + directory_offset + 4, 4, false)?;
        match (rva, size) {
            (0, 0) => Ok(None),
            (0, _) | (_, 0) => Err("incomplete PE debug directory".into()),
            _ => Ok(Some((rva, size))),
        }
    })();
    let entry = number(bytes, optional + 16, 4, false)?;
    let table_size = usize::from(sections)
        .checked_mul(40)
        .ok_or("PE section table too large")?;
    span(bytes, section_table, table_size)?;
    let end = section_table
        .checked_add(table_size)
        .ok_or("PE offset overflow")?;
    let mut section_info = Vec::with_capacity(usize::from(sections));
    let mut declared_file_end = u64::try_from(end.max(pe_headers_size.unwrap_or(0)))
        .map_err(|_| "PE header extent outside address space")?;
    for index in 0..usize::from(sections) {
        let offset = section_table + index * 40;
        let name_bytes = span(bytes, offset, 8)?;
        let name_end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
        let file_size = number(bytes, offset + 16, 4, false)? as usize;
        let file_offset = number(bytes, offset + 20, 4, false)? as usize;
        let section_end = file_offset
            .checked_add(file_size)
            .ok_or("PE section range overflow")?;
        if file_size > 0 {
            declared_file_end = declared_file_end.max(
                u64::try_from(section_end)
                    .map_err(|_| "PE section extent outside address space")?,
            );
        }
        let flags = number(bytes, offset + 36, 4, false)?;
        section_info.push(SectionInfo {
            name: Some(section_name(&name_bytes[..name_end])),
            virtual_size: number(bytes, offset + 8, 4, false)?,
            virtual_address: number(bytes, offset + 12, 4, false)?,
            file_size,
            file_offset,
            flags,
            flags_field: NumericField {
                offset: offset + 36,
                width: 4,
                value: flags,
                decoder: "u32le",
            },
            writable: flags & 0x8000_0000 != 0,
            executable: flags & 0x2000_0000 != 0,
            file_backed: file_size > 0,
        });
    }
    Ok(FormatReport {
        name,
        byte_order: "little-endian",
        machine,
        entry,
        entry_kind: "rva",
        sections: Some(u64::from(sections)),
        header_span: (0, end),
        declared_file_end,
        machine_field: NumericField {
            offset: coff,
            width: 2,
            value: u64::from(machine),
            decoder: "u16le",
        },
        entry_field: NumericField {
            offset: optional + 16,
            width: 4,
            value: entry,
            decoder: "u32le",
        },
        sections_field: NumericField {
            offset: coff + 2,
            width: 2,
            value: u64::from(sections),
            decoder: "u16le",
        },
        section_info,
        pe_dll_characteristics_field,
        elf_stack_flags_field: None,
        elf_bind_now: ElfBindNow::Unknown,
        elf_relro_segment: false,
        elf_program_headers_present: false,
        elf_load_segments: Vec::new(),
        elf_dynamic: None,
        elf_file_type: 0,
        elf_section_types: Vec::new(),
        elf_dynsym_sections: Vec::new(),
        elf_symbols: Arc::new(OnceLock::new()),
        elf_symtab_sections: Vec::new(),
        elf_static_symbols: Arc::new(OnceLock::new()),
        elf_relocation_sections: Vec::new(),
        elf_relocations: Arc::new(OnceLock::new()),
        elf_needed: Arc::new(OnceLock::new()),
        pe_headers_size,
        pe_image_base_field,
        pe_import_directory,
        pe_delay_import_directory,
        pe_export_directory,
        pe_relocation_directory,
        pe_certificate_directory,
        pe_debug_directory,
        pe_thunk_width,
        pe_dependencies: Arc::new(OnceLock::new()),
        pe_imports: Arc::new(OnceLock::new()),
        pe_delay_imports: Arc::new(OnceLock::new()),
        pe_delay_dependencies: Arc::new(OnceLock::new()),
        pe_exports: Arc::new(OnceLock::new()),
        pe_relocations: Arc::new(OnceLock::new()),
        pe_certificates: Arc::new(OnceLock::new()),
        pe_debug_entries: Arc::new(OnceLock::new()),
    })
}

fn probe_elf(bytes: &[u8]) -> Result<FormatReport, String> {
    span(bytes, 0, 16)?;
    let (name, header_size, entry_width, shoff_offset, shentsize_offset, shnum_offset) =
        match bytes[4] {
            1 => ("ELF32", 52_usize, 4_usize, 32_usize, 46_usize, 48_usize),
            2 => ("ELF64", 64_usize, 8_usize, 40_usize, 58_usize, 60_usize),
            _ => return Err("invalid ELF class".into()),
        };
    let big = match bytes[5] {
        1 => false,
        2 => true,
        _ => return Err("invalid ELF byte order".into()),
    };
    if bytes[6] != 1 {
        return Err("invalid ELF version".into());
    }
    span(bytes, 0, header_size)?;
    if number(bytes, 20, 4, big)? != 1 {
        return Err("invalid ELF header version".into());
    }
    let ehsize_offset = if entry_width == 4 { 40 } else { 52 };
    if number(bytes, ehsize_offset, 2, big)? != header_size as u64 {
        return Err("invalid ELF header size".into());
    }
    let machine = number(bytes, 18, 2, big)? as u16;
    let elf_file_type = number(bytes, 16, 2, big)? as u16;
    let entry = number(bytes, 24, entry_width, big)?;
    let shoff = usize::try_from(number(bytes, shoff_offset, entry_width, big)?)
        .map_err(|_| "ELF section table outside address space")?;
    let shentsize = number(bytes, shentsize_offset, 2, big)? as usize;
    let shnum = number(bytes, shnum_offset, 2, big)? as usize;
    let (sections, sections_field, end) = if shoff == 0 {
        if shnum != 0 {
            return Err("ELF sections without a section table".into());
        }
        (
            Some(0),
            NumericField {
                offset: shnum_offset,
                width: 2,
                value: 0,
                decoder: if big { "u16be" } else { "u16le" },
            },
            header_size,
        )
    } else {
        let expected_entry_size = if entry_width == 4 { 40 } else { 64 };
        if shentsize != expected_entry_size {
            return Err("invalid ELF section entry size".into());
        }
        let (count, sections_field) = if shnum == 0 {
            // Extended section count is stored in sh_size of section header zero.
            span(bytes, shoff, shentsize)?;
            let size_offset = if entry_width == 4 { 20 } else { 32 };
            let field_offset = shoff + size_offset;
            let value = number(bytes, field_offset, entry_width, big)?;
            let count =
                usize::try_from(value).map_err(|_| "ELF section count outside address space")?;
            (
                count,
                NumericField {
                    offset: field_offset,
                    width: entry_width,
                    value,
                    decoder: match (entry_width, big) {
                        (4, false) => "u32le",
                        (4, true) => "u32be",
                        (8, false) => "u64le",
                        _ => "u64be",
                    },
                },
            )
        } else {
            (
                shnum,
                NumericField {
                    offset: shnum_offset,
                    width: 2,
                    value: shnum as u64,
                    decoder: if big { "u16be" } else { "u16le" },
                },
            )
        };
        let table_size = count
            .checked_mul(shentsize)
            .ok_or("ELF section table too large")?;
        span(bytes, shoff, table_size)?;
        let end = shoff.checked_add(table_size).ok_or("ELF offset overflow")?;
        (Some(count as u64), sections_field, end.max(header_size))
    };
    let count = usize::try_from(sections.unwrap())
        .map_err(|_| "ELF section count outside address space")?;
    if count > MAX_SECTIONS {
        return Err(format!("ELF section count exceeds {MAX_SECTIONS}"));
    }
    let mut section_info = Vec::with_capacity(count);
    let mut declared_file_end =
        u64::try_from(end).map_err(|_| "ELF header extent outside address space")?;
    let mut name_indices = Vec::with_capacity(count);
    let mut elf_section_types = Vec::with_capacity(count);
    let mut elf_dynsym_sections = Vec::new();
    let mut elf_symtab_sections = Vec::new();
    let mut elf_relocation_sections = Vec::new();
    if count > 0 {
        let (address_at, offset_at, size_at, link_at) = if entry_width == 4 {
            (12, 16, 20, 24)
        } else {
            (16, 24, 32, 40)
        };
        for index in 0..count {
            let offset = shoff + index * shentsize;
            let kind = number(bytes, offset + 4, 4, big)?;
            elf_section_types.push(kind as u32);
            let virtual_size = number(bytes, offset + size_at, entry_width, big)?;
            let file_size = usize::try_from(virtual_size)
                .map_err(|_| "ELF section size outside address space")?;
            let file_offset = usize::try_from(number(bytes, offset + offset_at, entry_width, big)?)
                .map_err(|_| "ELF section offset outside address space")?;
            if kind == 11 || kind == 2 {
                let entry_at = if entry_width == 4 { 36 } else { 56 };
                let entry_size =
                    usize::try_from(number(bytes, offset + entry_at, entry_width, big)?)
                        .map_err(|_| "ELF symbol entry size out of range")?;
                let link = usize::try_from(number(bytes, offset + link_at, 4, big)?)
                    .map_err(|_| "ELF symbol string table index out of range")?;
                if kind == 11 {
                    elf_dynsym_sections.push((index, link, entry_size));
                } else {
                    elf_symtab_sections.push((index, link, entry_size));
                }
            }
            if kind == 4 || kind == 9 || kind == 19 {
                let entry_at = if entry_width == 4 { 36 } else { 56 };
                let entry_size =
                    usize::try_from(number(bytes, offset + entry_at, entry_width, big)?)
                        .map_err(|_| "ELF relocation entry size out of range")?;
                elf_relocation_sections.push(RelocationTable {
                    file_offset,
                    size: file_size,
                    entry_size,
                    encoding: match kind {
                        4 => RelocationEncoding::Rela,
                        9 => RelocationEncoding::Rel,
                        _ => RelocationEncoding::Relr,
                    },
                });
            }
            if index != 0 && kind != 8 {
                let section_end = file_offset
                    .checked_add(file_size)
                    .ok_or("ELF section range overflow")?;
                if file_size > 0 {
                    declared_file_end = declared_file_end.max(
                        u64::try_from(section_end)
                            .map_err(|_| "ELF section extent outside address space")?,
                    );
                }
            }
            name_indices.push(number(bytes, offset, 4, big)? as usize);
            let flags = number(bytes, offset + 8, entry_width, big)?;
            section_info.push(SectionInfo {
                name: None,
                virtual_size,
                virtual_address: number(bytes, offset + address_at, entry_width, big)?,
                file_offset,
                file_size: if index == 0 || kind == 8 {
                    0
                } else {
                    file_size
                },
                flags,
                flags_field: NumericField {
                    offset: offset + 8,
                    width: entry_width,
                    value: flags,
                    decoder: match (entry_width, big) {
                        (4, false) => "u32le",
                        (4, true) => "u32be",
                        (8, false) => "u64le",
                        (8, true) => "u64be",
                        _ => unreachable!(),
                    },
                },
                writable: flags & 1 != 0,
                executable: flags & 4 != 0,
                file_backed: index != 0 && kind != 8 && file_size > 0,
            });
        }
        let raw_name_index =
            number(bytes, if entry_width == 4 { 50 } else { 62 }, 2, big)? as usize;
        let name_section = if raw_name_index == 0xffff {
            let link_offset = shoff + link_at;
            usize::try_from(number(bytes, link_offset, 4, big)?)
                .map_err(|_| "ELF section name index outside address space")?
        } else {
            raw_name_index
        };
        if name_section >= count {
            return Err("ELF section name table index out of range".into());
        }
        if name_section != 0 {
            let table_info = &section_info[name_section];
            if let Ok(table) = span(bytes, table_info.file_offset, table_info.file_size) {
                for (info, name_index) in section_info.iter_mut().zip(name_indices) {
                    if let Some(tail) = table.get(name_index..) {
                        if let Some(end) = tail.iter().position(|b| *b == 0) {
                            info.name = Some(section_name(&tail[..end]));
                        }
                    }
                }
            }
        }
    } else if number(bytes, if entry_width == 4 { 50 } else { 62 }, 2, big)? != 0 {
        return Err("ELF section names without a section table".into());
    }
    let phoff_offset = if entry_width == 4 { 28 } else { 32 };
    let phentsize_offset = if entry_width == 4 { 42 } else { 54 };
    let phnum_offset = if entry_width == 4 { 44 } else { 56 };
    let phoff = usize::try_from(number(bytes, phoff_offset, entry_width, big)?)
        .map_err(|_| "ELF program table outside address space")?;
    let phentsize = number(bytes, phentsize_offset, 2, big)? as usize;
    let raw_phnum = number(bytes, phnum_offset, 2, big)? as usize;
    let phnum = if raw_phnum == 0xffff {
        if shoff == 0 || shentsize == 0 {
            return Err("extended ELF program count needs section header zero".into());
        }
        let info_offset = if entry_width == 4 { 28 } else { 44 };
        let info_at = shoff
            .checked_add(info_offset)
            .ok_or("ELF offset overflow")?;
        usize::try_from(number(bytes, info_at, 4, big)?)
            .map_err(|_| "ELF program count outside address space")?
    } else {
        raw_phnum
    };
    if phnum > MAX_SEGMENTS {
        return Err(format!("ELF program count exceeds {MAX_SEGMENTS}"));
    }
    let mut elf_load_segments = Vec::new();
    let mut elf_dynamic = None;
    let mut elf_stack_flags_field = None;
    let mut elf_relro_segment = false;
    let mut header_end = end;
    if phnum > 0 {
        let expected_size = if entry_width == 4 { 32 } else { 56 };
        if phoff == 0 || phentsize != expected_size {
            return Err("invalid ELF program header table".into());
        }
        let table_size = phnum
            .checked_mul(phentsize)
            .ok_or("ELF program table too large")?;
        span(bytes, phoff, table_size)?;
        header_end = header_end.max(phoff.checked_add(table_size).ok_or("ELF offset overflow")?);
        declared_file_end = declared_file_end
            .max(u64::try_from(header_end).map_err(|_| "ELF header extent outside address space")?);
        for index in 0..phnum {
            let offset = phoff + index * phentsize;
            let kind = number(bytes, offset, 4, big)?;
            let (file_at, file_size_at) = if entry_width == 4 { (4, 16) } else { (8, 32) };
            let raw_file_offset = number(bytes, offset + file_at, entry_width, big)?;
            let file_size = number(bytes, offset + file_size_at, entry_width, big)?;
            if kind != 0 && file_size > 0 {
                declared_file_end = declared_file_end.max(
                    raw_file_offset
                        .checked_add(file_size)
                        .ok_or("ELF segment file range overflow")?,
                );
            }
            if kind == 0x6474_e551 {
                let flags_at = offset + if entry_width == 4 { 24 } else { 4 };
                elf_stack_flags_field = Some(NumericField {
                    offset: flags_at,
                    width: 4,
                    value: number(bytes, flags_at, 4, big)?,
                    decoder: if big { "u32be" } else { "u32le" },
                });
            }
            if kind == 0x6474_e552 {
                let size_at = offset + if entry_width == 4 { 20 } else { 40 };
                elf_relro_segment |= number(bytes, size_at, entry_width, big)? > 0;
            }
            if kind != 1 && kind != 2 {
                continue;
            }
            let (va_at, memory_size_at) = if entry_width == 4 { (8, 20) } else { (16, 40) };
            let file_offset = usize::try_from(raw_file_offset)
                .map_err(|_| "ELF segment file offset outside address space")?;
            let virtual_address = number(bytes, offset + va_at, entry_width, big)?;
            let memory_size = number(bytes, offset + memory_size_at, entry_width, big)?;
            let flags_at = if entry_width == 4 { 24 } else { 4 };
            let flags = number(bytes, offset + flags_at, 4, big)? as u32;
            (file_offset as u64)
                .checked_add(file_size)
                .ok_or("ELF segment file range overflow")?;
            if kind == 1 {
                if file_size > memory_size {
                    return Err("ELF load segment file size exceeds memory size".into());
                }
                let virtual_end = virtual_address
                    .checked_add(memory_size)
                    .ok_or("ELF segment VA overflow")?;
                if entry_width == 4 && virtual_end > u64::from(u32::MAX) + 1 {
                    return Err("ELF load segment outside ELF32 address space".into());
                }
                elf_load_segments.push(LoadSegment {
                    file_offset,
                    file_size,
                    virtual_address,
                    memory_size,
                    flags,
                });
            } else if elf_dynamic.replace((file_offset, file_size)).is_some() {
                return Err("multiple ELF PT_DYNAMIC segments".into());
            }
        }
    }
    Ok(FormatReport {
        name,
        byte_order: if big { "big-endian" } else { "little-endian" },
        machine,
        entry,
        entry_kind: "va",
        sections,
        header_span: (0, header_end),
        declared_file_end,
        machine_field: NumericField {
            offset: 18,
            width: 2,
            value: u64::from(machine),
            decoder: if big { "u16be" } else { "u16le" },
        },
        entry_field: NumericField {
            offset: 24,
            width: entry_width,
            value: entry,
            decoder: match (entry_width, big) {
                (4, false) => "u32le",
                (4, true) => "u32be",
                (8, false) => "u64le",
                _ => "u64be",
            },
        },
        sections_field,
        section_info,
        pe_dll_characteristics_field: None,
        elf_stack_flags_field,
        elf_bind_now: parse_elf_bind_now(bytes, elf_dynamic, entry_width, big),
        elf_relro_segment,
        elf_program_headers_present: phnum > 0,
        elf_load_segments,
        elf_dynamic,
        elf_file_type,
        elf_section_types,
        elf_dynsym_sections,
        elf_symbols: Arc::new(OnceLock::new()),
        elf_symtab_sections,
        elf_static_symbols: Arc::new(OnceLock::new()),
        elf_relocation_sections,
        elf_relocations: Arc::new(OnceLock::new()),
        elf_needed: Arc::new(OnceLock::new()),
        pe_headers_size: None,
        pe_image_base_field: None,
        pe_import_directory: Ok(None),
        pe_delay_import_directory: Ok(None),
        pe_export_directory: Ok(None),
        pe_relocation_directory: Ok(None),
        pe_certificate_directory: Ok(None),
        pe_debug_directory: Ok(None),
        pe_thunk_width: 0,
        pe_dependencies: Arc::new(OnceLock::new()),
        pe_imports: Arc::new(OnceLock::new()),
        pe_delay_imports: Arc::new(OnceLock::new()),
        pe_delay_dependencies: Arc::new(OnceLock::new()),
        pe_exports: Arc::new(OnceLock::new()),
        pe_relocations: Arc::new(OnceLock::new()),
        pe_certificates: Arc::new(OnceLock::new()),
        pe_debug_entries: Arc::new(OnceLock::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::{probe, section_name};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn exercise_mutated_format(bytes: &[u8]) {
        if let Ok(report) = probe(bytes) {
            let _ = report.summary();
            let _ = report.overlay_range(bytes.len());
            let _ = report.field("entry");
            let _ = report.section(0);
            let _ = report.dependencies(bytes);
            for name in [
                "pe.dynamic_base",
                "pe.nx_compat",
                "pe.guard_cf",
                "pe.high_entropy_va",
                "elf.et_dyn",
                "elf.gnu_stack_nx",
                "elf.gnu_relro",
                "elf.bind_now",
                "elf.relro_now",
                "elf.load_rwx",
            ] {
                let _ = report.signal(name);
            }
            if report.name.starts_with("PE") {
                let _ = report.certificates(bytes);
                let _ = report.imports(bytes);
                let _ = report.delay_imports(bytes);
                let _ = report.delay_dependencies(bytes);
                let _ = report.exports(bytes);
                let _ = report.relocations(bytes);
                for rva in [0, 1, 0x1000, u64::from(u32::MAX)] {
                    let _ = report.pe_rva_range(bytes.len(), rva, 1);
                }
            } else {
                let _ = report.relocations(bytes);
                let _ = report.dynamic_symbols(bytes);
                for va in [0, 1, report.entry, u64::MAX] {
                    let _ = report.elf_va_range(bytes.len(), va, 1);
                }
                let _ = report.needed_libraries(bytes);
            }
        }
    }

    fn elf64_with_needed() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x200];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400100_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x400100_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&0x100_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&0x100_u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&2_u32.to_le_bytes());
        bytes[128..136].copy_from_slice(&0x120_u64.to_le_bytes());
        bytes[136..144].copy_from_slice(&0x400120_u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&80_u64.to_le_bytes());
        bytes[160..168].copy_from_slice(&80_u64.to_le_bytes());
        for (index, (tag, value)) in [(5, 0x400180), (10, 32), (1, 1), (1, 11), (0, 0)]
            .into_iter()
            .enumerate()
        {
            let offset = 0x120 + index * 16;
            bytes[offset..offset + 8].copy_from_slice(&(tag as u64).to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&(value as u64).to_le_bytes());
        }
        bytes[0x180..0x195].copy_from_slice(b"\0libc.so.6\0libm.so.6\0");
        bytes
    }

    fn elf64_with_dynsym(sections: bool, gnu_only: bool) -> Vec<u8> {
        let mut bytes = elf64_with_needed();
        bytes.resize(0x500, 0);
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[96..104].copy_from_slice(&0x400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&0x400_u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&112_u64.to_le_bytes());
        bytes[160..168].copy_from_slice(&112_u64.to_le_bytes());
        let hash_tag = if gnu_only { 0x6fff_fef5 } else { 4 };
        let hash_va = if gnu_only { 0x400320 } else { 0x400300 };
        for (index, (tag, value)) in [
            (6_u64, 0x400200_u64),
            (11, 24),
            (5, 0x400280),
            (10, 14),
            (hash_tag, hash_va),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let base = 0x120 + index * 16;
            bytes[base..base + 8].copy_from_slice(&tag.to_le_bytes());
            bytes[base + 8..base + 16].copy_from_slice(&value.to_le_bytes());
        }
        for (index, (name, info, section, address, size)) in [
            (0_u32, 0_u8, 0_u16, 0_u64, 0_u64),
            (1, 0x12, 0, 0, 0),
            (6, 0x12, 1, 0x401000, 12),
        ]
        .into_iter()
        .enumerate()
        {
            let base = 0x200 + index * 24;
            bytes[base..base + 4].copy_from_slice(&name.to_le_bytes());
            bytes[base + 4] = info;
            bytes[base + 6..base + 8].copy_from_slice(&section.to_le_bytes());
            bytes[base + 8..base + 16].copy_from_slice(&address.to_le_bytes());
            bytes[base + 16..base + 24].copy_from_slice(&size.to_le_bytes());
        }
        bytes[0x280..0x28e].copy_from_slice(b"\0puts\0inspect\0");
        bytes[0x300..0x304].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x304..0x308].copy_from_slice(&3_u32.to_le_bytes());
        bytes[0x308..0x30c].copy_from_slice(&1_u32.to_le_bytes());
        for (index, value) in [1_u32, 1, 1, 5].into_iter().enumerate() {
            bytes[0x320 + index * 4..0x324 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x338..0x33c].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x33c..0x340].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0x340..0x344].copy_from_slice(&0x101_u32.to_le_bytes());
        if sections {
            bytes[40..48].copy_from_slice(&0x380_u64.to_le_bytes());
            bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
            bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
            let dynsym = 0x380 + 64;
            bytes[dynsym + 4..dynsym + 8].copy_from_slice(&11_u32.to_le_bytes());
            bytes[dynsym + 24..dynsym + 32].copy_from_slice(&0x200_u64.to_le_bytes());
            bytes[dynsym + 32..dynsym + 40].copy_from_slice(&72_u64.to_le_bytes());
            bytes[dynsym + 40..dynsym + 44].copy_from_slice(&2_u32.to_le_bytes());
            bytes[dynsym + 56..dynsym + 64].copy_from_slice(&24_u64.to_le_bytes());
            let dynstr = 0x380 + 128;
            bytes[dynstr + 4..dynstr + 8].copy_from_slice(&3_u32.to_le_bytes());
            bytes[dynstr + 24..dynstr + 32].copy_from_slice(&0x280_u64.to_le_bytes());
            bytes[dynstr + 32..dynstr + 40].copy_from_slice(&14_u64.to_le_bytes());
        }
        bytes
    }

    fn elf32_be_with_dynsym() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x300];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[1, 2, 1]);
        bytes[16..18].copy_from_slice(&3_u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&3_u16.to_be_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&52_u32.to_be_bytes());
        bytes[40..42].copy_from_slice(&52_u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&32_u16.to_be_bytes());
        bytes[44..46].copy_from_slice(&2_u16.to_be_bytes());
        for (index, (kind, offset, va, size)) in [
            (1_u32, 0x100_u32, 0x1000_u32, 0x200_u32),
            (2, 0x120, 0x1020, 48),
        ]
        .into_iter()
        .enumerate()
        {
            let base = 52 + index * 32;
            bytes[base..base + 4].copy_from_slice(&kind.to_be_bytes());
            bytes[base + 4..base + 8].copy_from_slice(&offset.to_be_bytes());
            bytes[base + 8..base + 12].copy_from_slice(&va.to_be_bytes());
            bytes[base + 16..base + 20].copy_from_slice(&size.to_be_bytes());
            bytes[base + 20..base + 24].copy_from_slice(&size.to_be_bytes());
            bytes[base + 24..base + 28].copy_from_slice(&5_u32.to_be_bytes());
        }
        for (index, (tag, value)) in [
            (6_u32, 0x1080_u32),
            (11, 16),
            (5, 0x10c0),
            (10, 14),
            (4, 0x10e0),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let base = 0x120 + index * 8;
            bytes[base..base + 4].copy_from_slice(&tag.to_be_bytes());
            bytes[base + 4..base + 8].copy_from_slice(&value.to_be_bytes());
        }
        for (index, (name, section, address)) in [(0_u32, 0_u16, 0_u32), (1, 0, 0), (6, 1, 0x2000)]
            .into_iter()
            .enumerate()
        {
            let base = 0x180 + index * 16;
            bytes[base..base + 4].copy_from_slice(&name.to_be_bytes());
            bytes[base + 4..base + 8].copy_from_slice(&address.to_be_bytes());
            bytes[base + 12] = if index == 0 { 0 } else { 0x12 };
            bytes[base + 14..base + 16].copy_from_slice(&section.to_be_bytes());
        }
        bytes[0x1c0..0x1ce].copy_from_slice(b"\0puts\0inspect\0");
        bytes[0x1e0..0x1e4].copy_from_slice(&1_u32.to_be_bytes());
        bytes[0x1e4..0x1e8].copy_from_slice(&3_u32.to_be_bytes());
        bytes
    }

    #[test]
    fn elf_dynamic_symbols_follow_sections_sysv_and_gnu_hash() {
        for (sections, gnu_only) in [(true, false), (false, false), (false, true)] {
            let bytes = elf64_with_dynsym(sections, gnu_only);
            let report = probe(&bytes).unwrap();
            let symbols = report.dynamic_symbols(&bytes).unwrap();
            assert_eq!(symbols.len(), 3);
            assert_eq!(symbols[0].name, "");
            assert_eq!(symbols[1].name, "puts");
            assert_eq!(symbols[1].role(), "undefined");
            assert_eq!(symbols[1].type_name(), "function");
            assert_eq!(symbols[2].name, "inspect");
            assert_eq!(symbols[2].role(), "exported");
            assert_eq!(symbols[2].address, 0x401000);
            assert_eq!(symbols[2].size, 12);
        }
        let bytes = elf32_be_with_dynsym();
        let report = probe(&bytes).unwrap();
        let symbols = report.dynamic_symbols(&bytes).unwrap();
        assert_eq!(report.name, "ELF32");
        assert_eq!(report.byte_order, "big-endian");
        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[1].name, "puts");
        assert_eq!(symbols[2].name, "inspect");
        assert_eq!(symbols[2].address, 0x2000);
    }

    #[test]
    fn elf_dynamic_symbols_reject_bad_links_names_and_missing_counts() {
        let mut bad_link = elf64_with_dynsym(true, false);
        bad_link[0x3e8..0x3ec].copy_from_slice(&3_u32.to_le_bytes());
        let report = probe(&bad_link).unwrap();
        assert!(report
            .dynamic_symbols(&bad_link)
            .unwrap_err()
            .contains("SHT_STRTAB"));

        let mut bad_name = elf64_with_dynsym(true, false);
        bad_name[0x218..0x21c].copy_from_slice(&100_u32.to_le_bytes());
        let report = probe(&bad_name).unwrap();
        assert!(report
            .dynamic_symbols(&bad_name)
            .unwrap_err()
            .contains("name offset"));

        let mut no_hash = elf64_with_dynsym(false, false);
        no_hash[0x160..0x168].copy_from_slice(&42_u64.to_le_bytes());
        let report = probe(&no_hash).unwrap();
        assert!(report
            .dynamic_symbols(&no_hash)
            .unwrap_err()
            .contains("DT_HASH"));

        let mut bad_chain = elf64_with_dynsym(false, true);
        bad_chain[0x340..0x344].copy_from_slice(&0x100_u32.to_le_bytes());
        let report = probe(&bad_chain).unwrap();
        assert!(report.dynamic_symbols(&bad_chain).is_err());

        let mut bad_buckets = elf64_with_dynsym(false, true);
        bad_buckets[0x320..0x324].copy_from_slice(&2_u32.to_le_bytes());
        bad_buckets[0x338..0x33c].copy_from_slice(&2_u32.to_le_bytes());
        bad_buckets[0x33c..0x340].copy_from_slice(&1_u32.to_le_bytes());
        let report = probe(&bad_buckets).unwrap();
        assert!(report
            .dynamic_symbols(&bad_buckets)
            .unwrap_err()
            .contains("out of order"));
    }

    fn elf64_with_relocations(sections: bool) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x400];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x400100_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&0x200_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&0x200_u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&2_u32.to_le_bytes());
        bytes[128..136].copy_from_slice(&0x120_u64.to_le_bytes());
        bytes[136..144].copy_from_slice(&0x400120_u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&128_u64.to_le_bytes());
        bytes[160..168].copy_from_slice(&128_u64.to_le_bytes());
        for (index, (tag, value)) in [
            (7_u64, 0x400200_u64),
            (8, 48),
            (9, 24),
            (23, 0x400230),
            (2, 24),
            (20, 7),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 0x120 + index * 16;
            bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
        }
        for (index, (address, info, addend)) in [
            (0x404000_u64, 8_u64, 0x1234_i64),
            (0x404008, (1_u64 << 32) | 6, -4),
            (0x404010, (2_u64 << 32) | 7, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 0x200 + index * 24;
            bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&info.to_le_bytes());
            bytes[offset + 16..offset + 24].copy_from_slice(&addend.to_le_bytes());
        }
        if sections {
            bytes[40..48].copy_from_slice(&0x300_u64.to_le_bytes());
            bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
            bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
            for (index, (offset, size)) in
                [(0x200_u64, 48_u64), (0x230, 24)].into_iter().enumerate()
            {
                let base = 0x340 + index * 64;
                bytes[base + 4..base + 8].copy_from_slice(&4_u32.to_le_bytes());
                bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
                bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
                bytes[base + 56..base + 64].copy_from_slice(&24_u64.to_le_bytes());
            }
        }
        bytes
    }

    fn elf64_with_relr(section: bool, dynamic: bool) -> Vec<u8> {
        let mut bytes = elf64_with_relocations(section);
        bytes.resize(0x500, 0);
        for (index, entry) in [0x405000_u64, 0b1011, 0b101].into_iter().enumerate() {
            bytes[0x280 + index * 8..0x288 + index * 8].copy_from_slice(&entry.to_le_bytes());
        }
        if section {
            bytes[60..62].copy_from_slice(&4_u16.to_le_bytes());
            let base = 0x3c0;
            bytes[base + 4..base + 8].copy_from_slice(&19_u32.to_le_bytes());
            bytes[base + 24..base + 32].copy_from_slice(&0x280_u64.to_le_bytes());
            bytes[base + 32..base + 40].copy_from_slice(&24_u64.to_le_bytes());
            bytes[base + 56..base + 64].copy_from_slice(&8_u64.to_le_bytes());
        }
        if dynamic {
            bytes[152..160].copy_from_slice(&160_u64.to_le_bytes());
            bytes[160..168].copy_from_slice(&160_u64.to_le_bytes());
            for (index, (tag, value)) in [(36_u64, 0x400280_u64), (35, 24), (37, 8), (0, 0)]
                .into_iter()
                .enumerate()
            {
                let offset = 0x120 + (6 + index) * 16;
                bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn elf64_relocations_follow_sections_or_dynamic_tables() {
        for sections in [false, true] {
            let bytes = elf64_with_relocations(sections);
            let report = probe(&bytes).unwrap();
            let relocations = report.relocations(&bytes).unwrap();
            assert_eq!(relocations.len(), 3);
            assert_eq!(report.relocation_location(), "va");
            assert_eq!(report.relocation_kind(8), "R_X86_64_RELATIVE");
            assert_eq!(relocations[0].address, 0x404000);
            assert_eq!(relocations[0].kind, 8);
            assert_eq!(relocations[0].symbol, Some(0));
            assert_eq!(relocations[0].addend, Some(0x1234));
            assert_eq!(relocations[1].kind, 6);
            assert_eq!(relocations[1].symbol, Some(1));
            assert_eq!(relocations[1].addend, Some(-4));
            assert_eq!(relocations[2].kind, 7);
            assert_eq!(relocations[2].symbol, Some(2));
        }
    }

    #[test]
    fn elf_relocations_reject_incomplete_tables() {
        let mut malformed = elf64_with_relocations(false);
        malformed[0x120 + 2 * 16 + 8..0x120 + 2 * 16 + 16].copy_from_slice(&8_u64.to_le_bytes());
        assert_eq!(
            probe(&malformed)
                .unwrap()
                .relocations(&malformed)
                .unwrap_err(),
            "invalid ELF relocation entry size"
        );
        let bytes = elf64_with_relocations(false);
        let truncated = &bytes[..0x230];
        assert!(probe(truncated).unwrap().relocations(truncated).is_err());
    }

    #[test]
    fn elf64_relr_decodes_sections_and_dynamic_tables_once() {
        for (section, dynamic) in [(true, false), (false, true), (true, true)] {
            let bytes = elf64_with_relr(section, dynamic);
            let report = probe(&bytes).unwrap();
            let relocations = report.relocations(&bytes).unwrap();
            assert_eq!(relocations.len(), 7);
            assert_eq!(
                relocations
                    .iter()
                    .filter(|entry| entry.relr)
                    .map(|entry| entry.address)
                    .collect::<Vec<_>>(),
                [0x405000, 0x405008, 0x405018, 0x405208]
            );
            assert_eq!(report.relocation_label(&relocations[3]), "RELR_RELATIVE");
            assert_eq!(relocations[3].symbol, None);
            assert_eq!(relocations[3].addend, None);
        }
    }

    #[test]
    fn elf64_relr_rejects_malformed_tables() {
        let mut bytes = elf64_with_relr(false, true);
        bytes[0x280..0x288].copy_from_slice(&3_u64.to_le_bytes());
        assert_eq!(
            probe(&bytes).unwrap().relocations(&bytes).unwrap_err(),
            "ELF RELR bitmap without address"
        );
        let mut bytes = elf64_with_relr(true, false);
        bytes[0x3f8..0x400].copy_from_slice(&16_u64.to_le_bytes());
        assert_eq!(
            probe(&bytes).unwrap().relocations(&bytes).unwrap_err(),
            "invalid ELF relocation entry size"
        );
        let mut bytes = elf64_with_relr(false, true);
        bytes[0x1a0..0x1a8].copy_from_slice(&0_u64.to_le_bytes());
        assert_eq!(
            probe(&bytes).unwrap().relocations(&bytes).unwrap_err(),
            "incomplete ELF RELR dynamic table"
        );
    }

    #[test]
    fn elf32_relr_decodes_both_byte_orders() {
        fn put(bytes: &mut [u8], offset: usize, value: u32, big: bool) {
            let encoded = if big {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            bytes[offset..offset + 4].copy_from_slice(&encoded);
        }
        fn put16(bytes: &mut [u8], offset: usize, value: u16, big: bool) {
            let encoded = if big {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            bytes[offset..offset + 2].copy_from_slice(&encoded);
        }
        for big in [false, true] {
            let mut bytes = vec![0_u8; 0x200];
            bytes[0..4].copy_from_slice(b"\x7fELF");
            bytes[4..7].copy_from_slice(&[1, if big { 2 } else { 1 }, 1]);
            put16(&mut bytes, 16, 3, big);
            put16(&mut bytes, 18, 3, big);
            put(&mut bytes, 20, 1, big);
            put(&mut bytes, 32, 0x80, big);
            put16(&mut bytes, 40, 52, big);
            put16(&mut bytes, 46, 40, big);
            put16(&mut bytes, 48, 2, big);
            put(&mut bytes, 0xa8 + 4, 19, big);
            put(&mut bytes, 0xa8 + 16, 0x150, big);
            put(&mut bytes, 0xa8 + 20, 12, big);
            put(&mut bytes, 0xa8 + 36, 4, big);
            for (index, entry) in [0x1000, 0b1011, 0b101].into_iter().enumerate() {
                put(&mut bytes, 0x150 + index * 4, entry, big);
            }
            let report = probe(&bytes).unwrap();
            assert_eq!(
                report
                    .relocations(&bytes)
                    .unwrap()
                    .iter()
                    .map(|entry| entry.address)
                    .collect::<Vec<_>>(),
                [0x1000, 0x1004, 0x100c, 0x1084]
            );
        }
    }

    #[test]
    fn elf32_rel_and_rela_support_both_byte_orders() {
        fn put(bytes: &mut [u8], offset: usize, value: u64, width: usize, big: bool) {
            let word = if big {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            let range = if big { 8 - width..8 } else { 0..width };
            bytes[offset..offset + width].copy_from_slice(&word[range]);
        }
        for big in [false, true] {
            for rela in [false, true] {
                let mut bytes = vec![0_u8; 0x200];
                bytes[0..4].copy_from_slice(b"\x7fELF");
                bytes[4..7].copy_from_slice(&[1, if big { 2 } else { 1 }, 1]);
                put(&mut bytes, 16, 1, 2, big);
                put(&mut bytes, 18, 3, 2, big);
                put(&mut bytes, 20, 1, 4, big);
                put(&mut bytes, 32, 0x80, 4, big);
                put(&mut bytes, 40, 52, 2, big);
                put(&mut bytes, 46, 40, 2, big);
                put(&mut bytes, 48, 2, 2, big);
                let section = 0xa8;
                let entry_size = if rela { 12 } else { 8 };
                put(&mut bytes, section + 4, if rela { 4 } else { 9 }, 4, big);
                put(&mut bytes, section + 16, 0x150, 4, big);
                put(&mut bytes, section + 20, entry_size, 4, big);
                put(&mut bytes, section + 36, entry_size, 4, big);
                put(&mut bytes, 0x150, 0x10, 4, big);
                put(&mut bytes, 0x154, (2 << 8) | 1, 4, big);
                if rela {
                    put(&mut bytes, 0x158, u64::from(u32::MAX - 3), 4, big);
                }
                let report = probe(&bytes).unwrap();
                let relocations = report.relocations(&bytes).unwrap();
                assert_eq!(report.relocation_location(), "section_offset");
                assert_eq!(relocations.len(), 1);
                assert_eq!(relocations[0].address, 0x10);
                assert_eq!(relocations[0].kind, 1);
                assert_eq!(relocations[0].symbol, Some(2));
                assert_eq!(relocations[0].addend, rela.then_some(-4));
            }
        }
    }

    #[test]
    fn elf_needed_libraries_follow_dynamic_string_table() {
        let bytes = elf64_with_needed();
        let report = probe(&bytes).unwrap();
        assert_eq!(
            report.needed_libraries(&bytes).unwrap(),
            ["libc.so.6", "libm.so.6"]
        );
        assert_eq!(report.needed_libraries(&bytes).unwrap().len(), 2);
        let mut invalid = bytes.clone();
        invalid[0x120 + 3 * 16 + 8..0x120 + 3 * 16 + 16].copy_from_slice(&99_u64.to_le_bytes());
        assert_eq!(
            probe(&invalid)
                .unwrap()
                .needed_libraries(&invalid)
                .unwrap_err(),
            "ELF needed name offset out of range"
        );
        let mut unterminated = bytes.clone();
        unterminated[0x120 + 4 * 16..0x120 + 4 * 16 + 8].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(
            probe(&unterminated)
                .unwrap()
                .needed_libraries(&unterminated)
                .unwrap_err(),
            "ELF dynamic table has no DT_NULL terminator"
        );
        let short = &bytes[..0x150];
        assert!(probe(short).unwrap().needed_libraries(short).is_err());
        assert_eq!(
            report.dependencies(&bytes).unwrap(),
            ["libc.so.6", "libm.so.6"]
        );
    }

    fn elf64_with_load() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x200];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x401000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&32_u64.to_le_bytes());
        bytes[0x100..0x104].copy_from_slice(b"GAK\0");
        bytes
    }

    #[test]
    fn elf_overlay_starts_after_all_declared_file_ranges() {
        let mut bytes = elf64_with_load();
        bytes.truncate(0x110);
        let report = probe(&bytes).unwrap();
        assert_eq!(report.overlay_range(bytes.len()).unwrap(), (0x110, 0x110));
        bytes.extend_from_slice(b"TAIL");
        assert_eq!(
            probe(&bytes).unwrap().overlay_range(bytes.len()).unwrap(),
            (0x110, 0x114)
        );

        let short = &bytes[..0x10f];
        assert_eq!(
            probe(short)
                .unwrap()
                .overlay_range(short.len())
                .unwrap_err(),
            "declared binary extent outside captured Source"
        );

        // A PT_NOTE after PT_LOAD is still declared file content, not an overlay.
        let mut noted = bytes;
        noted[56..58].copy_from_slice(&2_u16.to_le_bytes());
        noted[120..124].copy_from_slice(&4_u32.to_le_bytes());
        noted[128..136].copy_from_slice(&0x112_u64.to_le_bytes());
        noted[152..160].copy_from_slice(&2_u64.to_le_bytes());
        assert_eq!(
            probe(&noted).unwrap().overlay_range(noted.len()).unwrap(),
            (0x114, 0x114)
        );
    }

    #[test]
    fn elf32_big_endian_load_segment_maps_entry_bytes() {
        let mut bytes = vec![0_u8; 0x200];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[1, 2, 1]);
        bytes[20..24].copy_from_slice(&1_u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&0x0804_8000_u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&52_u32.to_be_bytes());
        bytes[40..42].copy_from_slice(&52_u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&32_u16.to_be_bytes());
        bytes[44..46].copy_from_slice(&1_u16.to_be_bytes());
        bytes[52..56].copy_from_slice(&1_u32.to_be_bytes());
        bytes[56..60].copy_from_slice(&0x100_u32.to_be_bytes());
        bytes[60..64].copy_from_slice(&0x0804_8000_u32.to_be_bytes());
        bytes[68..72].copy_from_slice(&4_u32.to_be_bytes());
        bytes[72..76].copy_from_slice(&8_u32.to_be_bytes());
        bytes[0x100..0x104].copy_from_slice(b"GAK\0");
        let report = probe(&bytes).unwrap();
        assert_eq!(report.entry, 0x0804_8000);
        assert_eq!(report.header_span, (0, 84));
        assert_eq!(
            report.elf_va_range(bytes.len(), report.entry, 4).unwrap(),
            (0x100, 0x104)
        );
        let mut overflow = bytes;
        overflow[60..64].copy_from_slice(&0xffff_fff0_u32.to_be_bytes());
        overflow[72..76].copy_from_slice(&32_u32.to_be_bytes());
        assert_eq!(
            probe(&overflow).err().unwrap(),
            "ELF load segment outside ELF32 address space"
        );
    }

    #[test]
    fn elf_load_segments_map_only_captured_file_bytes() {
        let bytes = elf64_with_load();
        let report = probe(&bytes).unwrap();
        assert_eq!(report.header_span, (0, 120));
        assert_eq!(
            report.elf_va_range(bytes.len(), report.entry, 4).unwrap(),
            (0x100, 0x104)
        );
        assert_eq!(
            report.elf_va_range(bytes.len(), 0x401010, 1).unwrap_err(),
            "VA range has no file-backed bytes"
        );
        assert_eq!(
            report.elf_va_range(0x105, report.entry, 16).unwrap_err(),
            "VA data outside captured Source"
        );
        assert_eq!(
            report.elf_va_range(bytes.len(), 0x40100f, 2).unwrap_err(),
            "VA range has no file-backed bytes"
        );
        assert_eq!(
            report
                .elf_va_range(bytes.len(), report.entry, 0)
                .unwrap_err(),
            "VA view length must be positive"
        );
    }

    #[test]
    fn elf_program_headers_reject_malformed_or_ambiguous_mapping() {
        let bytes = elf64_with_load();
        let mut wrong_size = bytes.clone();
        wrong_size[54..56].copy_from_slice(&48_u16.to_le_bytes());
        assert_eq!(
            probe(&wrong_size).err().unwrap(),
            "invalid ELF program header table"
        );
        let mut wrong_filesz = bytes.clone();
        wrong_filesz[96..104].copy_from_slice(&33_u64.to_le_bytes());
        assert_eq!(
            probe(&wrong_filesz).err().unwrap(),
            "ELF load segment file size exceeds memory size"
        );
        assert!(probe(&bytes[..100]).is_err());
        let mut overlap = bytes;
        overlap[56..58].copy_from_slice(&2_u16.to_le_bytes());
        overlap[120..124].copy_from_slice(&1_u32.to_le_bytes());
        overlap[128..136].copy_from_slice(&0x110_u64.to_le_bytes());
        overlap[136..144].copy_from_slice(&0x401008_u64.to_le_bytes());
        overlap[152..160].copy_from_slice(&8_u64.to_le_bytes());
        overlap[160..168].copy_from_slice(&8_u64.to_le_bytes());
        let report = probe(&overlap).unwrap();
        assert_eq!(
            report.elf_va_range(overlap.len(), 0x401008, 1).unwrap_err(),
            "VA maps to multiple ELF load segments"
        );

        let mut extended = elf64_with_load();
        extended[40..48].copy_from_slice(&0x180_u64.to_le_bytes());
        extended[56..58].copy_from_slice(&0xffff_u16.to_le_bytes());
        extended[58..60].copy_from_slice(&64_u16.to_le_bytes());
        extended[0x180 + 32..0x180 + 40].copy_from_slice(&1_u64.to_le_bytes());
        extended[0x180 + 44..0x180 + 48].copy_from_slice(&1_u32.to_le_bytes());
        let report = probe(&extended).unwrap();
        assert_eq!(
            report
                .elf_va_range(extended.len(), report.entry, 4)
                .unwrap(),
            (0x100, 0x104)
        );
    }

    #[test]
    fn mutated_and_truncated_pe_elf_inputs_do_not_panic() {
        let mut elf = vec![0_u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4..7].copy_from_slice(&[2, 1, 1]);
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        let seeds = [
            pe_with_imports(false),
            pe_with_delay_imports(true),
            pe_with_legacy_delay_imports(false),
            pe_with_exports(true),
            elf,
            elf64_with_load(),
            elf64_with_needed(),
        ];
        for (seed_index, seed) in seeds.iter().enumerate() {
            for length in 0..=seed.len() {
                assert!(
                    catch_unwind(AssertUnwindSafe(|| exercise_mutated_format(
                        &seed[..length]
                    )))
                    .is_ok(),
                    "seed {seed_index} truncated at {length} panicked"
                );
            }
            for offset in 0..seed.len() {
                for replacement in [0, 1, 0x7f, 0x80, 0xff] {
                    let mut bytes = seed.clone();
                    bytes[offset] = replacement;
                    assert!(
                        catch_unwind(AssertUnwindSafe(|| exercise_mutated_format(&bytes))).is_ok(),
                        "seed {seed_index} byte {offset} value {replacement:#04x} panicked"
                    );
                }
            }
            for offset in 0..seed.len().saturating_sub(3) {
                for replacement in [0_u32, 1, u32::MAX] {
                    let mut bytes = seed.clone();
                    bytes[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
                    assert!(
                        catch_unwind(AssertUnwindSafe(|| exercise_mutated_format(&bytes))).is_ok(),
                        "seed {seed_index} dword {offset} value {replacement:#010x} panicked"
                    );
                }
            }
        }
        let rounds = std::env::var("GALEIKAN_FORMAT_MUTATIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4096)
            .min(1_000_000);
        let mut state = 0x5e28_6f31_a4c9_7b0d_u64;
        for case in 0..rounds {
            let seed_index = case % seeds.len();
            let mut bytes = seeds[seed_index].clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let changes = 1 + (state as usize % 8);
            for _ in 0..changes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let offset = state as usize % bytes.len();
                bytes[offset] ^= (state >> 24) as u8;
            }
            if state & 3 == 0 {
                bytes.truncate(state as usize % (bytes.len() + 1));
            }
            assert!(
                catch_unwind(AssertUnwindSafe(|| exercise_mutated_format(&bytes))).is_ok(),
                "seed {seed_index} mutation {case} panicked"
            );
        }
    }

    fn pe_with_exports(plus: bool) -> Vec<u8> {
        let optional_size = if plus { 0xf0 } else { 0xe0 };
        let optional = 0x98;
        let section_table = optional + optional_size;
        let mut bytes = vec![0_u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[optional..optional + 2]
            .copy_from_slice(&(if plus { 0x20b_u16 } else { 0x10b_u16 }).to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        let count_at = if plus { 108 } else { 92 };
        let export_at = if plus { 112 } else { 96 };
        bytes[optional + count_at..optional + count_at + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[optional + export_at..optional + export_at + 4]
            .copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[optional + export_at + 4..optional + export_at + 8]
            .copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[section_table..section_table + 6].copy_from_slice(b".edata");
        bytes[section_table + 8..section_table + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section_table + 16..section_table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x210..0x214].copy_from_slice(&5_u32.to_le_bytes());
        bytes[0x214..0x218].copy_from_slice(&3_u32.to_le_bytes());
        bytes[0x218..0x21c].copy_from_slice(&2_u32.to_le_bytes());
        bytes[0x21c..0x220].copy_from_slice(&0x1040_u32.to_le_bytes());
        bytes[0x220..0x224].copy_from_slice(&0x1060_u32.to_le_bytes());
        bytes[0x224..0x228].copy_from_slice(&0x1070_u32.to_le_bytes());
        bytes[0x240..0x244].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[0x244..0x248].copy_from_slice(&0x1080_u32.to_le_bytes());
        bytes[0x248..0x24c].copy_from_slice(&0x3000_u32.to_le_bytes());
        bytes[0x260..0x264].copy_from_slice(&0x10a0_u32.to_le_bytes());
        bytes[0x264..0x268].copy_from_slice(&0x10a8_u32.to_le_bytes());
        bytes[0x272..0x274].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x280..0x28d].copy_from_slice(b"OTHER.Target\0");
        bytes[0x2a0..0x2a6].copy_from_slice(b"Alpha\0");
        bytes[0x2a8..0x2ad].copy_from_slice(b"Beta\0");
        bytes
    }

    #[test]
    fn pe_signals_report_declared_flags_and_missing_metadata() {
        let mut bytes = pe_with_exports(true);
        bytes[0x98 + 70..0x98 + 72].copy_from_slice(&0x4160_u16.to_le_bytes());
        let report = probe(&bytes).unwrap();
        assert_eq!(report.signal("pe.dynamic_base").unwrap(), "present");
        assert_eq!(report.signal("pe.nx_compat").unwrap(), "present");
        assert_eq!(report.signal("pe.guard_cf").unwrap(), "present");
        assert_eq!(report.signal("pe.high_entropy_va").unwrap(), "present");
        let field = report.field("dll_characteristics").unwrap();
        assert_eq!(
            (field.offset, field.width, field.value),
            (0x98 + 70, 2, 0x4160)
        );
        bytes[0x98 + 70..0x98 + 72].fill(0);
        assert_eq!(
            probe(&bytes).unwrap().signal("pe.nx_compat").unwrap(),
            "absent"
        );
        bytes[0x94..0x96].copy_from_slice(&20_u16.to_le_bytes());
        let short = probe(&bytes).unwrap();
        assert_eq!(short.signal("pe.nx_compat").unwrap(), "unknown");
        assert!(short.field("dll_characteristics").is_none());
        assert_eq!(short.signal("elf.gnu_relro").unwrap(), "not_applicable");
        assert!(short
            .signal("pe.unknown")
            .unwrap_err()
            .contains("unknown format signal"));
        let mut pe32 = pe_with_exports(false);
        pe32[0x98 + 70..0x98 + 72].copy_from_slice(&0x0020_u16.to_le_bytes());
        assert_eq!(
            probe(&pe32).unwrap().signal("pe.high_entropy_va").unwrap(),
            "not_applicable"
        );
    }

    #[test]
    fn pe_section_wx_signal_points_to_the_declared_section_flags() {
        let mut bytes = pe_with_exports(true);
        let flags_offset = 0x98 + 0xf0 + 36;
        bytes[flags_offset..flags_offset + 4].copy_from_slice(&0xe000_0020_u32.to_le_bytes());
        let report = probe(&bytes).unwrap();
        let section = report.section(0).unwrap();
        assert!(section.writable && section.executable);
        assert_eq!(report.signal("pe.section_wx").unwrap(), "present");
        let field = report.signal_field("pe.section_wx").unwrap();
        assert_eq!(
            (field.offset, field.width, field.value),
            (flags_offset, 4, 0xe000_0020)
        );
        assert_eq!(field.decoder, "u32le");

        bytes[flags_offset..flags_offset + 4].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        let report = probe(&bytes).unwrap();
        assert!(!report.section(0).unwrap().writable);
        assert_eq!(report.signal("pe.section_wx").unwrap(), "absent");
        assert!(report.signal_field("pe.section_wx").is_none());
        assert_eq!(
            probe(&elf_with_signals())
                .unwrap()
                .signal("pe.section_wx")
                .unwrap(),
            "not_applicable"
        );
    }

    fn elf_with_signals() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64 + 3 * 56];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&3_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[64 + 32..64 + 40].copy_from_slice(&1_u64.to_le_bytes());
        bytes[64 + 40..64 + 48].copy_from_slice(&1_u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&0x6474_e551_u32.to_le_bytes());
        bytes[124..128].copy_from_slice(&6_u32.to_le_bytes());
        bytes[176..180].copy_from_slice(&0x6474_e552_u32.to_le_bytes());
        bytes[176 + 40..176 + 48].copy_from_slice(&16_u64.to_le_bytes());
        bytes
    }

    fn elf64_with_bind_now(tag: u64, value: u64) -> Vec<u8> {
        let mut bytes = elf_with_signals();
        bytes.resize(0x220, 0);
        bytes[56..58].copy_from_slice(&4_u16.to_le_bytes());
        let header = 64 + 3 * 56;
        bytes[header..header + 4].copy_from_slice(&2_u32.to_le_bytes());
        bytes[header + 8..header + 16].copy_from_slice(&0x200_u64.to_le_bytes());
        bytes[header + 32..header + 40].copy_from_slice(&32_u64.to_le_bytes());
        bytes[header + 40..header + 48].copy_from_slice(&32_u64.to_le_bytes());
        bytes[0x200..0x208].copy_from_slice(&tag.to_le_bytes());
        bytes[0x208..0x210].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    #[test]
    fn elf_bind_now_and_relro_now_follow_validated_dynamic_metadata() {
        for (tag, value, field_offset, field_value) in [
            (24, 0, 0x200, 24),
            (30, 8, 0x208, 8),
            (0x6fff_fffb, 1, 0x208, 1),
        ] {
            let report = probe(&elf64_with_bind_now(tag, value)).unwrap();
            assert_eq!(report.signal("elf.bind_now").unwrap(), "present");
            assert_eq!(report.signal("elf.relro_now").unwrap(), "present");
            let field = report.signal_field("elf.bind_now").unwrap();
            assert_eq!(
                (field.offset, field.width, field.value),
                (field_offset, 8, field_value)
            );
            assert_eq!(field.decoder, "u64le");
            assert!(report.signal_field("elf.relro_now").is_none());
        }
        let absent = probe(&elf64_with_bind_now(30, 0)).unwrap();
        assert_eq!(absent.signal("elf.bind_now").unwrap(), "absent");
        assert_eq!(absent.signal("elf.relro_now").unwrap(), "absent");
        assert_eq!(absent.signal_field("elf.bind_now").unwrap().value, 0);
        let no_marker = probe(&elf64_with_bind_now(1, 0)).unwrap();
        assert_eq!(no_marker.signal("elf.bind_now").unwrap(), "absent");
        assert!(no_marker.signal_field("elf.bind_now").is_none());

        let no_dynamic = probe(&elf_with_signals()).unwrap();
        assert_eq!(no_dynamic.signal("elf.bind_now").unwrap(), "unknown");
        assert_eq!(no_dynamic.signal("elf.relro_now").unwrap(), "unknown");
        let mut no_relro = elf64_with_bind_now(24, 0);
        no_relro[176..180].fill(0);
        assert_eq!(
            probe(&no_relro).unwrap().signal("elf.relro_now").unwrap(),
            "absent"
        );

        let mut unterminated = elf64_with_bind_now(24, 0);
        unterminated[0x210..0x218].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(
            probe(&unterminated)
                .unwrap()
                .signal("elf.bind_now")
                .unwrap(),
            "unknown"
        );
        let mut duplicate = elf64_with_bind_now(24, 0);
        duplicate.resize(0x230, 0);
        duplicate[64 + 3 * 56 + 32..64 + 3 * 56 + 40].copy_from_slice(&48_u64.to_le_bytes());
        duplicate[0x210..0x218].copy_from_slice(&24_u64.to_le_bytes());
        assert_eq!(
            probe(&duplicate).unwrap().signal("elf.bind_now").unwrap(),
            "unknown"
        );
        let truncated = elf64_with_bind_now(24, 0);
        assert_eq!(
            probe(&truncated[..0x210])
                .unwrap()
                .signal("elf.bind_now")
                .unwrap(),
            "unknown"
        );
    }

    #[test]
    fn elf32_big_endian_bind_now_flag_has_field_provenance() {
        let mut bytes = vec![0_u8; 0x110];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[1, 2, 1]);
        bytes[16..18].copy_from_slice(&3_u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&3_u16.to_be_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&52_u32.to_be_bytes());
        bytes[40..42].copy_from_slice(&52_u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&32_u16.to_be_bytes());
        bytes[44..46].copy_from_slice(&2_u16.to_be_bytes());
        bytes[52..56].copy_from_slice(&0x6474_e552_u32.to_be_bytes());
        bytes[52 + 20..52 + 24].copy_from_slice(&16_u32.to_be_bytes());
        bytes[84..88].copy_from_slice(&2_u32.to_be_bytes());
        bytes[84 + 4..84 + 8].copy_from_slice(&0x100_u32.to_be_bytes());
        bytes[84 + 16..84 + 20].copy_from_slice(&16_u32.to_be_bytes());
        bytes[84 + 20..84 + 24].copy_from_slice(&16_u32.to_be_bytes());
        bytes[0x100..0x104].copy_from_slice(&0x6fff_fffb_u32.to_be_bytes());
        bytes[0x104..0x108].copy_from_slice(&1_u32.to_be_bytes());
        let report = probe(&bytes).unwrap();
        assert_eq!(report.signal("elf.bind_now").unwrap(), "present");
        assert_eq!(report.signal("elf.relro_now").unwrap(), "present");
        let field = report.signal_field("elf.bind_now").unwrap();
        assert_eq!((field.offset, field.width, field.value), (0x104, 4, 1));
        assert_eq!(field.decoder, "u32be");
    }

    #[test]
    fn elf_signals_distinguish_metadata_absence_from_disabled_flags() {
        let mut bytes = elf_with_signals();
        let report = probe(&bytes).unwrap();
        assert_eq!(report.signal("elf.et_dyn").unwrap(), "present");
        assert_eq!(report.signal("elf.gnu_stack_nx").unwrap(), "present");
        assert_eq!(report.signal("elf.gnu_relro").unwrap(), "present");
        assert_eq!(report.signal("elf.load_rwx").unwrap(), "absent");
        assert_eq!(report.signal("pe.nx_compat").unwrap(), "not_applicable");
        assert_eq!(report.field("file_type").unwrap().value, 3);
        assert_eq!(report.field("gnu_stack_flags").unwrap().offset, 124);
        bytes[124..128].copy_from_slice(&7_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&7_u32.to_le_bytes());
        let changed = probe(&bytes).unwrap();
        assert_eq!(changed.signal("elf.gnu_stack_nx").unwrap(), "absent");
        assert_eq!(changed.signal("elf.load_rwx").unwrap(), "present");
        bytes[120..124].fill(0);
        bytes[176..180].fill(0);
        let missing = probe(&bytes).unwrap();
        assert_eq!(missing.signal("elf.gnu_stack_nx").unwrap(), "unknown");
        assert_eq!(missing.signal("elf.gnu_relro").unwrap(), "absent");
        bytes[56..58].fill(0);
        let no_program_headers = probe(&bytes).unwrap();
        assert_eq!(
            no_program_headers.signal("elf.gnu_relro").unwrap(),
            "unknown"
        );
        assert_eq!(
            no_program_headers.signal("elf.load_rwx").unwrap(),
            "unknown"
        );

        let mut duplicate = elf_with_signals();
        duplicate.resize(64 + 4 * 56, 0);
        duplicate[56..58].copy_from_slice(&4_u16.to_le_bytes());
        duplicate[232..236].copy_from_slice(&0x6474_e551_u32.to_le_bytes());
        duplicate[236..240].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            probe(&duplicate)
                .unwrap()
                .signal("elf.gnu_stack_nx")
                .unwrap(),
            "absent"
        );
    }

    #[test]
    fn pe_exports_include_named_ordinal_and_forwarded_entries() {
        for plus in [false, true] {
            let bytes = pe_with_exports(plus);
            let report = probe(&bytes).unwrap();
            let exports = report.exports(&bytes).unwrap();
            assert_eq!(exports.len(), 3);
            assert_eq!((&exports[0].name, exports[0].ordinal), (&"Alpha".into(), 5));
            assert_eq!(
                (&exports[0].target, exports[0].kind),
                (&"0x2000".into(), "rva")
            );
            assert_eq!((&exports[1].name, exports[1].ordinal), (&"Beta".into(), 6));
            assert_eq!(
                (&exports[1].target, exports[1].kind),
                (&"OTHER.Target".into(), "forwarder")
            );
            assert_eq!((&exports[2].name, exports[2].ordinal), (&"#7".into(), 7));
            assert!(!exports[2].named);
        }
    }

    #[test]
    fn pe_exports_reject_invalid_ranges_and_ordinals() {
        let bytes = pe_with_exports(true);
        let short = &bytes[..0x240];
        assert!(probe(short)
            .unwrap()
            .exports(short)
            .unwrap_err()
            .contains("outside captured Source"));
        let mut invalid_index = bytes.clone();
        invalid_index[0x272..0x274].copy_from_slice(&9_u16.to_le_bytes());
        assert_eq!(
            probe(&invalid_index)
                .unwrap()
                .exports(&invalid_index)
                .unwrap_err(),
            "PE export name ordinal index out of range"
        );
        let mut short_directory = bytes.clone();
        short_directory[0x98 + 116..0x98 + 120].copy_from_slice(&20_u32.to_le_bytes());
        assert_eq!(
            probe(&short_directory)
                .unwrap()
                .exports(&short_directory)
                .unwrap_err(),
            "PE export directory is shorter than its header"
        );
        let mut unterminated = bytes.clone();
        unterminated[0x244..0x248].copy_from_slice(&0x10f8_u32.to_le_bytes());
        unterminated[0x2f8..0x300].fill(b'A');
        assert_eq!(
            probe(&unterminated)
                .unwrap()
                .exports(&unterminated)
                .unwrap_err(),
            "unterminated PE text"
        );
    }

    fn pe_with_imports(plus: bool) -> Vec<u8> {
        let optional_size = if plus { 0xf0 } else { 0xe0 };
        let optional = 0x98;
        let section_table = optional + optional_size;
        let mut bytes = vec![0_u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[optional..optional + 2]
            .copy_from_slice(&(if plus { 0x20b_u16 } else { 0x10b_u16 }).to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        let count_at = if plus { 108 } else { 92 };
        let import_at = if plus { 120 } else { 104 };
        bytes[optional + count_at..optional + count_at + 4].copy_from_slice(&2_u32.to_le_bytes());
        bytes[optional + import_at..optional + import_at + 4]
            .copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[optional + import_at + 4..optional + import_at + 8]
            .copy_from_slice(&40_u32.to_le_bytes());
        bytes[section_table..section_table + 6].copy_from_slice(b".idata");
        bytes[section_table + 8..section_table + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section_table + 16..section_table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(&0x1040_u32.to_le_bytes());
        bytes[0x20c..0x210].copy_from_slice(&0x1080_u32.to_le_bytes());
        bytes[0x210..0x214].copy_from_slice(&0x1060_u32.to_le_bytes());
        if plus {
            bytes[0x240..0x248].copy_from_slice(&0x10a0_u64.to_le_bytes());
            bytes[0x248..0x250].copy_from_slice(&(1_u64 << 63 | 7).to_le_bytes());
        } else {
            bytes[0x240..0x244].copy_from_slice(&0x10a0_u32.to_le_bytes());
            bytes[0x244..0x248].copy_from_slice(&(1_u32 << 31 | 7).to_le_bytes());
        }
        bytes[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
        bytes[0x2a0..0x2a2].copy_from_slice(&3_u16.to_le_bytes());
        bytes[0x2a2..0x2ae].copy_from_slice(b"CreateFileW\0");
        bytes
    }

    fn pe_with_delay_imports(plus: bool) -> Vec<u8> {
        let mut bytes = pe_with_imports(plus);
        let optional = 0x98;
        let count_at = if plus { 108 } else { 92 };
        let directory_at = if plus { 112 + 13 * 8 } else { 96 + 13 * 8 };
        bytes[optional + count_at..optional + count_at + 4].copy_from_slice(&14_u32.to_le_bytes());
        bytes[optional + directory_at..optional + directory_at + 4]
            .copy_from_slice(&0x1100_u32.to_le_bytes());
        bytes[optional + directory_at + 4..optional + directory_at + 8]
            .copy_from_slice(&64_u32.to_le_bytes());
        bytes[0x300..0x304].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x304..0x308].copy_from_slice(&0x1160_u32.to_le_bytes());
        bytes[0x30c..0x310].copy_from_slice(&0x1150_u32.to_le_bytes());
        bytes[0x310..0x314].copy_from_slice(&0x1140_u32.to_le_bytes());
        if plus {
            bytes[0x340..0x348].copy_from_slice(&0x1180_u64.to_le_bytes());
            bytes[0x348..0x350].copy_from_slice(&(1_u64 << 63 | 9).to_le_bytes());
        } else {
            bytes[0x340..0x344].copy_from_slice(&0x1180_u32.to_le_bytes());
            bytes[0x344..0x348].copy_from_slice(&(1_u32 << 31 | 9).to_le_bytes());
        }
        bytes[0x360..0x36b].copy_from_slice(b"USER32.dll\0");
        bytes[0x382..0x38e].copy_from_slice(b"MessageBoxA\0");
        bytes
    }

    fn pe_with_legacy_delay_imports(plus: bool) -> Vec<u8> {
        let mut bytes = pe_with_delay_imports(plus);
        let base = if plus { 0x1000_0000_u64 } else { 0x400000 };
        let image_base_at = if plus { 0x98 + 24 } else { 0x98 + 28 };
        if plus {
            bytes[image_base_at..image_base_at + 8].copy_from_slice(&base.to_le_bytes());
        } else {
            bytes[image_base_at..image_base_at + 4].copy_from_slice(&(base as u32).to_le_bytes());
        }
        bytes[0x300..0x304].fill(0);
        bytes[0x304..0x308].copy_from_slice(&((base + 0x1160) as u32).to_le_bytes());
        bytes[0x310..0x314].copy_from_slice(&((base + 0x1140) as u32).to_le_bytes());
        if plus {
            bytes[0x340..0x348].copy_from_slice(&(base + 0x1180).to_le_bytes());
        } else {
            bytes[0x340..0x344].copy_from_slice(&((base + 0x1180) as u32).to_le_bytes());
        }
        bytes
    }

    #[test]
    fn pe_delay_imports_decode_name_and_ordinal_in_both_widths() {
        for plus in [false, true] {
            for (legacy, bytes) in [
                (false, pe_with_delay_imports(plus)),
                (true, pe_with_legacy_delay_imports(plus)),
            ] {
                let report = probe(&bytes).unwrap();
                let image_base = report.field("image_base").unwrap();
                assert_eq!(image_base.width, if plus { 8 } else { 4 });
                assert_eq!(
                    image_base.value,
                    if legacy {
                        if plus {
                            0x1000_0000
                        } else {
                            0x400000
                        }
                    } else {
                        0
                    }
                );
                assert_eq!(report.dependencies(&bytes).unwrap(), ["KERNEL32.dll"]);
                assert_eq!(report.delay_dependencies(&bytes).unwrap(), ["USER32.dll"]);
                let imports = report.delay_imports(&bytes).unwrap();
                assert_eq!(imports.len(), 2);
                assert_eq!(
                    (&imports[0].library, &imports[0].symbol, imports[0].kind),
                    (&"USER32.dll".into(), &"MessageBoxA".into(), "name")
                );
                assert_eq!(
                    (&imports[1].symbol, imports[1].kind),
                    (&"#9".into(), "ordinal")
                );
                assert_eq!(report.imports(&bytes).unwrap().len(), 2);
            }
        }
    }

    #[test]
    fn pe_delay_imports_reject_malformed_descriptors() {
        let bytes = pe_with_delay_imports(true);
        let mut reserved = bytes.clone();
        reserved[0x300..0x304].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            probe(&reserved)
                .unwrap()
                .delay_imports(&reserved)
                .unwrap_err(),
            "PE delay import descriptor has reserved attribute bits"
        );
        let mut below_base = pe_with_legacy_delay_imports(false);
        below_base[0x304..0x308].copy_from_slice(&0x1160_u32.to_le_bytes());
        assert_eq!(
            probe(&below_base)
                .unwrap()
                .delay_imports(&below_base)
                .unwrap_err(),
            "PE delay import VA is below image base"
        );
        let mut missing_name = bytes.clone();
        missing_name[0x310..0x314].fill(0);
        assert_eq!(
            probe(&missing_name)
                .unwrap()
                .delay_imports(&missing_name)
                .unwrap_err(),
            "PE delay import descriptor lacks a library or name table"
        );
        let mut no_null = bytes.clone();
        no_null[0x98 + 112 + 13 * 8 + 4..0x98 + 112 + 13 * 8 + 8]
            .copy_from_slice(&32_u32.to_le_bytes());
        assert_eq!(
            probe(&no_null)
                .unwrap()
                .delay_imports(&no_null)
                .unwrap_err(),
            "PE delay import directory has no null descriptor"
        );
        let mut incomplete = bytes.clone();
        incomplete[0x98 + 112 + 13 * 8..0x98 + 112 + 13 * 8 + 4].fill(0);
        assert_eq!(
            probe(&incomplete)
                .unwrap()
                .delay_imports(&incomplete)
                .unwrap_err(),
            "incomplete PE delay import directory"
        );
        let short = &bytes[..0x340];
        assert!(probe(short).unwrap().delay_imports(short).is_err());
        let mut short_optional = bytes.clone();
        short_optional[0x94..0x96].copy_from_slice(&24_u16.to_le_bytes());
        assert!(probe(&short_optional)
            .unwrap()
            .field("image_base")
            .is_none());
    }

    fn pe_with_relocations(plus: bool) -> Vec<u8> {
        let mut bytes = pe_with_imports(plus);
        let optional = 0x98;
        let count_at = if plus { 108 } else { 92 };
        let relocation_at = if plus { 152 } else { 136 };
        bytes[optional + count_at..optional + count_at + 4].copy_from_slice(&6_u32.to_le_bytes());
        bytes[optional + relocation_at..optional + relocation_at + 4]
            .copy_from_slice(&0x1100_u32.to_le_bytes());
        bytes[optional + relocation_at + 4..optional + relocation_at + 8]
            .copy_from_slice(&16_u32.to_le_bytes());
        bytes[0x300..0x304].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[0x304..0x308].copy_from_slice(&16_u32.to_le_bytes());
        let first = if plus { 0xa020_u16 } else { 0x3020_u16 };
        bytes[0x308..0x30a].copy_from_slice(&first.to_le_bytes());
        bytes[0x30a..0x30c].copy_from_slice(&0_u16.to_le_bytes());
        bytes[0x30c..0x30e].copy_from_slice(&0x4030_u16.to_le_bytes());
        bytes[0x30e..0x310].copy_from_slice(&0x1234_u16.to_le_bytes());
        bytes
    }

    #[test]
    fn pe_base_relocations_decode_both_widths_and_skip_padding_and_pairs() {
        for plus in [false, true] {
            let bytes = pe_with_relocations(plus);
            let report = probe(&bytes).unwrap();
            let relocations = report.relocations(&bytes).unwrap();
            assert_eq!(relocations.len(), 2);
            assert_eq!(relocations[0].address, 0x1020);
            assert_eq!(relocations[0].kind, if plus { 10 } else { 3 });
            assert_eq!(relocations[1].address, 0x1030);
            assert_eq!(relocations[1].kind, 4);
            assert_eq!(report.relocations(&bytes).unwrap(), relocations);
        }
    }

    #[test]
    fn pe_base_relocations_reject_malformed_blocks() {
        let bytes = pe_with_relocations(true);
        let mut absent = bytes.clone();
        absent[0x98 + 108..0x98 + 112].copy_from_slice(&2_u32.to_le_bytes());
        assert!(probe(&absent)
            .unwrap()
            .relocations(&absent)
            .unwrap()
            .is_empty());
        let mut incomplete = bytes.clone();
        incomplete[0x98 + 152..0x98 + 156].fill(0);
        assert_eq!(
            probe(&incomplete)
                .unwrap()
                .relocations(&incomplete)
                .unwrap_err(),
            "incomplete PE base relocation directory"
        );
        let mut invalid = bytes.clone();
        invalid[0x304..0x308].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            probe(&invalid).unwrap().relocations(&invalid).unwrap_err(),
            "invalid PE base relocation block size"
        );
        let mut no_pair = bytes.clone();
        no_pair[0x98 + 156..0x98 + 160].copy_from_slice(&14_u32.to_le_bytes());
        no_pair[0x304..0x308].copy_from_slice(&14_u32.to_le_bytes());
        assert_eq!(
            probe(&no_pair).unwrap().relocations(&no_pair).unwrap_err(),
            "PE HIGHADJ relocation lacks its pair"
        );
        let short = &bytes[..0x30e];
        assert!(probe(short).unwrap().relocations(short).is_err());
    }

    #[test]
    fn pe_imports_decode_name_and_ordinal_in_both_widths() {
        for plus in [false, true] {
            let bytes = pe_with_imports(plus);
            let report = probe(&bytes).unwrap();
            assert!(report.delay_imports(&bytes).unwrap().is_empty());
            assert!(report.delay_dependencies(&bytes).unwrap().is_empty());
            let imports = report.imports(&bytes).unwrap();
            assert_eq!(imports.len(), 2);
            assert_eq!(imports[0].library, "KERNEL32.dll");
            assert_eq!(imports[0].symbol, "CreateFileW");
            assert_eq!(imports[0].kind, "name");
            assert_eq!(imports[1].symbol, "#7");
            assert_eq!(imports[1].kind, "ordinal");
            assert_eq!(report.dependencies(&bytes).unwrap(), ["KERNEL32.dll"]);
            let mut no_symbols = bytes.clone();
            no_symbols[0x240..0x250].fill(0);
            let no_symbols_report = probe(&no_symbols).unwrap();
            assert!(no_symbols_report.imports(&no_symbols).unwrap().is_empty());
            assert_eq!(
                no_symbols_report.dependencies(&no_symbols).unwrap(),
                ["KERNEL32.dll"]
            );
            let mut fallback = bytes.clone();
            fallback[0x200..0x204].fill(0);
            fallback[0x210..0x214].copy_from_slice(&0x1040_u32.to_le_bytes());
            assert_eq!(
                probe(&fallback).unwrap().imports(&fallback).unwrap().len(),
                2
            );
        }
    }

    #[test]
    fn pe_imports_reject_truncated_and_unterminated_tables() {
        let bytes = pe_with_imports(true);
        let mut no_directory = bytes.clone();
        no_directory[0x98 + 108..0x98 + 112].fill(0);
        assert!(probe(&no_directory)
            .unwrap()
            .imports(&no_directory)
            .unwrap()
            .is_empty());
        assert!(probe(&no_directory)
            .unwrap()
            .dependencies(&no_directory)
            .unwrap()
            .is_empty());
        let mut incomplete_directory = bytes.clone();
        incomplete_directory[0x98 + 120..0x98 + 124].fill(0);
        assert_eq!(
            probe(&incomplete_directory)
                .unwrap()
                .imports(&incomplete_directory)
                .unwrap_err(),
            "incomplete PE import directory"
        );
        assert_eq!(
            probe(&incomplete_directory)
                .unwrap()
                .dependencies(&incomplete_directory)
                .unwrap_err(),
            "incomplete PE import directory"
        );
        let short = &bytes[..0x240];
        let report = probe(short).unwrap();
        assert!(report
            .imports(short)
            .unwrap_err()
            .contains("outside captured Source"));
        let mut no_terminator = bytes.clone();
        no_terminator[0x98 + 124..0x98 + 128].copy_from_slice(&20_u32.to_le_bytes());
        let report = probe(&no_terminator).unwrap();
        assert_eq!(
            report.imports(&no_terminator).unwrap_err(),
            "PE import directory has no null descriptor"
        );
        let mut invalid_ordinal = bytes.clone();
        invalid_ordinal[0x248..0x250]
            .copy_from_slice(&(1_u64 << 63 | 1_u64 << 20 | 7).to_le_bytes());
        let report = probe(&invalid_ordinal).unwrap();
        assert_eq!(
            report.imports(&invalid_ordinal).unwrap_err(),
            "PE import ordinal has reserved bits set"
        );
        let mut unterminated = bytes.clone();
        unterminated[0x280..0x400].fill(b'A');
        assert_eq!(
            probe(&unterminated)
                .unwrap()
                .imports(&unterminated)
                .unwrap_err(),
            "unterminated PE text"
        );
    }

    #[test]
    fn section_names_escape_control_bytes() {
        assert_eq!(section_name(b".x\n\xff"), ".x\\x0a\\xff");
    }

    #[test]
    fn pe32_plus_reports_checked_header_span() {
        let mut bytes = vec![0_u8; 0x80 + 4 + 20 + 0xf0 + 40];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1234_u32.to_le_bytes());
        let report = probe(&bytes).unwrap();
        assert_eq!(report.name, "PE32+");
        assert_eq!(report.machine, 0x8664);
        assert_eq!(report.entry, 0x1234);
        assert_eq!(report.sections, Some(1));
        assert_eq!(report.header_span, (0, bytes.len()));
        let entry = report.field("entry").unwrap();
        assert_eq!(
            (entry.offset, entry.width, entry.value, entry.decoder),
            (0xa8, 4, 0x1234, "u32le")
        );
        let sections = report.field("sections").unwrap();
        assert_eq!(
            (sections.offset, sections.width, sections.value),
            (0x86, 2, 1)
        );
        assert!(probe(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn pe_overlay_follows_headers_and_raw_sections() {
        let section_table = 0x80 + 4 + 20 + 0xf0;
        let mut bytes = vec![0_u8; 0x207];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section_table + 16..section_table + 20].copy_from_slice(&4_u32.to_le_bytes());
        bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(b"CODE");
        bytes[0x204..].copy_from_slice(b"GAK");
        let report = probe(&bytes).unwrap();
        assert_eq!(report.overlay_range(bytes.len()).unwrap(), (0x204, 0x207));
        assert_eq!(report.overlay_range(0x204).unwrap(), (0x204, 0x204));
        assert_eq!(
            report.overlay_range(0x203).unwrap_err(),
            "declared binary extent outside captured Source"
        );

        // Header padding is part of the declared header extent.
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x208_u32.to_le_bytes());
        assert_eq!(
            probe(&bytes)
                .unwrap()
                .overlay_range(bytes.len())
                .unwrap_err(),
            "declared binary extent outside captured Source"
        );
    }

    fn pe_with_certificates() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x22c];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x98 + 108..0x98 + 112].copy_from_slice(&5_u32.to_le_bytes());
        bytes[0x98 + 144..0x98 + 148].copy_from_slice(&0x208_u32.to_le_bytes());
        bytes[0x98 + 148..0x98 + 152].copy_from_slice(&32_u32.to_le_bytes());
        let section = 0x80 + 4 + 20 + 0xf0;
        bytes[section + 16..section + 20].copy_from_slice(&4_u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(b"CODE");
        bytes[0x208..0x20c].copy_from_slice(&11_u32.to_le_bytes());
        bytes[0x20c..0x20e].copy_from_slice(&0x200_u16.to_le_bytes());
        bytes[0x20e..0x210].copy_from_slice(&2_u16.to_le_bytes());
        bytes[0x210..0x213].copy_from_slice(b"ABC");
        bytes[0x218..0x21c].copy_from_slice(&12_u32.to_le_bytes());
        bytes[0x21c..0x21e].copy_from_slice(&0x100_u16.to_le_bytes());
        bytes[0x21e..0x220].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x220..0x224].copy_from_slice(b"DATA");
        bytes[0x228..].copy_from_slice(b"TAIL");
        bytes
    }

    fn pe_with_debug_entries() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x500];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x98 + 108..0x98 + 112].copy_from_slice(&7_u32.to_le_bytes());
        bytes[0x98 + 160..0x98 + 164].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[0x98 + 164..0x98 + 168].copy_from_slice(&56_u32.to_le_bytes());
        let section = 0x98 + 0xf0;
        bytes[section..section + 6].copy_from_slice(b".rdata");
        bytes[section + 8..section + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x204..0x208].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        bytes[0x20c..0x210].copy_from_slice(&2_u32.to_le_bytes());
        bytes[0x210..0x214].copy_from_slice(&39_u32.to_le_bytes());
        bytes[0x218..0x21c].copy_from_slice(&0x480_u32.to_le_bytes());
        bytes[0x228..0x22c].copy_from_slice(&16_u32.to_le_bytes());
        bytes[0x480..0x484].copy_from_slice(b"RSDS");
        bytes[0x484..0x494].copy_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        bytes[0x494..0x498].copy_from_slice(&2_u32.to_le_bytes());
        bytes[0x498..0x4a7].copy_from_slice(b"build\\demo.pdb\0");
        bytes
    }

    #[test]
    fn pe_debug_entries_include_overlay_codeview_identity_and_validate_all_entries() {
        let bytes = pe_with_debug_entries();
        let report = probe(&bytes).unwrap();
        let entries = report.debug_entries(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].offset, entries[0].size), (0x480, 39));
        assert_eq!((entries[0].timestamp, entries[0].kind), (0x1234_5678, 2));
        assert_eq!(entries[0].type_name(), "codeview");
        assert_eq!(entries[0].pdb_path.as_deref(), Some("build\\demo.pdb"));
        assert_eq!(
            entries[0].pdb_guid.as_deref(),
            Some("00112233-4455-6677-8899-aabbccddeeff")
        );
        assert_eq!(entries[0].pdb_age, Some(2));
        assert_eq!(entries[1].type_name(), "repro");
        assert!(entries[1].pdb_path.is_none());

        let mut rva_data = bytes.clone();
        rva_data[0x214..0x218].copy_from_slice(&0x1080_u32.to_le_bytes());
        rva_data[0x218..0x21c].fill(0);
        rva_data.copy_within(0x480..0x4a7, 0x280);
        let entries = probe(&rva_data)
            .unwrap()
            .debug_entries(&rva_data)
            .unwrap()
            .to_vec();
        assert_eq!(entries[0].offset, 0x280);
        assert_eq!(entries[0].pdb_age, Some(2));

        let mut no_directory = bytes.clone();
        no_directory[0x98 + 108..0x98 + 112].copy_from_slice(&6_u32.to_le_bytes());
        assert!(probe(&no_directory)
            .unwrap()
            .debug_entries(&no_directory)
            .unwrap()
            .is_empty());
        let elf = elf64_with_load();
        assert_eq!(
            probe(&elf).unwrap().debug_entries(&elf).unwrap_err(),
            "PE debug entries require a PE image"
        );

        let mut malformed = bytes.clone();
        malformed[0x98 + 164..0x98 + 168].copy_from_slice(&55_u32.to_le_bytes());
        assert_eq!(
            probe(&malformed)
                .unwrap()
                .debug_entries(&malformed)
                .unwrap_err(),
            "PE debug directory has a partial entry"
        );
        let mut malformed = bytes.clone();
        malformed[0x218..0x21c].copy_from_slice(&0x4f0_u32.to_le_bytes());
        assert_eq!(
            probe(&malformed)
                .unwrap()
                .debug_entries(&malformed)
                .unwrap_err(),
            "PE debug data outside captured Source"
        );
        let mut malformed = bytes.clone();
        malformed[0x4a6] = b'X';
        assert_eq!(
            probe(&malformed)
                .unwrap()
                .debug_entries(&malformed)
                .unwrap_err(),
            "unterminated PE PDB path"
        );
        let mut malformed = bytes;
        malformed[0x210..0x214].copy_from_slice(&24_u32.to_le_bytes());
        assert_eq!(
            probe(&malformed)
                .unwrap()
                .debug_entries(&malformed)
                .unwrap_err(),
            "truncated PE CodeView RSDS data"
        );
    }

    #[test]
    fn pe_certificates_are_bounded_aligned_and_keep_payload_offsets() {
        let bytes = pe_with_certificates();
        let report = probe(&bytes).unwrap();
        let certificates = report.certificates(&bytes).unwrap();
        assert_eq!(certificates.len(), 2);
        assert_eq!((certificates[0].offset, certificates[0].size), (0x210, 3));
        assert_eq!((certificates[0].revision, certificates[0].kind), (0x200, 2));
        assert_eq!((certificates[1].offset, certificates[1].size), (0x220, 4));
        assert_eq!(
            &bytes[certificates[1].offset..certificates[1].offset + certificates[1].size],
            b"DATA"
        );
        assert_eq!(report.overlay_range(bytes.len()).unwrap(), (0x204, 0x22c));

        let mut unsigned = bytes.clone();
        unsigned[0x98 + 108..0x98 + 112].copy_from_slice(&0_u32.to_le_bytes());
        assert!(probe(&unsigned)
            .unwrap()
            .certificates(&unsigned)
            .unwrap()
            .is_empty());
        let elf = elf64_with_load();
        assert_eq!(
            probe(&elf).unwrap().certificates(&elf).unwrap_err(),
            "PE certificates require a PE image"
        );

        let mut malformed = bytes.clone();
        malformed[0x98 + 144..0x98 + 148].copy_from_slice(&0x209_u32.to_le_bytes());
        assert!(probe(&malformed)
            .unwrap()
            .certificates(&malformed)
            .unwrap_err()
            .contains("8-byte aligned"));
        let mut malformed = bytes.clone();
        malformed[0x208..0x20c].copy_from_slice(&7_u32.to_le_bytes());
        assert!(probe(&malformed)
            .unwrap()
            .certificates(&malformed)
            .unwrap_err()
            .contains("shorter than its header"));
        let mut malformed = bytes.clone();
        malformed[0x98 + 148..0x98 + 152].copy_from_slice(&31_u32.to_le_bytes());
        assert!(probe(&malformed)
            .unwrap()
            .certificates(&malformed)
            .unwrap_err()
            .contains("exceed directory size"));
        let short = &bytes[..0x21f];
        assert!(probe(short)
            .unwrap()
            .certificates(short)
            .unwrap_err()
            .contains("outside captured Source"));
        let mut malformed = bytes.clone();
        malformed[0x98 + 144..0x98 + 148].copy_from_slice(&0x200_u32.to_le_bytes());
        assert!(probe(&malformed)
            .unwrap()
            .certificates(&malformed)
            .unwrap_err()
            .contains("overlaps headers or sections"));
        let mut oversized = bytes;
        oversized[0x98 + 148..0x98 + 152]
            .copy_from_slice(&((16 * 1024 * 1024 + 1) as u32).to_le_bytes());
        assert!(probe(&oversized)
            .unwrap()
            .certificates(&oversized)
            .unwrap_err()
            .contains("exceeds"));
    }

    #[test]
    fn pe_section_metadata_is_distinct_from_captured_data() {
        let section_table = 0x80 + 4 + 20 + 0xf0;
        let payload = section_table + 40;
        let mut bytes = vec![0_u8; payload + 4];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[section_table..section_table + 5].copy_from_slice(b".text");
        bytes[section_table + 8..section_table + 12].copy_from_slice(&8_u32.to_le_bytes());
        bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section_table + 16..section_table + 20].copy_from_slice(&4_u32.to_le_bytes());
        bytes[section_table + 20..section_table + 24]
            .copy_from_slice(&(payload as u32).to_le_bytes());
        bytes[section_table + 36..section_table + 40]
            .copy_from_slice(&0x60000020_u32.to_le_bytes());
        bytes[payload..].copy_from_slice(b"GAK\0");
        let report = probe(&bytes).unwrap();
        let section = report.section(0).unwrap();
        assert_eq!(section.name.as_deref(), Some(".text"));
        assert_eq!((section.file_offset, section.file_size), (payload, 4));
        assert_eq!((section.virtual_address, section.virtual_size), (0x1000, 8));
        assert_eq!(section.flags, 0x60000020);
        assert!(section.file_backed);
        assert!(report.section(1).is_none());
        let short = probe(&bytes[..payload]).unwrap();
        assert_eq!(short.section(0).unwrap().file_size, 4);
    }

    #[test]
    fn pe_rva_views_only_captured_file_backed_bytes() {
        let section_table = 0x80 + 4 + 20 + 0xf0;
        let mut bytes = vec![0_u8; 0x204];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section_table + 8..section_table + 12].copy_from_slice(&8_u32.to_le_bytes());
        bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section_table + 16..section_table + 20].copy_from_slice(&4_u32.to_le_bytes());
        bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(b"GAK!");
        let report = probe(&bytes).unwrap();
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x1000, 0).unwrap_err(),
            "RVA view length must be positive"
        );
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x1001, 2).unwrap(),
            (0x201, 0x203)
        );
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x80, 4).unwrap(),
            (0x80, 0x84)
        );
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x1003, 2).unwrap_err(),
            "RVA range has no file-backed bytes"
        );
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x1008, 1).unwrap_err(),
            "RVA is not mapped to PE file bytes"
        );
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x1ff, 2).unwrap_err(),
            "RVA range crosses PE header boundary"
        );
        assert_eq!(
            report.pe_rva_range(0x200, 0x1000, 1).unwrap_err(),
            "RVA data outside captured Source"
        );
        let mut ambiguous = report.clone();
        ambiguous.section_info.push(report.section_info[0].clone());
        assert_eq!(
            ambiguous.pe_rva_range(bytes.len(), 0x1000, 1).unwrap_err(),
            "RVA maps to multiple PE regions"
        );
    }

    #[test]
    fn elf_section_names_and_offsets_use_checked_string_table() {
        let names = b"\0.shstrtab\0.text\0";
        let table_offset = 64 + 3 * 64;
        let data_offset = table_offset + names.len();
        let mut bytes = vec![0_u8; data_offset + 4];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());
        let shstr = 64 + 64;
        bytes[shstr..shstr + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[shstr + 4..shstr + 8].copy_from_slice(&3_u32.to_le_bytes());
        bytes[shstr + 24..shstr + 32].copy_from_slice(&(table_offset as u64).to_le_bytes());
        bytes[shstr + 32..shstr + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        let text = shstr + 64;
        bytes[text..text + 4].copy_from_slice(&11_u32.to_le_bytes());
        bytes[text + 4..text + 8].copy_from_slice(&1_u32.to_le_bytes());
        bytes[text + 8..text + 16].copy_from_slice(&6_u64.to_le_bytes());
        bytes[text + 16..text + 24].copy_from_slice(&0x401000_u64.to_le_bytes());
        bytes[text + 24..text + 32].copy_from_slice(&(data_offset as u64).to_le_bytes());
        bytes[text + 32..text + 40].copy_from_slice(&4_u64.to_le_bytes());
        bytes[table_offset..data_offset].copy_from_slice(names);
        bytes[data_offset..].copy_from_slice(b"GAK\0");
        let report = probe(&bytes).unwrap();
        let section = report.section(2).unwrap();
        assert_eq!(section.name.as_deref(), Some(".text"));
        assert_eq!((section.file_offset, section.file_size), (data_offset, 4));
        assert_eq!(section.virtual_address, 0x401000);
        assert_eq!(section.flags, 6);
        assert!(!section.writable);
        assert!(section.executable);
        assert_eq!(
            (section.flags_field.offset, section.flags_field.width),
            (text + 8, 8)
        );
        let short = probe(&bytes[..table_offset]).unwrap();
        assert_eq!(short.section(2).unwrap().name, None);
    }

    #[test]
    fn elf_rejects_overflowing_section_data_range() {
        let mut bytes = vec![0_u8; 64 + 2 * 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
        let section = 64 + 64;
        bytes[section + 4..section + 8].copy_from_slice(&1_u32.to_le_bytes());
        bytes[section + 24..section + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[section + 32..section + 40].copy_from_slice(&2_u64.to_le_bytes());
        assert_eq!(
            probe(&bytes).err().as_deref(),
            Some("ELF section range overflow")
        );
    }

    #[test]
    fn elf64_big_endian_and_truncation() {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 2, 1]);
        bytes[18..20].copy_from_slice(&0x003e_u16.to_be_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_be_bytes());
        bytes[24..32].copy_from_slice(&0x1234_u64.to_be_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_be_bytes());
        let report = probe(&bytes).unwrap();
        assert_eq!(report.name, "ELF64");
        assert_eq!(report.byte_order, "big-endian");
        assert_eq!(
            (report.kind(), report.bits(), report.endian(), report.arch()),
            ("elf", 64, "big", "x86_64")
        );
        assert_eq!(report.machine, 0x003e);
        assert_eq!(report.entry, 0x1234);
        assert_eq!(
            report.pe_rva_range(bytes.len(), 0x1234, 1).unwrap_err(),
            "formats.rva requires a PE image"
        );
        assert_eq!(report.header_span, (0, 64));
        let entry = report.field("entry").unwrap();
        assert_eq!(
            (entry.offset, entry.width, entry.value, entry.decoder),
            (24, 8, 0x1234, "u64be")
        );
        assert!(probe(&bytes[..63]).is_err());
        bytes[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        assert_eq!(probe(&bytes).unwrap().arch(), "unknown");
    }

    #[test]
    fn architecture_names_cover_arm_and_riscv_machine_codes() {
        let mut pe = probe(&pe_with_exports(true)).unwrap();
        for (machine, expected) in [
            (0x01c0, "arm"),
            (0x01c2, "arm"),
            (0x01c4, "arm"),
            (0xaa64, "aarch64"),
            (0xa641, "aarch64"),
            (0xa64e, "aarch64"),
            (0x5032, "riscv"),
            (0x5064, "riscv"),
            (0x5128, "riscv"),
        ] {
            pe.machine = machine;
            assert_eq!(pe.arch(), expected, "PE machine {machine:#06x}");
        }
        pe.machine = 0xffff;
        assert_eq!(pe.arch(), "unknown");

        let mut elf = probe(&elf64_with_needed()).unwrap();
        for (machine, expected) in [(40, "arm"), (183, "aarch64"), (243, "riscv")] {
            elf.machine = machine;
            assert_eq!(elf.arch(), expected, "ELF machine {machine}");
        }
        elf.machine = 0xffff;
        assert_eq!(elf.arch(), "unknown");
    }

    #[test]
    fn elf_extended_section_count_points_to_section_zero() {
        let mut bytes = vec![0_u8; 64 + 2 * 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[96..104].copy_from_slice(&2_u64.to_le_bytes());
        let report = probe(&bytes).unwrap();
        assert_eq!(report.sections, Some(2));
        let sections = report.field("sections").unwrap();
        assert_eq!(
            (
                sections.offset,
                sections.width,
                sections.value,
                sections.decoder
            ),
            (96, 8, 2, "u64le")
        );
        assert!(probe(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn unknown_format_fails() {
        assert_eq!(
            probe(b"plain text").err().as_deref(),
            Some("unknown binary format")
        );
    }
}
