use std::collections::HashSet;
use std::io;

pub const MAX_READ: usize = 1024 * 1024;
pub const MAX_REGIONS: usize = 50_000;
pub const MAX_THREADS: usize = 50_000;
pub const MAX_CHILDREN: usize = 50_000;
pub const MAX_SCAN: usize = 16 * 1024 * 1024;
pub const MAX_SCAN_PATTERN: usize = 4096;
pub const MAX_SCAN_HITS: usize = 10_000;

#[derive(Clone, Debug)]
pub struct Region {
    pub pid: u32,
    pub start: usize,
    pub size: usize,
    pub access: String,
    pub label: String,
    pub image_backed: bool,
}

pub fn kind(region: &Region) -> &'static str {
    let label = region.label.as_str();
    if label == "[heap]" {
        "heap"
    } else if label.starts_with("[stack") && label.ends_with(']') {
        "stack"
    } else if region.image_backed {
        if cfg!(windows) {
            "image"
        } else {
            "file"
        }
    } else if label == "mapped" {
        "mapped"
    } else if label == "private" {
        "private"
    } else if label.is_empty() {
        "anonymous"
    } else if label.starts_with('/') {
        "file"
    } else if label.starts_with('[') {
        "special"
    } else {
        "other"
    }
}

impl Region {
    fn reference_prefix(&self) -> String {
        let name = self
            .label
            .rsplit(['/', '\\'])
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("region");
        format!("{name}@{}:0x{:x}+0x", self.pid, self.start)
    }

    pub fn reference(&self, address: usize) -> Result<String, String> {
        let offset = self.offset_of(address)?;
        Ok(format!("{}{:x}", self.reference_prefix(), offset))
    }

    pub fn resolve_reference(&self, reference: &str) -> Result<usize, String> {
        let prefix = self.reference_prefix();
        let offset = reference
            .strip_prefix(&prefix)
            .filter(|offset| !offset.is_empty() && offset.bytes().all(|c| c.is_ascii_hexdigit()))
            .ok_or("address reference does not match process region")?;
        let offset = usize::from_str_radix(offset, 16)
            .map_err(|_| "address reference offset out of range")?;
        self.address_of(offset)
    }

    pub fn advance_reference(&self, reference: &str, delta: i64) -> Result<String, String> {
        let address = self.resolve_reference(reference)?;
        let offset = self.offset_of(address)?;
        let next = if delta >= 0 {
            offset.checked_add(usize::try_from(delta).map_err(|_| "reference offset out of range")?)
        } else {
            offset.checked_sub(
                usize::try_from(delta.unsigned_abs())
                    .map_err(|_| "reference offset out of range")?,
            )
        }
        .ok_or("reference offset out of range")?;
        if next >= self.size {
            return Err("reference offset out of range".into());
        }
        self.reference(self.address_of(next)?)
    }

    pub fn contains(&self, address: usize) -> bool {
        self.start
            .checked_add(self.size)
            .is_some_and(|end| self.start <= address && address < end)
    }

    pub fn offset_of(&self, address: usize) -> Result<usize, String> {
        if !self.contains(address) {
            return Err("address is outside process region".into());
        }
        Ok(address - self.start)
    }

    pub fn address_of(&self, offset: usize) -> Result<usize, String> {
        if offset >= self.size {
            return Err("offset is outside process region".into());
        }
        self.start
            .checked_add(offset)
            .ok_or_else(|| "process region address overflow".into())
    }
}

pub fn regions(pid: u32) -> Result<Vec<Region>, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("pid must be between 1 and 2147483647".into());
    }
    list_regions(pid)
}

pub fn images(pid: u32) -> Result<Vec<Region>, String> {
    Ok(regions(pid)?
        .into_iter()
        .filter(|region| region.image_backed && region.access.ends_with('x'))
        .collect())
}

pub fn writable_regions(pid: u32) -> Result<Vec<Region>, String> {
    Ok(regions(pid)?
        .into_iter()
        .filter(|region| region.access.as_bytes().get(1) == Some(&b'w'))
        .collect())
}

pub fn heap_candidates(pid: u32) -> Result<Vec<Region>, String> {
    Ok(regions(pid)?
        .into_iter()
        .filter(|region| {
            region.access.starts_with("rw")
                && !region.image_backed
                && matches!(kind(region), "heap" | "anonymous" | "private")
        })
        .collect())
}

pub fn readable_regions(pid: u32) -> Result<Vec<Region>, String> {
    Ok(regions(pid)?
        .into_iter()
        .filter(|region| region.access.as_bytes().first() == Some(&b'r'))
        .collect())
}

pub fn executable_regions(pid: u32) -> Result<Vec<Region>, String> {
    Ok(regions(pid)?
        .into_iter()
        .filter(|region| region.access.as_bytes().get(2) == Some(&b'x'))
        .collect())
}

pub fn wx_regions(pid: u32) -> Result<Vec<Region>, String> {
    Ok(regions(pid)?
        .into_iter()
        .filter(|region| region.access.as_bytes().get(1) == Some(&b'w')
            && region.access.as_bytes().get(2) == Some(&b'x'))
        .collect())
}

pub fn hunt_region(
    region: &Region,
    pattern: &[u8],
    masks: Option<&[u8]>,
    offset: usize,
    length: usize,
) -> Result<Vec<usize>, String> {
    if pattern.is_empty() || pattern.len() > MAX_SCAN_PATTERN {
        return Err(format!(
            "process search pattern must contain 1..{MAX_SCAN_PATTERN} bytes"
        ));
    }
    if length > MAX_SCAN {
        return Err(format!("process scan length exceeds {MAX_SCAN} bytes"));
    }
    if let Some(masks) = masks {
        if masks.len() != pattern.len()
            || (masks.iter().any(|mask| *mask != 0xff) && pattern.len() > 64)
        {
            return Err("invalid masked process search pattern".into());
        }
    }
    if offset > region.size
        || length > region.size - offset
        || offset
            .checked_add(length)
            .and_then(|end| i64::try_from(end).ok())
            .is_none()
    {
        return Err("search exceeds region boundaries".into());
    }
    if !region.access.starts_with('r') {
        return Err("region is not marked readable".into());
    }
    let masked = masks.filter(|masks| masks.iter().any(|mask| *mask != 0xff));
    let mut accept = [0_u64; 256];
    let mut prefix = Vec::new();
    if let Some(masks) = masked {
        for (position, (&value, &mask)) in pattern.iter().zip(masks).enumerate() {
            let bit = 1_u64 << position;
            for (byte, entry) in accept.iter_mut().enumerate() {
                if (byte as u8 & mask) == value {
                    *entry |= bit;
                }
            }
        }
    } else {
        prefix = vec![0; pattern.len()];
        for index in 1..pattern.len() {
            let mut matched = prefix[index - 1];
            while matched > 0 && pattern[index] != pattern[matched] {
                matched = prefix[matched - 1];
            }
            if pattern[index] == pattern[matched] {
                matched += 1;
            }
            prefix[index] = matched;
        }
    }
    let mut hits = Vec::new();
    let mut matched = 0;
    let mut state = 0_u64;
    let mut scanned = 0;
    while scanned < length {
        let count = (length - scanned).min(MAX_READ);
        let address = region.address_of(offset + scanned)?;
        let bytes = snapshot(region.pid, address, count)?;
        for (index, &byte) in bytes.iter().enumerate() {
            let found = if masked.is_some() {
                state = ((state << 1) | 1) & accept[byte as usize];
                state & (1_u64 << (pattern.len() - 1)) != 0
            } else {
                while matched > 0 && byte != pattern[matched] {
                    matched = prefix[matched - 1];
                }
                if byte == pattern[matched] {
                    matched += 1;
                }
                matched == pattern.len()
            };
            if found {
                hits.push(offset + scanned + index + 1 - pattern.len());
                if hits.len() > MAX_SCAN_HITS {
                    return Err(format!("process search exceeds {MAX_SCAN_HITS} matches"));
                }
                if masked.is_none() {
                    matched = prefix[matched - 1];
                }
            }
        }
        scanned += count;
    }
    Ok(hits)
}

pub fn pointer_refs_u64(
    region: &Region,
    target: u64,
    offset: usize,
    length: usize,
) -> Result<Vec<usize>, String> {
    hunt_region(region, &target.to_le_bytes(), None, offset, length)
}

/// Paths of executable, image-backed mappings in address order, once per path.
pub fn modules(pid: u32) -> Result<Vec<String>, String> {
    Ok(module_paths(&images(pid)?))
}

pub fn thread_ids(pid: u32) -> Result<Vec<u32>, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("pid must be between 1 and 2147483647".into());
    }
    list_thread_ids(pid)
}

pub fn executable(pid: u32) -> Result<String, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("pid must be between 1 and 2147483647".into());
    }
    executable_path(pid)
}

pub fn parent_pid(pid: u32) -> Result<u32, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("pid must be between 1 and 2147483647".into());
    }
    read_parent_pid(pid)
}

pub fn children(pid: u32) -> Result<Vec<u32>, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("pid must be between 1 and 2147483647".into());
    }
    list_child_pids(pid)
}

#[cfg(target_os = "linux")]
fn list_child_pids(pid: u32) -> Result<Vec<u32>, String> {
    read_parent_pid(pid)?;
    let entries = std::fs::read_dir("/proc")
        .map_err(|error| format!("cannot enumerate process {pid} children: {error}"))?;
    let mut children = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate process {pid} children: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(child) = name.parse::<u32>() else {
            continue;
        };
        if child != 0 && read_parent_pid(child).ok() == Some(pid) {
            children.push(child);
            if children.len() > MAX_CHILDREN {
                return Err(format!(
                    "process child list exceeds {MAX_CHILDREN} children"
                ));
            }
        }
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

#[cfg(windows)]
fn list_child_pids(pid: u32) -> Result<Vec<u32>, String> {
    let rows = windows_process_rows()
        .map_err(|error| format!("cannot enumerate process {pid} children: {error}"))?;
    if !rows.iter().any(|(process, _)| *process == pid) {
        return Err(format!(
            "cannot enumerate process {pid} children: process not found"
        ));
    }
    let mut children: Vec<u32> = rows
        .into_iter()
        .filter_map(|(child, parent)| (child != 0 && parent == pid).then_some(child))
        .collect();
    if children.len() > MAX_CHILDREN {
        return Err(format!(
            "process child list exceeds {MAX_CHILDREN} children"
        ));
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn list_child_pids(_pid: u32) -> Result<Vec<u32>, String> {
    Err("process.children is available only on Windows and Linux".into())
}

#[cfg(target_os = "linux")]
fn read_parent_pid(pid: u32) -> Result<u32, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("cannot read process {pid} parent: {error}"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or_else(|| format!("cannot parse process {pid} parent"))
}

#[cfg(windows)]
fn read_parent_pid(pid: u32) -> Result<u32, String> {
    windows_process_rows()
        .map_err(|error| format!("cannot read process {pid} parent: {error}"))?
        .into_iter()
        .find_map(|(process, parent)| (process == pid).then_some(parent))
        .ok_or_else(|| format!("cannot read process {pid} parent: process not found"))
}

#[cfg(windows)]
fn windows_process_rows() -> Result<Vec<(u32, u32)>, String> {
    use std::ffi::c_void;
    use std::mem::size_of;

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        threads: u32,
        parent_process_id: u32,
        base_priority: i32,
        flags: u32,
        executable: [u16; 260],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const TH32CS_SNAPPROCESS: u32 = 0x0002;
    const ERROR_NO_MORE_FILES: i32 = 18;
    // SAFETY: a process snapshot ignores the PID argument and returns a handle or INVALID_HANDLE_VALUE.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot as isize == -1 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut entry = ProcessEntry32W {
        size: size_of::<ProcessEntry32W>() as u32,
        usage: 0,
        process_id: 0,
        default_heap_id: 0,
        module_id: 0,
        threads: 0,
        parent_process_id: 0,
        base_priority: 0,
        flags: 0,
        executable: [0; 260],
    };
    // SAFETY: snapshot is valid and entry has the documented layout and size.
    let mut found = unsafe { Process32FirstW(snapshot, &mut entry) };
    let mut rows = Vec::new();
    while found != 0 {
        rows.push((entry.process_id, entry.parent_process_id));
        if rows.len() > 100_000 {
            // SAFETY: snapshot came from CreateToolhelp32Snapshot.
            unsafe { CloseHandle(snapshot) };
            return Err("process snapshot exceeds 100000 entries".into());
        }
        entry.size = size_of::<ProcessEntry32W>() as u32;
        // SAFETY: snapshot and entry remain valid throughout enumeration.
        found = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    let error = io::Error::last_os_error();
    // SAFETY: snapshot came from CreateToolhelp32Snapshot.
    unsafe { CloseHandle(snapshot) };
    if error.raw_os_error() != Some(ERROR_NO_MORE_FILES) {
        return Err(error.to_string());
    }
    Ok(rows)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn read_parent_pid(_pid: u32) -> Result<u32, String> {
    Err("process.parent_pid is available only on Windows and Linux".into())
}

#[cfg(target_os = "linux")]
fn executable_path(pid: u32) -> Result<String, String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|error| format!("cannot read process {pid} executable: {error}"))?;
    path.into_os_string()
        .into_string()
        .map_err(|_| format!("process {pid} executable path is not UTF-8"))
}

#[cfg(windows)]
fn executable_path(pid: u32) -> Result<String, String> {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            path: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    // SAFETY: pid is validated; OpenProcess returns a handle or null.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "cannot read process {pid} executable: {}",
            io::Error::last_os_error()
        ));
    }
    let mut path = vec![0u16; 32768];
    let mut size = path.len() as u32;
    // SAFETY: the buffer is writable for size UTF-16 code units, and process is valid.
    let status = unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut size) };
    let error = if status == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: process came from a successful OpenProcess call.
    unsafe { CloseHandle(process) };
    if let Some(error) = error {
        return Err(format!("cannot read process {pid} executable: {error}"));
    }
    String::from_utf16(&path[..size as usize])
        .map_err(|_| format!("process {pid} executable path is not valid UTF-16"))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn executable_path(_pid: u32) -> Result<String, String> {
    Err("process.executable is available only on Windows and Linux".into())
}

#[cfg(target_os = "linux")]
fn list_thread_ids(pid: u32) -> Result<Vec<u32>, String> {
    let path = format!("/proc/{pid}/task");
    let entries = std::fs::read_dir(&path)
        .map_err(|error| format!("cannot enumerate process {pid} threads: {error}"))?;
    let mut ids = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate process {pid} threads: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(id) = name.parse::<u32>() else {
            continue;
        };
        if id == 0 {
            continue;
        }
        ids.push(id);
        if ids.len() > MAX_THREADS {
            return Err(format!("process thread list exceeds {MAX_THREADS} threads"));
        }
    }
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Err(format!("process {pid} has no visible threads"));
    }
    Ok(ids)
}

#[cfg(windows)]
fn list_thread_ids(pid: u32) -> Result<Vec<u32>, String> {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};

    #[repr(C)]
    struct ThreadEntry32 {
        size: u32,
        usage: u32,
        thread_id: u32,
        owner_pid: u32,
        base_priority: i32,
        delta_priority: i32,
        flags: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const TH32CS_SNAPTHREAD: u32 = 0x0004;
    const ERROR_NO_MORE_FILES: i32 = 18;
    // SAFETY: the PID is validated; Windows returns a handle or null.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "cannot enumerate process {pid} threads: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: system-wide thread snapshots take zero as the second argument.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot as isize == -1 {
        let error = io::Error::last_os_error();
        // SAFETY: process came from OpenProcess.
        unsafe { CloseHandle(process) };
        return Err(format!("cannot enumerate process {pid} threads: {error}"));
    }
    let result = (|| {
        // SAFETY: the entry is initialized before each Toolhelp call.
        let mut entry: ThreadEntry32 = unsafe { zeroed() };
        entry.size = size_of::<ThreadEntry32>() as u32;
        // SAFETY: snapshot and entry remain valid for the enumeration.
        if unsafe { Thread32First(snapshot, &mut entry) } == 0 {
            return Err(format!(
                "cannot enumerate process {pid} threads: {}",
                io::Error::last_os_error()
            ));
        }
        let mut ids = Vec::new();
        loop {
            if entry.owner_pid == pid && entry.thread_id != 0 {
                ids.push(entry.thread_id);
                if ids.len() > MAX_THREADS {
                    return Err(format!("process thread list exceeds {MAX_THREADS} threads"));
                }
            }
            entry.size = size_of::<ThreadEntry32>() as u32;
            // SAFETY: snapshot and entry remain valid for the enumeration.
            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES) {
                    return Err(format!("cannot enumerate process {pid} threads: {error}"));
                }
                break;
            }
        }
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            return Err(format!("process {pid} has no visible threads"));
        }
        Ok(ids)
    })();
    // SAFETY: both handles came from successful Windows calls and are closed once.
    unsafe { CloseHandle(snapshot) };
    unsafe { CloseHandle(process) };
    result
}

#[cfg(not(any(target_os = "linux", windows)))]
fn list_thread_ids(_pid: u32) -> Result<Vec<u32>, String> {
    Err("process.thread_ids is available only on Windows and Linux".into())
}

fn module_paths(images: &[Region]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for image in images {
        if image.label.is_empty() || image.label == "image" {
            continue;
        }
        #[cfg(windows)]
        let key = image.label.to_lowercase();
        #[cfg(not(windows))]
        let key = image.label.clone();
        if seen.insert(key) {
            paths.push(image.label.clone());
        }
    }
    paths
}

#[cfg(target_os = "linux")]
fn map_field<'a>(rest: &mut &'a str) -> Result<&'a str, String> {
    let current = rest.trim_start_matches(|ch| ch == ' ' || ch == '\t');
    if current.is_empty() {
        return Err("malformed process memory map".into());
    }
    let end = current
        .find(|ch| ch == ' ' || ch == '\t')
        .unwrap_or(current.len());
    let (field, tail) = current.split_at(end);
    *rest = tail;
    Ok(field)
}

#[cfg(target_os = "linux")]
fn parse_linux_map_line(pid: u32, line: &str) -> Result<Region, String> {
    let mut rest = line;
    let addresses = map_field(&mut rest)?;
    let rights = map_field(&mut rest)?;
    map_field(&mut rest)?;
    map_field(&mut rest)?;
    let inode = map_field(&mut rest)?
        .parse::<u64>()
        .map_err(|_| "invalid process memory map inode")?;
    let (start, end) = addresses
        .split_once('-')
        .ok_or("malformed process memory address range")?;
    let start =
        usize::from_str_radix(start, 16).map_err(|_| "invalid process memory start address")?;
    let end = usize::from_str_radix(end, 16).map_err(|_| "invalid process memory end address")?;
    if start >= end || rights.len() != 4 {
        return Err("invalid process memory map entry".into());
    }
    let bytes = rights.as_bytes();
    if !matches!(bytes[0], b'r' | b'-')
        || !matches!(bytes[1], b'w' | b'-')
        || !matches!(bytes[2], b'x' | b'-')
    {
        return Err("invalid process memory access flags".into());
    }
    let label = rest
        .trim_start_matches(|ch| ch == ' ' || ch == '\t')
        .to_owned();
    let image_backed = inode != 0 && label.starts_with('/');
    Ok(Region {
        pid,
        start,
        size: end - start,
        access: rights[..3].to_string(),
        label,
        image_backed,
    })
}

#[cfg(target_os = "linux")]
fn list_regions(pid: u32) -> Result<Vec<Region>, String> {
    use std::fs::File;
    use std::io::Read;

    const MAX_MAP_BYTES: u64 = 16 * 1024 * 1024;
    let path = format!("/proc/{pid}/maps");
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|error| format!("cannot open {path}: {error}"))?
        .take(MAX_MAP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {path}: {error}"))?;
    if bytes.len() as u64 > MAX_MAP_BYTES {
        return Err("process memory map exceeds 16 MiB".into());
    }
    let content = String::from_utf8_lossy(&bytes);
    let mut regions = Vec::new();
    for line in content.lines() {
        regions.push(parse_linux_map_line(pid, line)?);
        if regions.len() > MAX_REGIONS {
            return Err(format!("process memory map exceeds {MAX_REGIONS} regions"));
        }
    }
    Ok(regions)
}

#[cfg(windows)]
fn list_regions(pid: u32) -> Result<Vec<Region>, String> {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};

    #[repr(C)]
    struct MemoryBasicInformation {
        base: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn VirtualQueryEx(
            process: *mut c_void,
            address: *const c_void,
            information: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn K32GetMappedFileNameW(
            process: *mut c_void,
            address: *const c_void,
            filename: *mut u16,
            size: u32,
        ) -> u32;
    }

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x1000000;
    // SAFETY: OpenProcess takes validated scalar arguments and returns a handle or null.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "cannot open process {pid} for memory-map query: {}",
            io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let mut regions = Vec::new();
        let mut image_paths = HashMap::<usize, String>::new();
        let mut address = 0_usize;
        loop {
            // SAFETY: information is initialized by VirtualQueryEx when it returns the full size.
            let mut information: MemoryBasicInformation = unsafe { zeroed() };
            // SAFETY: handle is valid for this scope, and information is writable.
            let returned = unsafe {
                VirtualQueryEx(
                    handle,
                    address as *const c_void,
                    &mut information,
                    size_of::<MemoryBasicInformation>(),
                )
            };
            if returned == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(87) {
                    break;
                }
                return Err(format!("cannot query process {pid} memory map: {error}"));
            }
            if returned != size_of::<MemoryBasicInformation>() {
                return Err("incomplete process memory-map entry".into());
            }
            let start = information.base as usize;
            let end = start
                .checked_add(information.region_size)
                .ok_or("process memory-map address overflow")?;
            if information.region_size == 0 || end <= address {
                return Err("process memory-map query made no progress".into());
            }
            if information.state == MEM_COMMIT {
                let access = windows_access(information.protect);
                let image_backed = information.kind == MEM_IMAGE;
                let label = if image_backed {
                    image_paths
                        .entry(information.allocation_base as usize)
                        .or_insert_with(|| {
                            let mut buffer = vec![0_u16; 32768];
                            // SAFETY: the process handle is valid and buffer is writable.
                            let length = unsafe {
                                K32GetMappedFileNameW(
                                    handle,
                                    information.base,
                                    buffer.as_mut_ptr(),
                                    buffer.len() as u32,
                                )
                            } as usize;
                            if length == 0 || length >= buffer.len() {
                                "image".to_owned()
                            } else {
                                String::from_utf16_lossy(&buffer[..length])
                            }
                        })
                        .clone()
                } else {
                    match information.kind {
                        0x40000 => "mapped",
                        0x20000 => "private",
                        _ => "other",
                    }
                    .to_owned()
                };
                regions.push(Region {
                    pid,
                    start,
                    size: information.region_size,
                    access,
                    label,
                    image_backed,
                });
                if regions.len() > MAX_REGIONS {
                    return Err(format!("process memory map exceeds {MAX_REGIONS} regions"));
                }
            }
            address = end;
        }
        Ok(regions)
    })();
    // SAFETY: handle came from OpenProcess and is closed once after enumeration.
    unsafe { CloseHandle(handle) };
    result
}

#[cfg(windows)]
fn windows_access(protect: u32) -> String {
    if protect & 0x100 != 0 {
        return "---".into();
    }
    match protect & 0xff {
        0x02 => "r--",
        0x04 | 0x08 => "rw-",
        0x10 => "--x",
        0x20 => "r-x",
        0x40 | 0x80 => "rwx",
        _ => "---",
    }
    .into()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn list_regions(_pid: u32) -> Result<Vec<Region>, String> {
    Err("process.regions is available only on Windows and Linux".into())
}

pub fn snapshot(pid: u32, address: usize, length: usize) -> Result<Vec<u8>, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("pid must be between 1 and 2147483647".into());
    }
    if address == 0 || length == 0 || length > MAX_READ || address.checked_add(length).is_none() {
        return Err(format!(
            "process address must be positive and length must be between 1 and {MAX_READ}"
        ));
    }
    read_memory(pid, address, length)
}

#[cfg(target_os = "linux")]
fn read_memory(pid: u32, address: usize, length: usize) -> Result<Vec<u8>, String> {
    use std::ffi::c_void;

    #[repr(C)]
    struct IoVec {
        base: *mut c_void,
        len: usize,
    }

    unsafe extern "C" {
        fn process_vm_readv(
            pid: i32,
            local: *const IoVec,
            local_count: usize,
            remote: *const IoVec,
            remote_count: usize,
            flags: usize,
        ) -> isize;
    }

    let mut bytes = vec![0_u8; length];
    let local = IoVec {
        base: bytes.as_mut_ptr().cast(),
        len: length,
    };
    let remote = IoVec {
        base: address as *mut c_void,
        len: length,
    };
    // SAFETY: both iovecs live for the call. The kernel validates the remote address.
    let read = unsafe { process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if read < 0 {
        return Err(format!(
            "cannot read process {pid} memory: {}",
            io::Error::last_os_error()
        ));
    }
    if read as usize != length {
        return Err(format!(
            "process {pid} memory read was incomplete: {read} of {length} bytes"
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn read_memory(pid: u32, address: usize, length: usize) -> Result<Vec<u8>, String> {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn ReadProcessMemory(
            process: *mut c_void,
            address: *const c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const PROCESS_VM_READ: u32 = 0x0010;
    // SAFETY: OpenProcess takes validated scalar arguments and returns a handle or null.
    let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "cannot open process {pid} for memory reading: {}",
            io::Error::last_os_error()
        ));
    }
    let mut bytes = vec![0_u8; length];
    let mut read = 0_usize;
    // SAFETY: the local buffer is writable for length bytes; Windows validates the remote range.
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            length,
            &mut read,
        )
    };
    let error = if ok == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: handle came from a successful OpenProcess call and is closed once.
    unsafe { CloseHandle(handle) };
    if let Some(error) = error {
        return Err(format!("cannot read process {pid} memory: {error}"));
    }
    if read != length {
        return Err(format!(
            "process {pid} memory read was incomplete: {read} of {length} bytes"
        ));
    }
    Ok(bytes)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn read_memory(_pid: u32, _address: usize, _length: usize) -> Result<Vec<u8>, String> {
    Err("process.snapshot is available only on Windows and Linux".into())
}

#[cfg(test)]
mod tests {
    use super::{
        executable, heap_candidates, hunt_region, kind, module_paths, pointer_refs_u64, regions,
        snapshot, thread_ids, writable_regions, Region, MAX_READ, MAX_SCAN,
    };

    #[test]
    fn executable_identifies_the_current_process() {
        assert!(executable(0).is_err());
        let path = executable(std::process::id()).unwrap();
        assert!(!path.is_empty());
        assert!(std::path::Path::new(&path).is_file(), "{path}");
    }

    #[test]
    fn thread_ids_are_bounded_sorted_and_include_self() {
        assert!(thread_ids(0).is_err());
        let ids = thread_ids(std::process::id()).unwrap();
        assert!(!ids.is_empty());
        assert!(ids.len() <= super::MAX_THREADS);
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        #[cfg(target_os = "linux")]
        assert!(ids.contains(&std::process::id()));
    }

    #[test]
    fn module_paths_deduplicates_mappings_and_skips_unresolved_names() {
        let image = |label: &str| Region {
            pid: 7,
            start: 0,
            size: 4096,
            access: "r-x".into(),
            label: label.into(),
            image_backed: true,
        };
        let paths = module_paths(&[
            image("/bin/main"),
            image("/lib/one.so"),
            image("/bin/main"),
            image("image"),
            image(""),
        ]);
        assert_eq!(paths, ["/bin/main", "/lib/one.so"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_module_paths_preserve_internal_whitespace() {
        let line = "00400000-00401000 r-xp 00000000 00:01 42   /tmp/a  b\tc (deleted)";
        let region = super::parse_linux_map_line(7, line).unwrap();
        assert_eq!(region.label, "/tmp/a  b\tc (deleted)");
        assert!(region.image_backed);
        assert_eq!(module_paths(&[region]), ["/tmp/a  b\tc (deleted)"]);
        assert!(super::parse_linux_map_line(7, "00400000-00401000 r-xp").is_err());
    }

    #[test]
    fn rejects_invalid_ranges_and_unreadable_memory() {
        let pid = std::process::id();
        assert!(snapshot(0, 1, 1).is_err());
        assert!(snapshot(pid, 0, 1).is_err());
        assert!(snapshot(pid, 1, 0).is_err());
        assert!(snapshot(pid, 1, MAX_READ + 1).is_err());
        #[cfg(any(target_os = "linux", windows))]
        assert!(snapshot(pid, 1, 1).is_err());
    }

    #[test]
    fn maps_contain_a_local_readable_allocation() {
        let data = Box::new(*b"GALEIKAN");
        let address = data.as_ptr() as usize;
        let maps = regions(std::process::id()).unwrap();
        assert!(maps
            .iter()
            .any(|region| { region.contains(address) && region.access.starts_with('r') }));
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn region_search_spans_read_chunks_and_checks_limits() {
        let mut data = vec![0_u8; MAX_READ + 32];
        let needle = b"GAK!";
        data[MAX_READ - 2..MAX_READ + 2].copy_from_slice(needle);
        data[MAX_READ + 10..MAX_READ + 14].copy_from_slice(needle);
        let region = Region {
            pid: std::process::id(),
            start: data.as_ptr() as usize,
            size: data.len(),
            access: "rw-".into(),
            label: "test allocation".into(),
            image_backed: false,
        };
        assert_eq!(
            hunt_region(&region, needle, None, 0, data.len()).unwrap(),
            [MAX_READ - 2, MAX_READ + 10]
        );
        assert_eq!(
            hunt_region(&region, needle, None, MAX_READ - 2, needle.len()).unwrap(),
            [MAX_READ - 2]
        );
        assert_eq!(
            hunt_region(
                &region,
                b"GA\0!",
                Some(&[0xff, 0xff, 0, 0xff]),
                0,
                data.len()
            )
            .unwrap(),
            [MAX_READ - 2, MAX_READ + 10]
        );
        assert!(hunt_region(&region, b"", None, 0, 4).is_err());
        assert!(hunt_region(&region, needle, None, 0, MAX_SCAN + 1).is_err());
        assert!(hunt_region(&region, needle, None, data.len(), 1).is_err());
        assert!(hunt_region(
            &Region {
                access: "---".into(),
                ..region.clone()
            },
            needle,
            None,
            0,
            4
        )
        .is_err());
        assert!(hunt_region(&region, &[0], None, 0, 10_001).is_err());
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn pointer_refs_find_unaligned_full_width_values_across_read_chunks() {
        let mut data = vec![0_u8; MAX_READ + 32];
        let target = 0xfedc_ba98_7654_3210_u64;
        data[MAX_READ - 4..MAX_READ + 4].copy_from_slice(&target.to_le_bytes());
        data[MAX_READ + 16..MAX_READ + 24].copy_from_slice(&target.to_le_bytes());
        let region = Region {
            pid: std::process::id(),
            start: data.as_ptr() as usize,
            size: data.len(),
            access: "rw-".into(),
            label: String::new(),
            image_backed: false,
        };
        assert_eq!(
            pointer_refs_u64(&region, target, 0, data.len()).unwrap(),
            [MAX_READ - 4, MAX_READ + 16]
        );
        assert!(pointer_refs_u64(&region, target, 0, 0).unwrap().is_empty());
        assert!(pointer_refs_u64(&region, target, data.len(), 1).is_err());
    }

    #[test]
    fn region_kind_keeps_heap_distinct_from_private_memory() {
        let mut region = Region {
            pid: 1,
            start: 0,
            size: 4096,
            access: "rw-".into(),
            label: "[heap]".into(),
            image_backed: false,
        };
        assert_eq!(kind(&region), "heap");
        region.label = "[stack]".into();
        assert_eq!(kind(&region), "stack");
        region.label = "private".into();
        assert_eq!(kind(&region), "private");
        region.label.clear();
        assert_eq!(kind(&region), "anonymous");
        region.label = "/tmp/mapped.bin".into();
        region.image_backed = true;
        assert_eq!(kind(&region), if cfg!(windows) { "image" } else { "file" });
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn writable_regions_include_local_mutable_memory_and_only_writable_maps() {
        let mut data = Box::new(*b"GALEIKAN");
        std::hint::black_box(&mut data);
        let address = data.as_ptr() as usize;
        let maps = writable_regions(std::process::id()).unwrap();
        assert!(maps.iter().any(|region| region.contains(address)));
        assert!(maps
            .iter()
            .all(|region| region.access.as_bytes().get(1) == Some(&b'w')));
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn heap_candidates_include_local_mutable_memory_and_exclude_other_mappings() {
        let mut data = Box::new(*b"GALEIKAN");
        std::hint::black_box(&mut data);
        let address = data.as_ptr() as usize;
        let maps = heap_candidates(std::process::id()).unwrap();
        assert!(maps.iter().any(|region| region.contains(address)));
        assert!(maps.iter().all(|region| {
            region.access.starts_with("rw")
                && !region.image_backed
                && matches!(kind(region), "heap" | "anonymous" | "private")
        }));
    }

    #[test]
    fn region_address_translation_checks_both_boundaries() {
        let region = Region {
            pid: 7,
            start: 0x1000,
            size: 4,
            access: "rw-".into(),
            label: String::new(),
            image_backed: false,
        };
        assert!(!region.contains(0xfff));
        assert!(region.contains(0x1000));
        assert!(region.contains(0x1003));
        assert!(!region.contains(0x1004));
        assert_eq!(region.offset_of(0x1003).unwrap(), 3);
        assert_eq!(region.address_of(3).unwrap(), 0x1003);
        assert!(region.offset_of(0x1004).is_err());
        assert!(region.address_of(4).is_err());
    }

    #[test]
    fn address_references_are_readable_and_bound_to_the_region() {
        let region = Region {
            pid: 7,
            start: 0x1000,
            size: 0x100,
            access: "r--".into(),
            label: "/tmp/sample.bin".into(),
            image_backed: true,
        };
        let reference = region.reference(0x1042).unwrap();
        assert_eq!(reference, "sample.bin@7:0x1000+0x42");
        assert_eq!(region.resolve_reference(&reference).unwrap(), 0x1042);
        assert_eq!(
            region
                .resolve_reference("sample.bin@7:0x1000+0x00000000000000000042")
                .unwrap(),
            0x1042
        );
        let last = region.advance_reference(&reference, 0xbd).unwrap();
        assert_eq!(region.resolve_reference(&last).unwrap(), 0x10ff);
        assert_eq!(region.advance_reference(&last, -0xbd).unwrap(), reference);
        assert!(region.advance_reference(&last, 1).is_err());
        assert!(region.advance_reference(&reference, -0x43).is_err());
        assert!(region.advance_reference(&reference, i64::MIN).is_err());
        let mut other = region.clone();
        other.start = 0x2000;
        assert!(other.resolve_reference(&reference).is_err());
        other = region.clone();
        other.pid = 8;
        assert!(other.resolve_reference(&reference).is_err());
        assert!(region
            .resolve_reference("sample.bin@7:0x1000+0x100")
            .is_err());
        assert!(region
            .resolve_reference("sample.bin@7:0x1000+0x-1")
            .is_err());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn address_references_preserve_high_bit_addresses() {
        let region = Region {
            pid: 9,
            start: 0x8000_0000_0000_0000,
            size: 0x100,
            access: "r--".into(),
            label: "[heap]".into(),
            image_backed: false,
        };
        let reference = region.reference(0x8000_0000_0000_0042).unwrap();
        assert_eq!(reference, "[heap]@9:0x8000000000000000+0x42");
        assert_eq!(
            region.resolve_reference(&reference).unwrap(),
            0x8000_0000_0000_0042
        );
    }
}
