#![deny(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)]
mod asm;
#[allow(dead_code)]
mod clr_signature;
#[allow(dead_code)]
mod formats;
#[allow(dead_code)]
mod net;

use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::time::Duration;

struct HttpFetchResult {
    bytes: Vec<u8>,
    label: String,
    origin: String,
    status: u16,
    request_sha256: String,
    headers: Vec<(String, String)>,
}

#[repr(C)]
pub struct GaleikanHttpRequest {
    method: *const u8,
    method_length: usize,
    url: *const u8,
    url_length: usize,
    headers: *const *const u8,
    header_count: usize,
    body: *const u8,
    body_length: usize,
    max_bytes: i64,
    timeout_ms: i64,
}

/// # Safety
/// `url` must be readable for `length` bytes. `output` and `error`, when used,
/// must be writable for their stated capacities and must not overlap `url`.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_authority(
    url: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if url.is_null() || length > 4096 || output.is_null() || capacity == 0 {
        return write_error(error, error_capacity, "invalid HTTP URL input");
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let raw = unsafe { std::slice::from_raw_parts(url, length) };
        let raw = std::str::from_utf8(raw).map_err(|_| "invalid HTTP URL encoding".to_string())?;
        net::http_url(raw).map(|(_, authority)| authority)
    }));
    match result {
        Ok(Ok(authority)) if authority.len() < capacity => {
            unsafe {
                ptr::copy_nonoverlapping(authority.as_ptr(), output, authority.len());
                *output.add(authority.len()) = 0;
            }
            0
        }
        Ok(Ok(_)) => write_error(error, error_capacity, "HTTP authority exceeds native limit"),
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "HTTP URL parsing failed"),
    }
}

/// # Safety
/// `url` must be readable for `length` bytes; `out` must be writable, and
/// `error` must be writable for `error_capacity` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_fetch(
    url: *const u8,
    length: usize,
    max_bytes: i64,
    timeout_ms: i64,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if out.is_null() || url.is_null() || length > 4096 {
        return write_error(error, error_capacity, "invalid HTTP fetch input");
    }
    unsafe { *out = ptr::null_mut() };
    if max_bytes < 0 {
        return write_error(error, error_capacity, "max_bytes out of range");
    }
    if max_bytes > 16_777_216 {
        return write_error(error, error_capacity, "max_bytes must be at most 16777216");
    }
    if !(1..=30_000).contains(&timeout_ms) {
        return write_error(error, error_capacity, "timeout_ms must be between 1 and 30000");
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let raw = unsafe { std::slice::from_raw_parts(url, length) };
        let raw = std::str::from_utf8(raw).map_err(|_| "invalid HTTP URL encoding".to_string())?;
        let (url, _) = net::http_url(raw)?;
        let response = net::fetch(
            url,
            max_bytes as usize,
            Duration::from_millis(timeout_ms as u64),
        )?;
        let origin = match response.peer {
            Some(peer) => format!("HTTP {} {} (peer {peer})", response.status, response.url),
            None => format!("HTTP {} {}", response.status, response.url),
        };
        Ok::<_, String>(HttpFetchResult {
            bytes: response.bytes,
            label: response.url,
            origin,
            status: response.status,
            request_sha256: String::new(),
            headers: response.headers,
        })
    }));
    match result {
        Ok(Ok(response)) => {
            unsafe { *out = Box::into_raw(Box::new(response)).cast() };
            0
        }
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "HTTP fetch failed"),
    }
}

/// # Safety
/// `handle` must be a live HTTP result handle returned by this library.
/// `output`, when non-null, must be writable for `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_fetch_copy(
    handle: *const c_void,
    kind: u32,
    output: *mut u8,
    capacity: usize,
) -> usize {
    let Some(result) = (unsafe { handle.cast::<HttpFetchResult>().as_ref() }) else {
        return usize::MAX;
    };
    let data = match kind {
        1 => result.bytes.as_slice(),
        2 => result.label.as_bytes(),
        3 => result.origin.as_bytes(),
        4 => result.request_sha256.as_bytes(),
        _ => return usize::MAX,
    };
    if !output.is_null() && capacity >= data.len() {
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), output, data.len()) };
    }
    data.len()
}

/// # Safety
/// A non-null `handle` must be a live HTTP result handle and must be freed
/// exactly once. It cannot be used after this call.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_fetch_free(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle.cast::<HttpFetchResult>())) };
    }
}

/// # Safety
/// `input` and its non-null pointer fields must remain readable for their
/// stated lengths throughout the call. Each header points to a valid boxed
/// string. `out` and the optional error buffer must be writable.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_request(
    input: *const GaleikanHttpRequest,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if input.is_null() || out.is_null() {
        return write_error(error, error_capacity, "invalid HTTP request input");
    }
    unsafe { *out = ptr::null_mut() };
    let input = unsafe { &*input };
    if input.method.is_null() || input.method_length > 16
        || input.url.is_null() || input.url_length > 4096
        || (input.header_count != 0 && input.headers.is_null())
        || (input.body_length != 0 && input.body.is_null())
    {
        return write_error(error, error_capacity, "invalid HTTP request input");
    }
    if input.header_count > 32 {
        return write_error(error, error_capacity, "HTTP request headers exceed 32 fields or 8192 bytes");
    }
    if input.body_length > 1_048_576 {
        return write_error(error, error_capacity, "HTTP request body exceeds 1048576 bytes");
    }
    if input.max_bytes < 0 {
        return write_error(error, error_capacity, "max_bytes out of range");
    }
    if input.max_bytes > 16_777_216 {
        return write_error(error, error_capacity, "max_bytes must be at most 16777216");
    }
    if !(1..=30_000).contains(&input.timeout_ms) {
        return write_error(error, error_capacity, "timeout_ms must be between 1 and 30000");
    }
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<HttpFetchResult, String> {
        let method = unsafe { std::slice::from_raw_parts(input.method, input.method_length) };
        let method = std::str::from_utf8(method).map_err(|_| "invalid HTTP method encoding")?;
        let url = unsafe { std::slice::from_raw_parts(input.url, input.url_length) };
        let url = std::str::from_utf8(url).map_err(|_| "invalid HTTP URL encoding")?;
        let (url, _) = net::http_url(url)?;
        let headers = if input.header_count == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(input.headers, input.header_count) }
        };
        let mut header_strings = Vec::with_capacity(headers.len());
        let mut header_bytes = 0usize;
        for &box_pointer in headers {
            if box_pointer.is_null() {
                return Err("invalid HTTP request header".into());
            }
            let length = unsafe { ptr::read_unaligned(box_pointer.cast::<u64>()) } as usize;
            header_bytes = header_bytes.saturating_add(length);
            if header_bytes > 8192 {
                return Err("HTTP request headers exceed 32 fields or 8192 bytes".into());
            }
            let bytes = unsafe { std::slice::from_raw_parts(box_pointer.add(8), length) };
            let value = std::str::from_utf8(bytes)
                .map_err(|_| "invalid HTTP request header encoding")?;
            header_strings.push(value.to_owned());
        }
        let body = if input.body_length == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(input.body, input.body_length) }
        };
        let response = net::request(
            url,
            method,
            &header_strings,
            body,
            input.max_bytes as usize,
            Duration::from_millis(input.timeout_ms as u64),
        )?;
        let origin = match response.peer {
            Some(peer) => format!("HTTP {method} {} {} (peer {peer})", response.status, response.url),
            None => format!("HTTP {method} {} {}", response.status, response.url),
        };
        let request_sha256 = Sha256::digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(HttpFetchResult {
            bytes: response.bytes,
            label: response.url,
            origin,
            status: response.status,
            request_sha256,
            headers: response.headers,
        })
    }));
    match result {
        Ok(Ok(response)) => {
            unsafe { *out = Box::into_raw(Box::new(response)).cast() };
            0
        }
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "HTTP request failed"),
    }
}

/// # Safety
/// `handle` must be a live HTTP result handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_response_number(handle: *const c_void, kind: u32) -> usize {
    let Some(response) = (unsafe { handle.cast::<HttpFetchResult>().as_ref() }) else {
        return usize::MAX;
    };
    match kind {
        1 => usize::from(response.status),
        2 => response.headers.len(),
        _ => usize::MAX,
    }
}

/// # Safety
/// `handle` must be a live HTTP result handle. A non-null `output` must be
/// writable for `capacity` bytes and must not overlap the stored header.
#[no_mangle]
pub unsafe extern "C" fn galeikan_http_response_header_copy(
    handle: *const c_void,
    index: usize,
    kind: u32,
    output: *mut u8,
    capacity: usize,
) -> usize {
    let Some(response) = (unsafe { handle.cast::<HttpFetchResult>().as_ref() }) else {
        return usize::MAX;
    };
    let Some((name, value)) = response.headers.get(index) else {
        return usize::MAX;
    };
    let bytes = match kind {
        1 => name.as_bytes(),
        2 => value.as_bytes(),
        _ => return usize::MAX,
    };
    if !output.is_null() && capacity >= bytes.len() {
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    }
    bytes.len()
}

struct DecodedCollection {
    instructions: Vec<(usize, asm::Decoded)>,
    blocks: Vec<asm::Block>,
    overlaps: Vec<bool>,
}

impl DecodedCollection {
    fn new(instructions: Vec<(usize, asm::Decoded)>) -> Result<Self, String> {
        Self::new_with_calls(instructions, true)
    }

    fn new_with_calls(instructions: Vec<(usize, asm::Decoded)>, follow_calls: bool) -> Result<Self, String> {
        let decoded = instructions
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        let blocks = if follow_calls {
            asm::blocks(&decoded)?
        } else {
            asm::blocks_with_calls(&decoded, false)?
        };
        let overlaps = asm::overlaps(&decoded)?;
        Ok(Self {
            instructions,
            blocks,
            overlaps,
        })
    }
}

fn write_error(error: *mut u8, capacity: usize, message: &str) -> i32 {
    if !error.is_null() && capacity > 0 {
        let bytes = message.as_bytes();
        let length = bytes.len().min(capacity - 1);
        // SAFETY: The C caller provides a writable buffer of `capacity` bytes.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), error, length);
            *error.add(length) = 0;
        }
    }
    -1
}

/// Decode one x86 instruction. The returned handle must be released with
/// `galeikan_asm_instruction_free`; no Rust allocation crosses the C allocator.
/// # Safety
/// `bytes` must be readable for `length` bytes when non-null; `out` and the
/// optional error buffer must be writable for their stated sizes.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_decode(
    bytes: *const u8,
    length: usize,
    offset: usize,
    ip: u64,
    bitness: u32,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if out.is_null() {
        return write_error(error, error_capacity, "invalid decoder input");
    }
    // SAFETY: `out` is non-null and points to a writable pointer supplied by C.
    unsafe { *out = ptr::null_mut() };
    if !error.is_null() && error_capacity > 0 {
        unsafe { *error = 0 };
    }
    if (bytes.is_null() && length != 0) || length > 512 * 1024 * 1024 {
        return write_error(error, error_capacity, "invalid decoder input");
    }
    let input = if length == 0 {
        &[]
    } else {
        // SAFETY: The caller keeps `length` readable bytes alive for this call.
        unsafe { std::slice::from_raw_parts(bytes, length) }
    };
    match catch_unwind(AssertUnwindSafe(|| asm::decode(input, offset, ip, bitness))) {
        Ok(Ok(instruction)) => {
            unsafe { *out = Box::into_raw(Box::new(instruction)).cast() };
            0
        }
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "x86 decoder failed"),
    }
}

/// Decode reachable instructions in ascending source-offset order. The handle
/// owns its instructions and must be released with `galeikan_asm_disassembly_free`.
/// # Safety
/// `bytes` must be readable for `length` bytes when non-null; `out` and the
/// optional error buffer must be writable for their stated sizes.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_reachable(
    bytes: *const u8,
    length: usize,
    start_offset: usize,
    base_ip: u64,
    bitness: u32,
    max_instructions: usize,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    // SAFETY: The caller upholds the documented pointer contract.
    unsafe { galeikan_asm_reachable_impl(bytes, length, start_offset, base_ip, bitness, max_instructions, out, error, error_capacity, true) }
}

/// Decode reachable instructions without descending into direct calls.
/// The returned handle must be released with `galeikan_asm_disassembly_free`.
/// # Safety
/// `bytes` must be readable for `length` bytes when non-null; `out` and the
/// optional error buffer must be writable for their stated sizes.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_function_reachable(
    bytes: *const u8,
    length: usize,
    start_offset: usize,
    base_ip: u64,
    bitness: u32,
    max_instructions: usize,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    // SAFETY: The caller upholds the documented pointer contract.
    unsafe { galeikan_asm_reachable_impl(bytes, length, start_offset, base_ip, bitness, max_instructions, out, error, error_capacity, false) }
}

unsafe fn galeikan_asm_reachable_impl(
    bytes: *const u8,
    length: usize,
    start_offset: usize,
    base_ip: u64,
    bitness: u32,
    max_instructions: usize,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
    follow_calls: bool,
) -> i32 {
    if out.is_null() {
        return write_error(error, error_capacity, "invalid decoder input");
    }
    // SAFETY: `out` is non-null and points to a writable pointer supplied by C.
    unsafe { *out = ptr::null_mut() };
    if !error.is_null() && error_capacity > 0 {
        // SAFETY: The caller provides a writable error buffer.
        unsafe { *error = 0 };
    }
    if (bytes.is_null() && length != 0) || length > 512 * 1024 * 1024 {
        return write_error(error, error_capacity, "invalid decoder input");
    }
    if !(1..=asm::MAX_DISASSEMBLY).contains(&max_instructions) {
        return write_error(
            error,
            error_capacity,
            &format!(
                "instruction count must be between 1 and {}",
                asm::MAX_DISASSEMBLY
            ),
        );
    }
    let input = if length == 0 {
        &[]
    } else {
        // SAFETY: The caller keeps `length` readable bytes alive for this call.
        unsafe { std::slice::from_raw_parts(bytes, length) }
    };
    match catch_unwind(AssertUnwindSafe(|| {
        if follow_calls {
            asm::reachable(input, start_offset, base_ip, bitness, max_instructions)
        } else {
            asm::function_reachable(input, start_offset, base_ip, bitness, max_instructions)
        }
    })) {
        Ok(Ok(instructions)) => {
            let collection = match DecodedCollection::new_with_calls(instructions, follow_calls) {
                Ok(collection) => collection,
                Err(message) => return write_error(error, error_capacity, &message),
            };
            // SAFETY: `out` is non-null and points to a writable pointer supplied by C.
            unsafe { *out = Box::into_raw(Box::new(collection)).cast() };
            0
        }
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "x86 decoder failed"),
    }
}

/// Decode a fixed number of consecutive instructions from a bounded entry region.
/// The returned handle uses the same accessors and ownership as reachable disassembly.
/// # Safety
/// `bytes` must be readable for `length` bytes when non-null; `out` and the
/// optional error buffer must be writable for their stated sizes.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_linear(
    bytes: *const u8,
    length: usize,
    base_ip: u64,
    bitness: u32,
    count: usize,
    out: *mut *mut c_void,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if out.is_null() {
        return write_error(error, error_capacity, "invalid decoder input");
    }
    // SAFETY: The caller provides a writable output pointer.
    unsafe { *out = ptr::null_mut() };
    if !error.is_null() && error_capacity > 0 {
        // SAFETY: The caller provides a writable error buffer.
        unsafe { *error = 0 };
    }
    if (bytes.is_null() && length != 0) || length > 512 * 1024 * 1024 {
        return write_error(error, error_capacity, "invalid decoder input");
    }
    if !(1..=asm::MAX_DISASSEMBLY).contains(&count) {
        return write_error(
            error,
            error_capacity,
            &format!("instruction count must be between 1 and {}", asm::MAX_DISASSEMBLY),
        );
    }
    let input = if length == 0 {
        &[]
    } else {
        // SAFETY: The caller keeps `length` readable bytes alive for this call.
        unsafe { std::slice::from_raw_parts(bytes, length) }
    };
    match catch_unwind(AssertUnwindSafe(|| {
        let mut instructions = Vec::with_capacity(count);
        let mut decoder = asm::DecodeContext::new();
        let mut offset = 0usize;
        let mut ip = base_ip;
        for _ in 0..count {
            if offset >= input.len() {
                return Err("linear disassembly exceeds executable entry region".to_owned());
            }
            let decoded = decoder.decode(input, offset, ip, bitness)?;
            ip = ip
                .checked_add(decoded.size as u64)
                .ok_or("instruction address overflow")?;
            let next = offset + decoded.size;
            instructions.push((offset, decoded));
            offset = next;
        }
        DecodedCollection::new(instructions)
    })) {
        Ok(Ok(collection)) => {
            // SAFETY: `out` is non-null and writable.
            unsafe { *out = Box::into_raw(Box::new(collection)).cast() };
            0
        }
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "x86 decoder failed"),
    }
}

/// # Safety
/// A non-null `handle` must be a live disassembly handle returned by this
/// library and must be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_free(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: This handle came from `galeikan_asm_reachable` and is freed once.
        drop(unsafe { Box::from_raw(handle.cast::<DecodedCollection>()) });
    }
}

/// # Safety
/// A non-null `handle` must be a live disassembly handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<DecodedCollection>().as_ref() }
        .map_or(0, |value| value.instructions.len())
}

/// # Safety
/// `handle` must be a live disassembly handle. Non-null `start` and `end`
/// must be writable output slots.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_bounds(
    handle: *const c_void,
    start: *mut usize,
    end: *mut usize,
) -> i32 {
    if start.is_null() || end.is_null() {
        return 0;
    }
    let Some(collection) = (unsafe { handle.cast::<DecodedCollection>().as_ref() }) else {
        return 0;
    };
    let Some(first) = collection.instructions.first() else {
        return 0;
    };
    let mut low = first.0;
    let mut high = 0usize;
    for (offset, instruction) in &collection.instructions {
        let Some(next) = offset.checked_add(instruction.size) else {
            return 0;
        };
        low = low.min(*offset);
        high = high.max(next);
    }
    // SAFETY: Both output slots are non-null and writable by the caller.
    unsafe {
        *start = low;
        *end = high;
    }
    1
}

/// Clone one instruction into an independently owned handle. On success the
/// caller frees `out` with `galeikan_asm_instruction_free`.
/// # Safety
/// `handle` must be a live disassembly handle; `out` and `offset` must be
/// writable output slots.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_at(
    handle: *const c_void,
    index: usize,
    out: *mut *mut c_void,
    offset: *mut usize,
) -> i32 {
    if out.is_null() || offset.is_null() {
        return 0;
    }
    // SAFETY: Both output slots are non-null and writable by the caller.
    unsafe { *out = ptr::null_mut() };
    let Some((instruction_offset, decoded)) =
        (unsafe { handle.cast::<DecodedCollection>().as_ref() })
            .and_then(|value| value.instructions.get(index))
    else {
        return 0;
    };
    // SAFETY: Both output slots are non-null and writable by the caller.
    unsafe {
        *out = Box::into_raw(Box::new(decoded.clone())).cast();
        *offset = *instruction_offset;
    }
    1
}

/// # Safety
/// A non-null `handle` must be a live disassembly handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_overlap_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<DecodedCollection>().as_ref() }.map_or(0, |value| {
        value.overlaps.iter().filter(|overlap| **overlap).count()
    })
}

/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// a writable `i32` slot.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_overlap_at(
    handle: *const c_void,
    index: usize,
    output: *mut i32,
) -> i32 {
    let overlap = unsafe { handle.cast::<DecodedCollection>().as_ref() }
        .and_then(|value| value.overlaps.get(index));
    match overlap {
        Some(overlap) if !output.is_null() => {
            // SAFETY: The caller provides a writable output slot.
            unsafe { *output = i32::from(*overlap) };
            1
        }
        _ => 0,
    }
}

/// # Safety
/// A non-null `handle` must be a live disassembly handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<DecodedCollection>().as_ref() }.map_or(0, |value| value.blocks.len())
}

/// Copies one block's scalar metadata. Successor addresses are queried below.
/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// a writable `GaleikanAsmBlock` slot.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block(
    handle: *const c_void,
    index: usize,
    output: *mut GaleikanAsmBlock,
) -> i32 {
    let block = unsafe { handle.cast::<DecodedCollection>().as_ref() }
        .and_then(|value| value.blocks.get(index));
    match block {
        Some(block) if !output.is_null() => {
            // SAFETY: The caller provides a writable output struct.
            unsafe {
                *output = GaleikanAsmBlock {
                    start: block.start,
                    end: block.end,
                    first_index: block.first_index,
                    instruction_count: block.instruction_count,
                    successor_count: block.successors.len(),
                    unresolved: i32::from(block.unresolved),
                }
            };
            1
        }
        _ => 0,
    }
}

#[repr(C)]
pub struct GaleikanAsmBlock {
    pub start: u64,
    pub end: u64,
    pub first_index: usize,
    pub instruction_count: usize,
    pub successor_count: usize,
    pub unresolved: i32,
}

/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// a writable `u64` slot.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block_successor(
    handle: *const c_void,
    block_index: usize,
    successor_index: usize,
    output: *mut u64,
) -> i32 {
    let address = unsafe { handle.cast::<DecodedCollection>().as_ref() }
        .and_then(|value| value.blocks.get(block_index))
        .and_then(|block| block.successors.get(successor_index).copied());
    optional_address(address, output)
}

/// Return the shortest known CFG path as block start addresses. An invalid
/// block index returns `usize::MAX`; an unreachable target returns zero.
/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// writable for `capacity` `u64` values without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block_path(
    handle: *const c_void,
    from: usize,
    to: usize,
    output: *mut u64,
    capacity: usize,
) -> usize {
    let Some(collection) = (unsafe { handle.cast::<DecodedCollection>().as_ref() }) else {
        return usize::MAX;
    };
    let Ok(path) = asm::block_path(&collection.blocks, from, to) else {
        return usize::MAX;
    };
    if !output.is_null() && capacity >= path.len() {
        unsafe { ptr::copy_nonoverlapping(path.as_ptr(), output, path.len()) };
    }
    path.len()
}

/// Return known CFG dominators from entry to target. Invalid indices return
/// `usize::MAX`; an unreachable target returns zero.
/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// writable for `capacity` `u64` values without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block_dominators(
    handle: *const c_void,
    entry: usize,
    target: usize,
    output: *mut u64,
    capacity: usize,
) -> usize {
    let Some(collection) = (unsafe { handle.cast::<DecodedCollection>().as_ref() }) else {
        return usize::MAX;
    };
    let Ok(dominators) = asm::block_dominators(&collection.blocks, entry, target) else {
        return usize::MAX;
    };
    if !output.is_null() && capacity >= dominators.len() {
        unsafe { ptr::copy_nonoverlapping(dominators.as_ptr(), output, dominators.len()) };
    }
    dominators.len()
}

/// Return the sorted known natural loop body. Invalid indices return
/// `usize::MAX`; a non-loop edge returns zero.
/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// writable for `capacity` `u64` values without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block_natural_loop(
    handle: *const c_void,
    entry: usize,
    header: usize,
    latch: usize,
    output: *mut u64,
    capacity: usize,
) -> usize {
    let Some(collection) = (unsafe { handle.cast::<DecodedCollection>().as_ref() }) else {
        return usize::MAX;
    };
    let Ok(body) = asm::block_natural_loop(&collection.blocks, entry, header, latch) else {
        return usize::MAX;
    };
    if !output.is_null() && capacity >= body.len() {
        unsafe { ptr::copy_nonoverlapping(body.as_ptr(), output, body.len()) };
    }
    body.len()
}

/// Query direct call targets, data references, direct xrefs, or data xrefs.
/// Returns the required count and copies only when capacity is sufficient.
/// # Safety
/// `handle` must be a live disassembly handle. A non-null `output` must be
/// writable for `capacity` `u64` values without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_references(
    handle: *const c_void,
    kind: u32,
    target: u64,
    output: *mut u64,
    capacity: usize,
) -> usize {
    let Some(collection) = (unsafe { handle.cast::<DecodedCollection>().as_ref() }) else {
        return 0;
    };
    let decoded = collection
        .instructions
        .iter()
        .map(|(_, instruction)| instruction)
        .collect::<Vec<_>>();
    let addresses = match kind {
        1 => asm::call_targets(&decoded),
        2 => asm::data_refs(&decoded),
        3 => asm::xrefs(&decoded, target),
        4 => asm::data_xrefs(&decoded, target),
        _ => return 0,
    };
    if !output.is_null() && capacity >= addresses.len() {
        // SAFETY: The caller provides an array with at least `capacity` entries.
        unsafe { ptr::copy_nonoverlapping(addresses.as_ptr(), output, addresses.len()) };
    }
    addresses.len()
}

/// # Safety
/// A non-null `handle` must be a live instruction handle returned by this
/// library and must be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_free(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: This handle came from `galeikan_asm_decode` and is freed once.
        drop(unsafe { Box::from_raw(handle.cast::<asm::Decoded>()) });
    }
}

/// # Safety
/// A non-null `handle` must be a live instruction handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_size(handle: *const c_void) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }.map_or(0, |value| value.size)
}

/// # Safety
/// A non-null `handle` must be a live instruction handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_ip(handle: *const c_void) -> u64 {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }.map_or(0, |value| value.ip)
}

/// Hash a readable source span. `output` must point to 32 writable bytes.
/// # Safety
/// `bytes` must be readable for `length` bytes when non-null; `output` must
/// point to 32 writable bytes without overlapping the input span.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_sha256(
    bytes: *const u8,
    length: usize,
    output: *mut u8,
) -> i32 {
    if output.is_null() || (bytes.is_null() && length != 0) || length > 512 * 1024 * 1024 {
        return -1;
    }
    let input = if length == 0 {
        &[]
    } else {
        // SAFETY: The caller keeps `length` readable bytes alive for this call.
        unsafe { std::slice::from_raw_parts(bytes, length) }
    };
    let digest = Sha256::digest(input);
    // SAFETY: The caller provides at least 32 writable output bytes.
    unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), output, digest.len()) };
    0
}

/// Write a 64-byte lowercase ASCII SHA-256 fingerprint of PE imports.
/// # Safety
/// `bytes` must be readable for `length` bytes when non-null; `output` must
/// point to 64 writable bytes, and the optional error buffer must be writable
/// for its stated capacity. Output must not overlap the input span.
#[no_mangle]
pub unsafe extern "C" fn galeikan_formats_import_fingerprint(
    bytes: *const u8,
    length: usize,
    output: *mut u8,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if output.is_null() || (bytes.is_null() && length != 0) || length > 512 * 1024 * 1024 {
        return write_error(error, error_capacity, "invalid import fingerprint input");
    }
    if !error.is_null() && error_capacity > 0 {
        // SAFETY: The caller provides a writable error buffer.
        unsafe { *error = 0 };
    }
    let input = if length == 0 {
        &[]
    } else {
        // SAFETY: The caller keeps `length` readable bytes alive for this call.
        unsafe { std::slice::from_raw_parts(bytes, length) }
    };
    match catch_unwind(AssertUnwindSafe(|| {
        formats::probe(input)?.import_fingerprint(input)
    })) {
        Ok(Ok(fingerprint)) => {
            if fingerprint.len() != 64 {
                return write_error(error, error_capacity, "invalid import fingerprint length");
            }
            // SAFETY: The caller provides 64 writable bytes that do not overlap input.
            unsafe { ptr::copy_nonoverlapping(fingerprint.as_ptr(), output, 64) };
            0
        }
        Ok(Err(message)) => write_error(error, error_capacity, &message),
        Err(_) => write_error(error, error_capacity, "import fingerprint failed"),
    }
}

fn optional_address(value: Option<u64>, output: *mut u64) -> i32 {
    match value {
        Some(address) if !output.is_null() => {
            // SAFETY: The caller provides a writable address slot.
            unsafe { *output = address };
            1
        }
        _ => 0,
    }
}

/// # Safety
/// `handle` must be a live instruction handle. A non-null `output` must be
/// a writable `u64` slot.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_target(
    handle: *const c_void,
    output: *mut u64,
) -> i32 {
    let target = unsafe { handle.cast::<asm::Decoded>().as_ref() }.and_then(|value| value.target);
    optional_address(target, output)
}

/// # Safety
/// `handle` must be a live instruction handle. A non-null `output` must be
/// a writable `u64` slot.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_data_target(
    handle: *const c_void,
    output: *mut u64,
) -> i32 {
    let target =
        unsafe { handle.cast::<asm::Decoded>().as_ref() }.and_then(|value| value.data_target);
    optional_address(target, output)
}

/// # Safety
/// A non-null `handle` must be a live instruction handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_register_usage_complete(
    handle: *const c_void,
) -> i32 {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .is_some_and(|value| value.register_usage_complete) as i32
}

fn copy_text(value: &str, output: *mut u8, capacity: usize) -> usize {
    let bytes = value.as_bytes();
    if !output.is_null() && capacity >= bytes.len() {
        // SAFETY: The C caller provides a writable buffer of `capacity` bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    }
    bytes.len()
}

/// # Safety
/// `handle` must be a live instruction handle. A non-null `output` must be
/// writable for `capacity` bytes without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_text(
    handle: *const c_void,
    output: *mut u8,
    capacity: usize,
) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .map_or(0, |value| copy_text(&value.text, output, capacity))
}

/// # Safety
/// `handle` must be a live instruction handle. A non-null `output` must be
/// writable for `capacity` bytes without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_mnemonic(
    handle: *const c_void,
    output: *mut u8,
    capacity: usize,
) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .map_or(0, |value| copy_text(&value.mnemonic, output, capacity))
}

/// # Safety
/// `handle` must be a live instruction handle. A non-null `output` must be
/// writable for `capacity` bytes without overlapping the handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_flow(
    handle: *const c_void,
    output: *mut u8,
    capacity: usize,
) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .map_or(0, |value| copy_text(value.flow, output, capacity))
}

macro_rules! string_list_accessors {
    ($count:ident, $get:ident, $field:ident) => {
        /// # Safety
        /// A non-null `handle` must be a live instruction handle.
        #[no_mangle]
        pub unsafe extern "C" fn $count(handle: *const c_void) -> usize {
            unsafe { handle.cast::<asm::Decoded>().as_ref() }.map_or(0, |value| value.$field.len())
        }

        /// # Safety
        /// `handle` must be a live instruction handle. A non-null `output`
        /// must be writable for `capacity` bytes without overlapping it.
        #[no_mangle]
        pub unsafe extern "C" fn $get(
            handle: *const c_void,
            index: usize,
            output: *mut u8,
            capacity: usize,
        ) -> usize {
            unsafe { handle.cast::<asm::Decoded>().as_ref() }
                .and_then(|value| value.$field.get(index))
                .map_or(0, |text| copy_text(text, output, capacity))
        }
    };
}

string_list_accessors!(
    galeikan_asm_instruction_register_reads_count,
    galeikan_asm_instruction_register_read,
    register_reads
);
string_list_accessors!(
    galeikan_asm_instruction_register_writes_count,
    galeikan_asm_instruction_register_write,
    register_writes
);
string_list_accessors!(
    galeikan_asm_instruction_flags_read_count,
    galeikan_asm_instruction_flag_read,
    flags_read
);
string_list_accessors!(
    galeikan_asm_instruction_flags_modified_count,
    galeikan_asm_instruction_flag_modified,
    flags_modified
);

/// # Safety
/// A non-null `handle` must be a live instruction handle.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_successors_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .and_then(|value| value.successors().ok())
        .map_or(0, |successors| successors.len())
}

/// # Safety
/// `handle` must be a live instruction handle. A non-null `output` must be
/// a writable `u64` slot.
#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_successor(
    handle: *const c_void,
    index: usize,
    output: *mut u64,
) -> i32 {
    let address = unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .and_then(|value| value.successors().ok())
        .and_then(|successors| successors.get(index).copied());
    optional_address(address, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_authority_ffi_canonicalizes_and_rejects_unsafe_urls() {
        let mut authority = [0_u8; 512];
        let mut error = [0_u8; 256];
        let url = b"http://127.0.0.1:8080/sample";
        assert_eq!(unsafe {
            galeikan_http_authority(
                url.as_ptr(), url.len(), authority.as_mut_ptr(), authority.len(),
                error.as_mut_ptr(), error.len(),
            )
        }, 0);
        assert_eq!(&authority[..15], b"127.0.0.1:8080\0");
        for rejected in [
            "http://user:password@127.0.0.1/sample",
            "http://127.0.0.1/sample#fragment",
            "ftp://127.0.0.1/sample",
        ] {
            assert_eq!(unsafe {
                galeikan_http_authority(
                    rejected.as_ptr(), rejected.len(), authority.as_mut_ptr(), authority.len(),
                    error.as_mut_ptr(), error.len(),
                )
            }, -1, "{rejected}");
        }
    }

    #[test]
    fn decoder_ffi_owns_results_and_preserves_errors() {
        let mut handle = ptr::null_mut();
        let mut error = [0_u8; 128];
        let code = [0x90_u8];
        let status = unsafe {
            galeikan_asm_decode(
                code.as_ptr(),
                code.len(),
                0,
                0x1000,
                64,
                &mut handle,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(status, 0);
        assert!(!handle.is_null());
        assert_eq!(unsafe { galeikan_asm_instruction_size(handle) }, 1);
        assert_eq!(unsafe { galeikan_asm_instruction_ip(handle) }, 0x1000);
        let mut text = [0_u8; 16];
        let size = unsafe { galeikan_asm_instruction_text(handle, text.as_mut_ptr(), text.len()) };
        assert_eq!(&text[..size], b"nop");
        unsafe { galeikan_asm_instruction_free(handle) };

        handle = ptr::dangling_mut::<c_void>();
        let status = unsafe {
            galeikan_asm_decode(
                ptr::null(),
                1,
                0,
                0x1000,
                64,
                &mut handle,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(status, -1);
        assert!(handle.is_null());

        let status = unsafe {
            galeikan_asm_decode(
                code.as_ptr(),
                code.len(),
                0,
                0x1000,
                8,
                &mut handle,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(status, -1);
        assert!(handle.is_null());
        assert!(std::ffi::CStr::from_bytes_until_nul(&error)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("bitness"));
    }

    #[test]
    fn decoder_ffi_exposes_control_flow_and_operands() {
        let branch = [0x75_u8, 0x02];
        let mut handle = ptr::null_mut();
        let mut error = [0_u8; 128];
        assert_eq!(
            unsafe {
                galeikan_asm_decode(
                    branch.as_ptr(),
                    branch.len(),
                    0,
                    0x1000,
                    64,
                    &mut handle,
                    error.as_mut_ptr(),
                    error.len(),
                )
            },
            0
        );
        let mut address = 0;
        assert_eq!(
            unsafe { galeikan_asm_instruction_target(handle, &mut address) },
            1
        );
        assert_eq!(address, 0x1004);
        assert_eq!(
            unsafe { galeikan_asm_instruction_successors_count(handle) },
            2
        );
        assert_eq!(
            unsafe { galeikan_asm_instruction_successor(handle, 0, &mut address) },
            1
        );
        assert_eq!(address, 0x1002);
        assert_eq!(
            unsafe { galeikan_asm_instruction_successor(handle, 1, &mut address) },
            1
        );
        assert_eq!(address, 0x1004);
        assert_eq!(
            unsafe { galeikan_asm_instruction_successor(handle, 2, &mut address) },
            0
        );
        assert_eq!(
            unsafe { galeikan_asm_instruction_flags_read_count(handle) },
            1
        );
        let mut flag = [0_u8; 4];
        assert_eq!(
            unsafe { galeikan_asm_instruction_flag_read(handle, 0, flag.as_mut_ptr(), flag.len()) },
            2
        );
        assert_eq!(&flag[..2], b"zf");
        unsafe { galeikan_asm_instruction_free(handle) };

        let memory = [0x48_u8, 0x8b, 0x05, 0, 0, 0, 0];
        assert_eq!(
            unsafe {
                galeikan_asm_decode(
                    memory.as_ptr(),
                    memory.len(),
                    0,
                    0x2000,
                    64,
                    &mut handle,
                    error.as_mut_ptr(),
                    error.len(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { galeikan_asm_instruction_data_target(handle, &mut address) },
            1
        );
        assert_eq!(address, 0x2007);
        assert_eq!(
            unsafe { galeikan_asm_instruction_register_usage_complete(handle) },
            1
        );
        assert!(unsafe { galeikan_asm_instruction_register_writes_count(handle) } > 0);
        unsafe { galeikan_asm_instruction_free(handle) };
    }

    #[test]
    fn linear_ffi_stops_at_region_boundary_and_keeps_offsets() {
        let code = [0xe8_u8, 0x02, 0, 0, 0, 0x90, 0x90];
        let mut disassembly = ptr::null_mut();
        let mut error = [0_u8; 128];
        assert_eq!(unsafe {
            galeikan_asm_linear(code.as_ptr(), code.len(), 0x1000, 64, 3,
                                &mut disassembly, error.as_mut_ptr(), error.len())
        }, 0);
        assert_eq!(unsafe { galeikan_asm_disassembly_count(disassembly) }, 3);
        let mut start = usize::MAX;
        let mut end = 0;
        assert_eq!(unsafe {
            galeikan_asm_disassembly_bounds(disassembly, &mut start, &mut end)
        }, 1);
        assert_eq!((start, end), (0, 7));
        for (index, expected_offset) in [(0, 0), (1, 5), (2, 6)] {
            let mut instruction = ptr::null_mut();
            let mut offset = usize::MAX;
            assert_eq!(unsafe {
                galeikan_asm_disassembly_at(disassembly, index, &mut instruction, &mut offset)
            }, 1);
            assert_eq!(offset, expected_offset);
            assert_eq!(unsafe { galeikan_asm_instruction_ip(instruction) },
                       0x1000 + expected_offset as u64);
            unsafe { galeikan_asm_instruction_free(instruction) };
        }
        unsafe { galeikan_asm_disassembly_free(disassembly) };
        assert_eq!(unsafe {
            galeikan_asm_linear(code.as_ptr(), code.len(), 0x1000, 64, 4,
                                &mut disassembly, error.as_mut_ptr(), error.len())
        }, -1);
        assert!(disassembly.is_null());
        assert!(std::ffi::CStr::from_bytes_until_nul(&error).unwrap().to_str().unwrap()
            .contains("linear disassembly exceeds executable entry region"));
    }

    #[test]
    fn reachable_ffi_preserves_instruction_lifetimes_and_errors() {
        let code = [0x75_u8, 0x02, 0x90, 0xc3, 0x90, 0xc3];
        let mut disassembly = ptr::null_mut();
        let mut error = [0_u8; 128];
        assert_eq!(
            unsafe {
                galeikan_asm_reachable(
                    code.as_ptr(),
                    code.len(),
                    0,
                    0x1000,
                    64,
                    5,
                    &mut disassembly,
                    error.as_mut_ptr(),
                    error.len(),
                )
            },
            0
        );
        assert_eq!(unsafe { galeikan_asm_disassembly_count(disassembly) }, 5);
        assert_eq!(
            unsafe { galeikan_asm_disassembly_block_count(disassembly) },
            3
        );
        assert_eq!(
            unsafe { galeikan_asm_disassembly_overlap_count(disassembly) },
            0
        );
        let mut overlap = -1;
        assert_eq!(
            unsafe { galeikan_asm_disassembly_overlap_at(disassembly, 0, &mut overlap) },
            1
        );
        assert_eq!(overlap, 0);
        let mut block = GaleikanAsmBlock {
            start: 0,
            end: 0,
            first_index: 0,
            instruction_count: 0,
            successor_count: 0,
            unresolved: 0,
        };
        assert_eq!(
            unsafe { galeikan_asm_disassembly_block(disassembly, 0, &mut block) },
            1
        );
        assert_eq!((block.start, block.end), (0x1000, 0x1002));
        assert_eq!(block.successor_count, 2);
        let mut destination = 0;
        assert_eq!(
            unsafe {
                galeikan_asm_disassembly_block_successor(disassembly, 0, 1, &mut destination)
            },
            1
        );
        assert_eq!(destination, 0x1004);
        let mut reference = 0;
        assert_eq!(
            unsafe {
                galeikan_asm_disassembly_references(disassembly, 3, 0x1004, &mut reference, 1)
            },
            1
        );
        assert_eq!(reference, 0x1000);
        let mut instruction = ptr::null_mut();
        let mut offset = usize::MAX;
        assert_eq!(
            unsafe { galeikan_asm_disassembly_at(disassembly, 1, &mut instruction, &mut offset) },
            1
        );
        assert_eq!(offset, 2);
        assert_eq!(unsafe { galeikan_asm_instruction_ip(instruction) }, 0x1002);
        unsafe { galeikan_asm_disassembly_free(disassembly) };
        assert_eq!(unsafe { galeikan_asm_instruction_size(instruction) }, 1);
        unsafe { galeikan_asm_instruction_free(instruction) };

        instruction = ptr::dangling_mut::<c_void>();
        assert_eq!(
            unsafe { galeikan_asm_disassembly_at(ptr::null(), 0, &mut instruction, &mut offset) },
            0
        );
        assert!(instruction.is_null());
        disassembly = ptr::dangling_mut::<c_void>();
        assert_eq!(
            unsafe {
                galeikan_asm_reachable(
                    code.as_ptr(),
                    code.len(),
                    0,
                    0x1000,
                    64,
                    0,
                    &mut disassembly,
                    error.as_mut_ptr(),
                    error.len(),
                )
            },
            -1
        );
        assert!(disassembly.is_null());
        assert!(std::ffi::CStr::from_bytes_until_nul(&error)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("instruction count"));
    }
}
