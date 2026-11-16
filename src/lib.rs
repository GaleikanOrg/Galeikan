#![deny(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)]
mod asm;

use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

struct DecodedCollection {
    instructions: Vec<(usize, asm::Decoded)>,
    blocks: Vec<asm::Block>,
    overlaps: Vec<bool>,
}

impl DecodedCollection {
    fn new(instructions: Vec<(usize, asm::Decoded)>) -> Result<Self, String> {
        let decoded = instructions
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        let blocks = asm::blocks(&decoded)?;
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
        asm::reachable(input, start_offset, base_ip, bitness, max_instructions)
    })) {
        Ok(Ok(instructions)) => {
            let collection = match DecodedCollection::new(instructions) {
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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_free(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: This handle came from `galeikan_asm_reachable` and is freed once.
        drop(unsafe { Box::from_raw(handle.cast::<DecodedCollection>()) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<DecodedCollection>().as_ref() }
        .map_or(0, |value| value.instructions.len())
}

/// Clone one instruction into an independently owned handle. On success the
/// caller frees `out` with `galeikan_asm_instruction_free`.
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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_overlap_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<DecodedCollection>().as_ref() }.map_or(0, |value| {
        value.overlaps.iter().filter(|overlap| **overlap).count()
    })
}

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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_disassembly_block_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<DecodedCollection>().as_ref() }.map_or(0, |value| value.blocks.len())
}

/// Copies one block's scalar metadata. Successor addresses are queried below.
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

/// Query direct call targets, data references, direct xrefs, or data xrefs.
/// Returns the required count and copies only when capacity is sufficient.
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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_free(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: This handle came from `galeikan_asm_decode` and is freed once.
        drop(unsafe { Box::from_raw(handle.cast::<asm::Decoded>()) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_size(handle: *const c_void) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }.map_or(0, |value| value.size)
}

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_ip(handle: *const c_void) -> u64 {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }.map_or(0, |value| value.ip)
}

/// Hash a readable source span. `output` must point to 32 writable bytes.
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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_target(
    handle: *const c_void,
    output: *mut u64,
) -> i32 {
    let target = unsafe { handle.cast::<asm::Decoded>().as_ref() }.and_then(|value| value.target);
    optional_address(target, output)
}

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_data_target(
    handle: *const c_void,
    output: *mut u64,
) -> i32 {
    let target =
        unsafe { handle.cast::<asm::Decoded>().as_ref() }.and_then(|value| value.data_target);
    optional_address(target, output)
}

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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_text(
    handle: *const c_void,
    output: *mut u8,
    capacity: usize,
) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .map_or(0, |value| copy_text(&value.text, output, capacity))
}

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_mnemonic(
    handle: *const c_void,
    output: *mut u8,
    capacity: usize,
) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .map_or(0, |value| copy_text(&value.mnemonic, output, capacity))
}

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
        #[no_mangle]
        pub unsafe extern "C" fn $count(handle: *const c_void) -> usize {
            unsafe { handle.cast::<asm::Decoded>().as_ref() }.map_or(0, |value| value.$field.len())
        }

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

#[no_mangle]
pub unsafe extern "C" fn galeikan_asm_instruction_successors_count(handle: *const c_void) -> usize {
    unsafe { handle.cast::<asm::Decoded>().as_ref() }
        .and_then(|value| value.successors().ok())
        .map_or(0, |successors| successors.len())
}

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

        handle = 1_usize as *mut c_void;
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

        instruction = 1_usize as *mut c_void;
        assert_eq!(
            unsafe { galeikan_asm_disassembly_at(ptr::null(), 0, &mut instruction, &mut offset) },
            0
        );
        assert!(instruction.is_null());
        disassembly = 1_usize as *mut c_void;
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
