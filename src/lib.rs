#![deny(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)]
mod asm;

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

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
}
