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
}
