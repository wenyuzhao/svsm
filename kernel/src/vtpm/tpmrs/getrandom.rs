// SPDX-License-Identifier: MIT
//
// Copyright (c) Coconut-SVSM authors

//! Custom `getrandom` backends for the SVSM.
//!
//! The RustCrypto based crypto provider of tpm-rs draws random numbers from
//! the operating system through the `getrandom` crate (versions 0.2 and 0.3),
//! which has no backend for bare-metal targets. The functions in this module
//! provide those backends on top of the SVSM RNG:
//!
//! * getrandom 0.2 calls `__getrandom_custom` when built with the `custom`
//!   feature.
//! * getrandom 0.3 calls `__getrandom_v03_custom` when built with
//!   `--cfg getrandom_backend="custom"` (see `.cargo/config.toml`).

use core::slice;

use crate::crypto::fill_random;

/// Initializes the possibly uninitialized buffer of `len` bytes at `dest` and
/// returns it as a byte slice.
///
/// # Safety
///
/// `dest` must be valid for writes of `len` bytes and must not be accessed
/// through any other pointer while the returned slice is alive.
unsafe fn init_buffer<'a>(dest: *mut u8, len: usize) -> &'a mut [u8] {
    // SAFETY: the caller guarantees that `dest` is valid for writes of `len`
    // bytes. Zeroing initializes the buffer, so that a slice may be created
    // from it, and the caller guarantees exclusive access.
    unsafe {
        dest.write_bytes(0, len);
        slice::from_raw_parts_mut(dest, len)
    }
}

/// Backend of getrandom 0.2. Returns 0 on success or a non-zero error code.
///
/// # Safety
///
/// `dest` must be valid for writes of `len` bytes.
#[unsafe(no_mangle)]
unsafe fn __getrandom_custom(dest: *mut u8, len: usize) -> u32 {
    if len == 0 {
        return 0;
    }
    // SAFETY: the caller (getrandom) guarantees that `dest` is valid for
    // writes of `len` bytes.
    let buf = unsafe { init_buffer(dest, len) };
    match fill_random(buf) {
        Ok(()) => 0,
        Err(_) => getrandom02::Error::CUSTOM_START,
    }
}

/// Backend of getrandom 0.3.
///
/// # Safety
///
/// `dest` must be valid for writes of `len` bytes.
#[unsafe(no_mangle)]
unsafe fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom03::Error> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: the caller (getrandom) guarantees that `dest` is valid for
    // writes of `len` bytes.
    let buf = unsafe { init_buffer(dest, len) };
    fill_random(buf).map_err(|_| getrandom03::Error::new_custom(0))
}
