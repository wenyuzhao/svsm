// SPDX-License-Identifier: MIT
//
// Copyright (c) Coconut-SVSM authors

//! SVSM implementations of the platform services required by the tpm-rs
//! engine: a monotonic timer, an entropy source and the NV storage medium.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use tpm2::crypto::{CryptoError, Rng};
use tpm2_impl::storage::{NvStorage, StorageError};
use tpm2_impl::timer::TpmTimer;
use zeroize::Zeroizing;

use crate::cpu::msr::rdtsc;
use crate::crypto::fill_random;

/// Number of TSC ticks per millisecond assumed by [`SvsmTimer`].
///
/// The SVSM does not calibrate the TSC, so a nominal frequency of 1 GHz is
/// assumed. The TPM clock only needs to be monotonic; its rate is merely
/// advisory (and can be adjusted with `TPM2_ClockRateAdjust`).
const TSC_TICKS_PER_MS: u64 = 1_000_000;

/// Monotonic millisecond timer for the TPM, derived from the TSC.
#[derive(Debug)]
pub struct SvsmTimer {
    /// TSC value at the time the timer was created.
    start: AtomicU64,
    /// Largest value returned by [`TpmTimer::timer_read`] so far, used to
    /// guarantee monotonicity even if the TSC is not synchronized across
    /// CPUs.
    last: AtomicU64,
}

impl SvsmTimer {
    pub fn new() -> Self {
        Self {
            start: AtomicU64::new(rdtsc()),
            last: AtomicU64::new(0),
        }
    }
}

impl Default for SvsmTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmTimer for SvsmTimer {
    fn timer_read(&self) -> u64 {
        let elapsed = rdtsc().saturating_sub(self.start.load(Ordering::Relaxed)) / TSC_TICKS_PER_MS;
        let last = self.last.fetch_max(elapsed, Ordering::Relaxed);
        last.max(elapsed)
    }
}

/// Platform entropy source for the TPM, backed by the SVSM RNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct SvsmPlatformRng;

impl Rng for SvsmPlatformRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        fill_random(dest).map_err(|_| CryptoError::Internal)
    }

    /// The SVSM RNG is continuously reseeded from the hardware entropy
    /// source and cannot be stirred, so `data` is ignored.
    fn reseed(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// Byte size of the TPM NV storage medium.
///
/// This matches the size used by the tpm-rs simulator, which is large enough
/// that the backing store never runs out before the NV space accounting of the
/// TPM does.
pub const NV_STORAGE_SIZE: usize = 32768;

/// RAM-backed NV storage for the TPM.
///
/// The TPM flushes the storage after every update of its NV state. The flush
/// only marks the storage as dirty; the owner of the storage is responsible
/// for persisting the image (see [`SvsmNvStorage::take_dirty`]).
#[derive(Debug)]
pub struct SvsmNvStorage {
    data: Zeroizing<Vec<u8>>,
    dirty: bool,
}

impl SvsmNvStorage {
    /// Creates an empty (unmanufactured) NV storage.
    pub fn new() -> Self {
        Self {
            data: Zeroizing::new(vec![0u8; NV_STORAGE_SIZE]),
            dirty: false,
        }
    }

    /// Creates an NV storage from a previously saved image.
    ///
    /// Returns `None` if the size of `image` does not match the size of the
    /// storage medium.
    pub fn from_image(image: Zeroizing<Vec<u8>>) -> Option<Self> {
        if image.len() != NV_STORAGE_SIZE {
            return None;
        }
        Some(Self {
            data: image,
            dirty: false,
        })
    }

    /// Returns the current NV image.
    pub fn image(&self) -> &[u8] {
        &self.data
    }

    /// Returns whether the NV image changed since the last call, and clears
    /// the dirty state.
    pub fn take_dirty(&mut self) -> bool {
        core::mem::take(&mut self.dirty)
    }
}

impl Default for SvsmNvStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl NvStorage for SvsmNvStorage {
    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn read_nv(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, StorageError> {
        let end = offset
            .checked_add(buffer.len())
            .ok_or(StorageError::OutOfBounds)?;
        let src = self
            .data
            .get(offset..end)
            .ok_or(StorageError::OutOfBounds)?;
        buffer.copy_from_slice(src);
        Ok(buffer.len())
    }

    fn write_nv(&mut self, offset: usize, buffer: &[u8]) -> Result<usize, StorageError> {
        let end = offset
            .checked_add(buffer.len())
            .ok_or(StorageError::OutOfBounds)?;
        let dst = self
            .data
            .get_mut(offset..end)
            .ok_or(StorageError::OutOfBounds)?;
        dst.copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.dirty = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nv_storage_bounds() {
        let mut nv = SvsmNvStorage::new();
        assert_eq!(nv.capacity(), NV_STORAGE_SIZE);
        assert_eq!(nv.write_nv(10, &[1, 2, 3]), Ok(3));
        let mut buf = [0u8; 3];
        assert_eq!(nv.read_nv(10, &mut buf), Ok(3));
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(
            nv.write_nv(NV_STORAGE_SIZE - 1, &[1, 2]),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            nv.read_nv(usize::MAX, &mut buf),
            Err(StorageError::OutOfBounds)
        );
    }

    #[test]
    fn nv_storage_dirty_on_flush() {
        let mut nv = SvsmNvStorage::new();
        assert!(!nv.take_dirty());
        nv.write_nv(0, &[1]).unwrap();
        nv.flush().unwrap();
        assert!(nv.take_dirty());
        assert!(!nv.take_dirty());
    }

    #[test]
    fn nv_storage_from_image() {
        assert!(SvsmNvStorage::from_image(Zeroizing::new(vec![0u8; 16])).is_none());
        let mut image = vec![0u8; NV_STORAGE_SIZE];
        image[5] = 0xaa;
        let nv = SvsmNvStorage::from_image(Zeroizing::new(image)).unwrap();
        assert_eq!(nv.image()[5], 0xaa);
    }

    #[test]
    fn timer_is_monotonic() {
        let timer = SvsmTimer::new();
        let mut last = timer.timer_read();
        for _ in 0..1000 {
            let now = timer.timer_read();
            assert!(now >= last);
            last = now;
        }
    }
}
