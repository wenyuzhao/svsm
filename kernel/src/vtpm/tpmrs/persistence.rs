// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Red Hat, Inc.

//! TPM persistence: manufacturing marker and NV image storage.
//!
//! With the `persistence` feature, the NV image of the TPM and a marker that
//! records a completed manufacture are stored in CocoonFS inodes. Without it,
//! the TPM state is volatile and the TPM is manufactured on every boot.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroizing;

use crate::error::SvsmError;

#[cfg(feature = "persistence")]
mod inode {
    use crate::persistence::{Inode, InodeNamespace};

    /// Local inode numbers in the TPM namespace.
    ///
    /// Inodes 0 (NV image) and 1 (manufacturing marker) are used by the
    /// TCG TPM 2.0 Reference Implementation backend (`tcgtpm`), whose NV
    /// image format is not compatible with tpm-rs. Distinct inodes are used,
    /// so that the state of one backend is never interpreted by the other.
    #[derive(Clone, Copy, Debug)]
    #[repr(u32)]
    pub enum TpmInode {
        NvImage = 2,
        Manufactured = 3,
    }

    impl From<TpmInode> for u32 {
        fn from(val: TpmInode) -> u32 {
            val as u32
        }
    }

    impl Inode for TpmInode {
        const NAMESPACE: InodeNamespace = InodeNamespace::Tpm;
    }
}

pub trait Marker {
    fn exists() -> Result<bool, SvsmError> {
        Ok(false)
    }
    fn write() -> Result<(), SvsmError> {
        Ok(())
    }
    fn clear() -> Result<(), SvsmError> {
        Ok(())
    }
}

/// Storage for the NV image of the TPM.
pub trait NvImage {
    /// Loads the NV image. Returns `None` if no image was saved before.
    fn load() -> Result<Option<Zeroizing<Vec<u8>>>, SvsmError> {
        Ok(None)
    }
    /// Saves the NV image.
    fn save(_image: &[u8]) -> Result<(), SvsmError> {
        Ok(())
    }
}

#[cfg(feature = "persistence")]
mod backend {
    extern crate alloc;

    use alloc::vec::Vec;
    use zeroize::Zeroizing;

    use crate::persistence::{
        Inode, persistence_available, persistence_read_inode_sync, persistence_write_inode_sync,
    };

    use super::inode::TpmInode;
    use super::*;

    const MANUFACTURED_MARKER: &[u8] = b"COCONUT-SVSM-TPM-RS";

    pub struct ManufacturedMarker;

    impl Marker for ManufacturedMarker {
        fn exists() -> Result<bool, SvsmError> {
            if !persistence_available() {
                return Ok(false);
            }
            match persistence_read_inode_sync(TpmInode::Manufactured.inode())? {
                Some(data) => Ok(data.as_slice() == MANUFACTURED_MARKER),
                None => Ok(false),
            }
        }

        fn write() -> Result<(), SvsmError> {
            if !persistence_available() {
                return Ok(());
            }
            persistence_write_inode_sync(
                TpmInode::Manufactured.inode(),
                Zeroizing::new(MANUFACTURED_MARKER.to_vec()),
                true,
            )?;
            Ok(())
        }

        fn clear() -> Result<(), SvsmError> {
            if !persistence_available() {
                return Ok(());
            }
            persistence_write_inode_sync(
                TpmInode::Manufactured.inode(),
                Zeroizing::new(Vec::new()),
                true,
            )?;
            Ok(())
        }
    }

    pub struct PersistentNvImage;

    impl NvImage for PersistentNvImage {
        fn load() -> Result<Option<Zeroizing<Vec<u8>>>, SvsmError> {
            if !persistence_available() {
                return Ok(None);
            }
            persistence_read_inode_sync(TpmInode::NvImage.inode())
        }

        fn save(image: &[u8]) -> Result<(), SvsmError> {
            if !persistence_available() {
                return Ok(());
            }
            persistence_write_inode_sync(
                TpmInode::NvImage.inode(),
                Zeroizing::new(image.to_vec()),
                true,
            )?;
            Ok(())
        }
    }
}

#[cfg(not(feature = "persistence"))]
mod backend {
    use super::*;

    pub struct ManufacturedMarker;

    impl Marker for ManufacturedMarker {}

    pub struct PersistentNvImage;

    impl NvImage for PersistentNvImage {}
}

pub use backend::{ManufacturedMarker, PersistentNvImage};
