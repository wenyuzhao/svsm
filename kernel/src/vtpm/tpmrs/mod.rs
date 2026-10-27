// SPDX-License-Identifier: MIT
//
// Copyright (c) Coconut-SVSM authors

//! This crate implements the virtual TPM interfaces on top of tpm-rs, a
//! TPM 2.0 implementation written in Rust.

#[cfg(target_os = "none")]
mod getrandom;
mod persistence;
mod platform;

use persistence::{ManufacturedMarker, Marker as _, NvImage as _, PersistentNvImage};
use platform::{SvsmNvStorage, SvsmPlatformRng, SvsmTimer};

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use tpm2_crypto_rust::RustCryptoProvider;
use tpm2_impl::{TPM_PROFILE_NO_SHA512, TpmEngine, TpmPlatform};

use crate::{
    protocols::{errors::SvsmReqError, vtpm::TpmPlatformCommand},
    vtpm::{
        TPM_BUFFER_MAX_SIZE, TpmSimulatorInterface, VtpmInterface, VtpmProtocolInterface,
        ek_templates::DEFAULT_PUBLIC_AREA, tss,
    },
};

/// The tpm-rs engine instantiated with the SVSM platform services.
type Engine = TpmEngine<'static, RustCryptoProvider, SvsmNvStorage, SvsmTimer, SvsmPlatformRng>;

pub struct TpmRs {
    /// The TPM engine, created by [`VtpmInterface::init`].
    engine: Option<Box<Engine>>,
    is_powered_on: bool,
    ekpub: Option<Vec<u8>>,
}

impl core::fmt::Debug for TpmRs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmRs")
            .field("initialized", &self.engine.is_some())
            .field("is_powered_on", &self.is_powered_on)
            .finish_non_exhaustive()
    }
}

impl TpmRs {
    pub const fn new() -> TpmRs {
        TpmRs {
            engine: None,
            is_powered_on: false,
            ekpub: None,
        }
    }

    fn engine(&mut self) -> Result<&mut Engine, SvsmReqError> {
        self.engine
            .as_deref_mut()
            .ok_or_else(SvsmReqError::invalid_request)
    }

    /// Creates the TPM engine on top of `storage`.
    ///
    /// The engine borrows its platform services for its whole lifetime. Since
    /// the engine is created once and never destroyed, the services are
    /// leaked to obtain `'static` references.
    fn create_engine(storage: SvsmNvStorage) -> Result<Box<Engine>, SvsmReqError> {
        let platform = TpmPlatform::new(
            Box::leak(Box::new(RustCryptoProvider)),
            Box::leak(Box::new(storage)),
            Box::leak(Box::new(SvsmTimer::new())),
            Box::leak(Box::new(SvsmPlatformRng)),
        );
        // Like the TCG TPM reference implementation configured in `libtcgtpm`
        // (`ALG_SHA512` is `ALG_NO` in `TpmProfile_Common.h`), the vTPM does
        // not implement SHA-512.
        let engine = TpmEngine::with_profile(platform, &TPM_PROFILE_NO_SHA512).map_err(|e| {
            log::error!("VTPM: failed to create TPM engine: {e}");
            SvsmReqError::incomplete()
        })?;
        Ok(Box::new(engine))
    }

    /// Persists the NV image of the TPM if it changed since it was last
    /// persisted.
    fn persist_nv(&mut self) -> Result<(), SvsmReqError> {
        let storage = &mut *self.engine()?.platform.storage;
        if storage.take_dirty() {
            PersistentNvImage::save(storage.image())?;
        }
        Ok(())
    }

    fn manufacture(&mut self) -> Result<(), SvsmReqError> {
        ManufacturedMarker::clear()?;

        // Draws the primary seeds and hierarchy proofs and writes them to the
        // (empty) NV storage.
        self.engine()?.init_storage();

        // Persist the NV image and then a manufacturing marker, so that the
        // next boot can distinguish a completed manufacture from an
        // interrupted one.
        let storage = &mut *self.engine()?.platform.storage;
        storage.take_dirty();
        PersistentNvImage::save(storage.image())?;
        ManufacturedMarker::write()?;

        Ok(())
    }
}

impl Default for TpmRs {
    fn default() -> Self {
        Self::new()
    }
}

const TPM_CMDS_SUPPORTED: &[TpmPlatformCommand] = &[TpmPlatformCommand::SendCommand];

impl VtpmProtocolInterface for TpmRs {
    fn get_supported_commands(&self) -> &[TpmPlatformCommand] {
        TPM_CMDS_SUPPORTED
    }
}

impl TpmSimulatorInterface for TpmRs {
    fn send_tpm_command(&mut self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        if command.len() > TPM_BUFFER_MAX_SIZE {
            return Err(SvsmReqError::invalid_parameter());
        }

        let engine = self.engine()?;
        engine.set_locality(locality);

        let mut response = vec![0u8; TPM_BUFFER_MAX_SIZE];
        let size = engine.execute_command_separate(command, &mut response);
        if size == 0 || size > response.len() {
            return Err(SvsmReqError::invalid_request());
        }
        response.truncate(size);

        self.persist_nv()?;

        Ok(response)
    }

    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError> {
        if self.is_powered_on && !only_reset {
            return Ok(());
        }
        if only_reset && !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }

        let engine = self.engine()?;
        if only_reset {
            // `_TPM_Init` without a power loss: NV availability is unchanged,
            // unless no TPM2_Startup has completed since the last power loss.
            engine.reset();
            if engine.state.power_lost_since_startup {
                engine.set_nv_available(true);
            }
        } else {
            // `_TPM_Init` after a power loss, which also resets the timer
            // and re-enables NV.
            engine.state.power_lost_since_startup = true;
            engine.platform_timer_reset();
            engine.reset();
            engine.set_nv_available(true);
        }
        self.is_powered_on = true;

        self.persist_nv()
    }

    fn signal_nvon(&mut self) -> Result<(), SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        self.engine()?.set_nv_available(true);

        Ok(())
    }
}

impl VtpmInterface for TpmRs {
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError> {
        if self.ekpub.is_none() {
            self.ekpub = Some(tss::create_ek(self, &DEFAULT_PUBLIC_AREA[..])?);
        }
        self.ekpub.clone().ok_or_else(SvsmReqError::invalid_request)
    }

    fn is_powered_on(&self) -> bool {
        self.is_powered_on
    }

    fn init(&mut self) -> Result<(), SvsmReqError> {
        let saved = if ManufacturedMarker::exists()? {
            PersistentNvImage::load()?.and_then(SvsmNvStorage::from_image)
        } else {
            None
        };
        let needs_manufacture = saved.is_none();

        self.engine = Some(Self::create_engine(saved.unwrap_or_default())?);

        if needs_manufacture {
            log::info!("VTPM: manufacturing new NV state");
            self.manufacture()?;
        } else {
            log::info!("VTPM: loaded existing NV state from persistent storage");
        }

        self.signal_poweron(false)?;
        self.signal_nvon()?;

        log::info!("VTPM: tpm-rs TPM 2.0 implementation initialized");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtpm::run_on_vtpm_stack;

    const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    const TPM_CC_STARTUP: u32 = 0x144;
    const TPM_CC_GET_RANDOM: u32 = 0x17b;
    const TPM_RC_SUCCESS: u32 = 0;
    const TPM_RC_INITIALIZE: u32 = 0x100;

    fn command(cc: u32, params: &[u8]) -> Vec<u8> {
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&((10 + params.len()) as u32).to_be_bytes());
        cmd.extend_from_slice(&cc.to_be_bytes());
        cmd.extend_from_slice(params);
        cmd
    }

    fn response_code(rsp: &[u8]) -> u32 {
        u32::from_be_bytes(rsp[6..10].try_into().unwrap())
    }

    #[test]
    fn tpm_lifecycle() {
        // The engine needs more stack than the default kernel stack provides.
        run_on_vtpm_stack(tpm_lifecycle_impl).unwrap();
    }

    fn tpm_lifecycle_impl() {
        let mut tpm = TpmRs::new();
        assert!(!tpm.is_powered_on());
        assert!(
            tpm.send_tpm_command(&command(TPM_CC_GET_RANDOM, &[0, 16]), 0)
                .is_err()
        );

        tpm.init().unwrap();
        assert!(tpm.is_powered_on());

        // Commands other than TPM2_Startup fail before startup.
        let rsp = tpm
            .send_tpm_command(&command(TPM_CC_GET_RANDOM, &[0, 16]), 0)
            .unwrap();
        assert_eq!(response_code(&rsp), TPM_RC_INITIALIZE);

        // TPM2_Startup(TPM_SU_CLEAR)
        let rsp = tpm
            .send_tpm_command(&command(TPM_CC_STARTUP, &[0, 0]), 0)
            .unwrap();
        assert_eq!(response_code(&rsp), TPM_RC_SUCCESS);

        // TPM2_GetRandom(16)
        let rsp = tpm
            .send_tpm_command(&command(TPM_CC_GET_RANDOM, &[0, 16]), 0)
            .unwrap();
        assert_eq!(response_code(&rsp), TPM_RC_SUCCESS);
        // Header (10 bytes) + TPM2B_DIGEST size (2 bytes) + 16 random bytes
        assert_eq!(rsp.len(), 28);
        assert_eq!(u16::from_be_bytes([rsp[10], rsp[11]]), 16);

        // Oversized commands are rejected.
        let big = vec![0u8; TPM_BUFFER_MAX_SIZE + 1];
        assert!(tpm.send_tpm_command(&big, 0).is_err());

        // The EK can be created and is cached.
        let ekpub = tpm.get_ekpub().unwrap();
        assert_eq!(&ekpub[..2], &DEFAULT_PUBLIC_AREA[..2]);
        assert_eq!(tpm.get_ekpub().unwrap(), ekpub);
    }
}
