// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate defines the Virtual TPM interfaces and shows what
//! TPM backends are supported

// The TPM backend is selected with a cargo feature: `tpmrs` (the default in
// the build recipes) or `tcgtpm`. Enabling both is only allowed through the
// `differential` feature: then the unit tests (on the host and inside the
// SVSM) run both backends side by side and check that their responses are
// byte-identical (see `difftest`). Other builds with `differential` use
// tpm-rs.
#[cfg(not(any(feature = "tpmrs", feature = "tcgtpm")))]
compile_error!("The `vtpm` feature requires a TPM backend: enable `tpmrs` or `tcgtpm`.");

#[cfg(all(feature = "tpmrs", feature = "tcgtpm", not(feature = "differential")))]
compile_error!(
    "The `tpmrs` and `tcgtpm` features are mutually exclusive. Enable only one \
     of them, or enable `differential` to test both backends against each other."
);

/// TPM 2.0 implementation in Rust (tpm-rs)
#[cfg(feature = "tpmrs")]
pub mod tpmrs;

/// TPM 2.0 Reference Implementation
#[cfg(feature = "tcgtpm")]
pub mod tcgtpm;

/// Differential testing of both TPM backends. If the `differential` feature
/// is enabled and the unit tests run (on the host or inside the SVSM), every
/// request is sent to
/// both backends and their responses must be byte-identical.
#[cfg(all(feature = "differential", test))]
pub mod difftest;

pub mod ek_templates;
mod tss;

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::types::PAGE_SIZE;
#[cfg(all(feature = "differential", test))]
use crate::vtpm::difftest::DiffTpm as Vtpm;
#[cfg(all(feature = "tcgtpm", not(feature = "tpmrs")))]
use crate::vtpm::tcgtpm::TcgTpm as Vtpm;
#[cfg(all(feature = "tpmrs", not(all(feature = "differential", test))))]
use crate::vtpm::tpmrs::TpmRs as Vtpm;
use crate::{locking::LockGuard, protocols::vtpm::TpmPlatformCommand};
use crate::{locking::SpinLock, protocols::errors::SvsmReqError};

/// Maximum size of a TPM command or response buffer.
pub const TPM_BUFFER_MAX_SIZE: usize = PAGE_SIZE;

/// Size of the kernel stack used to run vTPM operations.
///
/// The TPM backends keep large structures on the stack while they execute
/// commands (e.g. marshaling buffers and key material); the tpm-rs engine in
/// particular does not fit into the default kernel stack of
/// [`crate::mm::STACK_SIZE`] bytes.
/// Therefore, all operations that enter the engine run on a dedicated
/// kernel task with a larger stack (see [`run_on_vtpm_stack`]).
pub const VTPM_STACK_SIZE: usize = 256 * 1024;

/// Basic services required to perform the VTPM Protocol
pub trait VtpmProtocolInterface {
    /// Get the list of Platform Commands supported by the TPM implementation.
    fn get_supported_commands(&self) -> &[TpmPlatformCommand];
}

/// This implements one handler for each [`TpmPlatformCommand`] supported by the
/// VTPM Protocol. These handlers are modeled after the MSSIM TPM simulator
/// platform interface (as provided by the TPM 2.0 Reference Implementation),
/// but with a few changes to make it more Rust idiomatic.
///
/// `tpm-20-ref/TPMCmd/Simulator/include/prototypes/Simulator_fp.h`
pub trait TpmSimulatorInterface: VtpmProtocolInterface {
    /// Send a command for the TPM to run in a given locality
    ///
    /// # Arguments
    ///
    /// * `command`: Buffer with the command to be sent to the TPM.
    /// * `locality`: TPM locality the TPM command will be executed
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the response received from the TPM on success,
    /// or an error.
    fn send_tpm_command(&mut self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError>;

    /// Power-on the TPM, which also triggers a reset
    ///
    /// # Arguments
    ///
    /// *`only_reset``: If enabled, it will only reset the vTPM;
    ///                 however, the vtPM has to be powered on previously.
    ///                 Otherwise, it will fail.
    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError>;

    /// In a system where the NV memory used by the TPM is not within the TPM,
    /// the NV may not always be available. This function indicates that NV
    /// is available.
    fn signal_nvon(&mut self) -> Result<(), SvsmReqError>;
}

#[derive(Debug)]
pub enum SvsmVTpmError {
    ReqError(SvsmReqError),
    CommandError(u32),
}

impl From<SvsmReqError> for SvsmVTpmError {
    fn from(err: SvsmReqError) -> Self {
        SvsmVTpmError::ReqError(err)
    }
}

impl From<SvsmVTpmError> for SvsmReqError {
    fn from(err: SvsmVTpmError) -> Self {
        match err {
            SvsmVTpmError::ReqError(e) => e,
            SvsmVTpmError::CommandError(_) => SvsmReqError::invalid_request(),
        }
    }
}

/// Basic TPM driver services
pub trait VtpmInterface: TpmSimulatorInterface {
    /// Check if the TPM is powered on.
    fn is_powered_on(&self) -> bool;

    /// Prepare the TPM to be used for the first time. At this stage,
    /// the TPM is manufactured.
    fn init(&mut self) -> Result<(), SvsmReqError>;

    /// Returns the cached EK public key if it exists, otherwise it returns an error indicating
    /// that the EK public key does not exist.
    /// Needs mutability to cache the key.
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError>;
}

static VTPM: SpinLock<Vtpm> = SpinLock::new(Vtpm::new());

/// Runs `f` on a kernel stack of [`VTPM_STACK_SIZE`] bytes and returns its
/// result.
///
/// On the SVSM, `f` runs in a short-lived kernel task on the current CPU and
/// the calling task waits for its termination. Since the new task runs in its
/// own address space for task-local mappings (including the stack of the
/// calling task), `f` must only access data that lives on the heap or in
/// static memory, which is enforced by the `'static` bounds.
#[cfg(target_os = "none")]
fn run_on_vtpm_stack<F, R>(f: F) -> Result<R, SvsmReqError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    use crate::task::{KernelThreadStartInfo, start_kernel_task, wait_for_termination};

    struct Call<F, R> {
        f: Option<F>,
        result: Option<R>,
    }

    /// # Safety
    ///
    /// `param` must be a pointer to a valid `Call<F, R>` that is not accessed
    /// by anyone else until the task running this function terminates.
    unsafe fn trampoline<F: FnOnce() -> R, R>(param: usize) {
        // SAFETY: the caller guarantees that `param` points to a valid and
        // exclusively owned `Call<F, R>`.
        let call = unsafe { &mut *(param as *mut Call<F, R>) };
        if let Some(f) = call.f.take() {
            call.result = Some(f());
        }
    }

    // The call descriptor must live on the heap, which is shared between all
    // tasks, rather than on the stack of the calling task.
    let call = Box::into_raw(Box::new(Call {
        f: Some(f),
        result: None,
    }));

    // SAFETY: `trampoline::<F, R>` is called with a pointer to a heap
    // allocated `Call<F, R>`, which is not accessed by this task until the
    // new task has terminated.
    let start_info =
        unsafe { KernelThreadStartInfo::new_unsafe(trampoline::<F, R>, call as usize) }
            .with_stack_size(VTPM_STACK_SIZE);

    let result = start_kernel_task(start_info, "vTPM");
    let task = match result {
        Ok(task) => task,
        Err(e) => {
            // SAFETY: the task was not created, so `call` is still
            // exclusively owned by this function.
            drop(unsafe { Box::from_raw(call) });
            log::error!("vTPM: failed to start task: {e:?}");
            return Err(SvsmReqError::incomplete());
        }
    };
    wait_for_termination(task);

    // SAFETY: the task operating on `call` has terminated, so ownership of
    // the allocation is back with this function.
    let call = unsafe { Box::from_raw(call) };
    call.result.ok_or_else(SvsmReqError::incomplete)
}

/// On non-SVSM targets (e.g. unit tests running on the host), the default
/// stack is large enough, so `f` is called directly.
#[cfg(not(target_os = "none"))]
fn run_on_vtpm_stack<F, R>(f: F) -> Result<R, SvsmReqError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    Ok(f())
}

/// Initialize the TPM by calling the init() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_init() -> Result<(), SvsmReqError> {
    run_on_vtpm_stack(|| {
        let mut vtpm = VTPM.lock();
        if vtpm.is_powered_on() {
            return Ok(());
        }
        vtpm.init()
    })?
}

pub fn vtpm_get_locked<'a>() -> LockGuard<'a, Vtpm> {
    VTPM.lock()
}

/// Send a TPM command to the vTPM to run in a given locality.
///
/// # Arguments
///
/// * `command`: Buffer with the command to be sent to the TPM.
/// * `locality`: TPM locality the TPM command will be executed
///
/// # Returns
///
/// A [`Result`] containing the response received from the TPM on success,
/// or an error.
pub fn vtpm_send_command(command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError> {
    if command.len() > TPM_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }
    // The command must be copied to the heap so that it is accessible from
    // the vTPM task.
    let command = Box::<[u8]>::from(command);
    run_on_vtpm_stack(move || VTPM.lock().send_tpm_command(&command, locality))?
}

/// Get the TPM manifest i.e the EK public key by calling the get_ekpub() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_get_manifest() -> Result<Vec<u8>, SvsmReqError> {
    run_on_vtpm_stack(|| VTPM.lock().get_ekpub())?
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPM_RC_SUCCESS: u32 = 0;
    const TPM_RC_INITIALIZE: u32 = 0x100;

    fn response_code(rsp: &[u8]) -> u32 {
        u32::from_be_bytes(rsp[6..10].try_into().unwrap())
    }

    #[test]
    #[cfg_attr(
        all(feature = "tcgtpm", not(feature = "differential"), not(test_in_svsm)),
        ignore = "On the host, libtcgtpm stores its NV state in a file in the working directory"
    )]
    #[cfg_attr(
        feature = "differential",
        ignore = "Random numbers and the EK differ between the vTPM backends"
    )]
    fn vtpm_api() {
        // Initialization is idempotent (inside the SVSM, the vTPM has already
        // been initialized at boot).
        vtpm_init().unwrap();
        vtpm_init().unwrap();
        assert!(vtpm_get_locked().is_powered_on());
        assert_eq!(
            vtpm_get_locked().get_supported_commands(),
            &[TpmPlatformCommand::SendCommand]
        );

        // TPM2_Startup(TPM_SU_CLEAR). It may already have been sent.
        let startup = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0];
        let rsp = vtpm_send_command(&startup, 0).unwrap();
        let rc = response_code(&rsp);
        assert!(
            rc == TPM_RC_SUCCESS || rc == TPM_RC_INITIALIZE,
            "rc={rc:#x}"
        );

        // TPM2_GetRandom(32)
        let get_random = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7b, 0, 32];
        let rsp = vtpm_send_command(&get_random, 0).unwrap();
        assert_eq!(response_code(&rsp), TPM_RC_SUCCESS);
        assert_eq!(rsp.len(), 10 + 2 + 32);

        // Oversized commands are rejected.
        let big = [0u8; TPM_BUFFER_MAX_SIZE + 1];
        assert!(vtpm_send_command(&big, 0).is_err());

        // The manifest is the public area of the EK, created from the default
        // template, and it is stable.
        let manifest = vtpm_get_manifest().unwrap();
        assert_eq!(&manifest[..4], &ek_templates::DEFAULT_PUBLIC_AREA[..4]);
        assert_eq!(vtpm_get_manifest().unwrap(), manifest);
    }
}
