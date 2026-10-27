// SPDX-License-Identifier: MIT
//
// Copyright (c) Coconut-SVSM authors

//! Differential testing of the vTPM backends.
//!
//! When the `differential` feature (which enables both the `tpmrs` and the
//! `tcgtpm` features) is enabled and the kernel unit tests run (on the host or
//! inside the SVSM), the vTPM is
//! backed by [`DiffTpm`]. It forwards every request to both tpm-rs and the
//! TCG TPM 2.0 Reference Implementation, and panics if the two backends do not
//! produce byte-identical responses.

extern crate alloc;
#[cfg(not(target_os = "none"))]
extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::{
    protocols::{errors::SvsmReqError, vtpm::TpmPlatformCommand},
    vtpm::{
        TpmSimulatorInterface, VtpmInterface, VtpmProtocolInterface,
        ek_templates::DEFAULT_PUBLIC_AREA, tcgtpm::TcgTpm, tpmrs::TpmRs, tss,
    },
};

/// A vTPM that runs every request on both tpm-rs and the TCG TPM 2.0
/// Reference Implementation and checks that the responses are identical.
///
/// The TCG TPM 2.0 Reference Implementation keeps its state in global
/// variables of the C library, so at most one `DiffTpm` may be in use at any
/// given time.
#[derive(Debug, Default)]
pub struct DiffTpm {
    tpmrs: TpmRs,
    tcgtpm: TcgTpm,
    ekpub: Option<Vec<u8>>,
}

/// Formats `buf` as a hex dump with 16 bytes per line.
fn hex_dump(buf: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in buf.chunks(16).enumerate() {
        let _ = write!(out, "\n  {:04x}:", i * 16);
        for b in chunk {
            let _ = write!(out, " {b:02x}");
        }
    }
    out
}

/// Returns the TPM command code of `command`, if it has a complete header.
fn command_code(command: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(command.get(6..10)?.try_into().ok()?))
}

/// Panics with a description of the mismatch if `tpmrs` and `tcgtpm` are
/// not identical, otherwise returns the common result.
fn check_results<T>(
    what: &str,
    tpmrs: Result<T, SvsmReqError>,
    tcgtpm: Result<T, SvsmReqError>,
    describe: impl Fn(&T) -> String,
) -> Result<T, SvsmReqError>
where
    T: PartialEq,
{
    match (tpmrs, tcgtpm) {
        (Ok(a), Ok(b)) if a == b => Ok(a),
        // `SvsmReqError` does not implement `PartialEq`.
        (Err(a), Err(b)) if format!("{a:?}") == format!("{b:?}") => Err(a),
        (a, b) => {
            let describe = |r: &Result<T, SvsmReqError>| match r {
                Ok(v) => format!("Ok({})", describe(v)),
                Err(e) => format!("Err({e:?})"),
            };
            panic!(
                "vTPM differential test: {what}: backends disagree\n\
                 tpm-rs: {}\n\
                 tcgtpm: {}",
                describe(&a),
                describe(&b)
            );
        }
    }
}

fn describe_response(rsp: &[u8]) -> String {
    let rc = rsp
        .get(6..10)
        .map(|rc| u32::from_be_bytes(rc.try_into().unwrap()));
    match rc {
        Some(rc) => format!("rc={rc:#x}, {} bytes:{}", rsp.len(), hex_dump(rsp)),
        None => format!("{} bytes:{}", rsp.len(), hex_dump(rsp)),
    }
}

impl DiffTpm {
    pub const fn new() -> Self {
        Self {
            tpmrs: TpmRs::new(),
            tcgtpm: TcgTpm::new(),
            ekpub: None,
        }
    }

    /// On the host, the TCG TPM 2.0 Reference Implementation stores its NV
    /// state in the `NVChip` file of the current working directory. Move
    /// the working directory of the test process to a private temporary
    /// directory, so that the source tree is not polluted and stale state
    /// from previous runs is not picked up.
    #[cfg(not(target_os = "none"))]
    fn enter_private_workdir() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let dir =
                std::env::temp_dir().join(format!("svsm-vtpm-difftest-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("failed to create vTPM test directory");
            std::env::set_current_dir(&dir).expect("failed to enter vTPM test directory");
        });
    }
}

const TPM_CMDS_SUPPORTED: &[TpmPlatformCommand] = &[TpmPlatformCommand::SendCommand];

impl VtpmProtocolInterface for DiffTpm {
    fn get_supported_commands(&self) -> &[TpmPlatformCommand] {
        assert_eq!(
            self.tpmrs.get_supported_commands(),
            self.tcgtpm.get_supported_commands(),
            "vTPM differential test: supported platform commands differ"
        );
        TPM_CMDS_SUPPORTED
    }
}

impl TpmSimulatorInterface for DiffTpm {
    fn send_tpm_command(&mut self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError> {
        let tpmrs = self.tpmrs.send_tpm_command(command, locality);
        let tcgtpm = self.tcgtpm.send_tpm_command(command, locality);
        let what = match command_code(command) {
            Some(cc) => format!(
                "command cc={cc:#x} at locality {locality}:{}",
                hex_dump(command)
            ),
            None => format!("command at locality {locality}:{}", hex_dump(command)),
        };
        check_results(&what, tpmrs, tcgtpm, |rsp| describe_response(rsp))
    }

    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError> {
        let tpmrs = self.tpmrs.signal_poweron(only_reset);
        let tcgtpm = self.tcgtpm.signal_poweron(only_reset);
        check_results(
            &format!("signal_poweron(only_reset={only_reset})"),
            tpmrs,
            tcgtpm,
            |_| String::new(),
        )
    }

    fn signal_nvon(&mut self) -> Result<(), SvsmReqError> {
        let tpmrs = self.tpmrs.signal_nvon();
        let tcgtpm = self.tcgtpm.signal_nvon();
        check_results("signal_nvon()", tpmrs, tcgtpm, |_| String::new())
    }
}

impl VtpmInterface for DiffTpm {
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError> {
        // Create the EK through `self`, so that the TPM2_CreatePrimary
        // responses of both backends are compared.
        if self.ekpub.is_none() {
            self.ekpub = Some(tss::create_ek(self, &DEFAULT_PUBLIC_AREA[..])?);
        }
        self.ekpub.clone().ok_or_else(SvsmReqError::invalid_request)
    }

    fn is_powered_on(&self) -> bool {
        let powered_on = self.tpmrs.is_powered_on();
        assert_eq!(
            powered_on,
            self.tcgtpm.is_powered_on(),
            "vTPM differential test: power state differs"
        );
        powered_on
    }

    fn init(&mut self) -> Result<(), SvsmReqError> {
        // Inside the SVSM, libtcgtpm keeps its NV state in memory (or in the
        // persistent storage).
        #[cfg(not(target_os = "none"))]
        Self::enter_private_workdir();
        let tpmrs = self.tpmrs.init();
        let tcgtpm = self.tcgtpm.init();
        check_results("init()", tpmrs, tcgtpm, |_| String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locking::SpinLock;
    use crate::vtpm::run_on_vtpm_stack;
    use alloc::vec;

    const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    const TPM_ST_SESSIONS: u16 = 0x8002;

    const TPM_CC_PCR_RESET: u32 = 0x13d;
    const TPM_CC_SELF_TEST: u32 = 0x143;
    const TPM_CC_STARTUP: u32 = 0x144;
    const TPM_CC_SHUTDOWN: u32 = 0x145;
    const TPM_CC_GET_CAPABILITY: u32 = 0x17a;
    const TPM_CC_GET_RANDOM: u32 = 0x17b;
    const TPM_CC_HASH: u32 = 0x17d;
    const TPM_CC_PCR_READ: u32 = 0x17e;
    const TPM_CC_PCR_EXTEND: u32 = 0x182;

    const TPM_RC_SUCCESS: u32 = 0x000;
    const TPM_RC_INITIALIZE: u32 = 0x100;

    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_RH_NULL: u32 = 0x4000_0007;
    const TPM_RS_PW: u32 = 0x4000_0009;
    const TPM_CAP_PCRS: u32 = 0x5;
    const TPM_SU_CLEAR: u16 = 0x0000;
    const TPM_SU_STATE: u16 = 0x0001;

    /// The C state of the TCG TPM 2.0 Reference Implementation is global, so
    /// only one test may use a [`DiffTpm`] at a time.
    static LOCK: SpinLock<()> = SpinLock::new(());

    /// Runs the test `f` exclusively and on a stack that is large enough for
    /// the TPM engines.
    fn run(f: fn()) {
        run_on_vtpm_stack(move || {
            let _guard = LOCK.lock();
            f();
        })
        .unwrap();
    }

    fn command(tag: u16, cc: u32, body: &[u8]) -> Vec<u8> {
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&tag.to_be_bytes());
        cmd.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        cmd.extend_from_slice(&cc.to_be_bytes());
        cmd.extend_from_slice(body);
        cmd
    }

    /// Authorization area with a single empty password session.
    fn empty_pw_auth() -> Vec<u8> {
        let mut auth = Vec::new();
        auth.extend_from_slice(&9u32.to_be_bytes()); // authorizationSize
        auth.extend_from_slice(&TPM_RS_PW.to_be_bytes()); // sessionHandle
        auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
        auth.push(0); // sessionAttributes
        auth.extend_from_slice(&0u16.to_be_bytes()); // hmac
        auth
    }

    /// TPML_PCR_SELECTION selecting `pcrs` in the SHA-256 bank.
    fn pcr_selection(pcrs: &[u8]) -> Vec<u8> {
        let mut select = [0u8; 3];
        for &pcr in pcrs {
            select[usize::from(pcr / 8)] |= 1 << (pcr % 8);
        }
        let mut sel = Vec::new();
        sel.extend_from_slice(&1u32.to_be_bytes());
        sel.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        sel.push(select.len() as u8);
        sel.extend_from_slice(&select);
        sel
    }

    fn pcr_extend(pcr: u32, digest: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&pcr.to_be_bytes());
        body.extend_from_slice(&empty_pw_auth());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        body.extend_from_slice(digest);
        command(TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND, &body)
    }

    fn pcr_reset(pcr: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&pcr.to_be_bytes());
        body.extend_from_slice(&empty_pw_auth());
        command(TPM_ST_SESSIONS, TPM_CC_PCR_RESET, &body)
    }

    fn pcr_read(pcrs: &[u8]) -> Vec<u8> {
        command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, &pcr_selection(pcrs))
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(data.len() as u16).to_be_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        // A NULL hierarchy yields a NULL ticket, which does not depend on
        // the (random) hierarchy proofs.
        body.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
        command(TPM_ST_NO_SESSIONS, TPM_CC_HASH, &body)
    }

    fn response_code(rsp: &[u8]) -> u32 {
        u32::from_be_bytes(rsp[6..10].try_into().unwrap())
    }

    /// Sends `cmd` to both backends (which checks that their responses are
    /// identical) and returns the response code.
    fn send(tpm: &mut DiffTpm, cmd: &[u8]) -> u32 {
        response_code(&tpm.send_tpm_command(cmd, 0).unwrap())
    }

    fn startup(tpm: &mut DiffTpm, su: u16) -> u32 {
        send(
            tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP, &su.to_be_bytes()),
        )
    }

    fn shutdown(tpm: &mut DiffTpm, su: u16) -> u32 {
        send(
            tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_SHUTDOWN, &su.to_be_bytes()),
        )
    }

    /// Creates an initialized [`DiffTpm`] on which TPM2_Startup has run.
    fn started_tpm() -> DiffTpm {
        let mut tpm = DiffTpm::new();
        tpm.init().unwrap();
        assert_eq!(startup(&mut tpm, TPM_SU_CLEAR), TPM_RC_SUCCESS);
        tpm
    }

    fn diff_lifecycle_impl() {
        let get_random = command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &[0, 16]);

        let mut tpm = DiffTpm::new();
        assert!(!tpm.is_powered_on());
        assert!(tpm.send_tpm_command(&get_random, 0).is_err());
        assert!(tpm.signal_nvon().is_err());
        assert!(tpm.signal_poweron(true).is_err());

        tpm.init().unwrap();
        assert!(tpm.is_powered_on());
        assert_eq!(
            tpm.get_supported_commands(),
            &[TpmPlatformCommand::SendCommand]
        );

        // Only TPM2_Startup is accepted before startup.
        assert_eq!(send(&mut tpm, &get_random), TPM_RC_INITIALIZE);
        assert_eq!(startup(&mut tpm, TPM_SU_CLEAR), TPM_RC_SUCCESS);
        assert_eq!(startup(&mut tpm, TPM_SU_CLEAR), TPM_RC_INITIALIZE);

        // Orderly shutdown, reset and TPM Resume.
        assert_eq!(shutdown(&mut tpm, TPM_SU_STATE), TPM_RC_SUCCESS);
        tpm.signal_poweron(true).unwrap();
        tpm.signal_nvon().unwrap();
        assert_eq!(startup(&mut tpm, TPM_SU_STATE), TPM_RC_SUCCESS);

        // Orderly shutdown, reset and TPM Reset.
        assert_eq!(shutdown(&mut tpm, TPM_SU_CLEAR), TPM_RC_SUCCESS);
        tpm.signal_poweron(true).unwrap();
        assert_eq!(startup(&mut tpm, TPM_SU_CLEAR), TPM_RC_SUCCESS);
    }

    fn diff_malformed_commands_impl() {
        let mut tpm = started_tpm();

        // Bad tag.
        send(&mut tpm, &command(0x1234, TPM_CC_GET_RANDOM, &[0, 16]));
        // Unknown command code.
        send(&mut tpm, &command(TPM_ST_NO_SESSIONS, 0x0000_01ff, &[]));
        // Vendor command code.
        send(&mut tpm, &command(TPM_ST_NO_SESSIONS, 0x2000_0000, &[]));
        // Truncated parameters.
        send(
            &mut tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &[0]),
        );
        // Trailing parameters.
        send(
            &mut tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &[0, 16, 0]),
        );
        // Header size does not match the buffer size.
        let mut cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &[0, 16]);
        cmd[5] += 1;
        send(&mut tpm, &cmd);
        // Truncated header.
        let _ = tpm.send_tpm_command(&cmd[..6], 0);
        // Sessions tag without an authorization area.
        send(
            &mut tpm,
            &command(TPM_ST_SESSIONS, TPM_CC_PCR_RESET, &16u32.to_be_bytes()),
        );
        // Oversized commands are rejected.
        let big = vec![0u8; crate::vtpm::TPM_BUFFER_MAX_SIZE + 1];
        assert!(tpm.send_tpm_command(&big, 0).is_err());
    }

    fn diff_self_test_impl() {
        let mut tpm = started_tpm();
        // fullTest = YES
        let rc = send(
            &mut tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_SELF_TEST, &[1]),
        );
        assert_eq!(rc, TPM_RC_SUCCESS);
    }

    fn diff_pcr_banks_impl() {
        let mut tpm = started_tpm();
        let mut body = Vec::new();
        body.extend_from_slice(&TPM_CAP_PCRS.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        let rc = send(
            &mut tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY, &body),
        );
        assert_eq!(rc, TPM_RC_SUCCESS);
    }

    fn diff_pcrs_impl() {
        let mut tpm = started_tpm();

        let all: Vec<u8> = (0..24).collect();
        assert_eq!(send(&mut tpm, &pcr_read(&all)), TPM_RC_SUCCESS);
        assert_eq!(send(&mut tpm, &pcr_read(&all[8..])), TPM_RC_SUCCESS);
        assert_eq!(send(&mut tpm, &pcr_read(&all[16..])), TPM_RC_SUCCESS);
        assert_eq!(send(&mut tpm, &pcr_read(&[])), TPM_RC_SUCCESS);

        for pcr in [0, 16, 23] {
            let digest = [pcr as u8; 32];
            assert_eq!(send(&mut tpm, &pcr_extend(pcr, &digest)), TPM_RC_SUCCESS);
            assert_eq!(send(&mut tpm, &pcr_extend(pcr, &digest)), TPM_RC_SUCCESS);
        }
        assert_eq!(send(&mut tpm, &pcr_read(&[0, 16, 23])), TPM_RC_SUCCESS);

        // Only some PCRs can be reset, depending on the locality.
        for pcr in [0, 16, 23] {
            send(&mut tpm, &pcr_reset(pcr));
        }
        assert_eq!(send(&mut tpm, &pcr_read(&[0, 16, 23])), TPM_RC_SUCCESS);

        // Out-of-range PCR handle.
        send(&mut tpm, &pcr_extend(24, &[0; 32]));
    }

    fn diff_hash_impl() {
        let mut tpm = started_tpm();
        assert_eq!(send(&mut tpm, &hash(b"")), TPM_RC_SUCCESS);
        assert_eq!(send(&mut tpm, &hash(b"abc")), TPM_RC_SUCCESS);
        assert_eq!(send(&mut tpm, &hash(&[0x5a; 1024])), TPM_RC_SUCCESS);
    }

    #[test]
    fn diff_lifecycle() {
        run(diff_lifecycle_impl);
    }

    #[test]
    fn diff_malformed_commands() {
        run(diff_malformed_commands_impl);
    }

    #[test]
    fn diff_self_test() {
        run(diff_self_test_impl);
    }

    #[test]
    #[ignore = "Known discrepancy: tpm-rs allocates the SHA-1 and SHA-256 PCR banks and \
                implements SHA-512, tcgtpm allocates the SHA-256 and SHA-384 banks"]
    fn diff_pcr_banks() {
        run(diff_pcr_banks_impl);
    }

    #[test]
    fn diff_pcrs() {
        run(diff_pcrs_impl);
    }

    #[test]
    fn diff_hash() {
        run(diff_hash_impl);
    }
}
