#[cfg(windows)]
mod windows_probe {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    const TBS_SUCCESS: u32 = 0;
    const TBS_CONTEXT_VERSION_TWO: u32 = 2;
    const TBS_E_OWNERAUTH_NOT_FOUND: u32 = 0x8028_4015;
    const TBS_E_ACCESS_DENIED: u32 = 0x8028_4012;

    const TBS_OWNERAUTH_TYPE_FULL: u32 = 1;
    const TBS_OWNERAUTH_TYPE_ENDORSEMENT_20: u32 = 12;
    const TBS_OWNERAUTH_TYPE_STORAGE_20: u32 = 13;

    #[repr(C)]
    struct TbsContextParams2 {
        version: u32,
        flags: u32,
    }

    #[link(name = "Tbs")]
    unsafe extern "system" {
        fn Tbsi_Context_Create(params: *const TbsContextParams2, context: *mut *mut c_void) -> u32;
        fn Tbsip_Context_Close(context: *mut c_void) -> u32;
        fn Tbsi_Get_OwnerAuth(
            context: *mut c_void,
            ownerauth_type: u32,
            output: *mut u8,
            output_len: *mut u32,
        ) -> u32;
    }

    struct TbsContext(*mut c_void);

    impl Drop for TbsContext {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = Tbsip_Context_Close(self.0);
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AuthAvailability {
        Available(usize),
        NotFound,
        AccessDenied,
        Other(u32),
    }

    fn classify(rc: u32, len: u32) -> AuthAvailability {
        match rc {
            TBS_SUCCESS => AuthAvailability::Available(len as usize),
            TBS_E_OWNERAUTH_NOT_FOUND => AuthAvailability::NotFound,
            TBS_E_ACCESS_DENIED => AuthAvailability::AccessDenied,
            other => AuthAvailability::Other(other),
        }
    }

    fn open_tbs() -> Result<TbsContext, String> {
        let params = TbsContextParams2 {
            version: TBS_CONTEXT_VERSION_TWO,
            flags: 1 << 2, // includeTpm20=1; requestRaw=0; includeTpm12=0
        };
        let mut raw: *mut c_void = null_mut();
        let rc = unsafe { Tbsi_Context_Create(&params, &mut raw) };
        if rc != TBS_SUCCESS {
            return Err(format!("Tbsi_Context_Create failed: 0x{rc:08x}"));
        }
        Ok(TbsContext(raw))
    }

    fn probe_auth(ctx: &TbsContext, kind: u32) -> AuthAvailability {
        let mut buf = vec![0u8; 256];
        let mut len = buf.len() as u32;
        let rc = unsafe { Tbsi_Get_OwnerAuth(ctx.0, kind, buf.as_mut_ptr(), &mut len) };
        // Intentionally never print, hash, persist, or otherwise expose returned authorization bytes.
        buf.fill(0);
        classify(rc, len)
    }

    fn print_result(label: &str, result: AuthAvailability) {
        match result {
            AuthAvailability::Available(len) => {
                println!("{label}: AVAILABLE ({len} bytes; secret value intentionally suppressed)");
            }
            AuthAvailability::NotFound => {
                println!("{label}: NOT FOUND (TBS_E_OWNERAUTH_NOT_FOUND 0x80284015)");
            }
            AuthAvailability::AccessDenied => {
                println!("{label}: ACCESS DENIED (0x80284012)");
            }
            AuthAvailability::Other(rc) => {
                println!("{label}: FAILED 0x{rc:08x}");
            }
        }
    }

    pub fn run() -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-006.1 v0.6.1");
        println!("READ-ONLY WINDOWS TPM 2.0 HIERARCHY-AUTH ROUTE PROBE");
        println!("Purpose: determine whether Windows retains a TPM 2.0 storage-hierarchy authorization route even though FULL ownerAuth is absent");
        println!("TPM STATE MODIFICATION: NONE");
        println!("No NV define, increment, undefine, clear, PCR write, hierarchy change, or existing NV write is performed.");
        println!();

        let ctx = open_tbs()?;
        let full = probe_auth(&ctx, TBS_OWNERAUTH_TYPE_FULL);
        let storage = probe_auth(&ctx, TBS_OWNERAUTH_TYPE_STORAGE_20);
        let endorsement = probe_auth(&ctx, TBS_OWNERAUTH_TYPE_ENDORSEMENT_20);

        println!("=== TBS AUTHORIZATION AVAILABILITY ===");
        print_result("FULL ownerAuth (type 1)", full);
        print_result("TPM2 STORAGE hierarchy auth (type 13)", storage);
        print_result("TPM2 ENDORSEMENT hierarchy auth (type 12)", endorsement);
        println!();

        println!("=== SEC-006.1 DECISION ===");
        println!("TPM STATE MODIFIED: NO");
        match storage {
            AuthAvailability::Available(_) => {
                println!("TPM2 STORAGE HIERARCHY AUTH AVAILABLE TO TBS: PASS");
                println!("SAFE NEXT STEP: adapt the temporary CALIBRE NV counter test to use TBS_OWNERAUTH_TYPE_STORAGE_20, with explicit irreversible-counter acknowledgement before any write.");
            }
            AuthAvailability::NotFound => {
                println!("TPM2 STORAGE HIERARCHY AUTH AVAILABLE TO TBS: NO");
                println!("WINDOWS/PLUTON OWNER-AUTHORIZED NV DEFINE ROUTE: BLOCKED WITHOUT REPROVISIONING/POLICY CHANGE");
                println!("DO NOT CLEAR OR REPROVISION THE TPM FOR CALIBRE.");
                println!("SAFE NEXT STEP: move the real NV-counter experiment to a separate TPM test machine or use a non-owner-authorized hardware anti-rollback primitive exposed by the platform.");
            }
            AuthAvailability::AccessDenied => {
                println!("TPM2 STORAGE HIERARCHY AUTH PROBE: ACCESS DENIED");
                println!("Rerun only from an elevated Administrator PowerShell; do not alter TPM provisioning.");
            }
            AuthAvailability::Other(rc) => {
                println!("TPM2 STORAGE HIERARCHY AUTH PROBE: INCONCLUSIVE (0x{rc:08x})");
                println!("Do not perform a live TPM write until this result is understood.");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn known_tbs_codes_classify_correctly() {
            assert_eq!(classify(TBS_SUCCESS, 32), AuthAvailability::Available(32));
            assert_eq!(classify(TBS_E_OWNERAUTH_NOT_FOUND, 0), AuthAvailability::NotFound);
            assert_eq!(classify(TBS_E_ACCESS_DENIED, 0), AuthAvailability::AccessDenied);
        }

        #[test]
        fn tpm2_auth_type_constants_are_distinct() {
            assert_eq!(TBS_OWNERAUTH_TYPE_FULL, 1);
            assert_eq!(TBS_OWNERAUTH_TYPE_ENDORSEMENT_20, 12);
            assert_eq!(TBS_OWNERAUTH_TYPE_STORAGE_20, 13);
        }
    }
}

#[cfg(windows)]
fn main() {
    if let Err(e) = windows_probe::run() {
        eprintln!("SEC-006.1 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("CALIBRE SECURITY SEC-006.1 requires Windows TPM Base Services.");
}
