#[cfg(windows)]
mod windows_live {
    use std::ffi::c_void;
    use std::process::Command;
    use std::ptr::null_mut;

    const TBS_SUCCESS: u32 = 0;
    const TBS_CONTEXT_VERSION_TWO: u32 = 2;
    const TBS_OWNERAUTH_TYPE_FULL: u32 = 1;
    const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;
    const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200;

    const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    const TPM_ST_SESSIONS: u16 = 0x8002;
    const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
    const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
    const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
    const TPM_CC_NV_INCREMENT: u32 = 0x0000_0134;
    const TPM_CC_NV_READ: u32 = 0x0000_014E;
    const TPM_CAP_HANDLES: u32 = 0x0000_0001;
    const TPM_NV_INDEX_FIRST: u32 = 0x0100_0000;
    const TPM_RH_OWNER: u32 = 0x4000_0001;
    const TPM_RS_PW: u32 = 0x4000_0009;
    const TPM_ALG_SHA256: u16 = 0x000B;

    // TPMA_NV = OWNERWRITE | COUNTER(NT=1) | OWNERREAD | NO_DA.
    const CALIBRE_NV_ATTRS: u32 = 0x0202_0012;
    const COUNTER_SIZE: u16 = 8;
    const CANDIDATE_FIRST: u32 = 0x0150_4341;
    const CANDIDATE_LAST: u32 = 0x0150_4360;

    #[repr(C)]
    struct TbsContextParams2 {
        version: u32,
        flags: u32,
    }

    #[link(name = "Tbs")]
    unsafe extern "system" {
        fn Tbsi_Context_Create(params: *const TbsContextParams2, context: *mut *mut c_void) -> u32;
        fn Tbsip_Context_Close(context: *mut c_void) -> u32;
        fn Tbsip_Submit_Command(
            context: *mut c_void,
            locality: u32,
            priority: u32,
            command: *const u8,
            command_len: u32,
            result: *mut u8,
            result_len: *mut u32,
        ) -> u32;
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

    fn push_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn be_u16(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }

    fn be_u32(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    fn open_tbs() -> Result<TbsContext, String> {
        let params = TbsContextParams2 {
            version: TBS_CONTEXT_VERSION_TWO,
            flags: 1 << 2, // includeTpm20=1 in the Windows TBS v2 bitfield layout used by SEC-005.
        };
        let mut raw: *mut c_void = null_mut();
        let rc = unsafe { Tbsi_Context_Create(&params, &mut raw) };
        if rc != TBS_SUCCESS {
            return Err(format!("Tbsi_Context_Create failed: 0x{rc:08x}"));
        }
        Ok(TbsContext(raw))
    }

    fn owner_auth(ctx: &TbsContext) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 128];
        let mut len = buf.len() as u32;
        let rc = unsafe {
            Tbsi_Get_OwnerAuth(
                ctx.0,
                TBS_OWNERAUTH_TYPE_FULL,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != TBS_SUCCESS {
            return Err(format!(
                "TPM full owner authorization is not available to this process (Tbsi_Get_OwnerAuth=0x{rc:08x})"
            ));
        }
        buf.truncate(len as usize);
        if buf.is_empty() {
            return Err("TPM full owner authorization returned empty".into());
        }
        Ok(buf)
    }

    fn submit(ctx: &TbsContext, command: &[u8]) -> Result<Vec<u8>, String> {
        let mut result = vec![0u8; 64 * 1024];
        let mut len = result.len() as u32;
        let rc = unsafe {
            Tbsip_Submit_Command(
                ctx.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                result.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != TBS_SUCCESS {
            return Err(format!("Tbsip_Submit_Command failed: 0x{rc:08x}"));
        }
        result.truncate(len as usize);
        if result.len() < 10 {
            return Err("TPM response shorter than header".into());
        }
        let declared = be_u32(&result[2..6]) as usize;
        if declared < 10 || declared > result.len() {
            return Err(format!("TPM response size invalid: declared={declared} actual={}", result.len()));
        }
        Ok(result)
    }

    fn tpm_rc(response: &[u8]) -> u32 {
        be_u32(&response[6..10])
    }

    fn require_success(response: &[u8], operation: &str) -> Result<(), String> {
        let rc = tpm_rc(response);
        if rc != 0 {
            return Err(format!("{operation}: TPM returned 0x{rc:08x}"));
        }
        Ok(())
    }

    fn no_session_command(cc: u32, handles_and_params: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + handles_and_params.len());
        push_u16(&mut out, TPM_ST_NO_SESSIONS);
        push_u32(&mut out, (10 + handles_and_params.len()) as u32);
        push_u32(&mut out, cc);
        out.extend_from_slice(handles_and_params);
        out
    }

    fn password_session(owner: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + owner.len());
        push_u32(&mut out, TPM_RS_PW);
        push_u16(&mut out, 0); // nonce
        out.push(0); // session attributes
        push_u16(&mut out, owner.len() as u16);
        out.extend_from_slice(owner);
        out
    }

    fn session_command(cc: u32, handles: &[u32], params: &[u8], owner: &[u8]) -> Vec<u8> {
        let auth = password_session(owner);
        let total = 10 + handles.len() * 4 + 4 + auth.len() + params.len();
        let mut out = Vec::with_capacity(total);
        push_u16(&mut out, TPM_ST_SESSIONS);
        push_u32(&mut out, total as u32);
        push_u32(&mut out, cc);
        for h in handles {
            push_u32(&mut out, *h);
        }
        push_u32(&mut out, auth.len() as u32);
        out.extend_from_slice(&auth);
        out.extend_from_slice(params);
        out
    }

    fn getcap_handles_command() -> Vec<u8> {
        let mut params = Vec::new();
        push_u32(&mut params, TPM_CAP_HANDLES);
        push_u32(&mut params, TPM_NV_INDEX_FIRST);
        push_u32(&mut params, 256);
        no_session_command(TPM_CC_GET_CAPABILITY, &params)
    }

    fn existing_nv_handles(ctx: &TbsContext) -> Result<Vec<u32>, String> {
        let response = submit(ctx, &getcap_handles_command())?;
        require_success(&response, "GetCapability handles")?;
        if response.len() < 19 {
            return Err("GetCapability handles response too short".into());
        }
        let cap = be_u32(&response[11..15]);
        if cap != TPM_CAP_HANDLES {
            return Err(format!("GetCapability returned unexpected capability 0x{cap:08x}"));
        }
        let count = be_u32(&response[15..19]) as usize;
        if response.len() < 19 + count * 4 {
            return Err("GetCapability handle list truncated".into());
        }
        let mut handles = Vec::with_capacity(count);
        let mut off = 19;
        for _ in 0..count {
            handles.push(be_u32(&response[off..off + 4]));
            off += 4;
        }
        Ok(handles)
    }

    fn select_handle(existing: &[u32]) -> Result<u32, String> {
        for h in CANDIDATE_FIRST..=CANDIDATE_LAST {
            if !existing.contains(&h) {
                return Ok(h);
            }
        }
        Err("no unused CALIBRE candidate NV handle found".into())
    }

    fn define_counter(ctx: &TbsContext, handle: u32, owner: &[u8]) -> Result<(), String> {
        let mut public = Vec::with_capacity(14);
        push_u32(&mut public, handle);
        push_u16(&mut public, TPM_ALG_SHA256);
        push_u32(&mut public, CALIBRE_NV_ATTRS);
        push_u16(&mut public, 0); // authPolicy empty
        push_u16(&mut public, COUNTER_SIZE);

        let mut params = Vec::with_capacity(2 + 2 + public.len());
        push_u16(&mut params, 0); // index authValue empty
        push_u16(&mut params, public.len() as u16);
        params.extend_from_slice(&public);

        let response = submit(
            ctx,
            &session_command(TPM_CC_NV_DEFINE_SPACE, &[TPM_RH_OWNER], &params, owner),
        )?;
        require_success(&response, "NV_DefineSpace")
    }

    fn increment_counter(ctx: &TbsContext, handle: u32, owner: &[u8]) -> Result<(), String> {
        let response = submit(
            ctx,
            &session_command(
                TPM_CC_NV_INCREMENT,
                &[TPM_RH_OWNER, handle],
                &[],
                owner,
            ),
        )?;
        require_success(&response, "NV_Increment")
    }

    fn read_counter(ctx: &TbsContext, handle: u32, owner: &[u8]) -> Result<u64, String> {
        let mut params = Vec::with_capacity(4);
        push_u16(&mut params, COUNTER_SIZE);
        push_u16(&mut params, 0);
        let response = submit(
            ctx,
            &session_command(
                TPM_CC_NV_READ,
                &[TPM_RH_OWNER, handle],
                &params,
                owner,
            ),
        )?;
        require_success(&response, "NV_Read")?;

        let param_start = if be_u16(&response[0..2]) == TPM_ST_SESSIONS {
            if response.len() < 14 {
                return Err("NV_Read session response too short".into());
            }
            14
        } else {
            10
        };
        if response.len() < param_start + 2 {
            return Err("NV_Read missing TPM2B size".into());
        }
        let size = be_u16(&response[param_start..param_start + 2]) as usize;
        if size != COUNTER_SIZE as usize || response.len() < param_start + 2 + size {
            return Err(format!("NV_Read counter data size invalid: {size}"));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&response[param_start + 2..param_start + 10]);
        Ok(u64::from_be_bytes(bytes))
    }

    fn undefine_counter(ctx: &TbsContext, handle: u32, owner: &[u8]) -> Result<(), String> {
        let response = submit(
            ctx,
            &session_command(
                TPM_CC_NV_UNDEFINE_SPACE,
                &[TPM_RH_OWNER, handle],
                &[],
                owner,
            ),
        )?;
        require_success(&response, "NV_UndefineSpace")
    }

    fn parse_handle(s: &str) -> Result<u32, String> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).map_err(|e| format!("invalid handle: {e}"))
        } else {
            s.parse::<u32>().map_err(|e| format!("invalid handle: {e}"))
        }
    }

    fn child_read(handle: u32) -> Result<(), String> {
        let ctx = open_tbs()?;
        let owner = owner_auth(&ctx)?;
        let value = read_counter(&ctx, handle, &owner)?;
        println!("COUNTER={value}");
        Ok(())
    }

    fn run_probe() -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-006 v0.6.0");
        println!("WINDOWS PLUTON/TPM2 OWNER-AUTH PREFLIGHT FOR LIVE NV COUNTER TEST");
        println!("TPM STATE MODIFICATION IN THIS MODE: NONE");
        let ctx = open_tbs()?;
        match owner_auth(&ctx) {
            Ok(auth) => {
                println!("TBS FULL OWNER AUTH AVAILABLE: YES ({} bytes; value intentionally not displayed)", auth.len());
                println!("LIVE COUNTER TEST CAN ATTEMPT OWNER-AUTHORIZED NV DEFINE: YES");
            }
            Err(e) => {
                println!("TBS FULL OWNER AUTH AVAILABLE: NO");
                println!("DETAIL: {e}");
                println!("LIVE COUNTER TEST CAN ATTEMPT OWNER-AUTHORIZED NV DEFINE: NO");
            }
        }
        let handles = existing_nv_handles(&ctx)?;
        let handle = select_handle(&handles)?;
        println!("UNUSED CALIBRE CANDIDATE HANDLE: 0x{handle:08x}");
        println!("EXISTING TPM NV INDEXES WILL NOT BE MODIFIED");
        Ok(())
    }

    fn run_live() -> Result<(), String> {
        if std::env::var("CALIBRE_TPM_ACK").ok().as_deref() != Some("ADVANCE_TPM_COUNTER") {
            return Err(
                "live test refused. Set CALIBRE_TPM_ACK=ADVANCE_TPM_COUNTER only after accepting that the TPM lifetime counter high-water mark may permanently advance".into(),
            );
        }

        println!("CALIBRE SECURITY SEC-006 v0.6.0");
        println!("REAL TEMPORARY TPM 2.0 NV COUNTER ANTI-ROLLBACK TEST");
        println!("WARNING: one NV counter increment will be performed.");
        println!("The temporary NV index will be undefined afterward, but TPM lifetime counter high-water state may remain permanently advanced.");
        println!("NO TPM CLEAR, NO PCR WRITE, NO HIERARCHY-AUTH CHANGE, NO EXISTING NV INDEX WRITE.");
        println!();

        let ctx = open_tbs()?;
        let owner = owner_auth(&ctx)?;
        println!("TBS FULL OWNER AUTH AVAILABLE: YES (value not displayed)");
        let before_handles = existing_nv_handles(&ctx)?;
        let handle = select_handle(&before_handles)?;
        println!("TEMPORARY NV HANDLE SELECTED: 0x{handle:08x}");

        let mut created = false;
        let result = (|| -> Result<(), String> {
            define_counter(&ctx, handle, &owner)?;
            created = true;
            println!("TEMPORARY NV COUNTER DEFINE: PASS");

            let initial = read_counter(&ctx, handle, &owner)?;
            println!("COUNTER BEFORE INCREMENT: {initial}");
            let stale_software_snapshot = initial;

            increment_counter(&ctx, handle, &owner)?;
            let advanced = read_counter(&ctx, handle, &owner)?;
            println!("COUNTER AFTER ONE INCREMENT: {advanced}");
            if advanced <= initial {
                return Err(format!("monotonicity failure: initial={initial} advanced={advanced}"));
            }
            println!("REAL TPM COUNTER MONOTONIC ADVANCE: PASS");

            let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
            let output = Command::new(exe)
                .arg("--child-read-counter")
                .arg(format!("0x{handle:08x}"))
                .output()
                .map_err(|e| format!("spawn child read: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "child restart read failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let child_value = stdout
                .lines()
                .find_map(|line| line.strip_prefix("COUNTER="))
                .ok_or_else(|| format!("child output missing counter: {stdout}"))?
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("parse child counter: {e}"))?;
            if child_value != advanced {
                return Err(format!("process-restart persistence mismatch: parent={advanced} child={child_value}"));
            }
            println!("SEPARATE PROCESS REOPEN/READ SAME TPM COUNTER: PASS ({child_value})");

            if advanced > stale_software_snapshot {
                println!("SOFTWARE SNAPSHOT ROLLBACK DETECTION: PASS (snapshot={stale_software_snapshot}, TPM={advanced})");
            } else {
                return Err("software rollback detector did not observe TPM ahead of snapshot".into());
            }

            undefine_counter(&ctx, handle, &owner)?;
            created = false;
            let after_handles = existing_nv_handles(&ctx)?;
            if after_handles.contains(&handle) {
                return Err("temporary NV handle still appears after undefine".into());
            }
            println!("TEMPORARY NV COUNTER UNDEFINE/CLEANUP: PASS");
            Ok(())
        })();

        if result.is_err() && created {
            eprintln!("SEC-006 encountered an error after creating 0x{handle:08x}; attempting cleanup...");
            match undefine_counter(&ctx, handle, &owner) {
                Ok(()) => eprintln!("EMERGENCY CLEANUP OF TEMPORARY NV INDEX: PASS"),
                Err(e) => eprintln!("EMERGENCY CLEANUP FAILED: {e}; temporary handle may remain at 0x{handle:08x}"),
            }
        }

        result?;
        println!();
        println!("=== SEC-006 DECISION ===");
        println!("REAL TPM NV COUNTER CREATED: PASS");
        println!("REAL TPM NV COUNTER MONOTONIC INCREMENT: PASS");
        println!("COUNTER SURVIVES SEPARATE SOFTWARE PROCESS REOPEN: PASS");
        println!("STALE SOFTWARE SNAPSHOT DETECTED BY TPM-AHEAD COMPARISON: PASS");
        println!("TEMPORARY NV INDEX CLEANED UP: PASS");
        println!("TPM LIFETIME COUNTER HIGH-WATER STATE RESTORED TO PRE-TEST VALUE: NOT CLAIMED / GENERALLY NOT REVERSIBLE BY UNDEFINE");
        println!("POWER-CYCLE / FIRMWARE-ROLLBACK RESISTANCE: NOT YET PROVEN");
        Ok(())
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("--live-counter-test") => run_live(),
            Some("--child-read-counter") => {
                let handle = parse_handle(args.get(2).ok_or("missing child handle")?)?;
                child_read(handle)
            }
            Some(other) => Err(format!("unknown argument: {other}")),
            None => run_probe(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn define_public_is_counter_owner_rw_no_da() {
            assert_eq!(CALIBRE_NV_ATTRS & 0xF0, 0x10);
            assert_ne!(CALIBRE_NV_ATTRS & 0x0000_0002, 0);
            assert_ne!(CALIBRE_NV_ATTRS & 0x0002_0000, 0);
            assert_ne!(CALIBRE_NV_ATTRS & 0x0200_0000, 0);
        }

        #[test]
        fn password_session_encodes_auth_without_display_or_transform() {
            let auth = [1u8, 2, 3, 4];
            let s = password_session(&auth);
            assert_eq!(be_u32(&s[0..4]), TPM_RS_PW);
            assert_eq!(be_u16(&s[4..6]), 0);
            assert_eq!(s[6], 0);
            assert_eq!(be_u16(&s[7..9]), 4);
            assert_eq!(&s[9..13], &auth);
        }

        #[test]
        fn define_packet_has_sessions_and_owner_handle() {
            let owner = [0xAAu8; 32];
            let handle = CANDIDATE_FIRST;
            let mut public = Vec::new();
            push_u32(&mut public, handle);
            push_u16(&mut public, TPM_ALG_SHA256);
            push_u32(&mut public, CALIBRE_NV_ATTRS);
            push_u16(&mut public, 0);
            push_u16(&mut public, COUNTER_SIZE);
            let mut params = Vec::new();
            push_u16(&mut params, 0);
            push_u16(&mut params, public.len() as u16);
            params.extend_from_slice(&public);
            let p = session_command(TPM_CC_NV_DEFINE_SPACE, &[TPM_RH_OWNER], &params, &owner);
            assert_eq!(be_u16(&p[0..2]), TPM_ST_SESSIONS);
            assert_eq!(be_u32(&p[6..10]), TPM_CC_NV_DEFINE_SPACE);
            assert_eq!(be_u32(&p[10..14]), TPM_RH_OWNER);
            assert_eq!(be_u32(&p[2..6]) as usize, p.len());
        }
    }
}

#[cfg(not(windows))]
fn main() {
    println!("CALIBRE SEC-006 requires Windows TPM Base Services for this experiment.");
}

#[cfg(windows)]
fn main() {
    if let Err(e) = windows_live::run() {
        eprintln!("SEC-006 ERROR: {e}");
        std::process::exit(1);
    }
}
