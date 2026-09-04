#[cfg(windows)]
mod windows_probe {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    const TBS_SUCCESS: u32 = 0;
    const TBS_CONTEXT_VERSION_TWO: u32 = 2;
    const TPM_VERSION_20: u32 = 2;
    const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;
    const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200;

    const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
    const TPM_CAP_HANDLES: u32 = 0x0000_0001;
    const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
    const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
    const TPM_PT_FIXED: u32 = 0x0000_0100;
    const TPM_PT_VAR: u32 = 0x0000_0200;
    const TPM_NV_INDEX_FIRST: u32 = 0x0100_0000;
    const TPM_CC_FIRST: u32 = 0x0000_011F;

    const TPM_PT_MANUFACTURER: u32 = TPM_PT_FIXED + 5;
    const TPM_PT_VENDOR_STRING_1: u32 = TPM_PT_FIXED + 6;
    const TPM_PT_VENDOR_STRING_2: u32 = TPM_PT_FIXED + 7;
    const TPM_PT_VENDOR_STRING_3: u32 = TPM_PT_FIXED + 8;
    const TPM_PT_VENDOR_STRING_4: u32 = TPM_PT_FIXED + 9;
    const TPM_PT_FIRMWARE_VERSION_1: u32 = TPM_PT_FIXED + 11;
    const TPM_PT_FIRMWARE_VERSION_2: u32 = TPM_PT_FIXED + 12;
    const TPM_PT_NV_COUNTERS_MAX: u32 = TPM_PT_FIXED + 22;
    const TPM_PT_NV_INDEX_MAX: u32 = TPM_PT_FIXED + 23;
    const TPM_PT_ORDERLY_COUNT: u32 = TPM_PT_FIXED + 29;
    const TPM_PT_NV_BUFFER_MAX: u32 = TPM_PT_FIXED + 44;
    const TPM_PT_HR_NV_INDEX: u32 = TPM_PT_VAR + 2;
    const TPM_PT_NV_COUNTERS: u32 = TPM_PT_VAR + 10;
    const TPM_PT_NV_COUNTERS_AVAIL: u32 = TPM_PT_VAR + 11;
    const TPM_PT_NV_WRITE_RECOVERY: u32 = TPM_PT_VAR + 18;

    const TPM_CC_NV_UNDEFINE_SPACE: u16 = 0x0122;
    const TPM_CC_NV_DEFINE_SPACE: u16 = 0x012A;
    const TPM_CC_NV_INCREMENT: u16 = 0x0134;
    const TPM_CC_NV_EXTEND: u16 = 0x0136;
    const TPM_CC_NV_READ: u16 = 0x014E;
    const TPM_CC_NV_READ_PUBLIC: u16 = 0x0169;
    const TPM_CC_NV_CERTIFY: u16 = 0x0184;

    #[repr(C)]
    struct TbsContextParams2 {
        version: u32,
        flags: u32,
    }

    #[repr(C)]
    #[derive(Default, Debug)]
    struct TpmDeviceInfo {
        struct_version: u32,
        tpm_version: u32,
        tpm_interface_type: u32,
        tpm_imp_revision: u32,
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
        fn Tbsi_GetDeviceInfo(size: u32, info: *mut c_void) -> u32;
    }

    fn be_u16(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }

    fn be_u32(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    fn push_u16_be(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn push_u32_be(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn getcap_command(capability: u32, property: u32, count: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(22);
        push_u16_be(&mut out, TPM_ST_NO_SESSIONS);
        push_u32_be(&mut out, 22);
        push_u32_be(&mut out, TPM_CC_GET_CAPABILITY);
        push_u32_be(&mut out, capability);
        push_u32_be(&mut out, property);
        push_u32_be(&mut out, count);
        out
    }

    fn validate_tpm_response(buf: &[u8]) -> Result<(), String> {
        if buf.len() < 10 {
            return Err("TPM response shorter than 10-byte header".into());
        }
        let declared = be_u32(&buf[2..6]) as usize;
        if declared > buf.len() || declared < 10 {
            return Err(format!("TPM response size invalid: declared={declared} actual={}", buf.len()));
        }
        let rc = be_u32(&buf[6..10]);
        if rc != 0 {
            return Err(format!("TPM returned error code 0x{rc:08x}"));
        }
        Ok(())
    }

    unsafe fn submit_getcap(
        context: *mut c_void,
        capability: u32,
        property: u32,
        count: u32,
    ) -> Result<Vec<u8>, String> {
        let command = getcap_command(capability, property, count);
        let mut result = vec![0u8; 64 * 1024];
        let mut result_len = result.len() as u32;
        let rc = unsafe {
            Tbsip_Submit_Command(
                context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                result.as_mut_ptr(),
                &mut result_len,
            )
        };
        if rc != TBS_SUCCESS {
            return Err(format!("Tbsip_Submit_Command failed: 0x{rc:08x}"));
        }
        result.truncate(result_len as usize);
        validate_tpm_response(&result)?;
        Ok(result)
    }

    fn parse_cap_list_prefix(buf: &[u8], expected_cap: u32) -> Result<(bool, usize, usize), String> {
        validate_tpm_response(buf)?;
        if buf.len() < 19 {
            return Err("GetCapability response too short".into());
        }
        let more = buf[10] != 0;
        let cap = be_u32(&buf[11..15]);
        if cap != expected_cap {
            return Err(format!("unexpected capability in response: 0x{cap:08x}"));
        }
        let count = be_u32(&buf[15..19]) as usize;
        Ok((more, count, 19))
    }

    fn parse_properties(buf: &[u8]) -> Result<(bool, Vec<(u32, u32)>), String> {
        let (more, count, mut off) = parse_cap_list_prefix(buf, TPM_CAP_TPM_PROPERTIES)?;
        if buf.len() < off + count * 8 {
            return Err("truncated TPM property list".into());
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push((be_u32(&buf[off..off + 4]), be_u32(&buf[off + 4..off + 8])));
            off += 8;
        }
        Ok((more, out))
    }

    fn parse_u32_list(buf: &[u8], expected_cap: u32) -> Result<(bool, Vec<u32>), String> {
        let (more, count, mut off) = parse_cap_list_prefix(buf, expected_cap)?;
        if buf.len() < off + count * 4 {
            return Err("truncated capability u32 list".into());
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(be_u32(&buf[off..off + 4]));
            off += 4;
        }
        Ok((more, out))
    }

    fn property<'a>(props: &'a [(u32, u32)], id: u32) -> Option<u32> {
        props.iter().find_map(|(p, v)| (*p == id).then_some(*v))
    }

    fn ascii_property(v: u32) -> String {
        v.to_be_bytes()
            .into_iter()
            .filter(|b| *b != 0)
            .map(|b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect()
    }

    fn interface_name(v: u32) -> &'static str {
        match v {
            1 => "TPM 1.2 I/O/MMIO",
            2 => "TrustZone",
            3 => "Hardware TPM",
            4 => "Software emulator",
            5 => "SPB-attached",
            _ => "Unknown/reserved",
        }
    }

    fn command_supported(attrs: &[u32], command_index: u16) -> bool {
        attrs.iter().any(|v| (*v as u16) == command_index)
    }

    fn print_prop(props: &[(u32, u32)], id: u32, name: &str) {
        match property(props, id) {
            Some(v) => println!("{name}: {v} (0x{v:08x})"),
            None => println!("{name}: NOT REPORTED"),
        }
    }

    pub fn run() -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-005 v0.5.0");
        println!("READ-ONLY TPM 2.0 MONOTONIC/NV CAPABILITY PROBE");
        println!("Purpose: verify actual Windows TPM capabilities before any CALIBRE NV counter/anti-rollback write test");
        println!("TPM WRITES / NV DEFINE / NV INCREMENT / CLEAR: NONE");
        println!();

        let mut info = TpmDeviceInfo::default();
        let info_rc = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TpmDeviceInfo>() as u32,
                &mut info as *mut _ as *mut c_void,
            )
        };
        if info_rc == TBS_SUCCESS {
            println!("=== WINDOWS TBS DEVICE INFO ===");
            println!("TPM version code: {}{}", info.tpm_version, if info.tpm_version == TPM_VERSION_20 { " (TPM 2.0)" } else { "" });
            println!("TPM interface type: {} ({})", info.tpm_interface_type, interface_name(info.tpm_interface_type));
            println!("TPM implementation revision: {}", info.tpm_imp_revision);
        } else {
            println!("Tbsi_GetDeviceInfo: FAILED 0x{info_rc:08x}");
        }

        let params = TbsContextParams2 {
            version: TBS_CONTEXT_VERSION_TWO,
            flags: 1 << 2, // includeTpm20=1; requestRaw=0; includeTpm12=0
        };
        let mut context: *mut c_void = null_mut();
        let rc = unsafe { Tbsi_Context_Create(&params, &mut context) };
        if rc != TBS_SUCCESS {
            return Err(format!(
                "Tbsi_Context_Create failed: 0x{rc:08x}. If this is access denied/restricted, rerun from an elevated Administrator PowerShell."
            ));
        }

        let result = (|| -> Result<(), String> {
            let fixed_buf = unsafe { submit_getcap(context, TPM_CAP_TPM_PROPERTIES, TPM_PT_FIXED, 64)? };
            let variable_buf = unsafe { submit_getcap(context, TPM_CAP_TPM_PROPERTIES, TPM_PT_VAR, 64)? };
            let handles_buf = unsafe { submit_getcap(context, TPM_CAP_HANDLES, TPM_NV_INDEX_FIRST, 128)? };
            let commands_buf = unsafe { submit_getcap(context, TPM_CAP_COMMANDS, TPM_CC_FIRST, 256)? };

            let (_, fixed) = parse_properties(&fixed_buf)?;
            let (_, variable) = parse_properties(&variable_buf)?;
            let (_, nv_handles) = parse_u32_list(&handles_buf, TPM_CAP_HANDLES)?;
            let (_, command_attrs) = parse_u32_list(&commands_buf, TPM_CAP_COMMANDS)?;

            println!();
            println!("=== TPM FIXED PROPERTIES ===");
            if let Some(v) = property(&fixed, TPM_PT_MANUFACTURER) {
                println!("MANUFACTURER: {} (0x{v:08x})", ascii_property(v));
            }
            let vendor = [
                property(&fixed, TPM_PT_VENDOR_STRING_1),
                property(&fixed, TPM_PT_VENDOR_STRING_2),
                property(&fixed, TPM_PT_VENDOR_STRING_3),
                property(&fixed, TPM_PT_VENDOR_STRING_4),
            ]
            .into_iter()
            .flatten()
            .map(ascii_property)
            .collect::<String>();
            println!("VENDOR STRING: {}", if vendor.is_empty() { "NOT REPORTED" } else { &vendor });
            print_prop(&fixed, TPM_PT_FIRMWARE_VERSION_1, "FIRMWARE_VERSION_1");
            print_prop(&fixed, TPM_PT_FIRMWARE_VERSION_2, "FIRMWARE_VERSION_2");
            print_prop(&fixed, TPM_PT_NV_COUNTERS_MAX, "NV_COUNTERS_MAX");
            print_prop(&fixed, TPM_PT_NV_INDEX_MAX, "NV_INDEX_MAX");
            print_prop(&fixed, TPM_PT_ORDERLY_COUNT, "ORDERLY_COUNT");
            print_prop(&fixed, TPM_PT_NV_BUFFER_MAX, "NV_BUFFER_MAX");

            println!();
            println!("=== TPM VARIABLE NV PROPERTIES ===");
            print_prop(&variable, TPM_PT_HR_NV_INDEX, "DEFINED_NV_INDEXES");
            print_prop(&variable, TPM_PT_NV_COUNTERS, "DEFINED_NV_COUNTERS");
            print_prop(&variable, TPM_PT_NV_COUNTERS_AVAIL, "NV_COUNTERS_AVAILABLE_ESTIMATE");
            print_prop(&variable, TPM_PT_NV_WRITE_RECOVERY, "NV_WRITE_RECOVERY_MS");

            println!();
            println!("=== REQUIRED TPM NV COMMANDS ===");
            let checks = [
                ("NV_UndefineSpace", TPM_CC_NV_UNDEFINE_SPACE),
                ("NV_DefineSpace", TPM_CC_NV_DEFINE_SPACE),
                ("NV_Increment", TPM_CC_NV_INCREMENT),
                ("NV_Extend", TPM_CC_NV_EXTEND),
                ("NV_Read", TPM_CC_NV_READ),
                ("NV_ReadPublic", TPM_CC_NV_READ_PUBLIC),
                ("NV_Certify", TPM_CC_NV_CERTIFY),
            ];
            for (name, cc) in checks {
                println!("{name}: {}", if command_supported(&command_attrs, cc) { "SUPPORTED" } else { "NOT REPORTED" });
            }

            println!();
            println!("=== EXISTING NV INDEX HANDLES (READ-ONLY ENUMERATION) ===");
            println!("Count: {}", nv_handles.len());
            for h in &nv_handles {
                println!("0x{h:08x}");
            }

            let required_commands = [
                TPM_CC_NV_UNDEFINE_SPACE,
                TPM_CC_NV_DEFINE_SPACE,
                TPM_CC_NV_INCREMENT,
                TPM_CC_NV_READ,
                TPM_CC_NV_READ_PUBLIC,
            ];
            let commands_ok = required_commands
                .iter()
                .all(|cc| command_supported(&command_attrs, *cc));
            let counter_capacity = property(&variable, TPM_PT_NV_COUNTERS_AVAIL)
                .or_else(|| property(&fixed, TPM_PT_NV_COUNTERS_MAX));
            let capacity_ok = counter_capacity.map(|v| v > 0).unwrap_or(false);

            println!();
            println!("=== SEC-005 READ-ONLY DECISION ===");
            println!("TPM 2.0 TBS ACCESS: PASS");
            println!("REQUIRED NV COUNTER COMMAND SET: {}", if commands_ok { "PASS" } else { "NOT CONFIRMED" });
            println!("REPORTED AVAILABLE COUNTER CAPACITY > 0: {}", if capacity_ok { "PASS" } else { "NOT CONFIRMED / VALUE MAY REQUIRE INTERPRETATION" });
            println!("REAL NV COUNTER CREATE/INCREMENT TEST: NOT RUN");
            println!("TPM STATE MODIFIED BY SEC-005: NO");
            println!("SAFE NEXT STEP IF COMMANDS/CAPACITY PASS: DEFINE ONE TEMPORARY CALIBRE NV COUNTER, INCREMENT, READ, RESTART-CHECK, THEN UNDEFINE");
            Ok(())
        })();

        let close_rc = unsafe { Tbsip_Context_Close(context) };
        if close_rc != TBS_SUCCESS {
            eprintln!("warning: Tbsip_Context_Close returned 0x{close_rc:08x}");
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn getcap_packet_is_exactly_22_bytes_and_big_endian() {
            let p = getcap_command(TPM_CAP_TPM_PROPERTIES, TPM_PT_FIXED, 64);
            assert_eq!(p.len(), 22);
            assert_eq!(be_u16(&p[0..2]), TPM_ST_NO_SESSIONS);
            assert_eq!(be_u32(&p[2..6]), 22);
            assert_eq!(be_u32(&p[6..10]), TPM_CC_GET_CAPABILITY);
            assert_eq!(be_u32(&p[10..14]), TPM_CAP_TPM_PROPERTIES);
            assert_eq!(be_u32(&p[14..18]), TPM_PT_FIXED);
            assert_eq!(be_u32(&p[18..22]), 64);
        }

        #[test]
        fn command_attribute_matching_uses_command_index_low_16_bits() {
            let attrs = [0x2000_012A, 0x4000_0134, 0x0000_0169];
            assert!(command_supported(&attrs, TPM_CC_NV_DEFINE_SPACE));
            assert!(command_supported(&attrs, TPM_CC_NV_INCREMENT));
            assert!(command_supported(&attrs, TPM_CC_NV_READ_PUBLIC));
            assert!(!command_supported(&attrs, TPM_CC_NV_CERTIFY));
        }
    }
}

#[cfg(windows)]
fn main() {
    if let Err(e) = windows_probe::run() {
        eprintln!("SEC-005 probe error: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("CALIBRE SECURITY SEC-005 v0.5.0");
    println!("READ-ONLY TPM 2.0 MONOTONIC/NV CAPABILITY PROBE");
    println!("This probe targets Windows TPM Base Services; run it on the CALIBRE Windows ARM64 machine.");
}
