const SNAPSHOT_MAGIC: &[u8; 8] = b"CAL17SN1";
const SNAPSHOT_VERSION: u32 = 1;
const OLD_EPOCH: u64 = 60;
const COIN_ID: u64 = 0x4341_4c49_4252_4501;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppSnapshot {
    key_name: String,
    public_blob: Vec<u8>,
}

fn encode_snapshot(snapshot: &AppSnapshot) -> Result<Vec<u8>, String> {
    let name = snapshot.key_name.as_bytes();
    let name_len = u16::try_from(name.len()).map_err(|_| "snapshot key name too long")?;
    let public_len = u32::try_from(snapshot.public_blob.len()).map_err(|_| "snapshot public blob too long")?;
    let mut out = Vec::with_capacity(64 + name.len() + snapshot.public_blob.len());
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&public_len.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&snapshot.public_blob);
    let checksum = blake3::hash(&out);
    out.extend_from_slice(checksum.as_bytes());
    Ok(out)
}

fn decode_snapshot(bytes: &[u8]) -> Result<AppSnapshot, String> {
    const HEADER: usize = 8 + 4 + 2 + 4;
    const CHECKSUM: usize = 32;
    if bytes.len() < HEADER + CHECKSUM {
        return Err("snapshot is shorter than its header and checksum".into());
    }
    if &bytes[..8] != SNAPSHOT_MAGIC {
        return Err("snapshot magic mismatch".into());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != SNAPSHOT_VERSION {
        return Err(format!("unsupported snapshot version {version}"));
    }
    let name_len = u16::from_le_bytes(bytes[12..14].try_into().unwrap()) as usize;
    let public_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
    let expected = HEADER
        .checked_add(name_len)
        .and_then(|v| v.checked_add(public_len))
        .and_then(|v| v.checked_add(CHECKSUM))
        .ok_or("snapshot length overflow")?;
    if bytes.len() != expected {
        return Err(format!("snapshot length mismatch: expected {expected}, got {}", bytes.len()));
    }
    let body_end = expected - CHECKSUM;
    if blake3::hash(&bytes[..body_end]).as_bytes() != &bytes[body_end..] {
        return Err("snapshot checksum mismatch".into());
    }
    let name_end = HEADER + name_len;
    let key_name = String::from_utf8(bytes[HEADER..name_end].to_vec())
        .map_err(|_| "snapshot key name is not UTF-8")?;
    let public_blob = bytes[name_end..body_end].to_vec();
    Ok(AppSnapshot { key_name, public_blob })
}

fn freshness_transcript(key_name: &str, nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(160 + key_name.len());
    out.extend_from_slice(b"CALIBRE_SEC017_TPM_FRESHNESS_V1");
    out.extend_from_slice(&OLD_EPOCH.to_le_bytes());
    out.extend_from_slice(&COIN_ID.to_le_bytes());
    out.extend_from_slice(&(key_name.len() as u64).to_le_bytes());
    out.extend_from_slice(key_name.as_bytes());
    out.extend_from_slice(nonce);
    out
}

fn transcript_digest(key_name: &str, nonce: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(freshness_transcript(key_name, nonce)).into()
}

fn result_record(status: i32, signature: &[u8]) -> Result<Vec<u8>, String> {
    let len = u32::try_from(signature.len()).map_err(|_| "signature too long")?;
    let mut out = Vec::with_capacity(8 + signature.len());
    out.extend_from_slice(&(status as u32).to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

fn parse_result_record(bytes: &[u8]) -> Result<(i32, Vec<u8>), String> {
    if bytes.len() < 8 {
        return Err("child result is shorter than its header".into());
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as i32;
    let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if bytes.len() != 8 + len {
        return Err("child result length mismatch".into());
    }
    Ok((status, bytes[8..].to_vec()))
}

fn unique_key_name() -> String {
    use rand_core::{OsRng, RngCore};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let suffix = random.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("CALIBRE_SEC017_{}_{}_{}", std::process::id(), stamp, suffix)
}

fn is_generated_key_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("CALIBRE_SEC017_") else {
        return false;
    };
    let mut parts = rest.split('_');
    let (Some(pid), Some(stamp), Some(suffix), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && !stamp.is_empty()
        && stamp.bytes().all(|byte| byte.is_ascii_digit())
        && suffix.len() == 16
        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(windows)]
mod windows_live {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_PRIVATE_KEY_BLOB,
        MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG,
        NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_HANDLE,
        NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE,
        NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_OPAQUETRANSPORT_BLOB, NCRYPT_PERSIST_FLAG,
        NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
        NCryptFreeObject, NCryptGetProperty, NCryptImportKey, NCryptIsAlgSupported,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
        NCryptVerifySignature,
    };

    const ACK_VALUE: &str = "CREATE_DELETE_ONE_DISPOSABLE_KEY";
    const NTE_BAD_SIGNATURE_STATUS: i32 = 0x8009_0006u32 as i32;
    const NTE_BAD_TYPE_STATUS: i32 = 0x8009_000au32 as i32;
    const NTE_BAD_KEY_STATE_STATUS: i32 = 0x8009_000bu32 as i32;
    const NTE_PERM_STATUS: i32 = 0x8009_0010u32 as i32;
    const NTE_BAD_KEYSET_STATUS: i32 = 0x8009_0016u32 as i32;
    const NTE_INVALID_HANDLE_STATUS: i32 = 0x8009_0026u32 as i32;
    const NTE_NOT_SUPPORTED_STATUS: i32 = 0x8009_0029u32 as i32;

    struct Provider(NCRYPT_PROV_HANDLE);

    impl Provider {
        fn open(name: *const u16) -> Result<Self, String> {
            let mut handle = 0;
            let status = unsafe { NCryptOpenStorageProvider(&mut handle, name, 0) };
            if status != 0 {
                return Err(format!("NCryptOpenStorageProvider failed: 0x{:08x}", status as u32));
            }
            Ok(Self(handle))
        }
    }

    impl Drop for Provider {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { let _ = NCryptFreeObject(self.0 as NCRYPT_HANDLE); }
                self.0 = 0;
            }
        }
    }

    struct FreeKey(NCRYPT_KEY_HANDLE);

    impl FreeKey {
        fn take(&mut self) -> NCRYPT_KEY_HANDLE {
            let handle = self.0;
            self.0 = 0;
            handle
        }

        fn close_checked(&mut self) -> Result<(), i32> {
            if self.0 == 0 {
                return Ok(());
            }
            let status = unsafe { NCryptFreeObject(self.0 as NCRYPT_HANDLE) };
            if status == 0 {
                self.0 = 0;
                Ok(())
            } else {
                Err(status)
            }
        }

        fn delete_checked(&mut self) -> Result<(), i32> {
            if self.0 == 0 {
                return Ok(());
            }
            let status = unsafe { NCryptDeleteKey(self.0, 0) };
            if status == 0 {
                // NCryptDeleteKey frees the handle when it succeeds.
                self.0 = 0;
                Ok(())
            } else {
                Err(status)
            }
        }
    }

    impl Drop for FreeKey {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { let _ = NCryptFreeObject(self.0 as NCRYPT_HANDLE); }
                self.0 = 0;
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn status_hex(status: i32) -> String {
        format!("0x{:08x}", status as u32)
    }

    fn is_expected_retired_key_status(status: i32) -> bool {
        matches!(
            status,
            NTE_BAD_KEY_STATE_STATUS | NTE_BAD_KEYSET_STATUS | NTE_INVALID_HANDLE_STATUS
        )
    }

    fn get_dword(handle: NCRYPT_HANDLE, property: *const u16) -> Result<u32, String> {
        let mut value = 0u32;
        let mut written = 0u32;
        let status = unsafe {
            NCryptGetProperty(
                handle,
                property,
                &mut value as *mut u32 as *mut u8,
                std::mem::size_of::<u32>() as u32,
                &mut written,
                0,
            )
        };
        if status != 0 {
            return Err(format!("NCryptGetProperty failed: {}", status_hex(status)));
        }
        if written != std::mem::size_of::<u32>() as u32 {
            return Err(format!("NCryptGetProperty returned {written} bytes instead of 4"));
        }
        Ok(value)
    }

    fn set_dword(handle: NCRYPT_HANDLE, property: *const u16, value: u32) -> Result<(), String> {
        let status = unsafe {
            NCryptSetProperty(
                handle,
                property,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
                NCRYPT_PERSIST_FLAG,
            )
        };
        if status != 0 {
            return Err(format!("NCryptSetProperty failed: {}", status_hex(status)));
        }
        Ok(())
    }

    fn open_named(provider: &Provider, name: &str) -> Result<FreeKey, i32> {
        let name_w = wide(name);
        let mut key = 0;
        let status = unsafe { NCryptOpenKey(provider.0, &mut key, name_w.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if status == 0 { Ok(FreeKey(key)) } else { Err(status) }
    }

    fn create_key(
        provider: &Provider,
        name: &str,
        created_by_us: &mut bool,
    ) -> Result<(FreeKey, Vec<u8>), String> {
        let name_w = wide(name);
        let mut key = 0;
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                NCRYPT_ECDSA_P256_ALGORITHM,
                name_w.as_ptr(),
                0,
                0,
            )
        };
        if status != 0 {
            return Err(format!("NCryptCreatePersistedKey failed: {}", status_hex(status)));
        }
        *created_by_us = true;
        let mut key = FreeKey(key);
        let setup = (|| -> Result<Vec<u8>, String> {
            set_dword(
                key.0 as NCRYPT_HANDLE,
                NCRYPT_KEY_USAGE_PROPERTY,
                NCRYPT_ALLOW_SIGNING_FLAG,
            )?;
            // Zero is the default export policy. Query and enforce it after finalization instead
            // of persisting an explicit zero, which some Platform KSP versions reject.
            let status = unsafe { NCryptFinalizeKey(key.0, 0) };
            if status != 0 {
                return Err(format!("NCryptFinalizeKey failed: {}", status_hex(status)));
            }
            let public_blob = export_blob(key.0, BCRYPT_ECCPUBLIC_BLOB)
                .map_err(|s| format!("public export failed: {}", status_hex(s)))?;
            if public_blob.len() != 72 {
                return Err(format!(
                    "unexpected ECDSA P-256 public blob length {} (expected 72)",
                    public_blob.len()
                ));
            }
            Ok(public_blob)
        })();

        match setup {
            Ok(public_blob) => Ok((key, public_blob)),
            Err(error) => match key.delete_checked() {
                Ok(()) => {
                    *created_by_us = false;
                    Err(error)
                }
                Err(delete_status) => Err(format!(
                    "{error}; exact-key rollback delete also failed: {}",
                    status_hex(delete_status)
                )),
            },
        }
    }

    fn export_blob(key: NCRYPT_KEY_HANDLE, blob_type: *const u16) -> Result<Vec<u8>, i32> {
        let mut len = 0u32;
        let status = unsafe {
            NCryptExportKey(key, 0, blob_type, null(), null_mut(), 0, &mut len, NCRYPT_SILENT_FLAG)
        };
        if status != 0 { return Err(status); }
        let mut bytes = vec![0u8; len as usize];
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_type,
                null(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut len,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 { return Err(status); }
        bytes.truncate(len as usize);
        Ok(bytes)
    }

    fn export_size_probe(key: NCRYPT_KEY_HANDLE, blob_type: *const u16) -> (i32, u32) {
        let mut len = 0u32;
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_type,
                null(),
                null_mut(),
                0,
                &mut len,
                NCRYPT_SILENT_FLAG,
            )
        };
        (status, len)
    }

    fn sign_hash(key: NCRYPT_KEY_HANDLE, digest: &[u8; 32]) -> (i32, Vec<u8>) {
        let mut len = 0u32;
        let first = unsafe {
            NCryptSignHash(key, null(), digest.as_ptr(), digest.len() as u32, null_mut(), 0, &mut len, NCRYPT_SILENT_FLAG)
        };
        if first != 0 { return (first, Vec::new()); }
        let mut signature = vec![0u8; len as usize];
        let second = unsafe {
            NCryptSignHash(
                key,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut len,
                NCRYPT_SILENT_FLAG,
            )
        };
        if second != 0 { return (second, Vec::new()); }
        signature.truncate(len as usize);
        (0, signature)
    }

    fn verify_with_public(provider: &Provider, public: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<bool, String> {
        let mut key = 0;
        let status = unsafe {
            NCryptImportKey(
                provider.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                &mut key,
                public.as_ptr(),
                public.len() as u32,
                0,
            )
        };
        if status != 0 {
            return Err(format!("NCryptImportKey(public) failed: {}", status_hex(status)));
        }
        let key = FreeKey(key);
        let status = unsafe {
            NCryptVerifySignature(
                key.0,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                0,
            )
        };
        match status {
            0 => Ok(true),
            NTE_BAD_SIGNATURE_STATUS => Ok(false),
            other => Err(format!(
                "NCryptVerifySignature returned an operational error instead of a signature verdict: {}",
                status_hex(other)
            )),
        }
    }

    fn write_sync(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let temp = path.with_extension("tmp");
        let mut file = File::create(&temp).map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        fs::rename(&temp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn read_exact_32(path: &Path) -> Result<[u8; 32], String> {
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        bytes.try_into().map_err(|v: Vec<u8>| format!("nonce length was {}, expected 32", v.len()))
    }

    fn wait_for_file(path: &Path, child: Option<&mut Child>) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut child = child;
        loop {
            if path.exists() { return Ok(()); }
            if let Some(proc) = child.as_deref_mut() {
                if let Some(status) = proc.try_wait().map_err(|e| e.to_string())? {
                    return Err(format!("held-handle child exited early with {status}"));
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for {}", path.display()));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn run_held_child(name: &str, dir: &Path) -> Result<(), String> {
        if std::env::var("CALIBRE_TPM_KEY_ACK").ok().as_deref() != Some(ACK_VALUE) {
            return Err("held-handle child refused without the live-test acknowledgement".into());
        }
        if !is_generated_key_name(name) || dir.file_name().and_then(|v| v.to_str()) != Some(name) {
            return Err("held-handle child refused a non-SEC-017 key name or work directory".into());
        }
        let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER)?;
        let held = open_named(&provider, name).map_err(|s| format!("held child open failed: {}", status_hex(s)))?;
        let baseline_nonce = read_exact_32(&dir.join("baseline.nonce"))?;
        let baseline_digest = transcript_digest(name, &baseline_nonce);
        let (status, signature) = sign_hash(held.0, &baseline_digest);
        if status != 0 { return Err(format!("held child baseline sign failed: {}", status_hex(status))); }
        write_sync(&dir.join("baseline.result"), &result_record(status, &signature)?)?;

        wait_for_file(&dir.join("after-delete.nonce"), None)?;
        let fresh_nonce = read_exact_32(&dir.join("after-delete.nonce"))?;
        let fresh_digest = transcript_digest(name, &fresh_nonce);
        let (status, signature) = sign_hash(held.0, &fresh_digest);
        write_sync(&dir.join("after-delete.result"), &result_record(status, &signature)?)?;
        Ok(())
    }

    fn probe_open(provider: &Provider, name: &str) -> Result<(bool, i32), String> {
        match open_named(provider, name) {
            Ok(_key) => Ok((true, 0)),
            Err(status) if status == NTE_BAD_KEYSET_STATUS => Ok((false, status)),
            Err(status) => Err(format!(
                "fresh open of {name} returned an unexpected status: {}",
                status_hex(status)
            )),
        }
    }

    fn cleanup_exact(
        provider: &Provider,
        name: &str,
        expected_public: Option<&[u8]>,
    ) -> Result<bool, String> {
        let mut key = match open_named(provider, name) {
            Ok(key) => key,
            Err(status) if status == NTE_BAD_KEYSET_STATUS => return Ok(false),
            Err(status) => {
                return Err(format!(
                    "cleanup open failed for {name}: {}",
                    status_hex(status)
                ));
            }
        };
        if let Some(expected) = expected_public {
            let observed = export_blob(key.0, BCRYPT_ECCPUBLIC_BLOB)
                .map_err(|status| format!("cleanup public-key identity check failed: {}", status_hex(status)))?;
            if observed != expected {
                return Err(format!(
                    "cleanup refused because {name} no longer has the public key created by this run"
                ));
            }
        }
        let handle = key.take();
        let status = unsafe { NCryptDeleteKey(handle, 0) };
        if status != 0 {
            unsafe { let _ = NCryptFreeObject(handle as NCRYPT_HANDLE); }
            return Err(format!("cleanup NCryptDeleteKey failed for {name}: {}", status_hex(status)));
        }
        Ok(true)
    }

    fn run_controller() -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-017 v0.17.1");
        println!("WINDOWS TPM PLATFORM KEY CONTAINMENT / RETIREMENT / PRE-OPENED-HANDLE ATTACK");
        println!("One unique current-user ECDSA P-256 key; Microsoft Platform Crypto Provider; one physical host");
        println!("The provider must report a hardware implementation; TPM physical packaging is not inferred");
        println!("Purpose: test ordinary private-export denial, named-key deletion, and a cross-process handle opened before retirement");
        println!("TPM clear / PCR / NV / hierarchy / BitLocker / existing-key modification: NONE");
        println!("Global blockchain / universal transaction order: NOT USED");
        println!();

        if std::env::var("CALIBRE_TPM_KEY_ACK").ok().as_deref() != Some(ACK_VALUE) {
            return Err(format!(
                "live key test refused. Set CALIBRE_TPM_KEY_ACK={ACK_VALUE} to authorize creation and deletion of one unique disposable current-user key"
            ));
        }

        let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER)?;
        let impl_flags = get_dword(provider.0 as NCRYPT_HANDLE, NCRYPT_IMPL_TYPE_PROPERTY)?;
        if impl_flags & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
            return Err(format!("Platform provider did not report NCRYPT_IMPL_HARDWARE_FLAG: flags=0x{impl_flags:08x}"));
        }
        let alg_status = unsafe { NCryptIsAlgSupported(provider.0, NCRYPT_ECDSA_P256_ALGORITHM, 0) };
        if alg_status != 0 {
            return Err(format!("TPM provider does not support ECDSA P-256: {}", status_hex(alg_status)));
        }
        println!("PLATFORM PROVIDER HARDWARE IMPLEMENTATION FLAG: PASS (0x{impl_flags:08x})");
        println!("TPM PROVIDER ECDSA P-256 SUPPORT: PASS");

        let software = Provider::open(MS_KEY_STORAGE_PROVIDER)?;
        let key_name = unique_key_name();
        println!("DISPOSABLE KEY NAME: {key_name}");

        let root = std::env::temp_dir().join(&key_name);
        fs::create_dir(&root).map_err(|e| format!("create unique work directory: {e}"))?;

        let mut created_by_us = false;
        let mut expected_public = None;
        let result = (|| -> Result<(), String> {
            let (mut created, public_blob) = create_key(&provider, &key_name, &mut created_by_us)?;
            expected_public = Some(public_blob.clone());
            let export_policy = get_dword(created.0 as NCRYPT_HANDLE, NCRYPT_EXPORT_POLICY_PROPERTY)?;
            let usage = get_dword(created.0 as NCRYPT_HANDLE, NCRYPT_KEY_USAGE_PROPERTY)?;
            if export_policy != 0 { return Err(format!("export policy was 0x{export_policy:08x}, expected zero")); }
            if usage & NCRYPT_ALLOW_SIGNING_FLAG == 0 { return Err(format!("signing usage flag missing: 0x{usage:08x}")); }

            println!("CURRENT-USER TPM KEY CREATED / FINALIZED / SIGNING-ONLY: PASS");
            println!("PUBLIC KEY EXPORT: PASS ({} bytes)", public_blob.len());

            let private_routes = [
                ("ECC_PRIVATE", BCRYPT_ECCPRIVATE_BLOB),
                ("GENERIC_PRIVATE", BCRYPT_PRIVATE_KEY_BLOB),
                ("PKCS8_PRIVATE", NCRYPT_PKCS8_PRIVATE_KEY_BLOB),
            ];
            let mut private_route_succeeded = false;
            let mut private_route_unexpected = false;
            let mut private_route_policy_denied = false;
            for (label, blob_type) in private_routes {
                let (status, len) = export_size_probe(created.0, blob_type);
                let interpretation = match status {
                    0 => {
                        private_route_succeeded = true;
                        format!("SIZE QUERY SUCCEEDED ({len} bytes) -> SECURITY FINDING; BYTES NOT EXPORTED")
                    }
                    NTE_PERM_STATUS => {
                        private_route_policy_denied = true;
                        "REJECTED BY EXPORT POLICY".to_string()
                    }
                    NTE_BAD_TYPE_STATUS | NTE_NOT_SUPPORTED_STATUS => {
                        "FORMAT UNSUPPORTED BY THIS PROVIDER".to_string()
                    }
                    other => {
                        private_route_unexpected = true;
                        format!("UNEXPECTED OPERATIONAL ERROR {} -> INCONCLUSIVE", status_hex(other))
                    }
                };
                println!(
                    "PRIVATE EXPORT ROUTE {label}: {interpretation} ({})",
                    status_hex(status)
                );
            }
            let private_export_result = if private_route_succeeded {
                "AT_LEAST_ONE_STANDARD_SIZE_QUERY_SUCCEEDED_SECURITY_FINDING"
            } else if private_route_unexpected {
                "NO_ROUTE_SUCCEEDED_BUT_AT_LEAST_ONE_STATUS_WAS_INCONCLUSIVE"
            } else if private_route_policy_denied {
                "PASS_TESTED_ROUTES_POLICY_DENIED_OR_UNSUPPORTED"
            } else {
                "NO_TESTED_STANDARD_PRIVATE_EXPORT_FORMAT_SUPPORTED"
            };

            let (opaque_status, opaque_len) =
                export_size_probe(created.0, NCRYPT_OPAQUETRANSPORT_BLOB);
            let opaque_export_result = match opaque_status {
                0 => format!("SIZE_QUERY_SUPPORTED_{opaque_len}_BYTES_NOT_EXPORTED"),
                NTE_PERM_STATUS => "REJECTED_BY_EXPORT_POLICY".to_string(),
                NTE_BAD_TYPE_STATUS | NTE_NOT_SUPPORTED_STATUS => {
                    "FORMAT_UNSUPPORTED_BY_THIS_PROVIDER".to_string()
                }
                other => format!("INCONCLUSIVE_STATUS_{}", status_hex(other)),
            };
            println!(
                "OPAQUE PROVIDER-BLOB SIZE QUERY: {opaque_export_result} ({})",
                status_hex(opaque_status)
            );

            let snapshot = AppSnapshot { key_name: key_name.clone(), public_blob: public_blob.clone() };
            let snapshot_bytes = encode_snapshot(&snapshot)?;
            let snapshot_path = root.join("pre-retirement-app.snapshot");
            write_sync(&snapshot_path, &snapshot_bytes)?;
            let restored_path = root.join("restored-app.snapshot");
            fs::copy(&snapshot_path, &restored_path).map_err(|e| e.to_string())?;
            let restored = decode_snapshot(&fs::read(&restored_path).map_err(|e| e.to_string())?)?;
            if restored != snapshot { return Err("restored application snapshot changed".into()); }
            println!("PRE-RETIREMENT APPLICATION SNAPSHOT: CREATED / CHECKSUM VERIFIED / CONTAINS KEY NAME + PUBLIC BLOB ONLY");

            let baseline_nonce = random_nonce();
            write_sync(&root.join("baseline.nonce"), &baseline_nonce)?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut child = Command::new(&exe)
                .arg("--held-child")
                .arg(&key_name)
                .arg(&root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("spawn held-handle child: {e}"))?;

            let child_result = (|| -> Result<(), String> {
                wait_for_file(&root.join("baseline.result"), Some(&mut child))?;
                let (baseline_status, baseline_sig) = parse_result_record(
                    &fs::read(root.join("baseline.result")).map_err(|e| e.to_string())?
                )?;
                if baseline_status != 0 { return Err(format!("child baseline status {}", status_hex(baseline_status))); }
                let baseline_digest = transcript_digest(&key_name, &baseline_nonce);
                if !verify_with_public(&software, &public_blob, &baseline_digest, &baseline_sig)? {
                    return Err("baseline signature did not verify under cached public key".into());
                }
                let mut changed = baseline_digest;
                changed[0] ^= 1;
                if verify_with_public(&software, &public_blob, &changed, &baseline_sig)? {
                    return Err("baseline signature verified against a mutated digest".into());
                }
                println!("CROSS-PROCESS PRE-RETIREMENT HELD HANDLE: OPENED / BASELINE FRESHNESS SIGNATURE VERIFIED");
                println!("MUTATED TRANSCRIPT SIGNATURE REPLAY: REJECTED -> PASS");

                created.close_checked().map_err(|status| format!(
                    "closing the parent creation handle failed and would contaminate the held-handle test: {}",
                    status_hex(status)
                ))?;
                let mut delete_handle = open_named(&provider, &key_name)
                    .map_err(|s| format!("open deletion handle failed: {}", status_hex(s)))?;
                let raw_delete = delete_handle.take();
                let delete_status = unsafe { NCryptDeleteKey(raw_delete, 0) };
                if delete_status != 0 {
                    unsafe { let _ = NCryptFreeObject(raw_delete as NCRYPT_HANDLE); }
                    return Err(format!("NCryptDeleteKey failed: {}", status_hex(delete_status)));
                }
                println!("NAMED TPM KEY DELETE THROUGH INDEPENDENT HANDLE: PASS");

                let (open_while_held, open_while_status) = probe_open(&provider, &key_name)?;
                println!(
                    "FRESH OPEN BY NAME WHILE ATTACKER HANDLE REMAINS: {} ({})",
                    if open_while_held { "SUCCEEDED -> FINDING" } else { "REJECTED -> PASS" },
                    status_hex(open_while_status)
                );

                let fresh_nonce = random_nonce();
                write_sync(&root.join("after-delete.nonce"), &fresh_nonce)?;
                wait_for_file(&root.join("after-delete.result"), Some(&mut child))?;
                let (held_status, held_sig) = parse_result_record(
                    &fs::read(root.join("after-delete.result")).map_err(|e| e.to_string())?
                )?;
                let held_rejected = held_status != 0 && is_expected_retired_key_status(held_status);
                let held_signature_valid = if held_status == 0 {
                    let digest = transcript_digest(&key_name, &fresh_nonce);
                    verify_with_public(&software, &public_blob, &digest, &held_sig)?
                } else {
                    false
                };
                if held_status == 0 && !held_signature_valid {
                    return Err("held handle returned success but its signature did not verify".into());
                }
                println!(
                    "PRE-OPENED CROSS-PROCESS HANDLE ON NEVER-BEFORE-SEEN POST-DELETE NONCE: {} ({})",
                    if held_signature_valid {
                        "VALID SIGNATURE -> ATTACK WITNESS CONFIRMED"
                    } else if held_rejected {
                        "REJECTED WITH AN EXPECTED RETIRED-KEY STATUS IN TESTED PROVIDER"
                    } else {
                        "OPERATIONAL ERROR -> INCONCLUSIVE"
                    },
                    status_hex(held_status)
                );

                let status = child.wait().map_err(|e| e.to_string())?;
                if !status.success() { return Err(format!("held-handle child exited with {status}")); }
                let (open_after_close, open_after_status) = probe_open(&provider, &key_name)?;
                println!(
                    "FRESH OPEN BY NAME AFTER ATTACKER HANDLE CLOSED: {} ({})",
                    if open_after_close { "SUCCEEDED -> SECURITY FINDING" } else { "REJECTED -> PASS" },
                    status_hex(open_after_status)
                );

                let snapshot_name_resolves = probe_open(&provider, &restored.key_name)?.0;
                println!(
                    "KEY NAME FROM RESTORED CALIBRE APPLICATION SNAPSHOT RESOLVES TO A LIVE KEY: {}",
                    if snapshot_name_resolves { "YES -> DELETE/REOPEN SECURITY FINDING" } else { "NO -> PASS FOR APPLICATION SNAPSHOT ONLY" }
                );

                println!();
                println!("=== SEC-017 DECISION ===");
                println!("TPM_KEY_CONTAINMENT_NORMAL_PRIVATE_EXPORT={private_export_result}");
                println!("OPAQUE_PROVIDER_BLOB_EXPORT_ROUTE={opaque_export_result}");
                println!("NAMED_KEY_REOPEN_AFTER_DELETE={}", if open_after_close { "SUCCEEDED_SECURITY_FAIL" } else { "REJECTED_IN_TESTED_PROVIDER" });
                println!(
                    "RAW_OLD_KEY_OPERATION_AFTER_DELETE={}",
                    if held_signature_valid {
                        "STILL_POSSIBLE_VIA_PREOPENED_HANDLE"
                    } else if held_rejected {
                        "REJECTED_EXPECTED_RETIRED_KEY_STATUS_IN_TESTED_PROVIDER"
                    } else {
                        "INCONCLUSIVE_OPERATIONAL_STATUS"
                    }
                );
                println!("RESTORED_APPLICATION_SNAPSHOT_KEY_NAME_RESOLVES={}", if snapshot_name_resolves { "YES_DELETE_OR_REOPEN_SECURITY_FAIL" } else { "NO_IN_TESTED_APP_SNAPSHOT" });
                println!("PROTOCOL_OLD_SHARE_ACCEPTANCE=NOT_TESTED_NO_FRESH_NV_ATTESTATION");
                println!("SAME_TPM_PROVIDER_BLOB_OR_FULL_DISK_ROLLBACK=UNKNOWN_NOT_PROVEN");
                println!("TPM_KEY_ATTESTATION_FIXEDTPM_FIXEDPARENT=NOT_YET");
                println!("TPM_NV_MONOTONIC_GENERATION_AND_NONCE_BOUND_CERTIFICATION=NOT_YET");
                println!("F2_STALE_QUORUM_SAFETY=NOT_TESTED_SINGLE_PHYSICAL_TPM");
                println!("PHYSICAL_KEY_ERASURE_AND_POWER_LOSS_ATOMICITY=NOT_PROVEN");
                println!("TPM_CLEAR_PCR_NV_HIERARCHY_BITLOCKER_MODIFIED=NO");
                println!("GLOBAL_BLOCKCHAIN_OR_UNIVERSAL_ORDER_USED=NO");
                Ok(())
            })();

            if child_result.is_err() {
                let _ = child.kill();
                let _ = child.wait();
            }
            child_result
        })();

        let cleanup = if created_by_us {
            cleanup_exact(&provider, &key_name, expected_public.as_deref())
        } else {
            Ok(false)
        };
        match &cleanup {
            Ok(true) => println!("EMERGENCY EXACT-NAME CLEANUP: REMOVED THE VERIFIED LEFTOVER DISPOSABLE KEY"),
            Ok(false) => println!("POST-TEST EXACT-NAME CLEANUP: NO OWNED NAMED KEY REMAINED"),
            Err(error) => eprintln!(
                "SEC-017 CLEANUP ERROR: {error}; manually inspect only this exact key name: {key_name}"
            ),
        }
        let _ = fs::remove_dir_all(&root);
        match (result, cleanup) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(error), Ok(_)) => Err(error),
            (Ok(()), Err(cleanup_error)) => Err(format!("test completed but cleanup failed: {cleanup_error}")),
            (Err(error), Err(cleanup_error)) => Err(format!(
                "{error}; cleanup also failed: {cleanup_error}"
            )),
        }
    }

    fn random_nonce() -> [u8; 32] {
        use rand_core::{OsRng, RngCore};
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn run_cleanup_exact(name: &str) -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-017 v0.17.1 — EXACT-NAME RECOVERY CLEANUP");
        if std::env::var("CALIBRE_TPM_KEY_ACK").ok().as_deref() != Some(ACK_VALUE) {
            return Err("cleanup refused without the live-test acknowledgement".into());
        }
        if !is_generated_key_name(name) {
            return Err("cleanup refused: name does not match the generated SEC-017 key format".into());
        }
        let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER)?;
        match cleanup_exact(&provider, name, None)? {
            true => println!("EXACT-NAME RECOVERY CLEANUP: REMOVED {name}"),
            false => println!("EXACT-NAME RECOVERY CLEANUP: KEY ALREADY ABSENT ({name})"),
        }
        println!("TPM CLEAR / PCR / NV / HIERARCHY / BITLOCKER MODIFIED: NO");
        Ok(())
    }

    pub fn run(args: &[String]) -> Result<(), String> {
        match args.get(1).map(String::as_str) {
            Some("--held-child") => {
                if args.len() != 4 { return Err("usage: --held-child <key-name> <work-dir>".into()); }
                run_held_child(&args[2], &PathBuf::from(&args[3]))
            }
            Some("--cleanup-exact") => {
                if args.len() != 3 { return Err("usage: --cleanup-exact <key-name>".into()); }
                run_cleanup_exact(&args[2])
            }
            None => run_controller(),
            Some(_) => Err("usage: calibre-sec017 [--cleanup-exact <generated-key-name>]".into()),
        }
    }
}

#[cfg(windows)]
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Err(error) = windows_live::run(&args) {
        eprintln!("SEC-017 ERROR: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("CALIBRE SECURITY SEC-017 v0.17.1");
    println!("This live experiment requires Windows CNG and the Microsoft Platform Crypto Provider.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> AppSnapshot {
        AppSnapshot {
            key_name: "CALIBRE_SEC017_TEST_ONLY".into(),
            public_blob: (0u8..72).collect(),
        }
    }

    #[test]
    fn snapshot_round_trip_contains_public_material_only() {
        let snapshot = sample_snapshot();
        let encoded = encode_snapshot(&snapshot).unwrap();
        assert_eq!(decode_snapshot(&encoded).unwrap(), snapshot);
        assert!(!encoded.windows(7).any(|w| w == b"PRIVATE"));
    }

    #[test]
    fn snapshot_checksum_detects_mutation() {
        let mut encoded = encode_snapshot(&sample_snapshot()).unwrap();
        encoded[25] ^= 1;
        assert!(decode_snapshot(&encoded).is_err());
    }

    #[test]
    fn freshness_digest_binds_nonce_and_key_name() {
        let a = transcript_digest("key-a", &[1u8; 32]);
        let b = transcript_digest("key-a", &[2u8; 32]);
        let c = transcript_digest("key-b", &[1u8; 32]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn child_result_round_trip_preserves_hresult_and_signature() {
        let bytes = result_record(0x8009_0016u32 as i32, &[3u8; 64]).unwrap();
        let (status, signature) = parse_result_record(&bytes).unwrap();
        assert_eq!(status as u32, 0x8009_0016);
        assert_eq!(signature, vec![3u8; 64]);
    }

    #[test]
    fn unique_names_are_calibre_namespaced() {
        let a = unique_key_name();
        let b = unique_key_name();
        assert!(is_generated_key_name(&a));
        assert_ne!(a, b);
    }

    #[test]
    fn cleanup_name_validation_is_exact() {
        assert!(is_generated_key_name(
            "CALIBRE_SEC017_3684_1788610804510636400_52227aa81d9ed89f"
        ));
        assert!(!is_generated_key_name("CALIBRE_SEC017_TEST_ONLY"));
        assert!(!is_generated_key_name("CALIBRE_SEC017_1_2_abc/def"));
        assert!(!is_generated_key_name("unrelated-key"));
    }
}
