const SNAPSHOT_MAGIC: &[u8; 8] = b"CAL18SN1";
const SNAPSHOT_VERSION: u32 = 1;
const OLD_GENERATION: u64 = 60;
const ACTIVE_GENERATION: u64 = 61;
const VALIDATOR_ID: u64 = 0;
const STATE_ID: u64 = 0x4341_4c49_4252_4501;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GenerationView {
    generation: u64,
    validator_id: u64,
    key_id: [u8; 32],
    keyset_hash: [u8; 32],
    state_root: [u8; 32],
    public_blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShareClaim {
    generation: u64,
    validator_id: u64,
    key_id: [u8; 32],
    keyset_hash: [u8; 32],
    state_root: [u8; 32],
    nonce: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateReject {
    Generation,
    Validator,
    KeyId,
    Keyset,
    State,
    Nonce,
    Signature,
}

impl GateReject {
    fn label(self) -> &'static str {
        match self {
            Self::Generation => "GENERATION_MISMATCH",
            Self::Validator => "VALIDATOR_ID_MISMATCH",
            Self::KeyId => "ACTIVE_KEY_ID_MISMATCH",
            Self::Keyset => "ACTIVE_KEYSET_HASH_MISMATCH",
            Self::State => "ACTIVE_STATE_ROOT_MISMATCH",
            Self::Nonce => "CLIENT_NONCE_MISMATCH",
            Self::Signature => "ACTIVE_KEY_SIGNATURE_INVALID",
        }
    }
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn key_id(public_blob: &[u8]) -> [u8; 32] {
    hash_parts(b"CALIBRE_SEC018_KEY_ID_V1", &[public_blob])
}

fn keyset_hash(generation: u64, validator_id: u64, key_id: &[u8; 32]) -> [u8; 32] {
    hash_parts(
        b"CALIBRE_SEC018_KEYSET_V1",
        &[&generation.to_le_bytes(), &validator_id.to_le_bytes(), key_id],
    )
}

fn state_root(generation: u64) -> [u8; 32] {
    hash_parts(
        b"CALIBRE_SEC018_STATE_ROOT_V1",
        &[&STATE_ID.to_le_bytes(), &generation.to_le_bytes()],
    )
}

fn generation_view(generation: u64, public_blob: Vec<u8>) -> GenerationView {
    let key_id = key_id(&public_blob);
    GenerationView {
        generation,
        validator_id: VALIDATOR_ID,
        key_id,
        keyset_hash: keyset_hash(generation, VALIDATOR_ID, &key_id),
        state_root: state_root(generation),
        public_blob,
    }
}

fn unsigned_claim(view: &GenerationView, nonce: [u8; 32]) -> ShareClaim {
    ShareClaim {
        generation: view.generation,
        validator_id: view.validator_id,
        key_id: view.key_id,
        keyset_hash: view.keyset_hash,
        state_root: view.state_root,
        nonce,
        signature: Vec::new(),
    }
}

fn share_transcript(claim: &ShareClaim) -> Vec<u8> {
    let mut out = Vec::with_capacity(208);
    out.extend_from_slice(b"CALIBRE_SEC018_GENERATION_BOUND_SHARE_V1");
    out.extend_from_slice(&claim.generation.to_le_bytes());
    out.extend_from_slice(&claim.validator_id.to_le_bytes());
    out.extend_from_slice(&STATE_ID.to_le_bytes());
    out.extend_from_slice(&claim.key_id);
    out.extend_from_slice(&claim.keyset_hash);
    out.extend_from_slice(&claim.state_root);
    out.extend_from_slice(&claim.nonce);
    out
}

fn share_digest(claim: &ShareClaim) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(share_transcript(claim)).into()
}

fn metadata_gate(
    active: &GenerationView,
    expected_nonce: &[u8; 32],
    claim: &ShareClaim,
) -> Result<(), GateReject> {
    if claim.generation != active.generation {
        return Err(GateReject::Generation);
    }
    if claim.validator_id != active.validator_id {
        return Err(GateReject::Validator);
    }
    if claim.key_id != active.key_id {
        return Err(GateReject::KeyId);
    }
    if claim.keyset_hash != active.keyset_hash {
        return Err(GateReject::Keyset);
    }
    if claim.state_root != active.state_root {
        return Err(GateReject::State);
    }
    if &claim.nonce != expected_nonce {
        return Err(GateReject::Nonce);
    }
    Ok(())
}

fn encode_view(view: &GenerationView) -> Result<Vec<u8>, String> {
    let public_len = u32::try_from(view.public_blob.len()).map_err(|_| "public blob too long")?;
    let mut out = Vec::with_capacity(132 + view.public_blob.len());
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    out.extend_from_slice(&view.generation.to_le_bytes());
    out.extend_from_slice(&view.validator_id.to_le_bytes());
    out.extend_from_slice(&view.key_id);
    out.extend_from_slice(&view.keyset_hash);
    out.extend_from_slice(&view.state_root);
    out.extend_from_slice(&public_len.to_le_bytes());
    out.extend_from_slice(&view.public_blob);
    let checksum = blake3::hash(&out);
    out.extend_from_slice(checksum.as_bytes());
    Ok(out)
}

fn decode_view(bytes: &[u8]) -> Result<GenerationView, String> {
    const HEADER: usize = 8 + 4 + 8 + 8 + 32 + 32 + 32 + 4;
    const CHECKSUM: usize = 32;
    if bytes.len() < HEADER + CHECKSUM {
        return Err("generation snapshot is shorter than its header and checksum".into());
    }
    if &bytes[..8] != SNAPSHOT_MAGIC {
        return Err("generation snapshot magic mismatch".into());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != SNAPSHOT_VERSION {
        return Err(format!("unsupported generation snapshot version {version}"));
    }
    let public_len = u32::from_le_bytes(bytes[124..128].try_into().unwrap()) as usize;
    let expected = HEADER
        .checked_add(public_len)
        .and_then(|value| value.checked_add(CHECKSUM))
        .ok_or("generation snapshot length overflow")?;
    if bytes.len() != expected {
        return Err(format!(
            "generation snapshot length mismatch: expected {expected}, got {}",
            bytes.len()
        ));
    }
    let body_end = expected - CHECKSUM;
    if blake3::hash(&bytes[..body_end]).as_bytes() != &bytes[body_end..] {
        return Err("generation snapshot checksum mismatch".into());
    }
    let mut key_id_bytes = [0u8; 32];
    key_id_bytes.copy_from_slice(&bytes[28..60]);
    let mut keyset = [0u8; 32];
    keyset.copy_from_slice(&bytes[60..92]);
    let mut state = [0u8; 32];
    state.copy_from_slice(&bytes[92..124]);
    let view = GenerationView {
        generation: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        validator_id: u64::from_le_bytes(bytes[20..28].try_into().unwrap()),
        key_id: key_id_bytes,
        keyset_hash: keyset,
        state_root: state,
        public_blob: bytes[HEADER..body_end].to_vec(),
    };
    if view.key_id != key_id(&view.public_blob) {
        return Err("generation snapshot public key does not match key id".into());
    }
    if view.keyset_hash != keyset_hash(view.generation, view.validator_id, &view.key_id) {
        return Err("generation snapshot keyset hash is inconsistent".into());
    }
    if view.state_root != state_root(view.generation) {
        return Err("generation snapshot state root is inconsistent".into());
    }
    Ok(view)
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

fn unique_key_name(role: &str) -> String {
    use rand_core::{OsRng, RngCore};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let suffix = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!(
        "CALIBRE_SEC018_{role}_{}_{}_{}",
        std::process::id(),
        stamp,
        suffix
    )
}

fn is_generated_key_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("CALIBRE_SEC018_") else {
        return false;
    };
    let mut parts = rest.split('_');
    let (Some(role), Some(pid), Some(stamp), Some(suffix), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    matches!(role, "OLD" | "ACTIVE")
        && !pid.is_empty()
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
        BCRYPT_ECCPUBLIC_BLOB, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
        NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY,
        NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE,
        NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_PERSIST_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
        NCryptFreeObject, NCryptGetProperty, NCryptImportKey, NCryptIsAlgSupported, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, NCryptVerifySignature,
    };

    const ACK_VALUE: &str = "CREATE_DELETE_TWO_DISPOSABLE_KEYS";
    const NTE_BAD_SIGNATURE_STATUS: i32 = 0x8009_0006u32 as i32;
    const NTE_BAD_KEY_STATE_STATUS: i32 = 0x8009_000bu32 as i32;
    const NTE_BAD_KEYSET_STATUS: i32 = 0x8009_0016u32 as i32;
    const NTE_INVALID_HANDLE_STATUS: i32 = 0x8009_0026u32 as i32;

    struct Provider(NCRYPT_PROV_HANDLE);

    impl Provider {
        fn open(name: *const u16) -> Result<Self, String> {
            let mut handle = 0;
            let status = unsafe { NCryptOpenStorageProvider(&mut handle, name, 0) };
            if status != 0 {
                return Err(format!(
                    "NCryptOpenStorageProvider failed: 0x{:08x}",
                    status as u32
                ));
            }
            Ok(Self(handle))
        }
    }

    impl Drop for Provider {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    let _ = NCryptFreeObject(self.0 as NCRYPT_HANDLE);
                }
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
    }

    impl Drop for FreeKey {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    let _ = NCryptFreeObject(self.0 as NCRYPT_HANDLE);
                }
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
            return Err(format!(
                "NCryptGetProperty returned {written} bytes instead of 4"
            ));
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
        let status = unsafe {
            NCryptOpenKey(
                provider.0,
                &mut key,
                name_w.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status == 0 { Ok(FreeKey(key)) } else { Err(status) }
    }

    fn export_public(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>, i32> {
        let mut len = 0u32;
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                null_mut(),
                0,
                &mut len,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 { return Err(status); }
        let mut bytes = vec![0u8; len as usize];
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
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
            return Err(format!(
                "NCryptCreatePersistedKey failed for {name}: {}",
                status_hex(status)
            ));
        }
        *created_by_us = true;
        let mut key = FreeKey(key);
        let setup = (|| -> Result<Vec<u8>, String> {
            set_dword(
                key.0 as NCRYPT_HANDLE,
                NCRYPT_KEY_USAGE_PROPERTY,
                NCRYPT_ALLOW_SIGNING_FLAG,
            )?;
            let status = unsafe { NCryptFinalizeKey(key.0, 0) };
            if status != 0 {
                return Err(format!(
                    "NCryptFinalizeKey failed for {name}: {}",
                    status_hex(status)
                ));
            }
            let export_policy = get_dword(key.0 as NCRYPT_HANDLE, NCRYPT_EXPORT_POLICY_PROPERTY)?;
            if export_policy != 0 {
                return Err(format!(
                    "{name} export policy was 0x{export_policy:08x}, expected zero"
                ));
            }
            let usage = get_dword(key.0 as NCRYPT_HANDLE, NCRYPT_KEY_USAGE_PROPERTY)?;
            if usage & NCRYPT_ALLOW_SIGNING_FLAG == 0 {
                return Err(format!("{name} signing usage flag missing: 0x{usage:08x}"));
            }
            let public = export_public(key.0)
                .map_err(|code| format!("public export failed: {}", status_hex(code)))?;
            if public.len() != 72 {
                return Err(format!(
                    "unexpected ECDSA P-256 public blob length {} (expected 72)",
                    public.len()
                ));
            }
            Ok(public)
        })();

        match setup {
            Ok(public) => Ok((key, public)),
            Err(error) => {
                let raw = key.take();
                let delete = unsafe { NCryptDeleteKey(raw, 0) };
                if delete == 0 {
                    *created_by_us = false;
                    Err(error)
                } else {
                    unsafe { let _ = NCryptFreeObject(raw as NCRYPT_HANDLE); }
                    Err(format!(
                        "{error}; exact-key rollback delete also failed: {}",
                        status_hex(delete)
                    ))
                }
            }
        }
    }

    fn sign_hash(key: NCRYPT_KEY_HANDLE, digest: &[u8; 32]) -> (i32, Vec<u8>) {
        let mut len = 0u32;
        let first = unsafe {
            NCryptSignHash(
                key, null(), digest.as_ptr(), digest.len() as u32, null_mut(), 0,
                &mut len, NCRYPT_SILENT_FLAG,
            )
        };
        if first != 0 { return (first, Vec::new()); }
        let mut signature = vec![0u8; len as usize];
        let second = unsafe {
            NCryptSignHash(
                key, null(), digest.as_ptr(), digest.len() as u32, signature.as_mut_ptr(),
                signature.len() as u32, &mut len, NCRYPT_SILENT_FLAG,
            )
        };
        if second != 0 { return (second, Vec::new()); }
        signature.truncate(len as usize);
        (0, signature)
    }

    fn verify_with_public(
        provider: &Provider,
        public: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, String> {
        let mut key = 0;
        let status = unsafe {
            NCryptImportKey(
                provider.0, 0, BCRYPT_ECCPUBLIC_BLOB, null(), &mut key, public.as_ptr(),
                public.len() as u32, 0,
            )
        };
        if status != 0 {
            return Err(format!(
                "NCryptImportKey(public) failed: {}",
                status_hex(status)
            ));
        }
        let key = FreeKey(key);
        let status = unsafe {
            NCryptVerifySignature(
                key.0, null(), digest.as_ptr(), digest.len() as u32, signature.as_ptr(),
                signature.len() as u32, 0,
            )
        };
        match status {
            0 => Ok(true),
            NTE_BAD_SIGNATURE_STATUS => Ok(false),
            other => Err(format!(
                "NCryptVerifySignature returned an operational error: {}",
                status_hex(other)
            )),
        }
    }

    fn verify_share(
        provider: &Provider,
        active: &GenerationView,
        expected_nonce: &[u8; 32],
        claim: &ShareClaim,
    ) -> Result<Result<(), GateReject>, String> {
        if let Err(reject) = metadata_gate(active, expected_nonce, claim) {
            return Ok(Err(reject));
        }
        if verify_with_public(
            provider,
            &active.public_blob,
            &share_digest(claim),
            &claim.signature,
        )? {
            Ok(Ok(()))
        } else {
            Ok(Err(GateReject::Signature))
        }
    }

    fn write_sync(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let temp = path.with_extension("tmp");
        let mut file = File::create(&temp).map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        Ok(())
    }

    fn read_exact_32(path: &Path) -> Result<[u8; 32], String> {
        let bytes = fs::read(path).map_err(|error| error.to_string())?;
        bytes.try_into().map_err(|value: Vec<u8>| {
            format!("digest length was {}, expected 32", value.len())
        })
    }

    fn wait_for_file(path: &Path, child: Option<&mut Child>) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut child = child;
        loop {
            if path.exists() { return Ok(()); }
            if let Some(process) = child.as_deref_mut() {
                if let Some(status) = process.try_wait().map_err(|error| error.to_string())? {
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
        if !is_generated_key_name(name)
            || !name.starts_with("CALIBRE_SEC018_OLD_")
            || dir.file_name().and_then(|value| value.to_str()) != Some(name)
        {
            return Err("held-handle child refused an invalid old-key name or work directory".into());
        }
        let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER)?;
        let held = open_named(&provider, name)
            .map_err(|status| format!("held child open failed: {}", status_hex(status)))?;
        for label in ["baseline", "old-after-retirement", "relabel-after-retirement"] {
            let request = dir.join(format!("{label}.digest"));
            let response = dir.join(format!("{label}.result"));
            wait_for_file(&request, None)?;
            let digest = read_exact_32(&request)?;
            let (status, signature) = sign_hash(held.0, &digest);
            write_sync(&response, &result_record(status, &signature)?)?;
        }
        Ok(())
    }

    fn request_child_signature(
        root: &Path,
        label: &str,
        digest: &[u8; 32],
        child: &mut Child,
    ) -> Result<(i32, Vec<u8>), String> {
        write_sync(&root.join(format!("{label}.digest")), digest)?;
        let result_path = root.join(format!("{label}.result"));
        wait_for_file(&result_path, Some(child))?;
        parse_result_record(&fs::read(result_path).map_err(|error| error.to_string())?)
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
            let observed = export_public(key.0).map_err(|status| {
                format!("cleanup public-key identity check failed: {}", status_hex(status))
            })?;
            if observed != expected {
                return Err(format!(
                    "cleanup refused because {name} no longer has the public key created by this run"
                ));
            }
        }
        let raw = key.take();
        let status = unsafe { NCryptDeleteKey(raw, 0) };
        if status != 0 {
            unsafe { let _ = NCryptFreeObject(raw as NCRYPT_HANDLE); }
            return Err(format!(
                "cleanup NCryptDeleteKey failed for {name}: {}",
                status_hex(status)
            ));
        }
        Ok(true)
    }

    fn delete_named_key(
        provider: &Provider,
        name: &str,
        expected_public: &[u8],
    ) -> Result<(), String> {
        let mut key = open_named(provider, name)
            .map_err(|status| format!("open deletion handle failed: {}", status_hex(status)))?;
        let observed = export_public(key.0)
            .map_err(|status| format!("deletion identity check failed: {}", status_hex(status)))?;
        if observed != expected_public {
            return Err("deletion refused because the named key identity changed".into());
        }
        let raw = key.take();
        let status = unsafe { NCryptDeleteKey(raw, 0) };
        if status != 0 {
            unsafe { let _ = NCryptFreeObject(raw as NCRYPT_HANDLE); }
            return Err(format!("NCryptDeleteKey failed: {}", status_hex(status)));
        }
        Ok(())
    }

    fn signed_claim(
        key: NCRYPT_KEY_HANDLE,
        view: &GenerationView,
        nonce: [u8; 32],
    ) -> Result<ShareClaim, String> {
        let mut claim = unsigned_claim(view, nonce);
        let (status, signature) = sign_hash(key, &share_digest(&claim));
        if status != 0 {
            return Err(format!("current-key signing failed: {}", status_hex(status)));
        }
        claim.signature = signature;
        Ok(claim)
    }

    fn random_nonce() -> [u8; 32] {
        use rand_core::{OsRng, RngCore};
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn run_controller() -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-018 v0.18.0");
        println!("GENERATION-BOUND PROTOCOL GATE AGAINST A RETAINED TPM KEY HANDLE");
        println!("Two unique current-user ECDSA P-256 keys; Microsoft Platform Crypto Provider; one physical host");
        println!("Purpose: distinguish raw old-key validity from CALIBRE protocol acceptance");
        println!("TPM clear / PCR / NV / hierarchy / BitLocker / existing-key modification: NONE");
        println!("Global blockchain / universal transaction order: NOT USED");
        println!();

        if std::env::var("CALIBRE_TPM_KEY_ACK").ok().as_deref() != Some(ACK_VALUE) {
            return Err(format!(
                "live key test refused. Set CALIBRE_TPM_KEY_ACK={ACK_VALUE} to authorize creation and deletion of exactly two unique disposable current-user keys"
            ));
        }

        let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER)?;
        let software = Provider::open(MS_KEY_STORAGE_PROVIDER)?;
        let impl_flags = get_dword(provider.0 as NCRYPT_HANDLE, NCRYPT_IMPL_TYPE_PROPERTY)?;
        if impl_flags & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
            return Err(format!(
                "Platform provider did not report NCRYPT_IMPL_HARDWARE_FLAG: flags=0x{impl_flags:08x}"
            ));
        }
        let alg_status = unsafe { NCryptIsAlgSupported(provider.0, NCRYPT_ECDSA_P256_ALGORITHM, 0) };
        if alg_status != 0 {
            return Err(format!(
                "TPM provider does not support ECDSA P-256: {}",
                status_hex(alg_status)
            ));
        }
        println!("PLATFORM PROVIDER HARDWARE IMPLEMENTATION FLAG: PASS (0x{impl_flags:08x})");
        println!("TPM PROVIDER ECDSA P-256 SUPPORT: PASS");

        let old_name = unique_key_name("OLD");
        let active_name = unique_key_name("ACTIVE");
        println!("OLD DISPOSABLE KEY NAME: {old_name}");
        println!("ACTIVE DISPOSABLE KEY NAME: {active_name}");
        let root = std::env::temp_dir().join(&old_name);
        fs::create_dir(&root).map_err(|error| format!("create unique work directory: {error}"))?;

        let mut old_created = false;
        let mut active_created = false;
        let mut old_public_for_cleanup: Option<Vec<u8>> = None;
        let mut active_public_for_cleanup: Option<Vec<u8>> = None;

        let result = (|| -> Result<(), String> {
            let (mut old_key, old_public) = create_key(&provider, &old_name, &mut old_created)?;
            old_public_for_cleanup = Some(old_public.clone());
            let (active_key, active_public) = create_key(&provider, &active_name, &mut active_created)?;
            active_public_for_cleanup = Some(active_public.clone());
            println!("GENERATION-{OLD_GENERATION} TPM SIGNING KEY CREATED: PASS");
            println!("GENERATION-{ACTIVE_GENERATION} TPM SIGNING KEY CREATED: PASS");

            let old_view = generation_view(OLD_GENERATION, old_public.clone());
            let active_view = generation_view(ACTIVE_GENERATION, active_public.clone());
            let old_snapshot = decode_view(&encode_view(&old_view)?)?;
            let active_snapshot = decode_view(&encode_view(&active_view)?)?;
            if old_snapshot != old_view || active_snapshot != active_view {
                return Err("checksummed generation snapshot round trip changed data".into());
            }
            println!("CHECKSUMMED OLD + ACTIVE GENERATION VIEWS: CREATED / VERIFIED");
            println!("ACTIVE VIEW SOURCE: CALIBRE APPLICATION STATE ONLY; TPM NV NOT USED");

            let exe = std::env::current_exe().map_err(|error| error.to_string())?;
            let mut child = Command::new(&exe)
                .arg("--held-child")
                .arg(&old_name)
                .arg(&root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|error| format!("spawn held-handle child: {error}"))?;

            let child_result = (|| -> Result<(), String> {
                let baseline_nonce = random_nonce();
                let mut baseline_claim = unsigned_claim(&old_view, baseline_nonce);
                let (status, signature) = request_child_signature(
                    &root, "baseline", &share_digest(&baseline_claim), &mut child,
                )?;
                if status != 0 {
                    return Err(format!("old child baseline sign failed: {}", status_hex(status)));
                }
                baseline_claim.signature = signature;
                if verify_share(&software, &old_view, &baseline_nonce, &baseline_claim)? != Ok(()) {
                    return Err("old-generation baseline share was not accepted before retirement".into());
                }
                println!("BEFORE RETIREMENT: GENERATION-{OLD_GENERATION} SHARE ACCEPTED -> BASELINE PASS");

                old_key.close_checked().map_err(|status| {
                    format!(
                        "closing parent old-key handle failed and would contaminate the test: {}",
                        status_hex(status)
                    )
                })?;
                delete_named_key(&provider, &old_name, &old_public)?;
                println!("GENERATION-{OLD_GENERATION} NAMED TPM KEY DELETED THROUGH INDEPENDENT HANDLE: PASS");
                let (reopened, reopen_status) = probe_open(&provider, &old_name)?;
                if reopened { return Err("deleted old key unexpectedly reopened by name".into()); }
                println!(
                    "FRESH OPEN OF RETIRED KEY BY NAME: REJECTED -> PASS ({})",
                    status_hex(reopen_status)
                );

                let attack_nonce = random_nonce();
                let mut truthful_old_claim = unsigned_claim(&old_view, attack_nonce);
                let (old_status, old_signature) = request_child_signature(
                    &root, "old-after-retirement", &share_digest(&truthful_old_claim), &mut child,
                )?;
                if old_status != 0 {
                    if matches!(old_status, NTE_BAD_KEY_STATE_STATUS | NTE_INVALID_HANDLE_STATUS) {
                        return Err(format!(
                            "this provider revoked the pre-opened handle; SEC-018 needs a retained-handle attack witness but received {}",
                            status_hex(old_status)
                        ));
                    }
                    return Err(format!(
                        "pre-opened old handle returned an inconclusive operational error: {}",
                        status_hex(old_status)
                    ));
                }
                truthful_old_claim.signature = old_signature;
                if !verify_with_public(
                    &software, &old_public, &share_digest(&truthful_old_claim),
                    &truthful_old_claim.signature,
                )? {
                    return Err("post-retirement old signature was not valid under its old public key".into());
                }
                println!("RAW RETIRED TPM HANDLE ON NEW POST-DELETE NONCE: VALID SIGNATURE -> SEC-017 ATTACK REPRODUCED");
                let truthful_reject = verify_share(
                    &software, &active_view, &attack_nonce, &truthful_old_claim,
                )?;
                if truthful_reject != Err(GateReject::Generation) {
                    return Err(format!("truthful old share had unexpected gate result {truthful_reject:?}"));
                }
                println!(
                    "CURRENT GENERATION-{ACTIVE_GENERATION} VIEW CHECKS OLD SHARE: REJECTED_{} -> PASS",
                    GateReject::Generation.label()
                );

                let relabel_nonce = random_nonce();
                let mut relabel_claim = unsigned_claim(&active_view, relabel_nonce);
                let (relabel_status, relabel_signature) = request_child_signature(
                    &root, "relabel-after-retirement", &share_digest(&relabel_claim), &mut child,
                )?;
                if relabel_status != 0 {
                    return Err(format!(
                        "old handle failed generation-relabel signing attempt: {}",
                        status_hex(relabel_status)
                    ));
                }
                relabel_claim.signature = relabel_signature;
                if !verify_with_public(
                    &software, &old_public, &share_digest(&relabel_claim), &relabel_claim.signature,
                )? {
                    return Err("relabel attack signature did not verify under the retired key".into());
                }
                let relabel_reject = verify_share(
                    &software, &active_view, &relabel_nonce, &relabel_claim,
                )?;
                if relabel_reject != Err(GateReject::Signature) {
                    return Err(format!("generation-relabel attack had unexpected gate result {relabel_reject:?}"));
                }
                println!("OLD HANDLE SIGNS A GENERATION-{ACTIVE_GENERATION} TRANSCRIPT: RAW SIGNATURE VALID UNDER OLD KEY");
                println!(
                    "CURRENT KEYSET VERIFIES RELABELLED CLAIM: REJECTED_{} -> PASS",
                    GateReject::Signature.label()
                );

                let mut substitution_claim = truthful_old_claim.clone();
                substitution_claim.generation = ACTIVE_GENERATION;
                substitution_claim.keyset_hash = active_view.keyset_hash;
                substitution_claim.state_root = active_view.state_root;
                let substitution_reject = verify_share(
                    &software, &active_view, &attack_nonce, &substitution_claim,
                )?;
                if substitution_reject != Err(GateReject::KeyId) {
                    return Err(format!("old-key substitution had unexpected gate result {substitution_reject:?}"));
                }
                println!(
                    "OLD KEY-ID SUBSTITUTION INTO ACTIVE GENERATION: REJECTED_{} -> PASS",
                    GateReject::KeyId.label()
                );

                let current_nonce = random_nonce();
                let current_claim = signed_claim(active_key.0, &active_view, current_nonce)?;
                if verify_share(&software, &active_view, &current_nonce, &current_claim)? != Ok(()) {
                    return Err("active-generation share was not accepted".into());
                }
                println!("GENERATION-{ACTIVE_GENERATION} ACTIVE TPM SHARE ON FRESH NONCE: ACCEPTED -> PASS");

                let replay_nonce = random_nonce();
                let replay_reject = verify_share(
                    &software, &active_view, &replay_nonce, &current_claim,
                )?;
                if replay_reject != Err(GateReject::Nonce) {
                    return Err(format!("nonce replay had unexpected gate result {replay_reject:?}"));
                }
                println!(
                    "ACTIVE SHARE REPLAYED TO DIFFERENT CLIENT NONCE: REJECTED_{} -> PASS",
                    GateReject::Nonce.label()
                );

                let stale_accepts = verify_share(
                    &software, &old_snapshot, &attack_nonce, &truthful_old_claim,
                )? == Ok(());
                if !stale_accepts {
                    return Err("rolled-back old verifier view did not reproduce the expected attack".into());
                }
                println!("ROLLED-BACK VERIFIER USING GENERATION-{OLD_GENERATION} SNAPSHOT ACCEPTS POST-RETIREMENT OLD SHARE -> LONG-RANGE ATTACK CONFIRMED");

                let child_status = child.wait().map_err(|error| error.to_string())?;
                if !child_status.success() {
                    return Err(format!("held-handle child exited with {child_status}"));
                }
                let (open_after_close, open_after_status) = probe_open(&provider, &old_name)?;
                if open_after_close { return Err("retired key reopened after attacker handle closed".into()); }
                println!(
                    "FRESH OPEN OF RETIRED KEY AFTER ATTACKER HANDLE CLOSED: REJECTED -> PASS ({})",
                    status_hex(open_after_status)
                );

                println!();
                println!("=== SEC-018 DECISION ===");
                println!("RAW_RETIRED_TPM_HANDLE_AFTER_NAMED_DELETE=STILL_SIGNS_VALID");
                println!("CURRENT_VIEW_REJECTS_TRUTHFUL_OLD_SHARE=PASS_GENERATION_MISMATCH");
                println!("CURRENT_VIEW_REJECTS_GENERATION_RELABEL=PASS_ACTIVE_KEY_SIGNATURE_INVALID");
                println!("CURRENT_VIEW_REJECTS_OLD_KEY_SUBSTITUTION=PASS_ACTIVE_KEY_ID_MISMATCH");
                println!("CURRENT_VIEW_ACCEPTS_ACTIVE_GENERATION_SHARE=PASS");
                println!("CLIENT_NONCE_REPLAY=REJECTED");
                println!("ROLLED_BACK_LOCAL_GENERATION_VIEW=ACCEPTS_OLD_SHARE_LONG_RANGE_ATTACK_CONFIRMED");
                println!("PROTOCOL_GENERATION_GATE_CONDITIONAL_ON_CORRECT_ACTIVE_VIEW=PASS_IN_TESTED_SINGLE_SIGNER_MODEL");
                println!("OFFLINE_CURRENTNESS_WITHOUT_FRESH_NONROLLBACKABLE_ANCHOR=NOT_SOLVED");
                println!("TPM_KEY_ATTESTATION_FIXEDTPM_FIXEDPARENT=NOT_TESTED");
                println!("TPM_NV_MONOTONIC_GENERATION=NOT_USED_NOT_MODIFIED");
                println!("F2_FIVE_OF_SEVEN_COMMITTEE_SAFETY=NOT_TESTED_SINGLE_PHYSICAL_TPM");
                println!("FORMAL_PROTOCOL_PROOF=NOT_CLAIMED");
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

        let old_cleanup = if old_created {
            cleanup_exact(&provider, &old_name, old_public_for_cleanup.as_deref())
        } else { Ok(false) };
        let active_cleanup = if active_created {
            cleanup_exact(&provider, &active_name, active_public_for_cleanup.as_deref())
        } else { Ok(false) };
        for (role, cleanup) in [("OLD", &old_cleanup), ("ACTIVE", &active_cleanup)] {
            match cleanup {
                Ok(true) => println!("{role} EXACT-NAME CLEANUP: REMOVED THE VERIFIED LEFTOVER DISPOSABLE KEY"),
                Ok(false) => println!("{role} POST-TEST CLEANUP: NO OWNED NAMED KEY REMAINED"),
                Err(error) => eprintln!("SEC-018 {role} CLEANUP ERROR: {error}"),
            }
        }
        let _ = fs::remove_dir_all(&root);

        let cleanup_error = match (old_cleanup, active_cleanup) {
            (Err(old), Err(active)) => Some(format!("old cleanup failed: {old}; active cleanup failed: {active}")),
            (Err(old), _) => Some(format!("old cleanup failed: {old}")),
            (_, Err(active)) => Some(format!("active cleanup failed: {active}")),
            _ => None,
        };
        match (result, cleanup_error) {
            (Ok(()), None) => Ok(()),
            (Err(error), None) => Err(error),
            (Ok(()), Some(cleanup)) => Err(format!("test completed but {cleanup}")),
            (Err(error), Some(cleanup)) => Err(format!("{error}; {cleanup}")),
        }
    }

    fn run_cleanup_exact(name: &str) -> Result<(), String> {
        println!("CALIBRE SECURITY SEC-018 v0.18.0 — EXACT-NAME RECOVERY CLEANUP");
        if std::env::var("CALIBRE_TPM_KEY_ACK").ok().as_deref() != Some(ACK_VALUE) {
            return Err("cleanup refused without the live-test acknowledgement".into());
        }
        if !is_generated_key_name(name) {
            return Err("cleanup refused: name does not match the generated SEC-018 key format".into());
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
                if args.len() != 4 { return Err("usage: --held-child <old-key-name> <work-dir>".into()); }
                run_held_child(&args[2], &PathBuf::from(&args[3]))
            }
            Some("--cleanup-exact") => {
                if args.len() != 3 { return Err("usage: --cleanup-exact <generated-key-name>".into()); }
                run_cleanup_exact(&args[2])
            }
            None => run_controller(),
            Some(_) => Err("usage: calibre-sec018 [--cleanup-exact <generated-key-name>]".into()),
        }
    }
}

#[cfg(windows)]
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Err(error) = windows_live::run(&args) {
        eprintln!("SEC-018 ERROR: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("CALIBRE SECURITY SEC-018 v0.18.0");
    println!("This live experiment requires Windows CNG and the Microsoft Platform Crypto Provider.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_view(generation: u64, marker: u8) -> GenerationView {
        generation_view(generation, vec![marker; 72])
    }

    #[test]
    fn generation_view_snapshot_round_trip() {
        let view = sample_view(ACTIVE_GENERATION, 7);
        assert_eq!(decode_view(&encode_view(&view).unwrap()).unwrap(), view);
    }

    #[test]
    fn snapshot_checksum_detects_mutation() {
        let mut bytes = encode_view(&sample_view(ACTIVE_GENERATION, 7)).unwrap();
        bytes[40] ^= 1;
        assert!(decode_view(&bytes).is_err());
    }

    #[test]
    fn keyset_and_state_are_generation_bound() {
        let old = sample_view(OLD_GENERATION, 7);
        let active_same_key = sample_view(ACTIVE_GENERATION, 7);
        assert_eq!(old.key_id, active_same_key.key_id);
        assert_ne!(old.keyset_hash, active_same_key.keyset_hash);
        assert_ne!(old.state_root, active_same_key.state_root);
    }

    #[test]
    fn old_generation_is_rejected_before_crypto() {
        let old = sample_view(OLD_GENERATION, 1);
        let active = sample_view(ACTIVE_GENERATION, 2);
        let nonce = [9u8; 32];
        let claim = unsigned_claim(&old, nonce);
        assert_eq!(metadata_gate(&active, &nonce, &claim), Err(GateReject::Generation));
    }

    #[test]
    fn old_key_substitution_is_rejected() {
        let old = sample_view(OLD_GENERATION, 1);
        let active = sample_view(ACTIVE_GENERATION, 2);
        let nonce = [9u8; 32];
        let mut claim = unsigned_claim(&active, nonce);
        claim.key_id = old.key_id;
        assert_eq!(metadata_gate(&active, &nonce, &claim), Err(GateReject::KeyId));
    }

    #[test]
    fn nonce_replay_is_rejected() {
        let active = sample_view(ACTIVE_GENERATION, 2);
        let claim = unsigned_claim(&active, [3u8; 32]);
        assert_eq!(metadata_gate(&active, &[4u8; 32], &claim), Err(GateReject::Nonce));
    }

    #[test]
    fn exact_active_metadata_reaches_crypto_gate() {
        let active = sample_view(ACTIVE_GENERATION, 2);
        let nonce = [4u8; 32];
        let claim = unsigned_claim(&active, nonce);
        assert_eq!(metadata_gate(&active, &nonce, &claim), Ok(()));
    }

    #[test]
    fn transcript_binds_every_protocol_field() {
        let active = sample_view(ACTIVE_GENERATION, 2);
        let claim = unsigned_claim(&active, [4u8; 32]);
        let baseline = share_digest(&claim);
        let mut mutations = Vec::new();
        let mut generation = claim.clone();
        generation.generation += 1;
        mutations.push(generation);
        let mut validator = claim.clone();
        validator.validator_id += 1;
        mutations.push(validator);
        let mut key = claim.clone();
        key.key_id[0] ^= 1;
        mutations.push(key);
        let mut keyset = claim.clone();
        keyset.keyset_hash[0] ^= 1;
        mutations.push(keyset);
        let mut state = claim.clone();
        state.state_root[0] ^= 1;
        mutations.push(state);
        let mut nonce = claim.clone();
        nonce.nonce[0] ^= 1;
        mutations.push(nonce);
        assert!(mutations.into_iter().all(|mutation| share_digest(&mutation) != baseline));
    }

    #[test]
    fn result_record_round_trip_preserves_hresult_and_signature() {
        let bytes = result_record(0x8009_0016u32 as i32, &[3u8; 64]).unwrap();
        let (status, signature) = parse_result_record(&bytes).unwrap();
        assert_eq!(status as u32, 0x8009_0016);
        assert_eq!(signature, vec![3u8; 64]);
    }

    #[test]
    fn generated_names_are_role_scoped_and_exact() {
        let old = unique_key_name("OLD");
        let active = unique_key_name("ACTIVE");
        assert!(is_generated_key_name(&old));
        assert!(is_generated_key_name(&active));
        assert_ne!(old, active);
        assert!(!is_generated_key_name("CALIBRE_SEC018_OLD_TEST_ONLY"));
        assert!(!is_generated_key_name("CALIBRE_SEC018_OTHER_1_2_0123456789abcdef"));
        assert!(!is_generated_key_name("unrelated-key"));
    }
}
