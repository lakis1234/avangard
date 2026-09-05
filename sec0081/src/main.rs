use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const NETWORK_ID: u32 = 1;
const EPOCH: u64 = 81;
const HONEST: [usize; 5] = [2, 3, 4, 5, 6];
const WAL_RECORD: usize = 96;
const WAL_MAGIC: [u8; 8] = *b"CLB81WAL";

const OP_PING: u8 = 0;
const OP_SIGN: u8 = 1;
const OP_SHUTDOWN: u8 = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Debug)]
struct SpendTx {
    input: InputRef,
    tx_id: u64,
    recipient: [u8; 32],
    value: u64,
}

#[derive(Clone, Copy)]
struct UserAuth {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct Share {
    index: usize,
    digest: [u8; 32],
    signature: [u8; 64],
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn user_key(label: u64) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC0081_USER_KEY_V1", label)
}

fn certifier_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC0081_CERTIFIER_KEY_V1", 100 + index as u64)
}

fn user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC0081_USER_SPEND_V1");
    out.extend_from_slice(&NETWORK_ID.to_le_bytes());
    out.extend_from_slice(&tx.input.id.to_le_bytes());
    out.extend_from_slice(&tx.input.generation.to_le_bytes());
    out.extend_from_slice(&tx.tx_id.to_le_bytes());
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&tx.value.to_le_bytes());
    out
}

fn digest_for(tx: &SpendTx, signer: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC0081_AUTHORIZED_TX_V1");
    h.update(&user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn share_message(input: InputRef, digest: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC0081_CERTIFIER_SHARE_V1");
    out.extend_from_slice(&EPOCH.to_le_bytes());
    out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes());
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(digest);
    out
}

fn sign_user(tx: &SpendTx, sk: &SigningKey) -> UserAuth {
    UserAuth {
        signer: sk.verifying_key().to_bytes(),
        signature: sk.sign(&user_message(tx)).to_bytes(),
    }
}

fn verify_user(tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<(), String> {
    let alice = user_key(1).verifying_key().to_bytes();
    if auth.signer != alice {
        return Err("owner mismatch".into());
    }
    if tx.value != 800 {
        return Err("value mismatch".into());
    }
    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "bad user key")?;
    let sig = Signature::from_bytes(&auth.signature);
    vk.verify_strict(&user_message(tx), &sig)
        .map_err(|_| "bad user signature")?;
    if &digest_for(tx, &auth.signer) != digest {
        return Err("digest mismatch".into());
    }
    Ok(())
}

fn record_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC0081_WAL_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_record(input: InputRef, digest: [u8; 32]) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&WAL_MAGIC);
    out[8..16].copy_from_slice(&EPOCH.to_le_bytes());
    out[16..24].copy_from_slice(&input.id.to_le_bytes());
    out[24..32].copy_from_slice(&input.generation.to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    let checksum = record_checksum(&out[..64]);
    out[64..96].copy_from_slice(&checksum);
    out
}

fn decode_record(buf: &[u8]) -> Result<(InputRef, [u8; 32]), String> {
    if buf.len() != WAL_RECORD {
        return Err("WAL record wrong size".into());
    }
    if buf[0..8] != WAL_MAGIC {
        return Err("WAL magic mismatch".into());
    }
    let epoch = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    if epoch != EPOCH {
        return Err(format!("WAL epoch mismatch: {epoch}"));
    }
    let expected = record_checksum(&buf[..64]);
    if buf[64..96] != expected {
        return Err("WAL checksum mismatch".into());
    }
    let input = InputRef {
        id: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        generation: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[32..64]);
    Ok((input, digest))
}

struct LockStore {
    file: File,
    locks: HashMap<InputRef, [u8; 32]>,
}

impl LockStore {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create WAL dir: {e}"))?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("open WAL: {e}"))?;

        file.seek(SeekFrom::Start(0)).map_err(|e| format!("seek WAL start: {e}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| format!("read WAL: {e}"))?;

        let full_records = bytes.len() / WAL_RECORD;
        let valid_len = full_records * WAL_RECORD;
        let mut locks = HashMap::new();
        for rec in bytes[..valid_len].chunks_exact(WAL_RECORD) {
            let (input, digest) = decode_record(rec)?;
            if let Some(old) = locks.insert(input, digest) {
                if old != digest {
                    return Err(format!("conflicting WAL records for input {} generation {}", input.id, input.generation));
                }
            }
        }

        if valid_len != bytes.len() {
            file.set_len(valid_len as u64).map_err(|e| format!("truncate incomplete WAL tail: {e}"))?;
            file.sync_all().map_err(|e| format!("sync truncated WAL: {e}"))?;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| format!("seek WAL end: {e}"))?;
        Ok(Self { file, locks })
    }

    fn lock(&mut self, input: InputRef, digest: [u8; 32]) -> Result<bool, String> {
        if let Some(existing) = self.locks.get(&input) {
            return Ok(existing == &digest);
        }
        let rec = encode_record(input, digest);
        self.file.seek(SeekFrom::End(0)).map_err(|e| format!("seek WAL append: {e}"))?;
        self.file.write_all(&rec).map_err(|e| format!("append WAL: {e}"))?;
        self.file.sync_all().map_err(|e| format!("sync WAL before share: {e}"))?;
        self.locks.insert(input, digest);
        Ok(true)
    }
}

fn inspect_wal(path: &Path, wanted: InputRef) -> Result<Option<[u8; 32]>, String> {
    let mut file = File::open(path).map_err(|e| format!("inspect open WAL: {e}"))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| format!("inspect read WAL: {e}"))?;
    if bytes.len() % WAL_RECORD != 0 {
        return Err(format!("inspect found incomplete WAL length {}", bytes.len()));
    }
    let mut found = None;
    for rec in bytes.chunks_exact(WAL_RECORD) {
        let (input, digest) = decode_record(rec)?;
        if input == wanted {
            if let Some(old) = found {
                if old != digest {
                    return Err("inspect found conflicting duplicate WAL records".into());
                }
            }
            found = Some(digest);
        }
    }
    Ok(found)
}

fn write_sign_request(stream: &mut TcpStream, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<(), String> {
    stream.write_all(&[OP_SIGN]).map_err(|e| e.to_string())?;
    stream.write_all(&tx.input.id.to_le_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&tx.input.generation.to_le_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&tx.tx_id.to_le_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&tx.recipient).map_err(|e| e.to_string())?;
    stream.write_all(&tx.value.to_le_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&auth.signer).map_err(|e| e.to_string())?;
    stream.write_all(&auth.signature).map_err(|e| e.to_string())?;
    stream.write_all(digest).map_err(|e| e.to_string())?;
    Ok(())
}

fn read_u64(stream: &mut TcpStream) -> Result<u64, String> {
    let mut b = [0u8; 8];
    stream.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn run_node(index: usize, port: u16, wal: PathBuf) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind node {index}: {e}"))?;
    let mut store = LockStore::open(&wal)?;
    let sk = certifier_key(index);

    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut op = [0u8; 1];
        if stream.read_exact(&mut op).is_err() {
            continue;
        }
        match op[0] {
            OP_PING => {
                let _ = stream.write_all(&[0xAA]);
            }
            OP_SHUTDOWN => {
                let _ = stream.write_all(&[0x55]);
                break;
            }
            OP_SIGN => {
                let input = InputRef {
                    id: read_u64(&mut stream)?,
                    generation: read_u64(&mut stream)?,
                };
                let tx_id = read_u64(&mut stream)?;
                let mut recipient = [0u8; 32];
                stream.read_exact(&mut recipient).map_err(|e| e.to_string())?;
                let value = read_u64(&mut stream)?;
                let mut signer = [0u8; 32];
                stream.read_exact(&mut signer).map_err(|e| e.to_string())?;
                let mut user_sig = [0u8; 64];
                stream.read_exact(&mut user_sig).map_err(|e| e.to_string())?;
                let mut digest = [0u8; 32];
                stream.read_exact(&mut digest).map_err(|e| e.to_string())?;

                let tx = SpendTx { input, tx_id, recipient, value };
                let auth = UserAuth { signer, signature: user_sig };
                if verify_user(&tx, &auth, &digest).is_err() {
                    let _ = stream.write_all(&[0]);
                    continue;
                }
                if !store.lock(input, digest)? {
                    let _ = stream.write_all(&[0]);
                    continue;
                }

                let signature = sk.sign(&share_message(input, &digest, index)).to_bytes();
                stream.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                stream.write_all(&digest).map_err(|e| e.to_string())?;
                stream.write_all(&signature).map_err(|e| e.to_string())?;
            }
            _ => {
                let _ = stream.write_all(&[0]);
            }
        }
    }
    Ok(())
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

struct NodeProc {
    index: usize,
    port: u16,
    wal: PathBuf,
    child: Child,
}

impl NodeProc {
    fn spawn(exe: &Path, index: usize, port: u16, wal: PathBuf) -> Result<Self, String> {
        let child = Command::new(exe)
            .arg("--node")
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn node {index}: {e}"))?;
        let mut node = Self { index, port, wal, child };
        node.wait_ready()?;
        Ok(node)
    }

    fn wait_ready(&mut self) -> Result<(), String> {
        for _ in 0..400 {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
                let _ = s.write_all(&[OP_PING]);
                let mut b = [0u8; 1];
                if s.read_exact(&mut b).is_ok() && b[0] == 0xAA {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        Err(format!("node {} not ready", self.index))
    }

    fn crash_restart(&mut self, exe: &Path) -> Result<(), String> {
        self.child.kill().map_err(|e| format!("kill node {}: {e}", self.index))?;
        self.child.wait().map_err(|e| format!("wait killed node {}: {e}", self.index))?;
        self.port = free_port()?;
        self.child = Command::new(exe)
            .arg("--node")
            .arg(self.index.to_string())
            .arg(self.port.to_string())
            .arg(&self.wal)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("restart node {}: {e}", self.index))?;
        self.wait_ready()
    }

    fn stop(&mut self) {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
            let _ = s.write_all(&[OP_SHUTDOWN]);
        }
        if self.child.wait().is_err() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn request_share(port: u16, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<Option<Share>, String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e| e.to_string())?;
    write_sign_request(&mut stream, tx, auth, digest)?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).map_err(|e| format!("read response status: {e}"))?;
    if status[0] == 0 {
        return Ok(None);
    }
    let mut idx = [0u8; 1];
    stream.read_exact(&mut idx).map_err(|e| e.to_string())?;
    let mut got_digest = [0u8; 32];
    stream.read_exact(&mut got_digest).map_err(|e| e.to_string())?;
    let mut sig = [0u8; 64];
    stream.read_exact(&mut sig).map_err(|e| e.to_string())?;
    Ok(Some(Share { index: idx[0] as usize, digest: got_digest, signature: sig }))
}

fn verify_share(share: &Share, input: InputRef, expected_digest: &[u8; 32], expected_index: usize) -> bool {
    if share.index != expected_index || &share.digest != expected_digest {
        return false;
    }
    let vk = certifier_key(share.index).verifying_key();
    let sig = Signature::from_bytes(&share.signature);
    vk.verify_strict(&share_message(input, expected_digest, share.index), &sig).is_ok()
}

fn expect_share(port: u16, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32], index: usize) -> Result<(), String> {
    match request_share(port, tx, auth, digest)? {
        Some(share) if verify_share(&share, tx.input, digest, index) => Ok(()),
        Some(_) => Err(format!("node {index} returned invalid share")),
        None => Err(format!("node {index} unexpectedly rejected its selected digest")),
    }
}

fn expect_reject(port: u16, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32], index: usize) -> Result<(), String> {
    match request_share(port, tx, auth, digest)? {
        None => Ok(()),
        Some(_) => Err(format!("node {index} accepted conflicting digest")),
    }
}

fn make_pair(trial: u64) -> (SpendTx, UserAuth, [u8; 32], SpendTx, UserAuth, [u8; 32]) {
    let alice = user_key(1);
    let bob = user_key(2).verifying_key().to_bytes();
    let mallory = user_key(3).verifying_key().to_bytes();
    let input = InputRef { id: 5_000_000 + trial, generation: EPOCH };
    let a = SpendTx { input, tx_id: 20_000_000 + trial * 2, recipient: bob, value: 800 };
    let b = SpendTx { input, tx_id: 20_000_001 + trial * 2, recipient: mallory, value: 800 };
    let aa = sign_user(&a, &alice);
    let ba = sign_user(&b, &alice);
    let ad = digest_for(&a, &aa.signer);
    let bd = digest_for(&b, &ba.signer);
    (a, aa, ad, b, ba, bd)
}

fn require_wal_digest(path: &Path, input: InputRef, expected: &[u8; 32], stage: &str, index: usize, trial: usize) -> Result<(), String> {
    match inspect_wal(path, input)? {
        Some(got) if &got == expected => Ok(()),
        Some(_) => Err(format!("{stage}: WAL digest mismatch at trial {trial} node {index}")),
        None => Err(format!("{stage}: WAL record missing at trial {trial} node {index}")),
    }
}

fn controller() -> Result<(), String> {
    let trials: usize = env::var("CALIBRE_SEC0081_TRIALS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2500);
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec0081-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    println!("CALIBRE SECURITY SEC-008.1 v0.8.1");
    println!("HARDENED DURABLE CONFLICT-LOCK WAL / PROCESS RESTART FORENSICS");
    println!("Purpose: isolate the SEC-008 local abort at trial 1000 node 4");
    println!("Scope: five separate honest certifier OS processes over real 127.0.0.1 TCP");
    println!("WAL: 96-byte magic+epoch+input+digest+BLAKE3-checksum records; explicit seek-end + sync_all before share");
    println!("Trials={trials}; scheduled crash/restart every 50 trials; trial 1000 explicitly targets node 4");
    println!();

    let mut nodes = Vec::new();
    for &index in &HONEST {
        let port = free_port()?;
        let wal = root.join(format!("node-{index}.wal"));
        nodes.push(NodeProc::spawn(&exe, index, port, wal)?);
    }

    let mut wal_checks = 0usize;
    let mut crash_restarts = 0usize;
    let mut restart_passes = 0usize;

    for t in 0..trials {
        let pos = if t == 1000 { 2 } else { t % HONEST.len() };
        let index = nodes[pos].index;
        let port = nodes[pos].port;
        let wal = nodes[pos].wal.clone();
        let (a, aa, ad, b, ba, bd) = make_pair(100_000 + t as u64);

        expect_share(port, &a, &aa, &ad, index)?;
        expect_reject(port, &b, &ba, &bd, index)?;
        require_wal_digest(&wal, a.input, &ad, "before restart", index, t)?;
        wal_checks += 1;

        if t % 50 == 0 {
            nodes[pos].crash_restart(&exe)?;
            crash_restarts += 1;
            let restarted_port = nodes[pos].port;
            require_wal_digest(&wal, a.input, &ad, "after restart", index, t)?;
            expect_share(restarted_port, &a, &aa, &ad, index)?;
            expect_reject(restarted_port, &b, &ba, &bd, index)?;
            restart_passes += 1;
            if t == 1000 {
                println!("EXPLICIT TRIAL-1000 / NODE-4 REPRODUCTION CHECK: DURABLE A LOCK PRESENT AFTER RESTART; B REJECTED -> PASS");
            }
        }

        if (t + 1) % 500 == 0 {
            println!("PROGRESS: {} / {} trials complete", t + 1, trials);
        }
    }

    for node in &mut nodes {
        node.stop();
    }
    let _ = fs::remove_dir_all(&root);

    if wal_checks != trials {
        return Err(format!("WAL inspection coverage mismatch: {wal_checks}/{trials}"));
    }
    if restart_passes != crash_restarts {
        return Err(format!("restart durability mismatch: {restart_passes}/{crash_restarts}"));
    }

    println!();
    println!("=== SEC-008.1 SUMMARY ===");
    println!("UNIQUE DURABLE LOCK TRIALS: {trials}");
    println!("CONTROLLER-SIDE CHECKSUMMED WAL VERIFICATIONS BEFORE RESTART: {wal_checks}/{trials}");
    println!("PROCESS CRASH/RESTARTS: {crash_restarts}");
    println!("RESTARTS PRESERVING SAME-DIGEST ACCEPTANCE + CONFLICT REJECTION: {restart_passes}/{crash_restarts}");
    println!("TRIAL-1000 NODE-4 CHECKPOINT: PASS");
    println!();
    println!("=== SEC-008.1 DECISION ===");
    println!("HARDENED CHECKSUMMED WAL SYNC-BEFORE-SHARE: PASS IN TESTED PROCESS-RESTART CAMPAIGN");
    println!("DURABLE LOCK REPLAY AFTER PROCESS KILL/RESTART: PASS");
    println!("EARLIER SEC-008 TRIAL-1000 ABORT REPRODUCED WITH HARDENED WAL: NO");
    println!("POWER-LOSS / DISK-CONTROLLER DURABILITY: NOT PROVEN");
    println!("STORAGE SNAPSHOT ROLLBACK RESISTANCE: NOT PROVEN");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--node") {
        if args.len() != 5 {
            Err("node usage: --node <index> <port> <wal>".into())
        } else {
            let index = args[2].parse::<usize>().map_err(|e| e.to_string());
            let port = args[3].parse::<u16>().map_err(|e| e.to_string());
            match (index, port) {
                (Ok(index), Ok(port)) => run_node(index, port, PathBuf::from(&args[4])),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
    } else {
        controller()
    };

    if let Err(e) = result {
        eprintln!("SEC-008.1 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_record_round_trip_and_checksum() {
        let input = InputRef { id: 77, generation: EPOCH };
        let digest = [9u8; 32];
        let rec = encode_record(input, digest);
        let (got_input, got_digest) = decode_record(&rec).unwrap();
        assert_eq!(got_input, input);
        assert_eq!(got_digest, digest);
    }

    #[test]
    fn wal_checksum_detects_mutation() {
        let input = InputRef { id: 88, generation: EPOCH };
        let mut rec = encode_record(input, [3u8; 32]);
        rec[40] ^= 0x80;
        assert!(decode_record(&rec).is_err());
    }

    #[test]
    fn conflicting_transactions_have_distinct_digests() {
        let (a, aa, ad, b, ba, bd) = make_pair(42);
        assert_eq!(a.input, b.input);
        assert_eq!(aa.signer, ba.signer);
        assert_ne!(ad, bd);
        assert!(verify_user(&a, &aa, &ad).is_ok());
        assert!(verify_user(&b, &ba, &bd).is_ok());
    }

    #[test]
    fn lock_store_reopen_preserves_conflict_choice() {
        let root = env::temp_dir().join(format!("calibre-sec0081-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("lock.wal");
        let input = InputRef { id: 999, generation: EPOCH };
        let a = [1u8; 32];
        let b = [2u8; 32];
        {
            let mut store = LockStore::open(&path).unwrap();
            assert!(store.lock(input, a).unwrap());
            assert!(!store.lock(input, b).unwrap());
        }
        {
            let mut reopened = LockStore::open(&path).unwrap();
            assert!(reopened.lock(input, a).unwrap());
            assert!(!reopened.lock(input, b).unwrap());
        }
        let _ = fs::remove_dir_all(&root);
    }
}
