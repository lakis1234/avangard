use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const NETWORK_ID: u32 = 1;
const EPOCH: u64 = 82;
const N: usize = 7;
const Q: usize = 5;
const BYZ: [usize; 2] = [0, 1];
const HONEST: [usize; 5] = [2, 3, 4, 5, 6];
const WAL_MAGIC: [u8; 8] = *b"CAL82WAL";
const WAL_RECORD: usize = 96;

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
    deterministic_key(b"CALIBRE_SEC0082_USER_KEY_V1", label)
}

fn certifier_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC0082_CERTIFIER_KEY_V1", 100 + index as u64)
}

fn user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC0082_USER_SPEND_V1");
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
    h.update(b"CALIBRE_SEC0082_AUTHORIZED_TX_V1");
    h.update(&user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn share_message(input: InputRef, digest: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC0082_CERTIFIER_SHARE_V1");
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

fn wal_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC0082_WAL_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_wal(input: InputRef, digest: [u8; 32]) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&WAL_MAGIC);
    out[8..16].copy_from_slice(&EPOCH.to_le_bytes());
    out[16..24].copy_from_slice(&input.id.to_le_bytes());
    out[24..32].copy_from_slice(&input.generation.to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    let checksum = wal_checksum(&out[..64]);
    out[64..96].copy_from_slice(&checksum);
    out
}

fn decode_wal(rec: &[u8]) -> Result<(InputRef, [u8; 32]), String> {
    if rec.len() != WAL_RECORD {
        return Err("wrong WAL record length".into());
    }
    if rec[0..8] != WAL_MAGIC {
        return Err("WAL magic mismatch".into());
    }
    let epoch = u64::from_le_bytes(rec[8..16].try_into().unwrap());
    if epoch != EPOCH {
        return Err("WAL epoch mismatch".into());
    }
    let expected = wal_checksum(&rec[..64]);
    if rec[64..96] != expected {
        return Err("WAL checksum mismatch".into());
    }
    let id = u64::from_le_bytes(rec[16..24].try_into().unwrap());
    let generation = u64::from_le_bytes(rec[24..32].try_into().unwrap());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&rec[32..64]);
    Ok((InputRef { id, generation }, digest))
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
        file.seek(SeekFrom::Start(0)).map_err(|e| format!("seek WAL: {e}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| format!("read WAL: {e}"))?;

        let full = bytes.len() / WAL_RECORD;
        let valid_len = full * WAL_RECORD;
        let mut locks = HashMap::new();
        for rec in bytes[..valid_len].chunks_exact(WAL_RECORD) {
            let (input, digest) = decode_wal(rec)?;
            if let Some(old) = locks.insert(input, digest) {
                if old != digest {
                    return Err("conflicting durable WAL records".into());
                }
            }
        }

        if bytes.len() != valid_len {
            file.set_len(valid_len as u64)
                .map_err(|e| format!("truncate torn WAL tail: {e}"))?;
            file.sync_all().map_err(|e| format!("sync truncated WAL: {e}"))?;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| format!("seek WAL end: {e}"))?;
        Ok(Self { file, locks })
    }

    fn lock(&mut self, input: InputRef, digest: [u8; 32]) -> Result<bool, String> {
        if let Some(existing) = self.locks.get(&input) {
            return Ok(existing == &digest);
        }
        let rec = encode_wal(input, digest);
        self.file.seek(SeekFrom::End(0)).map_err(|e| format!("seek WAL append: {e}"))?;
        self.file.write_all(&rec).map_err(|e| format!("WAL write: {e}"))?;
        self.file.sync_all().map_err(|e| format!("WAL sync: {e}"))?;
        self.locks.insert(input, digest);
        Ok(true)
    }
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

fn run_node(index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<(), String> {
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
                if !byzantine && !store.lock(input, digest)? {
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
    byzantine: bool,
    child: Child,
}

impl NodeProc {
    fn spawn(exe: &Path, index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<Self, String> {
        let child = Command::new(exe)
            .arg("--node")
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal)
            .arg(if byzantine { "1" } else { "0" })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn node {index}: {e}"))?;
        let mut node = Self { index, port, wal, byzantine, child };
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
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.port = free_port()?;
        self.child = Command::new(exe)
            .arg("--node")
            .arg(self.index.to_string())
            .arg(self.port.to_string())
            .arg(&self.wal)
            .arg(if self.byzantine { "1" } else { "0" })
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
        let _ = self.child.wait();
    }
}

fn request_share(port: u16, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<Option<Share>, String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(750)) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    stream.set_read_timeout(Some(Duration::from_millis(750))).ok();
    stream.set_write_timeout(Some(Duration::from_millis(750))).ok();
    if write_sign_request(&mut stream, tx, auth, digest).is_err() {
        return Ok(None);
    }
    let mut status = [0u8; 1];
    if stream.read_exact(&mut status).is_err() {
        return Ok(None);
    }
    if status[0] == 0 {
        return Ok(None);
    }
    let mut idx = [0u8; 1];
    if stream.read_exact(&mut idx).is_err() {
        return Ok(None);
    }
    let mut got_digest = [0u8; 32];
    if stream.read_exact(&mut got_digest).is_err() {
        return Ok(None);
    }
    let mut sig = [0u8; 64];
    if stream.read_exact(&mut sig).is_err() {
        return Ok(None);
    }
    Ok(Some(Share { index: idx[0] as usize, digest: got_digest, signature: sig }))
}

fn request_share_retry(port: u16, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<Option<Share>, String> {
    for _ in 0..3 {
        if let Some(s) = request_share(port, tx, auth, digest)? {
            return Ok(Some(s));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(None)
}

fn verify_share(share: &Share, input: InputRef, expected_digest: &[u8; 32]) -> bool {
    if share.index >= N || &share.digest != expected_digest {
        return false;
    }
    let vk = certifier_key(share.index).verifying_key();
    let sig = Signature::from_bytes(&share.signature);
    vk.verify_strict(&share_message(input, expected_digest, share.index), &sig).is_ok()
}

fn add_share(set: &mut HashSet<usize>, share: Option<Share>, input: InputRef, digest: &[u8; 32]) -> Result<bool, String> {
    if let Some(s) = share {
        if !verify_share(&s, input, digest) {
            return Err("invalid certifier share".into());
        }
        let is_new = set.insert(s.index);
        return Ok(is_new);
    }
    Ok(false)
}

#[derive(Clone, Copy)]
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
    fn chance(&mut self, numerator: usize, denominator: usize) -> bool {
        self.range(denominator) < numerator
    }
}

fn make_pair(trial: u64) -> (SpendTx, UserAuth, [u8; 32], SpendTx, UserAuth, [u8; 32]) {
    let alice = user_key(1);
    let bob = user_key(2).verifying_key().to_bytes();
    let mallory = user_key(3).verifying_key().to_bytes();
    let input = InputRef { id: 2_000_000 + trial, generation: 7 };
    let a = SpendTx { input, tx_id: 20_000_000 + trial * 2, recipient: bob, value: 800 };
    let b = SpendTx { input, tx_id: 20_000_001 + trial * 2, recipient: mallory, value: 800 };
    let aa = sign_user(&a, &alice);
    let ba = sign_user(&b, &alice);
    let ad = digest_for(&a, &aa.signer);
    let bd = digest_for(&b, &ba.signer);
    (a, aa, ad, b, ba, bd)
}

fn baseline(nodes: &[NodeProc], trial: u64) -> Result<usize, String> {
    let (a, aa, ad, _, _, _) = make_pair(trial);
    let mut sa = HashSet::new();
    for &i in &HONEST {
        add_share(&mut sa, request_share_retry(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
    }
    Ok(sa.len())
}

fn deterministic_deadlock(nodes: &[NodeProc], trial: u64) -> Result<(usize, usize), String> {
    let (a, aa, ad, b, ba, bd) = make_pair(trial);
    let mut sa = HashSet::new();
    let mut sb = HashSet::new();
    for &i in &[2usize, 3, 4] {
        add_share(&mut sa, request_share_retry(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
    }
    for &i in &[5usize, 6] {
        add_share(&mut sb, request_share_retry(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
    }
    for &i in &HONEST {
        add_share(&mut sa, request_share_retry(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
        add_share(&mut sb, request_share_retry(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
    }
    Ok((sa.len(), sb.len()))
}

fn controller() -> Result<(), String> {
    let trials: usize = env::var("CALIBRE_SEC0082_TRIALS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    let seed: u64 = env::var("CALIBRE_SEC0082_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0xC411_B8E5_0082_0001);
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec0082-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    println!("CALIBRE SECURITY SEC-008.2 v0.8.2");
    println!("HARDENED RANDOMIZED MULTI-PROCESS TCP FAULT CAMPAIGN");
    println!("N=7 Q=5 target f<=2; certifiers 0 and 1 Byzantine; 2..6 honest");
    println!("Trials={trials} Seed={seed}");
    println!("Scope: seven separate OS processes using real 127.0.0.1 TCP sockets on one host");
    println!("WAL: 96-byte magic+epoch+input+digest+BLAKE3 checksum; sync_all before honest share");
    println!("Fault injection: ACTUAL application-scheduler message drops, duplicate deliveries, randomized delivery order, bounded delay, Byzantine sign/withhold, and honest crash/restart");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!();

    let mut nodes = Vec::new();
    for i in 0..N {
        let port = free_port()?;
        let wal = root.join(format!("node-{i}.wal"));
        nodes.push(NodeProc::spawn(&exe, i, port, wal, BYZ.contains(&i))?);
    }

    let live = baseline(&nodes, 1)?;
    if live < Q {
        return Err(format!("baseline liveness failed: {live}/7"));
    }
    println!("BASELINE: TWO BYZANTINE NODES UNAVAILABLE; FIVE HONEST NODES FINALIZE A -> PASS ({live}/7)");

    let (da, db) = deterministic_deadlock(&nodes, 2)?;
    if da >= Q || db >= Q {
        return Err(format!("expected 3/2 deadlock unexpectedly finalized: A={da} B={db}"));
    }
    println!("DETERMINISTIC 3/2 HONEST LOCK SPLIT + TWO BYZANTINE WITHHOLDERS: A={da}/7 B={db}/7 -> LIVENESS DEADLOCK ATTACK CONFIRMED");
    println!();

    let mut rng = Prng::new(seed);
    let mut finalized = 0usize;
    let mut deadlocks = 0usize;
    let mut actual_drops = 0usize;
    let mut duplicate_attempts = 0usize;
    let mut crash_restarts = 0usize;
    let mut restart_checks_passed = 0usize;
    let mut initial_deliveries = 0usize;

    for t in 0..trials {
        let trial = 100_000 + t as u64;
        let (a, aa, ad, b, ba, bd) = make_pair(trial);
        let mut sa = HashSet::new();
        let mut sb = HashSet::new();
        let mut locked_choice: [Option<bool>; N] = [None; N]; // true=A, false=B

        let mut order = HONEST;
        for i in (1..order.len()).rev() {
            let j = rng.range(i + 1);
            order.swap(i, j);
        }

        for &i in &order {
            let choose_a = rng.chance(1, 2);
            if rng.chance(1, 4) {
                actual_drops += 1;
                continue; // real application-level drop: no TCP request is sent
            }

            initial_deliveries += 1;
            let share = if choose_a {
                request_share(nodes[i].port, &a, &aa, &ad)?
            } else {
                request_share(nodes[i].port, &b, &ba, &bd)?
            };
            if let Some(s) = share {
                if choose_a {
                    add_share(&mut sa, Some(s), a.input, &ad)?;
                } else {
                    add_share(&mut sb, Some(s), b.input, &bd)?;
                }
                locked_choice[i] = Some(choose_a);

                let conflicting = if choose_a {
                    request_share(nodes[i].port, &b, &ba, &bd)?
                } else {
                    request_share(nodes[i].port, &a, &aa, &ad)?
                };
                if conflicting.is_some() {
                    return Err(format!("honest node {i} double-signed at trial {t}"));
                }
            }

            if rng.chance(1, 3) {
                duplicate_attempts += 1;
                let dup = if choose_a {
                    request_share(nodes[i].port, &a, &aa, &ad)?
                } else {
                    request_share(nodes[i].port, &b, &ba, &bd)?
                };
                if choose_a {
                    add_share(&mut sa, dup, a.input, &ad)?;
                } else {
                    add_share(&mut sb, dup, b.input, &bd)?;
                }
            }

            if rng.chance(1, 8) {
                thread::sleep(Duration::from_millis(1 + rng.range(3) as u64));
            }
        }

        for &i in &BYZ {
            match rng.range(4) {
                0 => {} // withhold
                1 => {
                    add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
                }
                2 => {
                    add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
                }
                _ => {
                    add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
                    add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
                }
            }
        }

        if t % 50 == 0 {
            let mut candidates = Vec::new();
            for &i in &HONEST {
                if locked_choice[i].is_some() {
                    candidates.push(i);
                }
            }
            if candidates.is_empty() {
                let target = HONEST[rng.range(HONEST.len())];
                let s = request_share_retry(nodes[target].port, &a, &aa, &ad)?
                    .ok_or_else(|| format!("could not establish durable restart witness at trial {t}"))?;
                add_share(&mut sa, Some(s), a.input, &ad)?;
                locked_choice[target] = Some(true);
                candidates.push(target);
            }

            let target = candidates[rng.range(candidates.len())];
            let choice = locked_choice[target].unwrap();
            nodes[target].crash_restart(&exe)?;
            crash_restarts += 1;

            let same = if choice {
                request_share_retry(nodes[target].port, &a, &aa, &ad)?
            } else {
                request_share_retry(nodes[target].port, &b, &ba, &bd)?
            };
            if same.is_none() {
                return Err(format!("restart lost same-digest durable lock at trial {t} node {target}"));
            }
            let conflict = if choice {
                request_share_retry(nodes[target].port, &b, &ba, &bd)?
            } else {
                request_share_retry(nodes[target].port, &a, &aa, &ad)?
            };
            if conflict.is_some() {
                return Err(format!("restart lost conflict rejection at trial {t} node {target}"));
            }
            restart_checks_passed += 1;
        }

        // Network heal: all honest nodes become reachable and receive both conflicts.
        // Delivery order remains local/random, so permanent first-seen locks can still deadlock.
        for &i in &HONEST {
            if rng.chance(1, 2) {
                add_share(&mut sa, request_share_retry(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
                add_share(&mut sb, request_share_retry(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
            } else {
                add_share(&mut sb, request_share_retry(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
                add_share(&mut sa, request_share_retry(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
            }
        }

        if sa.len() >= Q && sb.len() >= Q {
            return Err(format!("DUAL FINALITY at trial {t}: A={} B={}", sa.len(), sb.len()));
        }
        if sa.len() >= Q || sb.len() >= Q {
            finalized += 1;
        } else {
            deadlocks += 1;
        }

        if (t + 1) % 500 == 0 {
            println!("PROGRESS: {} / {} trials", t + 1, trials);
        }
    }

    for n in &mut nodes {
        n.stop();
    }
    let _ = fs::remove_dir_all(&root);

    if finalized == 0 {
        return Err("no successful finalization observed".into());
    }
    if deadlocks == 0 {
        return Err("no liveness deadlock observed; expected current protocol limitation was not exercised".into());
    }
    if actual_drops == 0 {
        return Err("drop injector did not actually suppress any requests".into());
    }
    if restart_checks_passed != crash_restarts {
        return Err("not all crash/restart durability checks passed".into());
    }

    println!();
    println!("=== SEC-008.2 RANDOMIZED CAMPAIGN SUMMARY ===");
    println!("TRIALS: {trials}");
    println!("DUAL-FINALITY SAFETY VIOLATIONS WITH f<=2: 0");
    println!("TRIALS WITH ONE SUCCESSOR >=5/7 AFTER HEAL: {finalized}");
    println!("TRIALS DEADLOCKED BELOW 5/7 AFTER HEAL: {deadlocks}");
    println!("ACTUAL APPLICATION-SCHEDULER MESSAGE DROPS (NO TCP REQUEST SENT): {actual_drops}");
    println!("INITIAL DELIVERIES ACTUALLY SENT: {initial_deliveries}");
    println!("DUPLICATE DELIVERY ATTEMPTS: {duplicate_attempts}");
    println!("HONEST PROCESS CRASH/RESTARTS: {crash_restarts}");
    println!("RESTART DURABILITY CHECKS PASSED: {restart_checks_passed}/{crash_restarts}");
    println!();
    println!("=== SEC-008.2 DECISION ===");
    println!("HARDENED CHECKSUMMED WAL PROCESS-RESTART DURABILITY: PASS IN TESTED CAMPAIGN");
    println!("ACTUAL APPLICATION-LAYER DROP INJECTION: PASS / CONFIRMED");
    println!("RANDOMIZED REAL-TCP LOOPBACK CONFLICT SAFETY WITH f<=2: PASS IN TESTED SCHEDULES (0 DUAL CERTIFICATES)");
    println!("CONFLICT LIVENESS WITH PERMANENT FIRST-SEEN LOCKS: FAIL / DEADLOCKS CONFIRMED");
    println!("REQUIRED NEXT MECHANISM: CONFLICT-LOCAL ROUND CHANGE / CANONICAL WINNER WITHOUT UNIVERSAL TRANSACTION ORDER");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    println!("KERNEL-LEVEL PACKET LOSS / ARBITRARY ASYNCHRONOUS NETWORK: NOT PROVEN");
    println!("POWER-LOSS / DISK-CONTROLLER DURABILITY: NOT PROVEN");
    println!("STORAGE SNAPSHOT ROLLBACK RESISTANCE: NOT PROVEN");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--node") {
        if args.len() != 6 {
            Err("node usage: --node <index> <port> <wal> <byzantine 0|1>".into())
        } else {
            let index = args[2].parse::<usize>().map_err(|e| e.to_string());
            let port = args[3].parse::<u16>().map_err(|e| e.to_string());
            match (index, port) {
                (Ok(index), Ok(port)) => run_node(index, port, PathBuf::from(&args[4]), args[5] == "1"),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
    } else {
        controller()
    };

    if let Err(e) = result {
        eprintln!("SEC-008.2 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_intersection_matches_f2_boundary() {
        assert_eq!(Q + Q - N, 3);
        assert!(Q + Q - N > 2);
    }

    #[test]
    fn conflicting_transactions_have_distinct_commitments() {
        let (a, aa, ad, b, ba, bd) = make_pair(42);
        assert_eq!(a.input, b.input);
        assert_eq!(aa.signer, ba.signer);
        assert_ne!(ad, bd);
        assert!(verify_user(&a, &aa, &ad).is_ok());
        assert!(verify_user(&b, &ba, &bd).is_ok());
    }

    #[test]
    fn wal_record_round_trip_and_checksum() {
        let input = InputRef { id: 9, generation: 7 };
        let digest = [0xAB; 32];
        let rec = encode_wal(input, digest);
        let (decoded_input, decoded_digest) = decode_wal(&rec).unwrap();
        assert_eq!(decoded_input, input);
        assert_eq!(decoded_digest, digest);
    }

    #[test]
    fn wal_checksum_detects_mutation() {
        let input = InputRef { id: 10, generation: 7 };
        let digest = [0xCD; 32];
        let mut rec = encode_wal(input, digest);
        rec[40] ^= 1;
        assert!(decode_wal(&rec).is_err());
    }

    #[test]
    fn prng_is_reproducible() {
        let mut a = Prng::new(123);
        let mut b = Prng::new(123);
        for _ in 0..100 {
            assert_eq!(a.next(), b.next());
        }
    }
}
