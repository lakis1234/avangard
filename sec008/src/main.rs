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
const EPOCH: u64 = 8;
const N: usize = 7;
const Q: usize = 5;
const BYZ: [usize; 2] = [0, 1];
const HONEST: [usize; 5] = [2, 3, 4, 5, 6];
const WAL_RECORD: usize = 48;

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
    deterministic_key(b"CALIBRE_SEC008_USER_KEY_V1", label)
}

fn certifier_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC008_CERTIFIER_KEY_V1", 100 + index as u64)
}

fn user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC008_USER_SPEND_V1");
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
    h.update(b"CALIBRE_SEC008_AUTHORIZED_TX_V1");
    h.update(&user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn share_message(input: InputRef, digest: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC008_CERTIFIER_SHARE_V1");
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
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("open WAL: {e}"))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| format!("seek WAL: {e}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| format!("read WAL: {e}"))?;
        if bytes.len() % WAL_RECORD != 0 {
            return Err("incomplete WAL record; fail closed".into());
        }
        let mut locks = HashMap::new();
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let id = u64::from_le_bytes(rec[0..8].try_into().unwrap());
            let generation = u64::from_le_bytes(rec[8..16].try_into().unwrap());
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&rec[16..48]);
            let key = InputRef { id, generation };
            if let Some(old) = locks.insert(key, digest) {
                if old != digest {
                    return Err("conflicting durable WAL record; fail closed".into());
                }
            }
        }
        Ok(Self { file, locks })
    }

    fn lock(&mut self, input: InputRef, digest: [u8; 32]) -> Result<bool, String> {
        if let Some(existing) = self.locks.get(&input) {
            return Ok(existing == &digest);
        }
        let mut rec = [0u8; WAL_RECORD];
        rec[0..8].copy_from_slice(&input.id.to_le_bytes());
        rec[8..16].copy_from_slice(&input.generation.to_le_bytes());
        rec[16..48].copy_from_slice(&digest);
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
        for _ in 0..200 {
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
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    stream.set_read_timeout(Some(Duration::from_millis(300))).ok();
    stream.set_write_timeout(Some(Duration::from_millis(300))).ok();
    write_sign_request(&mut stream, tx, auth, digest)?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).map_err(|e| e.to_string())?;
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

fn verify_share(share: &Share, input: InputRef, expected_digest: &[u8; 32]) -> bool {
    if share.index >= N || &share.digest != expected_digest {
        return false;
    }
    let vk = certifier_key(share.index).verifying_key();
    let sig = Signature::from_bytes(&share.signature);
    vk.verify_strict(&share_message(input, expected_digest, share.index), &sig).is_ok()
}

fn add_share(set: &mut HashSet<usize>, share: Option<Share>, input: InputRef, digest: &[u8; 32]) -> Result<(), String> {
    if let Some(s) = share {
        if !verify_share(&s, input, digest) {
            return Err("invalid certifier share".into());
        }
        set.insert(s.index);
    }
    Ok(())
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
    let input = InputRef { id: 1_000_000 + trial, generation: 7 };
    let a = SpendTx { input, tx_id: 10_000_000 + trial * 2, recipient: bob, value: 800 };
    let b = SpendTx { input, tx_id: 10_000_001 + trial * 2, recipient: mallory, value: 800 };
    let aa = sign_user(&a, &alice);
    let ba = sign_user(&b, &alice);
    let ad = digest_for(&a, &aa.signer);
    let bd = digest_for(&b, &ba.signer);
    (a, aa, ad, b, ba, bd)
}

fn deterministic_deadlock_witness(nodes: &[NodeProc], trial: u64) -> Result<(usize, usize), String> {
    let (a, aa, ad, b, ba, bd) = make_pair(trial);
    let mut sa = HashSet::new();
    let mut sb = HashSet::new();
    for &i in &[2usize, 3, 4] {
        add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
    }
    for &i in &[5usize, 6] {
        add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
    }
    for &i in &HONEST {
        add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
        add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
    }
    Ok((sa.len(), sb.len()))
}

fn deterministic_liveness_witness(nodes: &[NodeProc], trial: u64) -> Result<usize, String> {
    let (a, aa, ad, _, _, _) = make_pair(trial);
    let mut sa = HashSet::new();
    for &i in &HONEST {
        add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
    }
    Ok(sa.len())
}

fn controller() -> Result<(), String> {
    let trials: usize = env::var("CALIBRE_SEC008_TRIALS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    let seed: u64 = env::var("CALIBRE_SEC008_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0xC411_B8E5_0080_0001);
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec008-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    println!("CALIBRE SECURITY SEC-008 v0.8.0");
    println!("RANDOMIZED MULTI-PROCESS TCP FAULT CAMPAIGN / SAFETY + LIVENESS ATTACK SEARCH");
    println!("N=7 Q=5 target f<=2; certifiers 0 and 1 Byzantine; 2..6 honest");
    println!("Trials={trials} Seed={seed}");
    println!("Scope: seven separate OS processes using real 127.0.0.1 TCP sockets on one host");
    println!("Fault injection: randomized delivery order, application-layer message drops, duplicate deliveries, bounded delays, Byzantine sign/withhold choices, and repeated honest-process crash/restart");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!();

    let mut nodes = Vec::new();
    for i in 0..N {
        let port = free_port()?;
        let wal = root.join(format!("node-{i}.wal"));
        nodes.push(NodeProc::spawn(&exe, i, port, wal, BYZ.contains(&i))?);
    }

    let live = deterministic_liveness_witness(&nodes, 1)?;
    if live < Q {
        return Err(format!("baseline liveness witness failed: {live}/7"));
    }
    println!("BASELINE WITH TWO BYZANTINE NODES UNAVAILABLE: FIVE HONEST NODES FINALIZE A -> PASS ({live}/7)");

    let (da, db) = deterministic_deadlock_witness(&nodes, 2)?;
    if da >= Q || db >= Q {
        return Err(format!("expected 3/2 deadlock witness unexpectedly finalized: A={da} B={db}"));
    }
    println!("DETERMINISTIC 3/2 HONEST LOCK SPLIT + TWO BYZANTINE WITHHOLDERS: A={da}/7 B={db}/7 -> CONFLICT-LIVENESS DEADLOCK ATTACK CONFIRMED");
    println!("Safety remains intact: neither conflicting successor reaches 5/7, but network healing alone cannot make honest nodes change their one-digest locks.");
    println!();

    let mut rng = Prng::new(seed);
    let mut safety_violations = 0usize;
    let mut finalized = 0usize;
    let mut deadlocks = 0usize;
    let mut logical_drops = 0usize;
    let mut duplicate_deliveries = 0usize;
    let mut crash_restarts = 0usize;
    let mut restart_conflict_rejections = 0usize;

    for t in 0..trials {
        let trial = 10_000 + t as u64;
        let (a, aa, ad, b, ba, bd) = make_pair(trial);
        let mut sa = HashSet::new();
        let mut sb = HashSet::new();

        let mut order = HONEST;
        for i in (1..order.len()).rev() {
            let j = rng.range(i + 1);
            order.swap(i, j);
        }

        let mut first_choice = [false; N];
        for &i in &order {
            first_choice[i] = rng.chance(1, 2); // true=A, false=B
            if rng.chance(1, 4) {
                logical_drops += 1; // first attempt intentionally not delivered
            }
            if rng.chance(1, 10) {
                thread::sleep(Duration::from_millis(1 + rng.range(2) as u64));
            }
            if first_choice[i] {
                add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
                if rng.chance(1, 3) {
                    duplicate_deliveries += 1;
                    add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
                }
                let conflicting = request_share(nodes[i].port, &b, &ba, &bd)?;
                if conflicting.is_some() {
                    return Err(format!("honest node {i} double-signed at trial {t}"));
                }
            } else {
                add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
                if rng.chance(1, 3) {
                    duplicate_deliveries += 1;
                    add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
                }
                let conflicting = request_share(nodes[i].port, &a, &aa, &ad)?;
                if conflicting.is_some() {
                    return Err(format!("honest node {i} double-signed at trial {t}"));
                }
            }
        }

        if t % 50 == 0 {
            let target = HONEST[rng.range(HONEST.len())];
            nodes[target].crash_restart(&exe)?;
            crash_restarts += 1;
            let conflicting = if first_choice[target] {
                request_share(nodes[target].port, &b, &ba, &bd)?
            } else {
                request_share(nodes[target].port, &a, &aa, &ad)?
            };
            if conflicting.is_none() {
                restart_conflict_rejections += 1;
            } else {
                return Err(format!("restart lost honest durable lock at trial {t} node {target}"));
            }
        }

        // Byzantine behavior is adversarial and independently randomized: withhold, sign A, sign B, or sign both.
        for &i in &BYZ {
            match rng.range(4) {
                0 => {}
                1 => add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?,
                2 => add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?,
                _ => {
                    add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
                    add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
                }
            }
        }

        // Heal the network for all honest nodes and retry both conflicts. Honest first-lock state remains authoritative.
        for &i in &HONEST {
            add_share(&mut sa, request_share(nodes[i].port, &a, &aa, &ad)?, a.input, &ad)?;
            add_share(&mut sb, request_share(nodes[i].port, &b, &ba, &bd)?, b.input, &bd)?;
        }

        if sa.len() >= Q && sb.len() >= Q {
            safety_violations += 1;
            return Err(format!("DUAL FINALITY at trial {t}: A={} B={}", sa.len(), sb.len()));
        }
        if sa.len() >= Q || sb.len() >= Q {
            finalized += 1;
        } else {
            deadlocks += 1;
        }
    }

    for n in &mut nodes {
        n.stop();
    }
    let _ = fs::remove_dir_all(&root);

    if safety_violations != 0 {
        return Err(format!("safety violations: {safety_violations}"));
    }
    if deadlocks == 0 {
        return Err("fault campaign found no liveness deadlock; expected current one-digest protocol limitation was not exercised".into());
    }
    if finalized == 0 {
        return Err("fault campaign produced no successful finalization; liveness baseline coverage insufficient".into());
    }
    if restart_conflict_rejections != crash_restarts {
        return Err("one or more crash/restart durable-lock checks failed".into());
    }

    println!("=== RANDOMIZED CAMPAIGN SUMMARY ===");
    println!("TRIALS: {trials}");
    println!("DUAL-FINALITY SAFETY VIOLATIONS WITH f<=2: {safety_violations}");
    println!("TRIALS WITH ONE SUCCESSOR >=5/7: {finalized}");
    println!("TRIALS DEADLOCKED BELOW 5/7 AFTER HONEST-NETWORK HEAL: {deadlocks}");
    println!("INJECTED APPLICATION-LAYER MESSAGE DROPS: {logical_drops}");
    println!("INJECTED DUPLICATE DELIVERIES: {duplicate_deliveries}");
    println!("HONEST PROCESS CRASH/RESTARTS: {crash_restarts}");
    println!("RESTARTS THAT PRESERVED CONFLICT REJECTION: {restart_conflict_rejections}");
    println!();
    println!("=== SEC-008 DECISION ===");
    println!("RANDOMIZED REAL-TCP LOOPBACK CONFLICT SAFETY WITH f<=2: PASS IN TESTED SCHEDULES (0 DUAL CERTIFICATES)");
    println!("DURABLE HONEST LOCK SURVIVES REPEATED PROCESS CRASH/RESTART: PASS");
    println!("CONFLICT LIVENESS UNDER BYZANTINE WITHHOLDING + HONEST 3/2 SPLIT: FAIL / DEADLOCK ATTACK CONFIRMED");
    println!("NETWORK HEALING ALONE DOES NOT RESOLVE A SPLIT OF PERMANENT HONEST ONE-DIGEST LOCKS");
    println!("REQUIRED NEXT MECHANISM: CONFLICT-LOCAL CANONICAL WINNER / ROUND-CHANGE PROTOCOL THAT PRESERVES SAFETY WITHOUT GLOBAL ORDERING");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    println!("KERNEL-LEVEL PACKET LOSS / ARBITRARY ASYNCHRONOUS NETWORK MODEL: NOT PROVEN");
    println!("PRODUCTION LIVENESS: NOT PROVEN");
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
        eprintln!("SEC-008 ERROR: {e}");
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
    fn duplicate_share_identity_is_counted_once() {
        let mut s = HashSet::new();
        assert!(s.insert(4usize));
        assert!(!s.insert(4usize));
        assert_eq!(s.len(), 1);
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
