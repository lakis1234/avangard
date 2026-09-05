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
const N: usize = 7;
const Q: usize = 5;
const PHASE_PREVOTE: u8 = 1;
const PHASE_PRECOMMIT: u8 = 2;
const OP_PING: u8 = 0;
const OP_VOTE: u8 = 1;
const OP_SHUTDOWN: u8 = 255;
const CRASH_NONE: u8 = 0;
const CRASH_BEFORE_PERSIST: u8 = 1;
const CRASH_AFTER_SYNC_BEFORE_REPLY: u8 = 2;
const EXIT_BEFORE_PERSIST: i32 = 71;
const EXIT_AFTER_SYNC: i32 = 72;
const WAL_MAGIC: [u8; 8] = *b"CAL011ST";
const WAL_RECORD: usize = 104;
const HONEST: [usize; 5] = [2, 3, 4, 5, 6];

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

#[derive(Clone, Copy, Debug)]
struct UserAuth {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct Vote {
    index: usize,
    phase: u8,
    round: u64,
    input: InputRef,
    digest: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct Qc {
    votes: Vec<Vote>,
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn user_key(label: u64) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC011_USER_KEY_V1", label)
}

fn certifier_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC011_CERTIFIER_KEY_V1", 100 + index as u64)
}

fn user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC011_USER_SPEND_V1");
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
    h.update(b"CALIBRE_SEC011_AUTHORIZED_TX_V1");
    h.update(&user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
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
    vk.verify_strict(&user_message(tx), &Signature::from_bytes(&auth.signature))
        .map_err(|_| "bad user signature")?;
    if &digest_for(tx, &auth.signer) != digest {
        return Err("digest mismatch".into());
    }
    Ok(())
}

fn vote_message(phase: u8, round: u64, input: InputRef, digest: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC011_VOTE_V1");
    out.push(phase);
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes());
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(digest);
    out
}

fn verify_vote(v: &Vote) -> bool {
    if v.index >= N || (v.phase != PHASE_PREVOTE && v.phase != PHASE_PRECOMMIT) {
        return false;
    }
    certifier_key(v.index)
        .verifying_key()
        .verify_strict(
            &vote_message(v.phase, v.round, v.input, &v.digest, v.index),
            &Signature::from_bytes(&v.signature),
        )
        .is_ok()
}

fn make_qc(votes: Vec<Vote>, phase: u8, round: u64, input: InputRef, digest: &[u8; 32]) -> Option<Qc> {
    let mut unique = HashMap::new();
    for v in votes {
        if v.phase == phase && v.round == round && v.input == input && &v.digest == digest && verify_vote(&v) {
            unique.entry(v.index).or_insert(v);
        }
    }
    if unique.len() < Q {
        return None;
    }
    Some(Qc {
        votes: unique.into_values().collect(),
    })
}

fn verify_qc(qc: &Qc, phase: u8, round: u64, input: InputRef, digest: &[u8; 32]) -> bool {
    if qc.votes.is_empty() {
        return false;
    }
    let mut unique = HashSet::new();
    for v in &qc.votes {
        if v.phase != phase || v.round != round || v.input != input || &v.digest != digest || !verify_vote(v) {
            return false;
        }
        unique.insert(v.index);
    }
    unique.len() >= Q
}

fn verify_qc_any(qc: &Qc, phase: u8) -> bool {
    if qc.votes.is_empty() {
        return false;
    }
    let f = qc.votes[0];
    verify_qc(qc, phase, f.round, f.input, &f.digest)
}

fn checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC011_STATE_WAL_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_record(phase: u8, input: InputRef, round: u64, digest: [u8; 32]) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&WAL_MAGIC);
    out[8] = phase;
    out[16..24].copy_from_slice(&input.id.to_le_bytes());
    out[24..32].copy_from_slice(&input.generation.to_le_bytes());
    out[32..40].copy_from_slice(&round.to_le_bytes());
    out[40..72].copy_from_slice(&digest);
    let c = checksum(&out[..72]);
    out[72..104].copy_from_slice(&c);
    out
}

fn decode_record(rec: &[u8]) -> Result<(u8, InputRef, u64, [u8; 32]), String> {
    if rec.len() != WAL_RECORD || rec[0..8] != WAL_MAGIC {
        return Err("bad state WAL record".into());
    }
    if rec[72..104] != checksum(&rec[..72]) {
        return Err("state WAL checksum mismatch".into());
    }
    let phase = rec[8];
    if phase != PHASE_PREVOTE && phase != PHASE_PRECOMMIT {
        return Err("unknown WAL phase".into());
    }
    let input = InputRef {
        id: u64::from_le_bytes(rec[16..24].try_into().unwrap()),
        generation: u64::from_le_bytes(rec[24..32].try_into().unwrap()),
    };
    let round = u64::from_le_bytes(rec[32..40].try_into().unwrap());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&rec[40..72]);
    Ok((phase, input, round, digest))
}

struct StateStore {
    file: File,
    votes: HashMap<(InputRef, u64, u8), [u8; 32]>,
    locks: HashMap<InputRef, (u64, [u8; 32])>,
}

impl StateStore {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.len() % WAL_RECORD != 0 {
            return Err("incomplete state WAL record; fail closed".into());
        }
        let mut votes = HashMap::new();
        let mut locks = HashMap::new();
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let (phase, input, round, digest) = decode_record(rec)?;
            let key = (input, round, phase);
            if let Some(old) = votes.insert(key, digest) {
                if old != digest {
                    return Err("conflicting durable same-round vote; fail closed".into());
                }
            }
            if phase == PHASE_PRECOMMIT {
                match locks.get(&input) {
                    Some((old_round, _)) if *old_round > round => {}
                    Some((old_round, old_digest)) if *old_round == round && old_digest != &digest => {
                        return Err("conflicting same-round lock; fail closed".into());
                    }
                    _ => {
                        locks.insert(input, (round, digest));
                    }
                }
            }
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        Ok(Self { file, votes, locks })
    }

    fn vote(&self, input: InputRef, round: u64, phase: u8) -> Option<[u8; 32]> {
        self.votes.get(&(input, round, phase)).copied()
    }

    fn lock(&self, input: InputRef) -> Option<(u64, [u8; 32])> {
        self.locks.get(&input).copied()
    }

    fn persist_vote(&mut self, input: InputRef, round: u64, phase: u8, digest: [u8; 32]) -> Result<(), String> {
        if let Some(old) = self.vote(input, round, phase) {
            if old != digest {
                return Err("conflicting same-round vote rejected".into());
            }
            return Ok(());
        }
        self.file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        self.file
            .write_all(&encode_record(phase, input, round, digest))
            .map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.votes.insert((input, round, phase), digest);
        if phase == PHASE_PRECOMMIT {
            match self.lock(input) {
                Some((old_round, _)) if old_round > round => {}
                _ => {
                    self.locks.insert(input, (round, digest));
                }
            }
        }
        Ok(())
    }

    fn safe_prevote(&self, input: InputRef, round: u64, digest: [u8; 32], justify: &Option<Qc>) -> bool {
        let Some((lock_round, lock_digest)) = self.lock(input) else {
            return true;
        };
        if lock_digest == digest {
            return true;
        }
        let Some(qc) = justify else {
            return false;
        };
        if !verify_qc_any(qc, PHASE_PREVOTE) {
            return false;
        }
        let f = qc.votes[0];
        f.input == input && f.digest == digest && f.round > lock_round && f.round < round
    }
}

fn write_u64(s: &mut TcpStream, v: u64) -> Result<(), String> {
    s.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

fn read_u64(s: &mut TcpStream) -> Result<u64, String> {
    let mut b = [0u8; 8];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn read_arr32(s: &mut TcpStream) -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

fn read_arr64(s: &mut TcpStream) -> Result<[u8; 64], String> {
    let mut b = [0u8; 64];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

fn write_qc(s: &mut TcpStream, qc: &Option<Qc>) -> Result<(), String> {
    match qc {
        None => s.write_all(&[0]).map_err(|e| e.to_string()),
        Some(q) => {
            s.write_all(&[1]).map_err(|e| e.to_string())?;
            let f = q.votes.first().ok_or("empty qc")?;
            s.write_all(&[f.phase]).map_err(|e| e.to_string())?;
            write_u64(s, f.round)?;
            write_u64(s, f.input.id)?;
            write_u64(s, f.input.generation)?;
            s.write_all(&f.digest).map_err(|e| e.to_string())?;
            s.write_all(&[q.votes.len() as u8]).map_err(|e| e.to_string())?;
            for v in &q.votes {
                s.write_all(&[v.index as u8]).map_err(|e| e.to_string())?;
                s.write_all(&v.signature).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }
}

fn read_qc(s: &mut TcpStream) -> Result<Option<Qc>, String> {
    let mut present = [0u8; 1];
    s.read_exact(&mut present).map_err(|e| e.to_string())?;
    if present[0] == 0 {
        return Ok(None);
    }
    let mut phase = [0u8; 1];
    s.read_exact(&mut phase).map_err(|e| e.to_string())?;
    let round = read_u64(s)?;
    let input = InputRef {
        id: read_u64(s)?,
        generation: read_u64(s)?,
    };
    let digest = read_arr32(s)?;
    let mut n = [0u8; 1];
    s.read_exact(&mut n).map_err(|e| e.to_string())?;
    if n[0] as usize > N {
        return Err("oversized qc".into());
    }
    let mut votes = Vec::with_capacity(n[0] as usize);
    for _ in 0..n[0] {
        let mut idx = [0u8; 1];
        s.read_exact(&mut idx).map_err(|e| e.to_string())?;
        let signature = read_arr64(s)?;
        votes.push(Vote {
            index: idx[0] as usize,
            phase: phase[0],
            round,
            input,
            digest,
            signature,
        });
    }
    Ok(Some(Qc { votes }))
}

fn write_request(
    s: &mut TcpStream,
    phase: u8,
    crash_mode: u8,
    round: u64,
    tx: &SpendTx,
    auth: &UserAuth,
    digest: &[u8; 32],
    justify: &Option<Qc>,
) -> Result<(), String> {
    s.write_all(&[OP_VOTE, phase, crash_mode]).map_err(|e| e.to_string())?;
    write_u64(s, round)?;
    write_u64(s, tx.input.id)?;
    write_u64(s, tx.input.generation)?;
    write_u64(s, tx.tx_id)?;
    s.write_all(&tx.recipient).map_err(|e| e.to_string())?;
    write_u64(s, tx.value)?;
    s.write_all(&auth.signer).map_err(|e| e.to_string())?;
    s.write_all(&auth.signature).map_err(|e| e.to_string())?;
    s.write_all(digest).map_err(|e| e.to_string())?;
    write_qc(s, justify)
}

fn run_node(index: usize, port: u16, wal: PathBuf) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind node {index}: {e}"))?;
    let mut store = StateStore::open(&wal)?;
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
            OP_VOTE => {
                let mut hdr = [0u8; 2];
                stream.read_exact(&mut hdr).map_err(|e| e.to_string())?;
                let phase = hdr[0];
                let crash_mode = hdr[1];
                let round = read_u64(&mut stream)?;
                let input = InputRef {
                    id: read_u64(&mut stream)?,
                    generation: read_u64(&mut stream)?,
                };
                let tx_id = read_u64(&mut stream)?;
                let recipient = read_arr32(&mut stream)?;
                let value = read_u64(&mut stream)?;
                let signer = read_arr32(&mut stream)?;
                let signature = read_arr64(&mut stream)?;
                let digest = read_arr32(&mut stream)?;
                let justify = read_qc(&mut stream)?;
                let tx = SpendTx { input, tx_id, recipient, value };
                let auth = UserAuth { signer, signature };

                let mut allowed = verify_user(&tx, &auth, &digest).is_ok();
                if phase == PHASE_PREVOTE {
                    allowed &= store.safe_prevote(input, round, digest, &justify);
                } else if phase == PHASE_PRECOMMIT {
                    allowed &= justify
                        .as_ref()
                        .map(|q| verify_qc(q, PHASE_PREVOTE, round, input, &digest))
                        .unwrap_or(false);
                } else {
                    allowed = false;
                }
                if let Some(old) = store.vote(input, round, phase) {
                    allowed &= old == digest;
                }
                if !allowed {
                    let _ = stream.write_all(&[0]);
                    continue;
                }

                if crash_mode == CRASH_BEFORE_PERSIST {
                    std::process::exit(EXIT_BEFORE_PERSIST);
                }
                store.persist_vote(input, round, phase, digest)?;
                if crash_mode == CRASH_AFTER_SYNC_BEFORE_REPLY {
                    std::process::exit(EXIT_AFTER_SYNC);
                }
                let sig = sk.sign(&vote_message(phase, round, input, &digest, index)).to_bytes();
                stream.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                stream.write_all(&sig).map_err(|e| e.to_string())?;
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
    fn spawn(exe: &Path, index: usize, wal: PathBuf) -> Result<Self, String> {
        let port = free_port()?;
        let child = Command::new(exe)
            .arg("--node")
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn node {index}: {e}"))?;
        let mut n = Self { index, port, wal, child };
        n.wait_ready()?;
        Ok(n)
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

    fn restart(&mut self, exe: &Path) -> Result<(), String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

    fn wait_crashed(&mut self) -> Result<i32, String> {
        for _ in 0..400 {
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                return Ok(status.code().unwrap_or(-1));
            }
            thread::sleep(Duration::from_millis(5));
        }
        Err(format!("node {} did not exit after crash injection", self.index))
    }

    fn stop(&mut self) {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
            let _ = s.write_all(&[OP_SHUTDOWN]);
        }
        let _ = self.child.wait();
    }
}

fn rpc_vote(
    port: u16,
    phase: u8,
    crash_mode: u8,
    round: u64,
    tx: &SpendTx,
    auth: &UserAuth,
    digest: &[u8; 32],
    justify: &Option<Qc>,
) -> Option<Vote> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(1000))).ok();
    s.set_write_timeout(Some(Duration::from_millis(1000))).ok();
    write_request(&mut s, phase, crash_mode, round, tx, auth, digest, justify).ok()?;
    let mut status = [0u8; 1];
    if s.read_exact(&mut status).is_err() || status[0] == 0 {
        return None;
    }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let signature = read_arr64(&mut s).ok()?;
    Some(Vote {
        index: idx[0] as usize,
        phase,
        round,
        input: tx.input,
        digest: *digest,
        signature,
    })
}

fn make_pair(label: u64) -> (SpendTx, UserAuth, [u8; 32], SpendTx, UserAuth, [u8; 32]) {
    let alice = user_key(1);
    let bob = user_key(2).verifying_key().to_bytes();
    let mallory = user_key(3).verifying_key().to_bytes();
    let input = InputRef {
        id: 11_000_000 + label,
        generation: 11,
    };
    let a = SpendTx {
        input,
        tx_id: 31_000_000 + label * 2,
        recipient: bob,
        value: 800,
    };
    let b = SpendTx {
        input,
        tx_id: 31_000_001 + label * 2,
        recipient: mallory,
        value: 800,
    };
    let aa = sign_user(&a, &alice);
    let ba = sign_user(&b, &alice);
    let ad = digest_for(&a, &aa.signer);
    let bd = digest_for(&b, &ba.signer);
    (a, aa, ad, b, ba, bd)
}

fn collect_qc(nodes: &[NodeProc], phase: u8, round: u64, tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32], justify: &Option<Qc>) -> Result<Qc, String> {
    let mut votes = Vec::new();
    for &i in &HONEST {
        if let Some(v) = rpc_vote(nodes[i].port, phase, CRASH_NONE, round, tx, auth, digest, justify) {
            votes.push(v);
        }
    }
    make_qc(votes, phase, round, tx.input, digest)
        .ok_or_else(|| format!("QC not reached for phase {phase} round {round}"))
}

fn wal_contains(path: &Path, phase: u8, input: InputRef, round: u64, digest: &[u8; 32]) -> Result<bool, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() % WAL_RECORD != 0 {
        return Err("controller saw torn WAL".into());
    }
    for rec in bytes.chunks_exact(WAL_RECORD) {
        let (p, i, r, d) = decode_record(rec)?;
        if p == phase && i == input && r == round && &d == digest {
            return Ok(true);
        }
    }
    Ok(false)
}

fn controller() -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec011-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let mut nodes = Vec::new();
    for i in 0..N {
        nodes.push(NodeProc::spawn(&exe, i, root.join(format!("node-{i}.wal")))?);
    }

    println!("CALIBRE SECURITY SEC-011 v0.11.0");
    println!("CRASH-WINDOW / DURABLE VOTE REPLAY / QC-LOCK SAFETY");
    println!("N=7 Q=5; seven separate OS processes over real 127.0.0.1 TCP");
    println!("Purpose: attack the exact windows between vote decision, WAL persistence, sync_all(), vote transmission, process death, and restart");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!();

    // Baseline finality.
    let (a0, aa0, ad0, _, _, _) = make_pair(0);
    let pv0 = collect_qc(&nodes, PHASE_PREVOTE, 1, &a0, &aa0, &ad0, &None)?;
    let pc0 = collect_qc(&nodes, PHASE_PRECOMMIT, 1, &a0, &aa0, &ad0, &Some(pv0.clone()))?;
    if !verify_qc(&pc0, PHASE_PRECOMMIT, 1, a0.input, &ad0) {
        return Err("baseline precommit QC invalid".into());
    }
    println!("BASELINE 5-OF-7 PREVOTE QC + PRECOMMIT QC: PASS");

    // Crash before persistence: no vote escaped, so restart must not invent a lock.
    let (a1, aa1, ad1, b1, ba1, bd1) = make_pair(1);
    let target = 4usize;
    let got = rpc_vote(nodes[target].port, PHASE_PREVOTE, CRASH_BEFORE_PERSIST, 2, &a1, &aa1, &ad1, &None);
    if got.is_some() {
        return Err("crash-before-persist unexpectedly returned a vote".into());
    }
    let code = nodes[target].wait_crashed()?;
    if code != EXIT_BEFORE_PERSIST {
        return Err(format!("wrong crash-before-persist exit code {code}"));
    }
    if nodes[target].wal.exists() && wal_contains(&nodes[target].wal, PHASE_PREVOTE, a1.input, 2, &ad1)? {
        return Err("crash-before-persist left a durable vote".into());
    }
    nodes[target].restart(&exe)?;
    let b_after = rpc_vote(nodes[target].port, PHASE_PREVOTE, CRASH_NONE, 2, &b1, &ba1, &bd1, &None);
    if b_after.is_none() {
        return Err("restart after pre-persist crash could not choose a fresh successor".into());
    }
    println!("CRASH BEFORE WAL PERSIST / BEFORE VOTE ESCAPES: NO PHANTOM LOCK; RESTART CAN CHOOSE FRESH SUCCESSOR -> PASS");

    // Crash after sync before reply: durable vote must exist even though controller received no vote.
    let (a2, aa2, ad2, b2, ba2, bd2) = make_pair(2);
    let got = rpc_vote(nodes[target].port, PHASE_PREVOTE, CRASH_AFTER_SYNC_BEFORE_REPLY, 3, &a2, &aa2, &ad2, &None);
    if got.is_some() {
        return Err("after-sync crash unexpectedly returned vote".into());
    }
    let code = nodes[target].wait_crashed()?;
    if code != EXIT_AFTER_SYNC {
        return Err(format!("wrong after-sync exit code {code}"));
    }
    if !wal_contains(&nodes[target].wal, PHASE_PREVOTE, a2.input, 3, &ad2)? {
        return Err("after-sync crash missing durable prevote".into());
    }
    nodes[target].restart(&exe)?;
    let same = rpc_vote(nodes[target].port, PHASE_PREVOTE, CRASH_NONE, 3, &a2, &aa2, &ad2, &None);
    let conflict = rpc_vote(nodes[target].port, PHASE_PREVOTE, CRASH_NONE, 3, &b2, &ba2, &bd2, &None);
    if same.is_none() || conflict.is_some() {
        return Err("durable same-round prevote replay invariant failed after restart".into());
    }
    println!("CRASH AFTER sync_all() BUT BEFORE PREVOTE REPLY: WAL PRESENT; SAME DIGEST REPLAYED; CONFLICTING SAME-ROUND PREVOTE REJECTED -> PASS");

    // Vote escaped, then process dies: durable record must still block conflict.
    let (a3, aa3, ad3, b3, ba3, bd3) = make_pair(3);
    let target2 = 6usize;
    if rpc_vote(nodes[target2].port, PHASE_PREVOTE, CRASH_NONE, 4, &a3, &aa3, &ad3, &None).is_none() {
        return Err("normal prevote failed before external kill".into());
    }
    nodes[target2].restart(&exe)?;
    if rpc_vote(nodes[target2].port, PHASE_PREVOTE, CRASH_NONE, 4, &b3, &ba3, &bd3, &None).is_some() {
        return Err("external kill/restart lost escaped prevote".into());
    }
    println!("PREVOTE REPLY ESCAPES THEN PROCESS KILL/RESTART: CONFLICTING SAME-ROUND VOTE STILL REJECTED -> PASS");

    // PRECOMMIT critical window: lock is synced before reply.
    let (a4, aa4, ad4, b4, ba4, bd4) = make_pair(4);
    let pv4 = collect_qc(&nodes, PHASE_PREVOTE, 5, &a4, &aa4, &ad4, &None)?;
    let target3 = 5usize;
    let got = rpc_vote(nodes[target3].port, PHASE_PRECOMMIT, CRASH_AFTER_SYNC_BEFORE_REPLY, 5, &a4, &aa4, &ad4, &Some(pv4.clone()));
    if got.is_some() {
        return Err("after-sync precommit crash unexpectedly returned vote".into());
    }
    let code = nodes[target3].wait_crashed()?;
    if code != EXIT_AFTER_SYNC {
        return Err(format!("wrong precommit after-sync exit code {code}"));
    }
    if !wal_contains(&nodes[target3].wal, PHASE_PRECOMMIT, a4.input, 5, &ad4)? {
        return Err("after-sync precommit crash missing durable lock".into());
    }
    nodes[target3].restart(&exe)?;
    if rpc_vote(nodes[target3].port, PHASE_PRECOMMIT, CRASH_NONE, 5, &a4, &aa4, &ad4, &Some(pv4.clone())).is_none() {
        return Err("same precommit not replayable after restart".into());
    }
    if rpc_vote(nodes[target3].port, PHASE_PREVOTE, CRASH_NONE, 6, &b4, &ba4, &bd4, &None).is_some() {
        return Err("locked node accepted unjustified higher-round conflict after restart".into());
    }
    if rpc_vote(nodes[target3].port, PHASE_PREVOTE, CRASH_NONE, 6, &a4, &aa4, &ad4, &None).is_none() {
        return Err("locked node rejected same digest in higher round".into());
    }
    println!("CRASH AFTER sync_all() BUT BEFORE PRECOMMIT REPLY: DURABLE QC-LOCK SURVIVES; SAME DIGEST ACCEPTED; UNJUSTIFIED CONFLICT REJECTED -> PASS");

    // End-to-end recovery with one prevote crash and one precommit crash.
    let (a5, aa5, ad5, _, _, _) = make_pair(5);
    let c1 = 2usize;
    let _ = rpc_vote(nodes[c1].port, PHASE_PREVOTE, CRASH_AFTER_SYNC_BEFORE_REPLY, 7, &a5, &aa5, &ad5, &None);
    if nodes[c1].wait_crashed()? != EXIT_AFTER_SYNC {
        return Err("end-to-end prevote crash exit code mismatch".into());
    }
    nodes[c1].restart(&exe)?;
    let pv5 = collect_qc(&nodes, PHASE_PREVOTE, 7, &a5, &aa5, &ad5, &None)?;
    let c2 = 3usize;
    let _ = rpc_vote(nodes[c2].port, PHASE_PRECOMMIT, CRASH_AFTER_SYNC_BEFORE_REPLY, 7, &a5, &aa5, &ad5, &Some(pv5.clone()));
    if nodes[c2].wait_crashed()? != EXIT_AFTER_SYNC {
        return Err("end-to-end precommit crash exit code mismatch".into());
    }
    nodes[c2].restart(&exe)?;
    let pc5 = collect_qc(&nodes, PHASE_PRECOMMIT, 7, &a5, &aa5, &ad5, &Some(pv5.clone()))?;
    if !verify_qc(&pc5, PHASE_PRECOMMIT, 7, a5.input, &ad5) {
        return Err("end-to-end recovered finality QC invalid".into());
    }
    println!("END-TO-END: PREVOTE CRASH-AFTER-SYNC + RESTART, THEN PRECOMMIT CRASH-AFTER-SYNC + RESTART -> 5/7 FINALITY RECOVERS: PASS");

    // Fail-closed parser checks for torn/corrupt durable state.
    let torn = root.join("torn-test.wal");
    fs::write(&torn, vec![0u8; WAL_RECORD - 1]).map_err(|e| e.to_string())?;
    if StateStore::open(&torn).is_ok() {
        return Err("torn WAL did not fail closed".into());
    }
    let corrupt = root.join("corrupt-test.wal");
    let mut rec = encode_record(PHASE_PREVOTE, InputRef { id: 99, generation: 1 }, 1, [7u8; 32]);
    rec[50] ^= 0x01;
    fs::write(&corrupt, rec).map_err(|e| e.to_string())?;
    if StateStore::open(&corrupt).is_ok() {
        return Err("corrupt WAL did not fail closed".into());
    }
    println!("TORN WAL + CHECKSUM-MUTATED WAL: FAIL-CLOSED ON REOPEN -> PASS");

    for n in &mut nodes {
        n.stop();
    }
    let _ = fs::remove_dir_all(&root);

    println!();
    println!("=== SEC-011 DECISION ===");
    println!("DURABLE SAME-ROUND PREVOTE BEFORE REPLY: PASS IN TESTED CRASH WINDOWS");
    println!("DURABLE PRECOMMIT/QC LOCK BEFORE REPLY: PASS IN TESTED CRASH WINDOWS");
    println!("CRASH BEFORE PERSIST AND BEFORE VOTE ESCAPES CREATES NO PHANTOM LOCK: PASS");
    println!("CRASH AFTER sync_all() BEFORE REPLY PRESERVES VOTE/LOCK ACROSS PROCESS RESTART: PASS");
    println!("ESCAPED VOTE THEN PROCESS KILL/RESTART DOES NOT ENABLE SAME-ROUND EQUIVOCATION: PASS");
    println!("END-TO-END FINALITY RECOVERS AFTER INJECTED PREVOTE + PRECOMMIT CRASH WINDOWS: PASS");
    println!("TORN/CORRUPT SOFTWARE WAL FAIL-CLOSED: PASS");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("POWER-LOSS / DISK-CONTROLLER FLUSH SEMANTICS: NOT PROVEN");
    println!("MALICIOUS STORAGE SNAPSHOT ROLLBACK: NOT PROVEN");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
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
        eprintln!("SEC-011 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_intersection_is_three() {
        assert_eq!(Q + Q - N, 3);
    }

    #[test]
    fn wal_record_round_trip_and_checksum() {
        let input = InputRef { id: 123, generation: 7 };
        let digest = [9u8; 32];
        let rec = encode_record(PHASE_PRECOMMIT, input, 11, digest);
        let (p, i, r, d) = decode_record(&rec).unwrap();
        assert_eq!(p, PHASE_PRECOMMIT);
        assert_eq!(i, input);
        assert_eq!(r, 11);
        assert_eq!(d, digest);
    }

    #[test]
    fn wal_checksum_detects_mutation() {
        let input = InputRef { id: 123, generation: 7 };
        let mut rec = encode_record(PHASE_PREVOTE, input, 11, [9u8; 32]);
        rec[41] ^= 1;
        assert!(decode_record(&rec).is_err());
    }

    #[test]
    fn duplicate_vote_identity_cannot_inflate_qc() {
        let (a, aa, ad, _, _, _) = make_pair(88);
        let sk = certifier_key(2);
        let sig = sk.sign(&vote_message(PHASE_PREVOTE, 1, a.input, &ad, 2)).to_bytes();
        let v = Vote { index: 2, phase: PHASE_PREVOTE, round: 1, input: a.input, digest: ad, signature: sig };
        assert!(make_qc(vec![v, v, v, v, v], PHASE_PREVOTE, 1, a.input, &ad).is_none());
        assert!(verify_user(&a, &aa, &ad).is_ok());
    }
}
