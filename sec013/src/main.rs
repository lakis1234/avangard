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

const N: usize = 7;
const Q: usize = 5;
const OLD_EPOCH: u64 = 12;
const NEW_EPOCH: u64 = 13;
const STATUS_LOCKED: u8 = 1;
const STATUS_FINAL: u8 = 2;

const OP_PING: u8 = 0;
const OP_OLD_SIGN: u8 = 1;
const OP_NEW_ACTIVATE: u8 = 2;
const OP_NEW_VOTE: u8 = 3;
const OP_SHUTDOWN: u8 = 255;

const OLD_WAL_MAGIC: [u8; 8] = *b"CAL13OLD";
const NEW_WAL_MAGIC: [u8; 8] = *b"CAL13NEW";
const WAL_RECORD: usize = 104;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handoff {
    from_epoch: u64,
    to_epoch: u64,
    input: InputRef,
    status: u8,
    round: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct OldShare {
    index: usize,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct HandoffCert {
    handoff: Handoff,
    shares: Vec<OldShare>,
}

#[derive(Clone, Copy, Debug)]
struct ActivationShare {
    index: usize,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct ActivationCert {
    handoff_hash: [u8; 32],
    shares: Vec<ActivationShare>,
}

#[derive(Clone, Copy, Debug)]
struct NewVote {
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

fn old_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC013_OLD_COMMITTEE_KEY_V1", 100 + index as u64)
}

fn new_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC013_NEW_COMMITTEE_KEY_V1", 200 + index as u64)
}

fn digest_for(input: InputRef, label: u8) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC013_CONFLICT_DIGEST_V1");
    h.update(&input.id.to_le_bytes());
    h.update(&input.generation.to_le_bytes());
    h.update(&[label]);
    *h.finalize().as_bytes()
}

fn handoff_message(h: &Handoff) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC013_HANDOFF_V1");
    out.extend_from_slice(&h.from_epoch.to_le_bytes());
    out.extend_from_slice(&h.to_epoch.to_le_bytes());
    out.extend_from_slice(&h.input.id.to_le_bytes());
    out.extend_from_slice(&h.input.generation.to_le_bytes());
    out.push(h.status);
    out.extend_from_slice(&h.round.to_le_bytes());
    out.extend_from_slice(&h.digest);
    out
}

fn handoff_hash(h: &Handoff) -> [u8; 32] {
    *blake3::hash(&handoff_message(h)).as_bytes()
}

fn old_share_message(hash: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(b"CALIBRE_SEC013_OLD_HANDOFF_SHARE_V1");
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(hash);
    out
}

fn activation_message(hash: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(b"CALIBRE_SEC013_NEW_ACTIVATION_SHARE_V1");
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(hash);
    out
}

fn new_vote_message(input: InputRef, digest: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC013_NEW_EPOCH_VOTE_V1");
    out.extend_from_slice(&NEW_EPOCH.to_le_bytes());
    out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes());
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(digest);
    out
}

fn verify_old_share(h: &Handoff, s: &OldShare) -> bool {
    if s.index >= N {
        return false;
    }
    let hash = handoff_hash(h);
    old_key(s.index)
        .verifying_key()
        .verify_strict(&old_share_message(&hash, s.index), &Signature::from_bytes(&s.signature))
        .is_ok()
}

fn verify_handoff_cert_any(cert: &HandoffCert) -> bool {
    if cert.handoff.status != STATUS_LOCKED && cert.handoff.status != STATUS_FINAL {
        return false;
    }
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_old_share(&cert.handoff, s) {
            return false;
        }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_handoff_cert_for_new_epoch(cert: &HandoffCert) -> bool {
    verify_handoff_cert_any(cert)
        && cert.handoff.from_epoch == OLD_EPOCH
        && cert.handoff.to_epoch == NEW_EPOCH
}

fn verify_activation_share(hash: &[u8; 32], s: &ActivationShare) -> bool {
    if s.index >= N {
        return false;
    }
    new_key(s.index)
        .verifying_key()
        .verify_strict(&activation_message(hash, s.index), &Signature::from_bytes(&s.signature))
        .is_ok()
}

fn verify_activation_cert(cert: &ActivationCert, old: &HandoffCert) -> bool {
    if !verify_handoff_cert_for_new_epoch(old) || cert.handoff_hash != handoff_hash(&old.handoff) {
        return false;
    }
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_activation_share(&cert.handoff_hash, s) {
            return false;
        }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_new_vote(v: &NewVote, input: InputRef, digest: &[u8; 32]) -> bool {
    if v.index >= N || &v.digest != digest {
        return false;
    }
    new_key(v.index)
        .verifying_key()
        .verify_strict(&new_vote_message(input, digest, v.index), &Signature::from_bytes(&v.signature))
        .is_ok()
}

fn wal_checksum(magic: &[u8; 8], prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC013_HANDOFF_WAL_CHECKSUM_V1");
    h.update(magic);
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_choice(magic: [u8; 8], h: &Handoff, hash: [u8; 32]) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&magic);
    out[8..16].copy_from_slice(&h.from_epoch.to_le_bytes());
    out[16..24].copy_from_slice(&h.to_epoch.to_le_bytes());
    out[24..32].copy_from_slice(&h.input.id.to_le_bytes());
    out[32..40].copy_from_slice(&h.input.generation.to_le_bytes());
    out[40..72].copy_from_slice(&hash);
    let c = wal_checksum(&magic, &out[..72]);
    out[72..104].copy_from_slice(&c);
    out
}

fn decode_choice(magic: [u8; 8], rec: &[u8]) -> Result<((u64, u64, InputRef), [u8; 32]), String> {
    if rec.len() != WAL_RECORD || rec[0..8] != magic {
        return Err("bad handoff WAL record".into());
    }
    if rec[72..104] != wal_checksum(&magic, &rec[..72]) {
        return Err("handoff WAL checksum mismatch".into());
    }
    let from_epoch = u64::from_le_bytes(rec[8..16].try_into().unwrap());
    let to_epoch = u64::from_le_bytes(rec[16..24].try_into().unwrap());
    let input = InputRef {
        id: u64::from_le_bytes(rec[24..32].try_into().unwrap()),
        generation: u64::from_le_bytes(rec[32..40].try_into().unwrap()),
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&rec[40..72]);
    Ok(((from_epoch, to_epoch, input), hash))
}

struct ChoiceStore {
    magic: [u8; 8],
    file: File,
    choices: HashMap<(u64, u64, InputRef), [u8; 32]>,
}

impl ChoiceStore {
    fn open(path: &Path, magic: [u8; 8]) -> Result<Self, String> {
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
            return Err("incomplete handoff WAL record; fail closed".into());
        }
        let mut choices = HashMap::new();
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let (key, hash) = decode_choice(magic, rec)?;
            if let Some(old) = choices.insert(key, hash) {
                if old != hash {
                    return Err("conflicting durable handoff choice; fail closed".into());
                }
            }
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        Ok(Self { magic, file, choices })
    }

    fn get(&self, h: &Handoff) -> Option<[u8; 32]> {
        self.choices.get(&(h.from_epoch, h.to_epoch, h.input)).copied()
    }

    fn choose(&mut self, h: &Handoff, hash: [u8; 32]) -> Result<bool, String> {
        if let Some(old) = self.get(h) {
            return Ok(old == hash);
        }
        let rec = encode_choice(self.magic, h, hash);
        self.file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        self.file.write_all(&rec).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.choices.insert((h.from_epoch, h.to_epoch, h.input), hash);
        Ok(true)
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

fn write_handoff(s: &mut TcpStream, h: &Handoff) -> Result<(), String> {
    write_u64(s, h.from_epoch)?;
    write_u64(s, h.to_epoch)?;
    write_u64(s, h.input.id)?;
    write_u64(s, h.input.generation)?;
    s.write_all(&[h.status]).map_err(|e| e.to_string())?;
    write_u64(s, h.round)?;
    s.write_all(&h.digest).map_err(|e| e.to_string())
}

fn read_handoff(s: &mut TcpStream) -> Result<Handoff, String> {
    let from_epoch = read_u64(s)?;
    let to_epoch = read_u64(s)?;
    let input = InputRef { id: read_u64(s)?, generation: read_u64(s)? };
    let mut status = [0u8; 1];
    s.read_exact(&mut status).map_err(|e| e.to_string())?;
    let round = read_u64(s)?;
    let digest = read_arr32(s)?;
    Ok(Handoff { from_epoch, to_epoch, input, status: status[0], round, digest })
}

fn write_handoff_cert(s: &mut TcpStream, cert: &HandoffCert) -> Result<(), String> {
    write_handoff(s, &cert.handoff)?;
    s.write_all(&[cert.shares.len() as u8]).map_err(|e| e.to_string())?;
    for sh in &cert.shares {
        s.write_all(&[sh.index as u8]).map_err(|e| e.to_string())?;
        s.write_all(&sh.signature).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_handoff_cert(s: &mut TcpStream) -> Result<HandoffCert, String> {
    let handoff = read_handoff(s)?;
    let mut n = [0u8; 1];
    s.read_exact(&mut n).map_err(|e| e.to_string())?;
    if n[0] as usize > N {
        return Err("oversized handoff certificate".into());
    }
    let mut shares = Vec::with_capacity(n[0] as usize);
    for _ in 0..n[0] {
        let mut i = [0u8; 1];
        s.read_exact(&mut i).map_err(|e| e.to_string())?;
        shares.push(OldShare { index: i[0] as usize, signature: read_arr64(s)? });
    }
    Ok(HandoffCert { handoff, shares })
}

fn write_activation_cert(s: &mut TcpStream, cert: &ActivationCert) -> Result<(), String> {
    s.write_all(&cert.handoff_hash).map_err(|e| e.to_string())?;
    s.write_all(&[cert.shares.len() as u8]).map_err(|e| e.to_string())?;
    for sh in &cert.shares {
        s.write_all(&[sh.index as u8]).map_err(|e| e.to_string())?;
        s.write_all(&sh.signature).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_activation_cert(s: &mut TcpStream) -> Result<ActivationCert, String> {
    let handoff_hash = read_arr32(s)?;
    let mut n = [0u8; 1];
    s.read_exact(&mut n).map_err(|e| e.to_string())?;
    if n[0] as usize > N {
        return Err("oversized activation certificate".into());
    }
    let mut shares = Vec::with_capacity(n[0] as usize);
    for _ in 0..n[0] {
        let mut i = [0u8; 1];
        s.read_exact(&mut i).map_err(|e| e.to_string())?;
        shares.push(ActivationShare { index: i[0] as usize, signature: read_arr64(s)? });
    }
    Ok(ActivationCert { handoff_hash, shares })
}

fn run_old_node(index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind old node {index}: {e}"))?;
    let mut store = if byzantine { None } else { Some(ChoiceStore::open(&wal, OLD_WAL_MAGIC)?) };
    let sk = old_key(index);
    for conn in listener.incoming() {
        let mut s = match conn { Ok(s) => s, Err(_) => continue };
        let mut op = [0u8; 1];
        if s.read_exact(&mut op).is_err() { continue; }
        match op[0] {
            OP_PING => { let _ = s.write_all(&[0xAA]); }
            OP_SHUTDOWN => { let _ = s.write_all(&[0x55]); break; }
            OP_OLD_SIGN => {
                let h = read_handoff(&mut s)?;
                if h.status != STATUS_LOCKED && h.status != STATUS_FINAL {
                    let _ = s.write_all(&[0]);
                    continue;
                }
                let hash = handoff_hash(&h);
                if let Some(st) = &mut store {
                    if !st.choose(&h, hash)? {
                        let _ = s.write_all(&[0]);
                        continue;
                    }
                }
                let sig = sk.sign(&old_share_message(&hash, index)).to_bytes();
                s.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                s.write_all(&sig).map_err(|e| e.to_string())?;
            }
            _ => { let _ = s.write_all(&[0]); }
        }
    }
    Ok(())
}

fn run_new_node(index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind new node {index}: {e}"))?;
    let mut store = if byzantine { None } else { Some(ChoiceStore::open(&wal, NEW_WAL_MAGIC)?) };
    let sk = new_key(index);
    for conn in listener.incoming() {
        let mut s = match conn { Ok(s) => s, Err(_) => continue };
        let mut op = [0u8; 1];
        if s.read_exact(&mut op).is_err() { continue; }
        match op[0] {
            OP_PING => { let _ = s.write_all(&[0xAA]); }
            OP_SHUTDOWN => { let _ = s.write_all(&[0x55]); break; }
            OP_NEW_ACTIVATE => {
                let cert = read_handoff_cert(&mut s)?;
                if !verify_handoff_cert_for_new_epoch(&cert) {
                    let _ = s.write_all(&[0]);
                    continue;
                }
                let hash = handoff_hash(&cert.handoff);
                if let Some(st) = &mut store {
                    if !st.choose(&cert.handoff, hash)? {
                        let _ = s.write_all(&[0]);
                        continue;
                    }
                }
                let sig = sk.sign(&activation_message(&hash, index)).to_bytes();
                s.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                s.write_all(&sig).map_err(|e| e.to_string())?;
            }
            OP_NEW_VOTE => {
                let old = read_handoff_cert(&mut s)?;
                let activation = read_activation_cert(&mut s)?;
                let digest = read_arr32(&mut s)?;
                if !verify_activation_cert(&activation, &old) {
                    let _ = s.write_all(&[0]);
                    continue;
                }
                let hash = handoff_hash(&old.handoff);
                if let Some(st) = &store {
                    if st.get(&old.handoff) != Some(hash) {
                        let _ = s.write_all(&[0]);
                        continue;
                    }
                }
                if !byzantine {
                    if old.handoff.status == STATUS_FINAL {
                        let _ = s.write_all(&[0]);
                        continue;
                    }
                    if old.handoff.status == STATUS_LOCKED && digest != old.handoff.digest {
                        let _ = s.write_all(&[0]);
                        continue;
                    }
                }
                let sig = sk.sign(&new_vote_message(old.handoff.input, &digest, index)).to_bytes();
                s.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                s.write_all(&digest).map_err(|e| e.to_string())?;
                s.write_all(&sig).map_err(|e| e.to_string())?;
            }
            _ => { let _ = s.write_all(&[0]); }
        }
    }
    Ok(())
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

#[derive(Clone, Copy)]
enum Role { Old, New }

struct NodeProc {
    role: Role,
    index: usize,
    port: u16,
    wal: PathBuf,
    byzantine: bool,
    child: Child,
}

impl NodeProc {
    fn spawn(exe: &Path, role: Role, index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<Self, String> {
        let role_arg = match role { Role::Old => "--old-node", Role::New => "--new-node" };
        let child = Command::new(exe)
            .arg(role_arg)
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal)
            .arg(if byzantine { "1" } else { "0" })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn node {index}: {e}"))?;
        let mut n = Self { role, index, port, wal, byzantine, child };
        n.wait_ready()?;
        Ok(n)
    }

    fn wait_ready(&mut self) -> Result<(), String> {
        for _ in 0..400 {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
                let _ = s.write_all(&[OP_PING]);
                let mut b = [0u8; 1];
                if s.read_exact(&mut b).is_ok() && b[0] == 0xAA { return Ok(()); }
            }
            thread::sleep(Duration::from_millis(5));
        }
        Err(format!("node {} not ready", self.index))
    }

    fn crash_restart(&mut self, exe: &Path) -> Result<(), String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.port = free_port()?;
        let role_arg = match self.role { Role::Old => "--old-node", Role::New => "--new-node" };
        self.child = Command::new(exe)
            .arg(role_arg)
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

fn connect(port: u16) -> Option<TcpStream> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    let s = TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(1000))).ok();
    s.set_write_timeout(Some(Duration::from_millis(1000))).ok();
    Some(s)
}

fn rpc_old_sign(port: u16, h: &Handoff) -> Option<OldShare> {
    let mut s = connect(port)?;
    s.write_all(&[OP_OLD_SIGN]).ok()?;
    write_handoff(&mut s, h).ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 0 { return None; }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let sh = OldShare { index: idx[0] as usize, signature: read_arr64(&mut s).ok()? };
    if verify_old_share(h, &sh) { Some(sh) } else { None }
}

fn collect_old(nodes: &[NodeProc], indices: &[usize], h: Handoff) -> HandoffCert {
    let mut by = HashMap::new();
    for &i in indices {
        if let Some(sh) = rpc_old_sign(nodes[i].port, &h) { by.entry(sh.index).or_insert(sh); }
    }
    HandoffCert { handoff: h, shares: by.into_values().collect() }
}

fn rpc_activate(port: u16, cert: &HandoffCert) -> Option<ActivationShare> {
    let mut s = connect(port)?;
    s.write_all(&[OP_NEW_ACTIVATE]).ok()?;
    write_handoff_cert(&mut s, cert).ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 0 { return None; }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let sh = ActivationShare { index: idx[0] as usize, signature: read_arr64(&mut s).ok()? };
    let hash = handoff_hash(&cert.handoff);
    if verify_activation_share(&hash, &sh) { Some(sh) } else { None }
}

fn collect_activation(nodes: &[NodeProc], indices: &[usize], cert: &HandoffCert) -> ActivationCert {
    let hash = handoff_hash(&cert.handoff);
    let mut by = HashMap::new();
    for &i in indices {
        if let Some(sh) = rpc_activate(nodes[i].port, cert) { by.entry(sh.index).or_insert(sh); }
    }
    ActivationCert { handoff_hash: hash, shares: by.into_values().collect() }
}

fn rpc_new_vote(port: u16, old: &HandoffCert, activation: &ActivationCert, digest: [u8; 32]) -> Option<NewVote> {
    let mut s = connect(port)?;
    s.write_all(&[OP_NEW_VOTE]).ok()?;
    write_handoff_cert(&mut s, old).ok()?;
    write_activation_cert(&mut s, activation).ok()?;
    s.write_all(&digest).ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 0 { return None; }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let got = read_arr32(&mut s).ok()?;
    let v = NewVote { index: idx[0] as usize, digest: got, signature: read_arr64(&mut s).ok()? };
    if verify_new_vote(&v, old.handoff.input, &digest) { Some(v) } else { None }
}

fn count_new_votes(nodes: &[NodeProc], indices: &[usize], old: &HandoffCert, activation: &ActivationCert, digest: [u8; 32]) -> usize {
    let mut unique = HashSet::new();
    for &i in indices {
        if let Some(v) = rpc_new_vote(nodes[i].port, old, activation, digest) { unique.insert(v.index); }
    }
    unique.len()
}

fn input(n: u64) -> InputRef { InputRef { id: 13_000_000 + n, generation: 13 } }

fn handoff(input: InputRef, status: u8, round: u64, digest: [u8; 32]) -> Handoff {
    Handoff { from_epoch: OLD_EPOCH, to_epoch: NEW_EPOCH, input, status, round, digest }
}

fn controller() -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec013-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    println!("CALIBRE SECURITY SEC-013 v0.13.0");
    println!("CROSS-EPOCH COMMITTEE HANDOFF / MONETARY UNICITY ACROSS ROTATION");
    println!("Old committee: epoch {OLD_EPOCH}, N=7 Q=5; New committee: epoch {NEW_EPOCH}, N=7 Q=5");
    println!("Old and new committee signing-key sets are deliberately disjoint (zero membership overlap in this experiment)");
    println!("Seven old + seven new certifier OS processes communicate over real 127.0.0.1 TCP");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!();

    let mut old_nodes = Vec::new();
    let mut new_nodes = Vec::new();
    for i in 0..N {
        old_nodes.push(NodeProc::spawn(&exe, Role::Old, i, free_port()?, root.join(format!("old-{i}.wal")), i < 2)?);
        new_nodes.push(NodeProc::spawn(&exe, Role::New, i, free_port()?, root.join(format!("new-{i}.wal")), i < 2)?);
    }

    // 1. Finalized state handoff: a consumed input must stay consumed after committee rotation.
    let i1 = input(1); let a1 = digest_for(i1, b'A'); let b1 = digest_for(i1, b'B');
    let h1 = handoff(i1, STATUS_FINAL, 9, a1);
    let c1 = collect_old(&old_nodes, &[0,1,2,3,4], h1);
    if !verify_handoff_cert_for_new_epoch(&c1) { return Err("finalized old handoff certificate failed".into()); }
    let ac1 = collect_activation(&new_nodes, &[0,1,2,3,4], &c1);
    if !verify_activation_cert(&ac1, &c1) { return Err("new activation certificate failed for finalized handoff".into()); }
    let final_conflict_votes = count_new_votes(&new_nodes, &[2,3,4,5,6], &c1, &ac1, b1);
    if final_conflict_votes != 0 { return Err(format!("finalized input revived after rotation: {final_conflict_votes} honest votes")); }
    println!("FINALIZED OLD-EPOCH INPUT HANDOFF: NEW COMMITTEE ACTIVATES 5/7; CONFLICTING SUCCESSOR GETS 0 HONEST VOTES -> PASS");

    // 2. Locked but not finalized state: new committee must continue the inherited lock.
    let i2 = input(2); let a2 = digest_for(i2, b'A'); let b2 = digest_for(i2, b'B');
    let h2 = handoff(i2, STATUS_LOCKED, 7, a2);
    let c2 = collect_old(&old_nodes, &[0,1,2,3,4], h2);
    let ac2 = collect_activation(&new_nodes, &[2,3,4,5,6], &c2);
    if !verify_handoff_cert_for_new_epoch(&c2) || !verify_activation_cert(&ac2, &c2) { return Err("locked handoff activation failed".into()); }
    let inherited = count_new_votes(&new_nodes, &[2,3,4,5,6], &c2, &ac2, a2);
    let conflict = count_new_votes(&new_nodes, &[2,3,4,5,6], &c2, &ac2, b2);
    if inherited != 5 || conflict != 0 { return Err(format!("locked handoff enforcement failed: inherited={inherited} conflict={conflict}")); }
    println!("LOCKED OLD-EPOCH STATE HANDOFF: NEW COMMITTEE VOTES INHERITED DIGEST 5/7, CONFLICTING DIGEST 0/7 HONEST -> PASS");

    // 3. f<=2 handoff unicity: after one 5/7 handoff, a conflicting handoff cannot reach 5/7.
    let i3 = input(3); let a3 = digest_for(i3, b'A'); let b3 = digest_for(i3, b'B');
    let ha3 = handoff(i3, STATUS_LOCKED, 8, a3); let hb3 = handoff(i3, STATUS_LOCKED, 8, b3);
    let ca3 = collect_old(&old_nodes, &[0,1,2,3,4], ha3);
    if !verify_handoff_cert_for_new_epoch(&ca3) { return Err("primary f2 handoff did not reach quorum".into()); }
    old_nodes[2].crash_restart(&exe)?;
    if rpc_old_sign(old_nodes[2].port, &hb3).is_some() { return Err("honest old node forgot handoff choice after restart".into()); }
    let cb3 = collect_old(&old_nodes, &[0,1,2,3,4,5,6], hb3);
    let cb_count = cb3.shares.iter().map(|s|s.index).collect::<HashSet<_>>().len();
    if cb_count >= Q { return Err(format!("conflicting f2 handoff reached quorum: {cb_count}/7")); }
    println!("F<=2 CONFLICTING OLD-COMMITTEE HANDOFF: FIRST CERTIFICATE 5/7; CONFLICTING CERTIFICATE ONLY {cb_count}/7; RESTARTED HONEST SIGNER REMEMBERS CHOICE -> PASS");

    // 4. New committee refuses an insufficient old handoff certificate.
    let i4 = input(4); let a4 = digest_for(i4, b'A');
    let h4 = handoff(i4, STATUS_LOCKED, 1, a4);
    let c4 = collect_old(&old_nodes, &[0,1,2,3], h4);
    let c4_count = c4.shares.iter().map(|s|s.index).collect::<HashSet<_>>().len();
    if c4_count != 4 { return Err(format!("expected 4 old shares, got {c4_count}")); }
    let mut accepted = 0;
    for i in 2..7 { if rpc_activate(new_nodes[i].port, &c4).is_some() { accepted += 1; } }
    if accepted != 0 { return Err(format!("new honest nodes activated insufficient handoff: {accepted}")); }
    println!("INSUFFICIENT OLD HANDOFF 4/7: NEW HONEST COMMITTEE ACTIVATION SHARES=0 -> PASS");

    // 5. Cryptographically valid but wrong target epoch is rejected by the new committee.
    let i5 = input(5); let a5 = digest_for(i5, b'A');
    let wrong = Handoff { from_epoch: OLD_EPOCH, to_epoch: NEW_EPOCH + 1, input: i5, status: STATUS_LOCKED, round: 2, digest: a5 };
    let c5 = collect_old(&old_nodes, &[0,1,2,3,4], wrong);
    if !verify_handoff_cert_any(&c5) { return Err("wrong-epoch certificate should still be cryptographically valid".into()); }
    let mut wrong_accept = 0;
    for i in 2..7 { if rpc_activate(new_nodes[i].port, &c5).is_some() { wrong_accept += 1; } }
    if wrong_accept != 0 { return Err(format!("wrong target epoch activated by {wrong_accept} honest new nodes")); }
    println!("WRONG TARGET-EPOCH HANDOFF: CRYPTOGRAPHIC 5/7 OLD CERT VALID, BUT EPOCH-13 NEW COMMITTEE REJECTS IT -> PASS");

    // 6. Partial new activation pauses; after heal the same handoff reaches 5/7 and voting proceeds.
    let i6 = input(6); let a6 = digest_for(i6, b'A');
    let h6 = handoff(i6, STATUS_LOCKED, 3, a6);
    let c6 = collect_old(&old_nodes, &[0,1,2,3,4], h6);
    let partial = collect_activation(&new_nodes, &[2,3,4], &c6);
    if partial.shares.len() != 3 || verify_activation_cert(&partial, &c6) { return Err("partial activation unexpectedly reached quorum".into()); }
    let full = collect_activation(&new_nodes, &[2,3,4,5,6], &c6);
    if !verify_activation_cert(&full, &c6) { return Err("activation did not recover after heal".into()); }
    let live6 = count_new_votes(&new_nodes, &[2,3,4,5,6], &c6, &full, a6);
    if live6 != 5 { return Err(format!("post-heal new committee did not continue inherited state: {live6}/7")); }
    println!("NEW-COMMITTEE ACTIVATION SPLIT 3/7: NO ACTIVATION QC; AFTER HEAL SAME HANDOFF REACHES 5/7 AND INHERITED STATE CONTINUES -> PASS");

    // 7. New committee activation choice survives process crash/restart.
    let i7 = input(7); let a7 = digest_for(i7, b'A'); let b7 = digest_for(i7, b'B');
    let h7 = handoff(i7, STATUS_LOCKED, 4, a7);
    let c7 = collect_old(&old_nodes, &[0,1,2,3,4], h7);
    if rpc_activate(new_nodes[2].port, &c7).is_none() { return Err("new node 2 failed initial activation".into()); }
    new_nodes[2].crash_restart(&exe)?;
    if rpc_activate(new_nodes[2].port, &c7).is_none() { return Err("new node 2 lost activation after restart".into()); }
    let ac7 = collect_activation(&new_nodes, &[2,3,4,5,6], &c7);
    if !verify_activation_cert(&ac7, &c7) { return Err("activation QC failed after restart".into()); }
    if rpc_new_vote(new_nodes[2].port, &c7, &ac7, a7).is_none() || rpc_new_vote(new_nodes[2].port, &c7, &ac7, b7).is_some() {
        return Err("restarted new node failed inherited lock enforcement".into());
    }
    println!("NEW-COMMITTEE PROCESS RESTART: DURABLE ACTIVATION SURVIVES; INHERITED DIGEST ACCEPTED, CONFLICT REJECTED -> PASS");

    // 8. Expected f=3 old-committee boundary: two conflicting 5/7 handoff certificates become reachable.
    let f3root = root.join("f3"); fs::create_dir_all(&f3root).map_err(|e| e.to_string())?;
    let mut f3 = Vec::new();
    for i in 0..N { f3.push(NodeProc::spawn(&exe, Role::Old, i, free_port()?, f3root.join(format!("old-{i}.wal")), i < 3)?); }
    let i8 = input(8); let a8 = digest_for(i8, b'A'); let b8 = digest_for(i8, b'B');
    let ha8 = handoff(i8, STATUS_LOCKED, 5, a8); let hb8 = handoff(i8, STATUS_LOCKED, 5, b8);
    let ca8 = collect_old(&f3, &[0,1,2,3,4], ha8);
    let cb8 = collect_old(&f3, &[0,1,2,5,6], hb8);
    let f3a = verify_handoff_cert_for_new_epoch(&ca8); let f3b = verify_handoff_cert_for_new_epoch(&cb8);
    if !f3a || !f3b { return Err("expected f3 dual handoff boundary was not reproduced".into()); }
    println!("F=3 EXPECTED OLD-COMMITTEE BOUNDARY: TWO CONFLICTING 5-OF-7 HANDOFF CERTIFICATES PRODUCED -> ATTACK CONFIRMED");
    for n in &mut f3 { n.stop(); }

    for n in &mut old_nodes { n.stop(); }
    for n in &mut new_nodes { n.stop(); }
    let _ = fs::remove_dir_all(&root);

    println!();
    println!("=== SEC-013 DECISION ===");
    println!("ZERO-OVERLAP OLD->NEW COMMITTEE HANDOFF WITH 5/7 OLD CERT + 5/7 NEW ACTIVATION: PASS IN TESTED SCENARIOS");
    println!("FINALIZED MONETARY INPUT CANNOT BE REVIVED BY NEW COMMITTEE: PASS");
    println!("INHERITED OLD-EPOCH QC LOCK CONSTRAINS NEW-EPOCH VOTES TO SAME DIGEST: PASS");
    println!("F<=2 CONFLICTING HANDOFF CERTIFICATE SAFETY + OLD-SIGNER RESTART MEMORY: PASS");
    println!("INSUFFICIENT / WRONG-EPOCH HANDOFF REJECTION: PASS");
    println!("NEW-COMMITTEE ACTIVATION PAUSES BELOW QUORUM AND RECOVERS AFTER HEAL: PASS");
    println!("NEW-COMMITTEE ACTIVATION SURVIVES PROCESS RESTART: PASS");
    println!("F=3 OLD-COMMITTEE HANDOFF SAFETY: FAIL AT EXPECTED 5-OF-7 QUORUM BOUNDARY / ATTACK CONFIRMED");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    println!("FULL PRODUCTION EPOCH ROTATION / MEMBERSHIP SELECTION / SYBIL RESISTANCE: NOT PROVEN");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("--old-node") | Some("--new-node") => {
            if args.len() != 6 {
                Err("node usage: --old-node|--new-node <index> <port> <wal> <byzantine 0|1>".into())
            } else {
                let index = args[2].parse::<usize>().map_err(|e| e.to_string());
                let port = args[3].parse::<u16>().map_err(|e| e.to_string());
                match (index, port) {
                    (Ok(index), Ok(port)) => {
                        if args[1] == "--old-node" {
                            run_old_node(index, port, PathBuf::from(&args[4]), args[5] == "1")
                        } else {
                            run_new_node(index, port, PathBuf::from(&args[4]), args[5] == "1")
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => Err(e),
                }
            }
        }
        _ => controller(),
    };
    if let Err(e) = result {
        eprintln!("SEC-013 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_intersection_is_three() {
        assert_eq!(Q + Q - N, 3);
        assert!(Q + Q - N > 2);
    }

    #[test]
    fn old_and_new_key_domains_are_disjoint() {
        for i in 0..N {
            assert_ne!(old_key(i).verifying_key().to_bytes(), new_key(i).verifying_key().to_bytes());
        }
    }

    #[test]
    fn handoff_hash_binds_epoch_status_round_and_digest() {
        let i = input(99); let a = digest_for(i, b'A'); let b = digest_for(i, b'B');
        let h1 = handoff(i, STATUS_LOCKED, 1, a);
        let h2 = handoff(i, STATUS_FINAL, 1, a);
        let h3 = handoff(i, STATUS_LOCKED, 2, a);
        let h4 = handoff(i, STATUS_LOCKED, 1, b);
        assert_ne!(handoff_hash(&h1), handoff_hash(&h2));
        assert_ne!(handoff_hash(&h1), handoff_hash(&h3));
        assert_ne!(handoff_hash(&h1), handoff_hash(&h4));
    }

    #[test]
    fn five_unique_old_shares_make_valid_certificate() {
        let i = input(100); let a = digest_for(i, b'A'); let h = handoff(i, STATUS_LOCKED, 3, a); let hash = handoff_hash(&h);
        let mut shares = Vec::new();
        for idx in 0..5 {
            shares.push(OldShare { index: idx, signature: old_key(idx).sign(&old_share_message(&hash, idx)).to_bytes() });
        }
        assert!(verify_handoff_cert_for_new_epoch(&HandoffCert { handoff: h, shares }));
    }

    #[test]
    fn four_old_shares_are_insufficient() {
        let i = input(101); let a = digest_for(i, b'A'); let h = handoff(i, STATUS_LOCKED, 3, a); let hash = handoff_hash(&h);
        let mut shares = Vec::new();
        for idx in 0..4 {
            shares.push(OldShare { index: idx, signature: old_key(idx).sign(&old_share_message(&hash, idx)).to_bytes() });
        }
        assert!(!verify_handoff_cert_for_new_epoch(&HandoffCert { handoff: h, shares }));
    }
}
