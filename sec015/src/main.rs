use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey};
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
const E0: u64 = 30;
const E1: u64 = 31;
const E2: u64 = 32;
const COIN_ID: u64 = 15_000_001;

const OP_PING: u8 = 0;
const OP_FINALIZE: u8 = 1;
const OP_HANDOFF: u8 = 2;
const OP_ACTIVATE: u8 = 3;
const OP_FRESHNESS: u8 = 4;
const OP_SHUTDOWN: u8 = 255;

const K_ACTIVE: u8 = 1;
const K_TRANSFER: u8 = 2;
const K_RETIRED: u8 = 3;
const K_ACTIVATED: u8 = 4;
const WAL_MAGIC: [u8; 8] = *b"CAL015ST";
const WAL_RECORD: usize = 144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct StateRef {
    coin_id: u64,
    generation: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Finality {
    epoch: u64,
    from: StateRef,
    successor_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct FinalShare {
    index: usize,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct FinalCert {
    finality: Finality,
    shares: Vec<FinalShare>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handoff {
    from_epoch: u64,
    to_epoch: u64,
    state: StateRef,
}

#[derive(Clone, Copy, Debug)]
struct HandoffShare {
    index: usize,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct HandoffCert {
    handoff: Handoff,
    shares: Vec<HandoffShare>,
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
struct FreshShare {
    index: usize,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct FreshCert {
    epoch: u64,
    state: StateRef,
    nonce: [u8; 32],
    shares: Vec<FreshShare>,
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn committee_key(epoch: u64, index: usize) -> SigningKey {
    deterministic_key(
        b"CALIBRE_SEC015_COMMITTEE_KEY_V1",
        epoch.wrapping_mul(1000).wrapping_add(index as u64),
    )
}

fn genesis_state() -> StateRef {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC015_GENESIS_STATE_V1");
    h.update(&COIN_ID.to_le_bytes());
    StateRef { coin_id: COIN_ID, generation: 0, digest: *h.finalize().as_bytes() }
}

fn successor_digest(from: StateRef, label: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC015_SUCCESSOR_V1");
    h.update(&from.coin_id.to_le_bytes());
    h.update(&from.generation.to_le_bytes());
    h.update(&from.digest);
    h.update(label);
    *h.finalize().as_bytes()
}

fn successor_state(f: Finality) -> StateRef {
    StateRef { coin_id: f.from.coin_id, generation: f.from.generation + 1, digest: f.successor_digest }
}

fn finality_message(f: &Finality) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC015_FINALITY_V1");
    out.extend_from_slice(&f.epoch.to_le_bytes());
    out.extend_from_slice(&f.from.coin_id.to_le_bytes());
    out.extend_from_slice(&f.from.generation.to_le_bytes());
    out.extend_from_slice(&f.from.digest);
    out.extend_from_slice(&f.successor_digest);
    out
}

fn final_share_message(f: &Finality, index: usize) -> Vec<u8> {
    let mut out = finality_message(f);
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out
}

fn handoff_message(h: &Handoff) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC015_HANDOFF_V1");
    out.extend_from_slice(&h.from_epoch.to_le_bytes());
    out.extend_from_slice(&h.to_epoch.to_le_bytes());
    out.extend_from_slice(&h.state.coin_id.to_le_bytes());
    out.extend_from_slice(&h.state.generation.to_le_bytes());
    out.extend_from_slice(&h.state.digest);
    out
}

fn handoff_hash(h: &Handoff) -> [u8; 32] {
    *blake3::hash(&handoff_message(h)).as_bytes()
}

fn handoff_share_message(h: &Handoff, index: usize) -> Vec<u8> {
    let mut out = handoff_message(h);
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out
}

fn activation_message(epoch: u64, hash: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC015_ACTIVATION_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(hash);
    out
}

fn freshness_message(epoch: u64, state: StateRef, nonce: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC015_FRESHNESS_CHALLENGE_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&state.coin_id.to_le_bytes());
    out.extend_from_slice(&state.generation.to_le_bytes());
    out.extend_from_slice(&state.digest);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out
}

fn verify_final_share(f: &Finality, s: &FinalShare) -> bool {
    if s.index >= N { return false; }
    committee_key(f.epoch, s.index)
        .verifying_key()
        .verify_strict(&final_share_message(f, s.index), &Signature::from_bytes(&s.signature))
        .is_ok()
}

fn verify_final_cert(cert: &FinalCert) -> bool {
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_final_share(&cert.finality, s) { return false; }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_handoff_share(h: &Handoff, s: &HandoffShare) -> bool {
    if s.index >= N { return false; }
    committee_key(h.from_epoch, s.index)
        .verifying_key()
        .verify_strict(&handoff_share_message(h, s.index), &Signature::from_bytes(&s.signature))
        .is_ok()
}

fn verify_handoff_cert(cert: &HandoffCert) -> bool {
    if cert.handoff.to_epoch != cert.handoff.from_epoch + 1 { return false; }
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_handoff_share(&cert.handoff, s) { return false; }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_activation_share(epoch: u64, hash: &[u8; 32], s: &ActivationShare) -> bool {
    if s.index >= N { return false; }
    committee_key(epoch, s.index)
        .verifying_key()
        .verify_strict(&activation_message(epoch, hash, s.index), &Signature::from_bytes(&s.signature))
        .is_ok()
}

fn verify_activation_cert(cert: &ActivationCert, handoff: &HandoffCert) -> bool {
    if !verify_handoff_cert(handoff) || cert.handoff_hash != handoff_hash(&handoff.handoff) { return false; }
    let epoch = handoff.handoff.to_epoch;
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_activation_share(epoch, &cert.handoff_hash, s) { return false; }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_fresh_share(epoch: u64, state: StateRef, nonce: &[u8; 32], s: &FreshShare) -> bool {
    if s.index >= N { return false; }
    committee_key(epoch, s.index)
        .verifying_key()
        .verify_strict(&freshness_message(epoch, state, nonce, s.index), &Signature::from_bytes(&s.signature))
        .is_ok()
}

fn verify_fresh_cert(cert: &FreshCert) -> bool {
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_fresh_share(cert.epoch, cert.state, &cert.nonce, s) { return false; }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn wal_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC015_WAL_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_record(kind: u8, epoch: u64, generation: u64, aux_epoch: u64, d1: [u8; 32], d2: [u8; 32]) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&WAL_MAGIC);
    out[8] = kind;
    out[16..24].copy_from_slice(&epoch.to_le_bytes());
    out[24..32].copy_from_slice(&COIN_ID.to_le_bytes());
    out[32..40].copy_from_slice(&generation.to_le_bytes());
    out[40..48].copy_from_slice(&aux_epoch.to_le_bytes());
    out[48..80].copy_from_slice(&d1);
    out[80..112].copy_from_slice(&d2);
    let c = wal_checksum(&out[..112]);
    out[112..144].copy_from_slice(&c);
    out
}

fn decode_record(rec: &[u8]) -> Result<(u8, u64, u64, u64, [u8; 32], [u8; 32]), String> {
    if rec.len() != WAL_RECORD || rec[0..8] != WAL_MAGIC { return Err("bad SEC-015 WAL record".into()); }
    if rec[112..144] != wal_checksum(&rec[..112]) { return Err("SEC-015 WAL checksum mismatch".into()); }
    let kind = rec[8];
    if !matches!(kind, K_ACTIVE | K_TRANSFER | K_RETIRED | K_ACTIVATED) { return Err("unknown SEC-015 WAL kind".into()); }
    let epoch = u64::from_le_bytes(rec[16..24].try_into().unwrap());
    let coin_id = u64::from_le_bytes(rec[24..32].try_into().unwrap());
    if coin_id != COIN_ID { return Err("wrong coin id in WAL".into()); }
    let generation = u64::from_le_bytes(rec[32..40].try_into().unwrap());
    let aux_epoch = u64::from_le_bytes(rec[40..48].try_into().unwrap());
    let mut d1 = [0u8; 32]; d1.copy_from_slice(&rec[48..80]);
    let mut d2 = [0u8; 32]; d2.copy_from_slice(&rec[80..112]);
    Ok((kind, epoch, generation, aux_epoch, d1, d2))
}

struct Store {
    file: File,
    epoch: u64,
    active: Option<StateRef>,
    transfers: HashMap<u64, [u8; 32]>,
    retired: HashMap<StateRef, [u8; 32]>,
    activations: HashMap<(u64, u64), [u8; 32]>,
}

impl Store {
    fn open(path: &Path, epoch: u64) -> Result<Self, String> {
        if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        let mut file = OpenOptions::new().read(true).write(true).create(true).open(path).map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.len() % WAL_RECORD != 0 { return Err("incomplete SEC-015 WAL record; fail closed".into()); }
        let mut s = Self { file, epoch, active: None, transfers: HashMap::new(), retired: HashMap::new(), activations: HashMap::new() };
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let (kind, rec_epoch, generation, aux, d1, d2) = decode_record(rec)?;
            if rec_epoch != epoch { return Err("SEC-015 WAL epoch mismatch".into()); }
            match kind {
                K_ACTIVE => s.active = Some(StateRef { coin_id: COIN_ID, generation, digest: d1 }),
                K_TRANSFER => {
                    if let Some(old) = s.transfers.insert(generation, d2) {
                        if old != d2 { return Err("conflicting durable transfer choice".into()); }
                    }
                    s.active = Some(StateRef { coin_id: COIN_ID, generation: generation + 1, digest: d2 });
                }
                K_RETIRED => {
                    let state = StateRef { coin_id: COIN_ID, generation, digest: d1 };
                    if let Some(old) = s.retired.insert(state, d2) {
                        if old != d2 { return Err("conflicting durable retirement".into()); }
                    }
                    if s.active == Some(state) { s.active = None; }
                }
                K_ACTIVATED => {
                    if let Some(old) = s.activations.insert((aux, generation), d2) {
                        if old != d2 { return Err("conflicting durable activation".into()); }
                    }
                    s.active = Some(StateRef { coin_id: COIN_ID, generation, digest: d1 });
                }
                _ => unreachable!(),
            }
        }
        s.file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        Ok(s)
    }

    fn append(&mut self, rec: [u8; WAL_RECORD]) -> Result<(), String> {
        self.file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        self.file.write_all(&rec).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())
    }

    fn bootstrap(&mut self, state: StateRef) -> Result<(), String> {
        if self.active.is_some() { return Ok(()); }
        self.append(encode_record(K_ACTIVE, self.epoch, state.generation, 0, state.digest, [0u8; 32]))?;
        self.active = Some(state);
        Ok(())
    }

    fn finalize(&mut self, f: &Finality) -> Result<bool, String> {
        if f.epoch != self.epoch || self.active != Some(f.from) { return Ok(false); }
        if let Some(old) = self.transfers.get(&f.from.generation) { return Ok(old == &f.successor_digest); }
        self.append(encode_record(K_TRANSFER, self.epoch, f.from.generation, 0, f.from.digest, f.successor_digest))?;
        self.transfers.insert(f.from.generation, f.successor_digest);
        self.active = Some(successor_state(*f));
        Ok(true)
    }

    fn retire(&mut self, h: &Handoff) -> Result<bool, String> {
        if h.from_epoch != self.epoch || h.to_epoch != self.epoch + 1 || self.active != Some(h.state) { return Ok(false); }
        let hash = handoff_hash(h);
        if let Some(old) = self.retired.get(&h.state) { return Ok(old == &hash); }
        self.append(encode_record(K_RETIRED, self.epoch, h.state.generation, h.to_epoch, h.state.digest, hash))?;
        self.retired.insert(h.state, hash);
        self.active = None;
        Ok(true)
    }

    fn activate(&mut self, h: &Handoff) -> Result<bool, String> {
        if h.to_epoch != self.epoch || h.from_epoch + 1 != self.epoch { return Ok(false); }
        let hash = handoff_hash(h);
        let key = (h.from_epoch, h.state.generation);
        if let Some(old) = self.activations.get(&key) { return Ok(old == &hash && self.active == Some(h.state)); }
        if let Some(current) = self.active {
            if current != h.state { return Ok(false); }
        }
        self.append(encode_record(K_ACTIVATED, self.epoch, h.state.generation, h.from_epoch, h.state.digest, hash))?;
        self.activations.insert(key, hash);
        self.active = Some(h.state);
        Ok(true)
    }

    fn active_matches(&self, state: StateRef) -> bool { self.active == Some(state) }
}

fn write_u64(s: &mut TcpStream, v: u64) -> Result<(), String> { s.write_all(&v.to_le_bytes()).map_err(|e| e.to_string()) }
fn read_u64(s: &mut TcpStream) -> Result<u64, String> { let mut b=[0u8;8]; s.read_exact(&mut b).map_err(|e|e.to_string())?; Ok(u64::from_le_bytes(b)) }
fn read_arr32(s: &mut TcpStream) -> Result<[u8;32], String> { let mut b=[0u8;32]; s.read_exact(&mut b).map_err(|e|e.to_string())?; Ok(b) }
fn read_arr64(s: &mut TcpStream) -> Result<[u8;64], String> { let mut b=[0u8;64]; s.read_exact(&mut b).map_err(|e|e.to_string())?; Ok(b) }

fn write_state(s: &mut TcpStream, st: StateRef) -> Result<(), String> {
    write_u64(s, st.coin_id)?; write_u64(s, st.generation)?; s.write_all(&st.digest).map_err(|e|e.to_string())
}
fn read_state(s: &mut TcpStream) -> Result<StateRef, String> {
    Ok(StateRef { coin_id: read_u64(s)?, generation: read_u64(s)?, digest: read_arr32(s)? })
}
fn write_finality(s: &mut TcpStream, f: &Finality) -> Result<(), String> {
    write_u64(s, f.epoch)?; write_state(s, f.from)?; s.write_all(&f.successor_digest).map_err(|e|e.to_string())
}
fn read_finality(s: &mut TcpStream) -> Result<Finality, String> {
    Ok(Finality { epoch: read_u64(s)?, from: read_state(s)?, successor_digest: read_arr32(s)? })
}
fn write_handoff(s: &mut TcpStream, h: &Handoff) -> Result<(), String> {
    write_u64(s, h.from_epoch)?; write_u64(s, h.to_epoch)?; write_state(s, h.state)
}
fn read_handoff(s: &mut TcpStream) -> Result<Handoff, String> {
    Ok(Handoff { from_epoch: read_u64(s)?, to_epoch: read_u64(s)?, state: read_state(s)? })
}
fn write_handoff_cert(s: &mut TcpStream, cert: &HandoffCert) -> Result<(), String> {
    write_handoff(s, &cert.handoff)?;
    s.write_all(&[cert.shares.len() as u8]).map_err(|e|e.to_string())?;
    for sh in &cert.shares { s.write_all(&[sh.index as u8]).map_err(|e|e.to_string())?; s.write_all(&sh.signature).map_err(|e|e.to_string())?; }
    Ok(())
}
fn read_handoff_cert(s: &mut TcpStream) -> Result<HandoffCert, String> {
    let handoff = read_handoff(s)?;
    let mut n=[0u8;1]; s.read_exact(&mut n).map_err(|e|e.to_string())?;
    if n[0] as usize > N { return Err("oversized handoff cert".into()); }
    let mut shares=Vec::with_capacity(n[0] as usize);
    for _ in 0..n[0] { let mut idx=[0u8;1]; s.read_exact(&mut idx).map_err(|e|e.to_string())?; shares.push(HandoffShare{index:idx[0] as usize,signature:read_arr64(s)?}); }
    Ok(HandoffCert{handoff,shares})
}

fn run_node(epoch: u64, index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e|format!("bind epoch {epoch} node {index}: {e}"))?;
    let mut store = if byzantine { None } else { Some(Store::open(&wal, epoch)?) };
    if epoch == E0 {
        if let Some(st) = &mut store { st.bootstrap(genesis_state())?; }
    }
    let sk = committee_key(epoch, index);
    for conn in listener.incoming() {
        let mut s = match conn { Ok(s)=>s, Err(_)=>continue };
        let mut op=[0u8;1]; if s.read_exact(&mut op).is_err(){continue;}
        match op[0] {
            OP_PING => { let _=s.write_all(&[0xAA]); }
            OP_SHUTDOWN => { let _=s.write_all(&[0x55]); break; }
            OP_FINALIZE => {
                let f=read_finality(&mut s)?;
                let allowed = if byzantine { f.epoch==epoch } else { store.as_mut().unwrap().finalize(&f)? };
                if !allowed { let _=s.write_all(&[0]); continue; }
                let sig=sk.sign(&final_share_message(&f,index)).to_bytes();
                s.write_all(&[1,index as u8]).map_err(|e|e.to_string())?; s.write_all(&sig).map_err(|e|e.to_string())?;
            }
            OP_HANDOFF => {
                let h=read_handoff(&mut s)?;
                let allowed = if byzantine { h.from_epoch==epoch } else { store.as_mut().unwrap().retire(&h)? };
                if !allowed { let _=s.write_all(&[0]); continue; }
                let sig=sk.sign(&handoff_share_message(&h,index)).to_bytes();
                s.write_all(&[1,index as u8]).map_err(|e|e.to_string())?; s.write_all(&sig).map_err(|e|e.to_string())?;
            }
            OP_ACTIVATE => {
                let cert=read_handoff_cert(&mut s)?;
                let allowed = verify_handoff_cert(&cert) && cert.handoff.to_epoch==epoch && if byzantine { true } else { store.as_mut().unwrap().activate(&cert.handoff)? };
                if !allowed { let _=s.write_all(&[0]); continue; }
                let hash=handoff_hash(&cert.handoff);
                let sig=sk.sign(&activation_message(epoch,&hash,index)).to_bytes();
                s.write_all(&[1,index as u8]).map_err(|e|e.to_string())?; s.write_all(&sig).map_err(|e|e.to_string())?;
            }
            OP_FRESHNESS => {
                let req_epoch=read_u64(&mut s)?; let state=read_state(&mut s)?; let nonce=read_arr32(&mut s)?;
                let allowed = req_epoch==epoch && if byzantine { true } else { store.as_ref().unwrap().active_matches(state) };
                if !allowed { let _=s.write_all(&[0]); continue; }
                let sig=sk.sign(&freshness_message(epoch,state,&nonce,index)).to_bytes();
                s.write_all(&[1,index as u8]).map_err(|e|e.to_string())?; s.write_all(&sig).map_err(|e|e.to_string())?;
            }
            _ => { let _=s.write_all(&[0]); }
        }
    }
    Ok(())
}

fn free_port() -> Result<u16,String> {
    let l=TcpListener::bind(("127.0.0.1",0)).map_err(|e|e.to_string())?;
    Ok(l.local_addr().map_err(|e|e.to_string())?.port())
}

struct NodeProc {
    epoch:u64,
    index:usize,
    port:u16,
    wal:PathBuf,
    byzantine:bool,
    child:Child,
}

impl NodeProc {
    fn spawn(exe:&Path, epoch:u64, index:usize, port:u16, wal:PathBuf, byzantine:bool)->Result<Self,String>{
        let child=Command::new(exe).arg("--node").arg(epoch.to_string()).arg(index.to_string()).arg(port.to_string()).arg(&wal).arg(if byzantine{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|format!("spawn epoch {epoch} node {index}: {e}"))?;
        let mut n=Self{epoch,index,port,wal,byzantine,child}; n.wait_ready()?; Ok(n)
    }
    fn wait_ready(&mut self)->Result<(),String>{
        for _ in 0..400 { if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_PING]);let mut b=[0u8;1];if s.read_exact(&mut b).is_ok()&&b[0]==0xAA{return Ok(());}} thread::sleep(Duration::from_millis(5)); }
        Err(format!("epoch {} node {} not ready",self.epoch,self.index))
    }
    fn crash_restart(&mut self,exe:&Path)->Result<(),String>{
        let _=self.child.kill();let _=self.child.wait();self.port=free_port()?;
        self.child=Command::new(exe).arg("--node").arg(self.epoch.to_string()).arg(self.index.to_string()).arg(self.port.to_string()).arg(&self.wal).arg(if self.byzantine{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|format!("restart epoch {} node {}: {e}",self.epoch,self.index))?;
        self.wait_ready()
    }
    fn stop(&mut self){if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_SHUTDOWN]);}let _=self.child.wait();}
}

fn connect(port:u16)->Option<TcpStream>{
    let addr:SocketAddr=format!("127.0.0.1:{port}").parse().ok()?;
    let s=TcpStream::connect_timeout(&addr,Duration::from_millis(1000)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(1000))).ok();s.set_write_timeout(Some(Duration::from_millis(1000))).ok();Some(s)
}

fn rpc_finalize(port:u16,f:&Finality)->Option<FinalShare>{
    let mut s=connect(port)?;s.write_all(&[OP_FINALIZE]).ok()?;write_finality(&mut s,f).ok()?;let mut status=[0u8;1];s.read_exact(&mut status).ok()?;if status[0]==0{return None;}let mut idx=[0u8;1];s.read_exact(&mut idx).ok()?;let sh=FinalShare{index:idx[0] as usize,signature:read_arr64(&mut s).ok()?};if verify_final_share(f,&sh){Some(sh)}else{None}
}
fn collect_final(nodes:&[NodeProc],indices:&[usize],f:Finality)->FinalCert{
    let mut by=HashMap::new();for &i in indices{if let Some(sh)=rpc_finalize(nodes[i].port,&f){by.entry(sh.index).or_insert(sh);}}FinalCert{finality:f,shares:by.into_values().collect()}
}
fn rpc_handoff(port:u16,h:&Handoff)->Option<HandoffShare>{
    let mut s=connect(port)?;s.write_all(&[OP_HANDOFF]).ok()?;write_handoff(&mut s,h).ok()?;let mut status=[0u8;1];s.read_exact(&mut status).ok()?;if status[0]==0{return None;}let mut idx=[0u8;1];s.read_exact(&mut idx).ok()?;let sh=HandoffShare{index:idx[0] as usize,signature:read_arr64(&mut s).ok()?};if verify_handoff_share(h,&sh){Some(sh)}else{None}
}
fn collect_handoff(nodes:&[NodeProc],indices:&[usize],h:Handoff)->HandoffCert{
    let mut by=HashMap::new();for &i in indices{if let Some(sh)=rpc_handoff(nodes[i].port,&h){by.entry(sh.index).or_insert(sh);}}HandoffCert{handoff:h,shares:by.into_values().collect()}
}
fn rpc_activate(port:u16,cert:&HandoffCert)->Option<ActivationShare>{
    let mut s=connect(port)?;s.write_all(&[OP_ACTIVATE]).ok()?;write_handoff_cert(&mut s,cert).ok()?;let mut status=[0u8;1];s.read_exact(&mut status).ok()?;if status[0]==0{return None;}let mut idx=[0u8;1];s.read_exact(&mut idx).ok()?;let sh=ActivationShare{index:idx[0] as usize,signature:read_arr64(&mut s).ok()?};let hash=handoff_hash(&cert.handoff);if verify_activation_share(cert.handoff.to_epoch,&hash,&sh){Some(sh)}else{None}
}
fn collect_activation(nodes:&[NodeProc],indices:&[usize],cert:&HandoffCert)->ActivationCert{
    let hash=handoff_hash(&cert.handoff);let mut by=HashMap::new();for &i in indices{if let Some(sh)=rpc_activate(nodes[i].port,cert){by.entry(sh.index).or_insert(sh);}}ActivationCert{handoff_hash:hash,shares:by.into_values().collect()}
}
fn rpc_fresh(port:u16,epoch:u64,state:StateRef,nonce:[u8;32])->Option<FreshShare>{
    let mut s=connect(port)?;s.write_all(&[OP_FRESHNESS]).ok()?;write_u64(&mut s,epoch).ok()?;write_state(&mut s,state).ok()?;s.write_all(&nonce).ok()?;let mut status=[0u8;1];s.read_exact(&mut status).ok()?;if status[0]==0{return None;}let mut idx=[0u8;1];s.read_exact(&mut idx).ok()?;let sh=FreshShare{index:idx[0] as usize,signature:read_arr64(&mut s).ok()?};if verify_fresh_share(epoch,state,&nonce,&sh){Some(sh)}else{None}
}
fn collect_fresh(nodes:&[NodeProc],indices:&[usize],epoch:u64,state:StateRef,nonce:[u8;32])->FreshCert{
    let mut by=HashMap::new();for &i in indices{if let Some(sh)=rpc_fresh(nodes[i].port,epoch,state,nonce){by.entry(sh.index).or_insert(sh);}}FreshCert{epoch,state,nonce,shares:by.into_values().collect()}
}

fn nonce(label:&[u8])->[u8;32]{*blake3::hash(label).as_bytes()}

fn naive_prefix_valid(fc0:&FinalCert,h01:&HandoffCert,a01:&ActivationCert,fc1:&FinalCert)->bool{
    verify_final_cert(fc0)
        && successor_state(fc0.finality)==h01.handoff.state
        && verify_handoff_cert(h01)
        && verify_activation_cert(a01,h01)
        && fc1.finality.epoch==h01.handoff.to_epoch
        && fc1.finality.from==h01.handoff.state
        && verify_final_cert(fc1)
}

fn controller()->Result<(),String>{
    let exe=env::current_exe().map_err(|e|e.to_string())?;
    let root=env::temp_dir().join(format!("calibre-sec015-{}",std::process::id()));let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).map_err(|e|e.to_string())?;
    println!("CALIBRE SECURITY SEC-015 v0.15.0");
    println!("OFFLINE-CLIENT LONG-RANGE / STALE-PREFIX BOOTSTRAP ATTACK + LIVE FRESHNESS CHALLENGE");
    println!("Epochs {E0}->{E1}->{E2}; each N=7 Q=5; nodes 0 and 1 Byzantine in the f<=2 scenarios");
    println!("21 separate OS processes use real 127.0.0.1 TCP sockets on one physical host");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!("Candidate freshness rule: a claimed terminal committee must answer a client-unique nonce with 5/7 signatures over exact epoch+state+nonce");
    println!();

    let mut c0=Vec::new();let mut c1=Vec::new();let mut c2=Vec::new();
    for i in 0..N{
        c0.push(NodeProc::spawn(&exe,E0,i,free_port()?,root.join(format!("e0-{i}.wal")),i<2)?);
        c1.push(NodeProc::spawn(&exe,E1,i,free_port()?,root.join(format!("e1-{i}.wal")),i<2)?);
        c2.push(NodeProc::spawn(&exe,E2,i,free_port()?,root.join(format!("e2-{i}.wal")),i<2)?);
    }

    let s0=genesis_state();
    let f0=Finality{epoch:E0,from:s0,successor_digest:successor_digest(s0,b"ALICE_TO_BOB")};
    let fc0=collect_final(&c0,&[0,1,2,3,4,5,6],f0);if !verify_final_cert(&fc0){return Err("epoch-30 finality failed".into());}
    let s1=successor_state(f0);
    let h01=Handoff{from_epoch:E0,to_epoch:E1,state:s1};
    let hc01=collect_handoff(&c0,&[0,1,2,3,4],h01);if !verify_handoff_cert(&hc01){return Err("30->31 handoff failed".into());}
    let ac01=collect_activation(&c1,&[0,1,2,3,4,5,6],&hc01);if !verify_activation_cert(&ac01,&hc01){return Err("epoch-31 activation failed".into());}

    let f1=Finality{epoch:E1,from:s1,successor_digest:successor_digest(s1,b"BOB_TO_CAROL")};
    let fc1=collect_final(&c1,&[0,1,2,3,4,5,6],f1);if !verify_final_cert(&fc1){return Err("epoch-31 finality failed".into());}
    let s2=successor_state(f1);

    let old_nonce=nonce(b"SEC015-OLD-CLIENT-NONCE");
    let old_fresh=collect_fresh(&c1,&[0,1,2,3,4],E1,s2,old_nonce);
    if !verify_fresh_cert(&old_fresh){return Err("pre-handoff epoch-31 freshness baseline failed".into());}

    let h12=Handoff{from_epoch:E1,to_epoch:E2,state:s2};
    let hc12=collect_handoff(&c1,&[0,1,2,3,4],h12);if !verify_handoff_cert(&hc12){return Err("31->32 handoff failed".into());}
    let ac12=collect_activation(&c2,&[0,1,2,3,4,5,6],&hc12);if !verify_activation_cert(&ac12,&hc12){return Err("epoch-32 activation failed".into());}

    if !naive_prefix_valid(&fc0,&hc01,&ac01,&fc1){return Err("stale prefix should be cryptographically valid".into());}
    println!("NAIVE OFFLINE BOOTSTRAP USING ONLY VALID CERTIFICATE PREFIX: STALE EPOCH-31 / GENERATION-2 PREFIX IS ACCEPTABLE AS A VALID HISTORY PREFIX -> LONG-RANGE CURRENTNESS ATTACK CONFIRMED");
    println!("The stale prefix is not forged; the attack is omission of the later valid 31->32 handoff, so certificate validity alone does not prove currentness.");

    let fresh_nonce=nonce(b"SEC015-FRESH-CLIENT-NONCE");
    let stale_fresh=collect_fresh(&c1,&[0,1,2,3,4,5,6],E1,s2,fresh_nonce);
    let stale_count=stale_fresh.shares.iter().map(|s|s.index).collect::<HashSet<_>>().len();
    if stale_count>=Q{return Err(format!("retired stale epoch unexpectedly answered fresh challenge {stale_count}/7"));}
    println!("STALE TERMINAL EPOCH-31 AFTER 31->32 HANDOFF: FRESH CLIENT NONCE GETS {stale_count}/7 <5 -> STALE PREFIX REJECTED / FAIL-CLOSED: PASS");

    let mut replay=old_fresh.clone();replay.nonce=fresh_nonce;
    if verify_fresh_cert(&replay){return Err("old freshness certificate replayed under a new client nonce".into());}
    println!("REPLAY OF OLD 5/7 FRESHNESS CERTIFICATE AGAINST NEW NONCE: SIGNATURES NO LONGER VERIFY -> PASS");

    c1[2].crash_restart(&exe)?;
    if rpc_fresh(c1[2].port,E1,s2,fresh_nonce).is_some(){return Err("restarted retired honest epoch-31 signer answered freshness challenge".into());}
    println!("RESTARTED RETIRED EPOCH-31 HONEST SIGNER: RETIREMENT SURVIVES; FRESHNESS CHALLENGE REJECTED -> PASS");

    let current_fresh=collect_fresh(&c2,&[2,3,4,5,6],E2,s2,fresh_nonce);
    if !verify_fresh_cert(&current_fresh){return Err("current epoch-32 honest quorum failed freshness challenge".into());}
    println!("CURRENT EPOCH-32: FIVE HONEST NODES ANSWER EXACT EPOCH+STATE+NONCE -> 5/7 FRESHNESS CERTIFICATE PASS");

    let partial=collect_fresh(&c2,&[2,3,4],E2,s2,nonce(b"SEC015-PARTIAL"));
    if verify_fresh_cert(&partial){return Err("partial current committee unexpectedly made freshness quorum".into());}
    println!("ONLY 3/7 CURRENT HONEST NODES REACHABLE: NO FRESHNESS QC -> CLIENT MUST PAUSE RATHER THAN ACCEPT STALE STATE: SAFETY PASS / LIVENESS PAUSES");

    let boundary_nonce=nonce(b"SEC015-F3-BOUNDARY");
    let mut boundary_shares=Vec::new();
    for &i in &[0usize,1,2,5,6]{
        let sig=committee_key(E1,i).sign(&freshness_message(E1,s2,&boundary_nonce,i)).to_bytes();
        boundary_shares.push(FreshShare{index:i,signature:sig});
    }
    let boundary=FreshCert{epoch:E1,state:s2,nonce:boundary_nonce,shares:boundary_shares};
    if !verify_fresh_cert(&boundary){return Err("expected f=3 stale-freshness boundary witness missing".into());}
    println!("F=3 / THREE OLD KEYS COMPROMISED BOUNDARY: 3 BYZANTINE OLD KEYS + 2 NON-RETIRED HONEST SIGNERS CAN FORM STALE 5/7 FRESHNESS RESPONSE -> ATTACK WITNESS CONFIRMED");

    for n in &mut c0{n.stop();}for n in &mut c1{n.stop();}for n in &mut c2{n.stop();}let _=fs::remove_dir_all(&root);
    println!();println!("=== SEC-015 DECISION ===");
    println!("CERTIFICATE-ONLY OFFLINE CURRENTNESS: FAIL / STALE VALID PREFIX ATTACK CONFIRMED");
    println!("LIVE CLIENT-NONCE 5-OF-7 CURRENT-STATE FRESHNESS CHALLENGE WITH f<=2: PASS IN TESTED HANDOFF SCENARIO");
    println!("RETIRED COMMITTEE CANNOT ANSWER NEW 5/7 FRESHNESS CHALLENGE WITH f<=2 IN TESTED SCENARIO: PASS");
    println!("OLD FRESHNESS RESPONSE REPLAY ACROSS CLIENT NONCES: REJECTED");
    println!("RETIRED-SIGNER PROCESS RESTART MEMORY: PASS");
    println!("TOTAL ECLIPSE / <5 CURRENT NODES REACHABLE: CLIENT FAILS CLOSED; LIVENESS NOT GUARANTEED");
    println!("F=3 OR LATER COMPROMISE OF >=3 RETIRED COMMITTEE KEYS: STALE-FRESHNESS SAFETY FAILS AT EXPECTED BOUNDARY");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("TRUSTED WALL CLOCK REQUIRED BY THIS CANDIDATE: NO");
    println!("LIVE REACHABILITY TO A 5/7 ACTIVE COMMITTEE QUORUM: REQUIRED FOR FRESH CURRENTNESS");
    println!("FORWARD-SECURE KEY ERASURE / LONG-TERM OLD-KEY COMPROMISE RESISTANCE: NOT PROVEN");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    Ok(())
}

fn main(){
    let args:Vec<String>=env::args().collect();
    let result=if args.get(1).map(String::as_str)==Some("--node"){
        if args.len()!=7{Err("node usage: --node <epoch> <index> <port> <wal> <byzantine 0|1>".into())}else{
            let epoch=args[2].parse::<u64>().map_err(|e|e.to_string());
            let index=args[3].parse::<usize>().map_err(|e|e.to_string());
            let port=args[4].parse::<u16>().map_err(|e|e.to_string());
            match(epoch,index,port){
                (Ok(epoch),Ok(index),Ok(port))=>run_node(epoch,index,port,PathBuf::from(&args[5]),args[6]=="1"),
                (Err(e),_,_)|(_,Err(e),_)|(_,_,Err(e))=>Err(e),
            }
        }
    }else{controller()};
    if let Err(e)=result{eprintln!("SEC-015 ERROR: {e}");std::process::exit(1);}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn quorum_intersection_is_three(){assert_eq!(Q+Q-N,3);}
    #[test]fn direct_predecessor_required(){let s=genesis_state();let h=Handoff{from_epoch:E0,to_epoch:E2,state:s};let mut shares=Vec::new();for i in 0..5{shares.push(HandoffShare{index:i,signature:committee_key(E0,i).sign(&handoff_share_message(&h,i)).to_bytes()});}assert!(!verify_handoff_cert(&HandoffCert{handoff:h,shares}));}
    #[test]fn freshness_nonce_is_bound(){let s=genesis_state();let n1=nonce(b"a");let n2=nonce(b"b");let sig=committee_key(E0,0).sign(&freshness_message(E0,s,&n1,0)).to_bytes();let sh=FreshShare{index:0,signature:sig};assert!(verify_fresh_share(E0,s,&n1,&sh));assert!(!verify_fresh_share(E0,s,&n2,&sh));}
    #[test]fn four_fresh_shares_fail_five_pass(){let s=genesis_state();let n=nonce(b"q");let mut shares=Vec::new();for i in 0..4{shares.push(FreshShare{index:i,signature:committee_key(E0,i).sign(&freshness_message(E0,s,&n,i)).to_bytes()});}let mut c=FreshCert{epoch:E0,state:s,nonce:n,shares};assert!(!verify_fresh_cert(&c));let i=4;c.shares.push(FreshShare{index:i,signature:committee_key(E0,i).sign(&freshness_message(E0,s,&n,i)).to_bytes()});assert!(verify_fresh_cert(&c));}
    #[test]fn finality_changes_generation(){let s=genesis_state();let f=Finality{epoch:E0,from:s,successor_digest:successor_digest(s,b"x")};let n=successor_state(f);assert_eq!(n.generation,s.generation+1);assert_ne!(n.digest,s.digest);}
}
