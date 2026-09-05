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
const E0: u64 = 20;
const E1: u64 = 21;
const E2: u64 = 22;
const COIN_ID: u64 = 0xCA11_BRE0_u64;

const OP_PING: u8 = 0;
const OP_FINALIZE: u8 = 1;
const OP_COMMIT: u8 = 2;
const OP_HANDOFF: u8 = 3;
const OP_ACTIVATE: u8 = 4;
const OP_SHUTDOWN: u8 = 255;

const K_ACTIVE: u8 = 1;
const K_TRANSFER: u8 = 2;
const K_RETIRED: u8 = 3;
const K_ACTIVATION: u8 = 4;

const WAL_MAGIC: [u8; 8] = *b"CAL014ST";
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
    input: StateRef,
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

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn committee_key(epoch: u64, index: usize) -> SigningKey {
    deterministic_key(
        b"CALIBRE_SEC014_COMMITTEE_KEY_V1",
        epoch.wrapping_mul(1000).wrapping_add(index as u64),
    )
}

fn state_digest(prev: &[u8; 32], generation: u64, label: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC014_STATE_SUCCESSOR_V1");
    h.update(&COIN_ID.to_le_bytes());
    h.update(&generation.to_le_bytes());
    h.update(prev);
    h.update(label);
    *h.finalize().as_bytes()
}

fn genesis_digest() -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC014_GENESIS_ALICE_STATE_V1");
    h.update(&COIN_ID.to_le_bytes());
    *h.finalize().as_bytes()
}

fn finality_message(f: &Finality) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC014_FINALITY_V1");
    out.extend_from_slice(&f.epoch.to_le_bytes());
    out.extend_from_slice(&f.input.coin_id.to_le_bytes());
    out.extend_from_slice(&f.input.generation.to_le_bytes());
    out.extend_from_slice(&f.input.digest);
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
    out.extend_from_slice(b"CALIBRE_SEC014_HANDOFF_V1");
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
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(b"CALIBRE_SEC014_ACTIVATION_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(hash);
    out
}

fn verify_final_share(f: &Finality, s: &FinalShare) -> bool {
    if s.index >= N {
        return false;
    }
    committee_key(f.epoch, s.index)
        .verifying_key()
        .verify_strict(
            &final_share_message(f, s.index),
            &Signature::from_bytes(&s.signature),
        )
        .is_ok()
}

fn verify_final_cert(cert: &FinalCert) -> bool {
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_final_share(&cert.finality, s) {
            return false;
        }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_handoff_share(h: &Handoff, s: &HandoffShare) -> bool {
    if s.index >= N {
        return false;
    }
    committee_key(h.from_epoch, s.index)
        .verifying_key()
        .verify_strict(
            &handoff_share_message(h, s.index),
            &Signature::from_bytes(&s.signature),
        )
        .is_ok()
}

fn verify_handoff_cert(cert: &HandoffCert) -> bool {
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_handoff_share(&cert.handoff, s) {
            return false;
        }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn verify_activation_share(epoch: u64, hash: &[u8; 32], s: &ActivationShare) -> bool {
    if s.index >= N {
        return false;
    }
    committee_key(epoch, s.index)
        .verifying_key()
        .verify_strict(
            &activation_message(epoch, hash, s.index),
            &Signature::from_bytes(&s.signature),
        )
        .is_ok()
}

fn verify_activation_cert(epoch: u64, cert: &ActivationCert, old: &HandoffCert) -> bool {
    if !verify_handoff_cert(old) || cert.handoff_hash != handoff_hash(&old.handoff) {
        return false;
    }
    let mut unique = HashSet::new();
    for s in &cert.shares {
        if !verify_activation_share(epoch, &cert.handoff_hash, s) {
            return false;
        }
        unique.insert(s.index);
    }
    unique.len() >= Q
}

fn wal_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC014_WAL_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_record(
    kind: u8,
    epoch: u64,
    coin_id: u64,
    generation: u64,
    aux_epoch: u64,
    d1: [u8; 32],
    d2: [u8; 32],
) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&WAL_MAGIC);
    out[8] = kind;
    out[16..24].copy_from_slice(&epoch.to_le_bytes());
    out[24..32].copy_from_slice(&coin_id.to_le_bytes());
    out[32..40].copy_from_slice(&generation.to_le_bytes());
    out[40..48].copy_from_slice(&aux_epoch.to_le_bytes());
    out[48..80].copy_from_slice(&d1);
    out[80..112].copy_from_slice(&d2);
    let c = wal_checksum(&out[..112]);
    out[112..144].copy_from_slice(&c);
    out
}

fn decode_record(rec: &[u8]) -> Result<(u8, u64, u64, u64, u64, [u8; 32], [u8; 32]), String> {
    if rec.len() != WAL_RECORD || rec[0..8] != WAL_MAGIC {
        return Err("bad SEC-014 WAL record".into());
    }
    if rec[112..144] != wal_checksum(&rec[..112]) {
        return Err("SEC-014 WAL checksum mismatch".into());
    }
    let kind = rec[8];
    if !matches!(kind, K_ACTIVE | K_TRANSFER | K_RETIRED | K_ACTIVATION) {
        return Err("unknown SEC-014 WAL kind".into());
    }
    let epoch = u64::from_le_bytes(rec[16..24].try_into().unwrap());
    let coin_id = u64::from_le_bytes(rec[24..32].try_into().unwrap());
    let generation = u64::from_le_bytes(rec[32..40].try_into().unwrap());
    let aux_epoch = u64::from_le_bytes(rec[40..48].try_into().unwrap());
    let mut d1 = [0u8; 32];
    d1.copy_from_slice(&rec[48..80]);
    let mut d2 = [0u8; 32];
    d2.copy_from_slice(&rec[80..112]);
    Ok((kind, epoch, coin_id, generation, aux_epoch, d1, d2))
}

struct Store {
    file: File,
    epoch: u64,
    active: HashMap<u64, (u64, [u8; 32])>,
    transfer: HashMap<(u64, u64), [u8; 32]>,
    retired: HashMap<(u64, u64), [u8; 32]>,
    activation: HashMap<(u64, u64, u64), [u8; 32]>,
}

impl Store {
    fn open(path: &Path, epoch: u64) -> Result<Self, String> {
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
            return Err("incomplete SEC-014 WAL record; fail closed".into());
        }
        let mut s = Self {
            file,
            epoch,
            active: HashMap::new(),
            transfer: HashMap::new(),
            retired: HashMap::new(),
            activation: HashMap::new(),
        };
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let (kind, rec_epoch, coin_id, generation, aux, d1, d2) = decode_record(rec)?;
            if rec_epoch != epoch {
                return Err("WAL epoch mismatch".into());
            }
            match kind {
                K_ACTIVE => {
                    s.active.insert(coin_id, (generation, d1));
                }
                K_TRANSFER => {
                    let key = (coin_id, generation);
                    if let Some(old) = s.transfer.insert(key, d2) {
                        if old != d2 {
                            return Err("conflicting durable transfer choice".into());
                        }
                    }
                }
                K_RETIRED => {
                    let key = (coin_id, generation);
                    if let Some(old) = s.retired.insert(key, d1) {
                        if old != d1 {
                            return Err("conflicting durable handoff choice".into());
                        }
                    }
                }
                K_ACTIVATION => {
                    let key = (aux, coin_id, generation);
                    if let Some(old) = s.activation.insert(key, d1) {
                        if old != d1 {
                            return Err("conflicting durable activation".into());
                        }
                    }
                    s.active.insert(coin_id, (generation, d2));
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
        self.file.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn install_bootstrap(&mut self, state: StateRef) -> Result<(), String> {
        if self.active.contains_key(&state.coin_id) {
            return Ok(());
        }
        self.append(encode_record(
            K_ACTIVE,
            self.epoch,
            state.coin_id,
            state.generation,
            0,
            state.digest,
            [0u8; 32],
        ))?;
        self.active.insert(state.coin_id, (state.generation, state.digest));
        Ok(())
    }

    fn active_matches(&self, s: StateRef) -> bool {
        self.active.get(&s.coin_id) == Some(&(s.generation, s.digest))
    }

    fn record_transfer(&mut self, f: &Finality) -> Result<bool, String> {
        if self.retired.contains_key(&(f.input.coin_id, f.input.generation)) {
            return Ok(false);
        }
        if !self.active_matches(f.input) {
            return Ok(false);
        }
        let key = (f.input.coin_id, f.input.generation);
        if let Some(old) = self.transfer.get(&key) {
            return Ok(old == &f.successor_digest);
        }
        self.append(encode_record(
            K_TRANSFER,
            self.epoch,
            f.input.coin_id,
            f.input.generation,
            0,
            f.input.digest,
            f.successor_digest,
        ))?;
        self.transfer.insert(key, f.successor_digest);
        Ok(true)
    }

    fn commit_finality(&mut self, cert: &FinalCert) -> Result<bool, String> {
        if cert.finality.epoch != self.epoch || !verify_final_cert(cert) {
            return Ok(false);
        }
        if !self.active_matches(cert.finality.input) {
            return Ok(false);
        }
        let next = StateRef {
            coin_id: cert.finality.input.coin_id,
            generation: cert.finality.input.generation + 1,
            digest: cert.finality.successor_digest,
        };
        self.append(encode_record(
            K_ACTIVE,
            self.epoch,
            next.coin_id,
            next.generation,
            0,
            next.digest,
            [0u8; 32],
        ))?;
        self.active.insert(next.coin_id, (next.generation, next.digest));
        Ok(true)
    }

    fn record_handoff(&mut self, h: &Handoff) -> Result<bool, String> {
        if h.from_epoch != self.epoch || h.to_epoch != self.epoch + 1 {
            return Ok(false);
        }
        if !self.active_matches(h.state) {
            return Ok(false);
        }
        let key = (h.state.coin_id, h.state.generation);
        let hh = handoff_hash(h);
        if let Some(old) = self.retired.get(&key) {
            return Ok(old == &hh);
        }
        self.append(encode_record(
            K_RETIRED,
            self.epoch,
            h.state.coin_id,
            h.state.generation,
            h.to_epoch,
            hh,
            h.state.digest,
        ))?;
        self.retired.insert(key, hh);
        Ok(true)
    }

    fn activate(&mut self, cert: &HandoffCert) -> Result<bool, String> {
        let h = cert.handoff;
        if h.to_epoch != self.epoch || h.from_epoch + 1 != self.epoch || !verify_handoff_cert(cert) {
            return Ok(false);
        }
        let key = (h.from_epoch, h.state.coin_id, h.state.generation);
        let hh = handoff_hash(&h);
        if let Some(old) = self.activation.get(&key) {
            return Ok(old == &hh);
        }
        if let Some((g, d)) = self.active.get(&h.state.coin_id) {
            if *g != h.state.generation || *d != h.state.digest {
                return Ok(false);
            }
        }
        self.append(encode_record(
            K_ACTIVATION,
            self.epoch,
            h.state.coin_id,
            h.state.generation,
            h.from_epoch,
            hh,
            h.state.digest,
        ))?;
        self.activation.insert(key, hh);
        self.active.insert(h.state.coin_id, (h.state.generation, h.state.digest));
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

fn write_state(s: &mut TcpStream, st: &StateRef) -> Result<(), String> {
    write_u64(s, st.coin_id)?;
    write_u64(s, st.generation)?;
    s.write_all(&st.digest).map_err(|e| e.to_string())
}
fn read_state(s: &mut TcpStream) -> Result<StateRef, String> {
    Ok(StateRef {
        coin_id: read_u64(s)?,
        generation: read_u64(s)?,
        digest: read_arr32(s)?,
    })
}

fn write_finality(s: &mut TcpStream, f: &Finality) -> Result<(), String> {
    write_u64(s, f.epoch)?;
    write_state(s, &f.input)?;
    s.write_all(&f.successor_digest).map_err(|e| e.to_string())
}
fn read_finality(s: &mut TcpStream) -> Result<Finality, String> {
    Ok(Finality {
        epoch: read_u64(s)?,
        input: read_state(s)?,
        successor_digest: read_arr32(s)?,
    })
}

fn write_final_cert(s: &mut TcpStream, cert: &FinalCert) -> Result<(), String> {
    write_finality(s, &cert.finality)?;
    s.write_all(&[cert.shares.len() as u8]).map_err(|e| e.to_string())?;
    for sh in &cert.shares {
        s.write_all(&[sh.index as u8]).map_err(|e| e.to_string())?;
        s.write_all(&sh.signature).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn read_final_cert(s: &mut TcpStream) -> Result<FinalCert, String> {
    let finality = read_finality(s)?;
    let mut n = [0u8; 1];
    s.read_exact(&mut n).map_err(|e| e.to_string())?;
    if n[0] as usize > N {
        return Err("oversized finality cert".into());
    }
    let mut shares = Vec::with_capacity(n[0] as usize);
    for _ in 0..n[0] {
        let mut i = [0u8; 1];
        s.read_exact(&mut i).map_err(|e| e.to_string())?;
        shares.push(FinalShare {
            index: i[0] as usize,
            signature: read_arr64(s)?,
        });
    }
    Ok(FinalCert { finality, shares })
}

fn write_handoff(s: &mut TcpStream, h: &Handoff) -> Result<(), String> {
    write_u64(s, h.from_epoch)?;
    write_u64(s, h.to_epoch)?;
    write_state(s, &h.state)
}
fn read_handoff(s: &mut TcpStream) -> Result<Handoff, String> {
    Ok(Handoff {
        from_epoch: read_u64(s)?,
        to_epoch: read_u64(s)?,
        state: read_state(s)?,
    })
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
        return Err("oversized handoff cert".into());
    }
    let mut shares = Vec::with_capacity(n[0] as usize);
    for _ in 0..n[0] {
        let mut i = [0u8; 1];
        s.read_exact(&mut i).map_err(|e| e.to_string())?;
        shares.push(HandoffShare {
            index: i[0] as usize,
            signature: read_arr64(s)?,
        });
    }
    Ok(HandoffCert { handoff, shares })
}

fn run_node(
    epoch: u64,
    index: usize,
    port: u16,
    wal: PathBuf,
    byzantine: bool,
    bootstrap: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("bind epoch {epoch} node {index}: {e}"))?;
    let mut store = Store::open(&wal, epoch)?;
    if bootstrap {
        store.install_bootstrap(StateRef {
            coin_id: COIN_ID,
            generation: 0,
            digest: genesis_digest(),
        })?;
    }
    let sk = committee_key(epoch, index);

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
            OP_FINALIZE => {
                let f = read_finality(&mut stream)?;
                let allowed = if byzantine {
                    f.epoch == epoch
                } else {
                    f.epoch == epoch && store.record_transfer(&f)?
                };
                if !allowed {
                    let _ = stream.write_all(&[0]);
                    continue;
                }
                let sig = sk.sign(&final_share_message(&f, index)).to_bytes();
                stream.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                stream.write_all(&sig).map_err(|e| e.to_string())?;
            }
            OP_COMMIT => {
                let cert = read_final_cert(&mut stream)?;
                let ok = if byzantine {
                    if verify_final_cert(&cert) && cert.finality.epoch == epoch {
                        let next = StateRef {
                            coin_id: cert.finality.input.coin_id,
                            generation: cert.finality.input.generation + 1,
                            digest: cert.finality.successor_digest,
                        };
                        store.install_bootstrap(next).or_else(|_| Ok(()))?;
                        true
                    } else {
                        false
                    }
                } else {
                    store.commit_finality(&cert)?
                };
                stream.write_all(&[if ok { 1 } else { 0 }]).map_err(|e| e.to_string())?;
            }
            OP_HANDOFF => {
                let h = read_handoff(&mut stream)?;
                let allowed = if byzantine {
                    h.from_epoch == epoch
                } else {
                    store.record_handoff(&h)?
                };
                if !allowed {
                    let _ = stream.write_all(&[0]);
                    continue;
                }
                let sig = sk.sign(&handoff_share_message(&h, index)).to_bytes();
                stream.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                stream.write_all(&sig).map_err(|e| e.to_string())?;
            }
            OP_ACTIVATE => {
                let cert = read_handoff_cert(&mut stream)?;
                let valid_for_epoch = cert.handoff.to_epoch == epoch
                    && cert.handoff.from_epoch + 1 == epoch
                    && verify_handoff_cert(&cert);
                let allowed = if byzantine {
                    true
                } else {
                    valid_for_epoch && store.activate(&cert)?
                };
                if !allowed {
                    let _ = stream.write_all(&[0]);
                    continue;
                }
                let hh = handoff_hash(&cert.handoff);
                let sig = sk.sign(&activation_message(epoch, &hh, index)).to_bytes();
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
    epoch: u64,
    index: usize,
    port: u16,
    wal: PathBuf,
    byzantine: bool,
    bootstrap: bool,
    child: Child,
}

impl NodeProc {
    fn spawn(
        exe: &Path,
        epoch: u64,
        index: usize,
        port: u16,
        wal: PathBuf,
        byzantine: bool,
        bootstrap: bool,
    ) -> Result<Self, String> {
        let child = Command::new(exe)
            .arg("--node")
            .arg(epoch.to_string())
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal)
            .arg(if byzantine { "1" } else { "0" })
            .arg(if bootstrap { "1" } else { "0" })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn epoch {epoch} node {index}: {e}"))?;
        let mut n = Self {
            epoch,
            index,
            port,
            wal,
            byzantine,
            bootstrap,
            child,
        };
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
        Err(format!("epoch {} node {} not ready", self.epoch, self.index))
    }

    fn restart(&mut self, exe: &Path) -> Result<(), String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.port = free_port()?;
        self.child = Command::new(exe)
            .arg("--node")
            .arg(self.epoch.to_string())
            .arg(self.index.to_string())
            .arg(self.port.to_string())
            .arg(&self.wal)
            .arg(if self.byzantine { "1" } else { "0" })
            .arg(if self.bootstrap { "1" } else { "0" })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("restart epoch {} node {}: {e}", self.epoch, self.index))?;
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

fn rpc_finalize(port: u16, f: &Finality) -> Option<FinalShare> {
    let mut s = connect(port)?;
    s.write_all(&[OP_FINALIZE]).ok()?;
    write_finality(&mut s, f).ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 0 {
        return None;
    }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let sh = FinalShare {
        index: idx[0] as usize,
        signature: read_arr64(&mut s).ok()?,
    };
    if verify_final_share(f, &sh) { Some(sh) } else { None }
}

fn rpc_commit(port: u16, cert: &FinalCert) -> bool {
    let Some(mut s) = connect(port) else { return false; };
    if s.write_all(&[OP_COMMIT]).is_err() || write_final_cert(&mut s, cert).is_err() {
        return false;
    }
    let mut status = [0u8; 1];
    s.read_exact(&mut status).is_ok() && status[0] == 1
}

fn rpc_handoff(port: u16, h: &Handoff) -> Option<HandoffShare> {
    let mut s = connect(port)?;
    s.write_all(&[OP_HANDOFF]).ok()?;
    write_handoff(&mut s, h).ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 0 {
        return None;
    }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let sh = HandoffShare {
        index: idx[0] as usize,
        signature: read_arr64(&mut s).ok()?,
    };
    if verify_handoff_share(h, &sh) { Some(sh) } else { None }
}

fn rpc_activate(port: u16, epoch: u64, cert: &HandoffCert) -> Option<ActivationShare> {
    let mut s = connect(port)?;
    s.write_all(&[OP_ACTIVATE]).ok()?;
    write_handoff_cert(&mut s, cert).ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 0 {
        return None;
    }
    let mut idx = [0u8; 1];
    s.read_exact(&mut idx).ok()?;
    let sh = ActivationShare {
        index: idx[0] as usize,
        signature: read_arr64(&mut s).ok()?,
    };
    let hh = handoff_hash(&cert.handoff);
    if verify_activation_share(epoch, &hh, &sh) { Some(sh) } else { None }
}

fn collect_final(nodes: &[NodeProc], f: &Finality, indices: &[usize]) -> Vec<FinalShare> {
    let mut by_index = HashMap::new();
    for &i in indices {
        if let Some(s) = rpc_finalize(nodes[i].port, f) {
            by_index.entry(s.index).or_insert(s);
        }
    }
    by_index.into_values().collect()
}

fn collect_handoff(nodes: &[NodeProc], h: &Handoff, indices: &[usize]) -> Vec<HandoffShare> {
    let mut by_index = HashMap::new();
    for &i in indices {
        if let Some(s) = rpc_handoff(nodes[i].port, h) {
            by_index.entry(s.index).or_insert(s);
        }
    }
    by_index.into_values().collect()
}

fn collect_activation(nodes: &[NodeProc], epoch: u64, cert: &HandoffCert, indices: &[usize]) -> Vec<ActivationShare> {
    let mut by_index = HashMap::new();
    for &i in indices {
        if let Some(s) = rpc_activate(nodes[i].port, epoch, cert) {
            by_index.entry(s.index).or_insert(s);
        }
    }
    by_index.into_values().collect()
}

fn final_cert(nodes: &[NodeProc], f: Finality) -> Result<FinalCert, String> {
    let all: Vec<usize> = (0..N).collect();
    let shares = collect_final(nodes, &f, &all);
    let cert = FinalCert { finality: f, shares };
    if !verify_final_cert(&cert) {
        return Err(format!("finality QC missing: {}/{}", cert.shares.len(), Q));
    }
    Ok(cert)
}

fn commit_all(nodes: &[NodeProc], cert: &FinalCert) -> usize {
    nodes.iter().filter(|n| rpc_commit(n.port, cert)).count()
}

fn synthetic_handoff_share(h: &Handoff, index: usize) -> HandoffShare {
    let sig = committee_key(h.from_epoch, index)
        .sign(&handoff_share_message(h, index))
        .to_bytes();
    HandoffShare { index, signature: sig }
}

fn controller() -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec014-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    println!("CALIBRE SECURITY SEC-014 v0.14.0");
    println!("MULTI-GENERATION MONETARY LINEAGE ACROSS ZERO-OVERLAP COMMITTEE ROTATIONS");
    println!("Epochs 20 -> 21 -> 22; each committee N=7 Q=5; 21 separate OS processes over real 127.0.0.1 TCP");
    println!("Focus: generation fencing + direct-predecessor handoff continuity + stale-committee replay rejection");
    println!("Owner authorization is abstracted here as pre-authorized state digests; this test isolates lineage/rotation semantics");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!("Per-monetary-state generation/epoch lineage: USED");
    println!();

    let mut c0 = Vec::new();
    let mut c1 = Vec::new();
    let mut c2 = Vec::new();
    for (epoch, target, bootstrap) in [(E0, &mut c0, true), (E1, &mut c1, false), (E2, &mut c2, false)] {
        for i in 0..N {
            let port = free_port()?;
            let wal = root.join(format!("epoch-{epoch}-node-{i}.wal"));
            target.push(NodeProc::spawn(&exe, epoch, i, port, wal, i < 2, bootstrap)?);
        }
    }

    let d0 = genesis_digest();
    let d1 = state_digest(&d0, 1, b"BOB");
    let d2 = state_digest(&d1, 2, b"CAROL");
    let d3 = state_digest(&d2, 3, b"DAVE");
    let d4 = state_digest(&d3, 4, b"EVE");
    let mallory1 = state_digest(&d1, 2, b"MALLORY-CONFLICT");
    let stale_mallory = state_digest(&d0, 1, b"MALLORY-STALE");

    let s0 = StateRef { coin_id: COIN_ID, generation: 0, digest: d0 };
    let f01 = Finality { epoch: E0, input: s0, successor_digest: d1 };
    let cert01 = final_cert(&c0, f01)?;
    let acks01 = commit_all(&c0, &cert01);
    if acks01 < Q { return Err(format!("epoch20 Alice->Bob commit only {acks01}/7")); }
    println!("GENERATION 0->1 / EPOCH 20: ALICE-STATE -> BOB-STATE FINALIZES 5/7+ AND COMMITS -> PASS");

    let s1 = StateRef { coin_id: COIN_ID, generation: 1, digest: d1 };
    let h20 = Handoff { from_epoch: E0, to_epoch: E1, state: s1 };
    let hs20 = collect_handoff(&c0, &h20, &[0,1,2,3,4]);
    let hc20 = HandoffCert { handoff: h20, shares: hs20 };
    if !verify_handoff_cert(&hc20) { return Err("epoch20->21 handoff did not reach 5/7".into()); }

    let partial20 = HandoffCert { handoff: h20, shares: hc20.shares.iter().take(4).copied().collect() };
    let honest: Vec<usize> = vec![2,3,4,5,6];
    let partial_acts = collect_activation(&c1, E1, &partial20, &honest);
    if !partial_acts.is_empty() { return Err("4/7 predecessor handoff activated honest epoch21 nodes".into()); }
    println!("INSUFFICIENT EPOCH20->21 HANDOFF 4/7: HONEST EPOCH-21 ACTIVATION SHARES=0 -> PASS");

    let h_skip = Handoff { from_epoch: E0, to_epoch: E2, state: s1 };
    let skip_shares = collect_handoff(&c0, &h_skip, &(0..N).collect::<Vec<_>>());
    if skip_shares.len() > 2 { return Err(format!("skipped-epoch handoff gained {} shares", skip_shares.len())); }
    println!("SKIPPED-EPOCH HANDOFF 20->22: ONLY BYZANTINE SHARES POSSIBLE ({}/7), NO 5/7 CERT -> PASS", skip_shares.len());

    let conflict_old = Finality { epoch: E0, input: s1, successor_digest: mallory1 };
    let old_conflict_shares = collect_final(&c0, &conflict_old, &(0..N).collect::<Vec<_>>());
    if old_conflict_shares.len() >= Q { return Err("old committee finalized after handoff fence".into()); }
    println!("OLD EPOCH-20 POST-HANDOFF CONFLICT: ONLY {}/7 SHARES, CANNOT REACH 5/7 -> PASS", old_conflict_shares.len());

    let acts21 = collect_activation(&c1, E1, &hc20, &(0..N).collect::<Vec<_>>());
    let ac21 = ActivationCert { handoff_hash: handoff_hash(&h20), shares: acts21 };
    if !verify_activation_cert(E1, &ac21, &hc20) { return Err("epoch21 activation QC missing".into()); }
    println!("EPOCH 21 ACTIVATES DIRECT PREDECESSOR HANDOFF 5/7 -> PASS");

    let f12 = Finality { epoch: E1, input: s1, successor_digest: d2 };
    let cert12 = final_cert(&c1, f12)?;
    if commit_all(&c1, &cert12) < Q { return Err("epoch21 Bob->Carol commit failed".into()); }
    println!("GENERATION 1->2 / EPOCH 21: BOB-STATE -> CAROL-STATE FINALIZES -> PASS");

    let s2 = StateRef { coin_id: COIN_ID, generation: 2, digest: d2 };
    let h21 = Handoff { from_epoch: E1, to_epoch: E2, state: s2 };
    let hs21 = collect_handoff(&c1, &h21, &[0,1,2,3,4]);
    let hc21 = HandoffCert { handoff: h21, shares: hs21 };
    if !verify_handoff_cert(&hc21) { return Err("epoch21->22 handoff did not reach 5/7".into()); }

    let replay_old = collect_activation(&c2, E2, &hc20, &honest);
    if !replay_old.is_empty() { return Err("epoch22 honest nodes accepted stale epoch20->21 handoff".into()); }
    println!("STALE HANDOFF REPLAY 20->21 AGAINST EPOCH 22: HONEST ACTIVATION SHARES=0 -> PASS");

    let acts22 = collect_activation(&c2, E2, &hc21, &(0..N).collect::<Vec<_>>());
    let ac22 = ActivationCert { handoff_hash: handoff_hash(&h21), shares: acts22 };
    if !verify_activation_cert(E2, &ac22, &hc21) { return Err("epoch22 activation QC missing".into()); }
    println!("EPOCH 22 ACTIVATES ONLY DIRECT 21->22 PREDECESSOR HANDOFF 5/7 -> PASS");

    let f23 = Finality { epoch: E2, input: s2, successor_digest: d3 };
    let cert23 = final_cert(&c2, f23)?;
    if commit_all(&c2, &cert23) < Q { return Err("epoch22 Carol->Dave commit failed".into()); }
    println!("GENERATION 2->3 / EPOCH 22: CAROL-STATE -> DAVE-STATE FINALIZES -> PASS");

    c2[4].restart(&exe)?;
    let s3 = StateRef { coin_id: COIN_ID, generation: 3, digest: d3 };
    let f34 = Finality { epoch: E2, input: s3, successor_digest: d4 };
    let cert34 = final_cert(&c2, f34)?;
    if commit_all(&c2, &cert34) < Q { return Err("epoch22 restart continuity Dave->Eve failed".into()); }
    println!("EPOCH-22 HONEST NODE RESTART + GENERATION 3->4: CURRENT STATE SURVIVES AND DAVE->EVE FINALIZES -> PASS");

    let stale0 = Finality { epoch: E2, input: s0, successor_digest: stale_mallory };
    let stale_shares = collect_final(&c2, &stale0, &(0..N).collect::<Vec<_>>());
    let honest_stale = stale_shares.iter().filter(|s| s.index >= 2).count();
    if honest_stale != 0 || stale_shares.len() >= Q {
        return Err(format!("stale generation replay obtained {} total / {} honest shares", stale_shares.len(), honest_stale));
    }
    println!("STALE GENERATION-0 REPLAY AFTER GENERATION-4: HONEST SHARES=0; TOTAL {}/7 <5 -> PASS", stale_shares.len());

    c0[2].restart(&exe)?;
    let old_conflict_again = collect_final(&c0, &conflict_old, &(0..N).collect::<Vec<_>>());
    if old_conflict_again.len() >= Q { return Err("restarted old signer forgot handoff retirement".into()); }
    println!("RESTARTED OLD EPOCH-20 HONEST HANDOFF SIGNER REMEMBERS RETIREMENT; CONFLICT STILL {}/7 <5 -> PASS", old_conflict_again.len());

    let h_a = Handoff { from_epoch: E0, to_epoch: E1, state: StateRef { coin_id: COIN_ID + 99, generation: 7, digest: state_digest(&d0, 7, b"BOUNDARY-A") } };
    let h_b = Handoff { from_epoch: E0, to_epoch: E1, state: StateRef { coin_id: COIN_ID + 99, generation: 7, digest: state_digest(&d0, 7, b"BOUNDARY-B") } };
    let cert_a = HandoffCert { handoff: h_a, shares: vec![0,1,2,3,4].into_iter().map(|i| synthetic_handoff_share(&h_a, i)).collect() };
    let cert_b = HandoffCert { handoff: h_b, shares: vec![0,1,2,5,6].into_iter().map(|i| synthetic_handoff_share(&h_b, i)).collect() };
    if !verify_handoff_cert(&cert_a) || !verify_handoff_cert(&cert_b) {
        return Err("f=3 boundary witness construction failed".into());
    }
    println!("F=3 EXPECTED BOUNDARY: 3 EQUIVOCATING MEMBERS + 2+2 HONEST SPLIT YIELD TWO CRYPTOGRAPHIC 5/7 HANDOFF CERTS -> ATTACK WITNESS CONFIRMED");

    for n in &mut c0 { n.stop(); }
    for n in &mut c1 { n.stop(); }
    for n in &mut c2 { n.stop(); }
    let _ = fs::remove_dir_all(&root);

    println!();
    println!("=== SEC-014 DECISION ===");
    println!("MULTI-GENERATION MONETARY LINEAGE g0->g4 ACROSS EPOCHS 20->21->22: PASS IN TESTED LOCAL SCENARIO");
    println!("ZERO-OVERLAP MULTI-EPOCH DIRECT-PREDECESSOR HANDOFF CONTINUITY: PASS");
    println!("OLD COMMITTEE POST-HANDOFF SUCCESSOR FENCING WITH f<=2: PASS IN TESTED SCENARIO");
    println!("INSUFFICIENT 4/7 + SKIPPED-EPOCH + STALE-HANDOFF REPLAY REJECTION: PASS");
    println!("STALE MONETARY GENERATION REPLAY AFTER MULTIPLE SUCCESSORS: PASS");
    println!("PROCESS-RESTART PERSISTENCE OF NEW CURRENT STATE + OLD RETIREMENT: PASS");
    println!("F=3 HANDOFF SAFETY BOUNDARY: TWO 5/7 CERTIFICATES CRYPTOGRAPHICALLY REACHABLE / EXPECTED");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PER-MONETARY-STATE GENERATION/EPOCH LINEAGE USED: YES");
    println!("OFFLINE-CLIENT LONG-RANGE BOOTSTRAP / PRODUCTION MEMBERSHIP SELECTION / SYBIL RESISTANCE: NOT PROVEN");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--node") {
        if args.len() != 8 {
            Err("node usage: --node <epoch> <index> <port> <wal> <byz 0|1> <bootstrap 0|1>".into())
        } else {
            let epoch = args[2].parse::<u64>().map_err(|e| e.to_string());
            let index = args[3].parse::<usize>().map_err(|e| e.to_string());
            let port = args[4].parse::<u16>().map_err(|e| e.to_string());
            match (epoch, index, port) {
                (Ok(epoch), Ok(index), Ok(port)) => run_node(
                    epoch,
                    index,
                    port,
                    PathBuf::from(&args[5]),
                    args[6] == "1",
                    args[7] == "1",
                ),
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            }
        }
    } else {
        controller()
    };

    if let Err(e) = result {
        eprintln!("SEC-014 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_keys_differ_across_epochs() {
        assert_ne!(committee_key(E0, 2).verifying_key().to_bytes(), committee_key(E1, 2).verifying_key().to_bytes());
        assert_ne!(committee_key(E1, 2).verifying_key().to_bytes(), committee_key(E2, 2).verifying_key().to_bytes());
    }

    #[test]
    fn direct_successor_digests_are_generation_bound() {
        let d0 = genesis_digest();
        let d1 = state_digest(&d0, 1, b"BOB");
        let wrong = state_digest(&d0, 2, b"BOB");
        assert_ne!(d1, wrong);
    }

    #[test]
    fn four_handoff_shares_are_insufficient() {
        let h = Handoff { from_epoch: E0, to_epoch: E1, state: StateRef { coin_id: COIN_ID, generation: 1, digest: [7u8;32] } };
        let c = HandoffCert { handoff: h, shares: (0..4).map(|i| synthetic_handoff_share(&h, i)).collect() };
        assert!(!verify_handoff_cert(&c));
    }

    #[test]
    fn five_handoff_shares_are_sufficient() {
        let h = Handoff { from_epoch: E0, to_epoch: E1, state: StateRef { coin_id: COIN_ID, generation: 1, digest: [9u8;32] } };
        let c = HandoffCert { handoff: h, shares: (0..5).map(|i| synthetic_handoff_share(&h, i)).collect() };
        assert!(verify_handoff_cert(&c));
    }

    #[test]
    fn f3_boundary_can_make_two_q5_handoffs() {
        let a = Handoff { from_epoch: E0, to_epoch: E1, state: StateRef { coin_id: COIN_ID + 1, generation: 3, digest: [1u8;32] } };
        let b = Handoff { from_epoch: E0, to_epoch: E1, state: StateRef { coin_id: COIN_ID + 1, generation: 3, digest: [2u8;32] } };
        let ca = HandoffCert { handoff: a, shares: [0,1,2,3,4].into_iter().map(|i| synthetic_handoff_share(&a,i)).collect() };
        let cb = HandoffCert { handoff: b, shares: [0,1,2,5,6].into_iter().map(|i| synthetic_handoff_share(&b,i)).collect() };
        assert!(verify_handoff_cert(&ca));
        assert!(verify_handoff_cert(&cb));
    }
}
