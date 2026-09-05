use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const N: usize = 7;
const Q: usize = 5;
const OLD_EPOCH: u64 = 50;
const NEW_EPOCH: u64 = 51;
const STATE_GENERATION: u64 = 9;
const COIN_ID: u64 = 16_000_001;

const STAGE_ACTIVE: u8 = 0;
const STAGE_RETIRED: u8 = 1;

const OP_PING: u8 = 0;
const OP_PUBLIC: u8 = 1;
const OP_FRESH: u8 = 2;
const OP_RETIRE: u8 = 3;
const OP_SHUTDOWN: u8 = 255;

const STATE_MAGIC: [u8; 8] = *b"CAL016KR";
const STATE_RECORD: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyState {
    stage: u8,
    generation: u64,
    secret: [u8; 32],
    handoff_hash: [u8; 32],
}

fn stale_state_digest() -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC016_STALE_MONETARY_STATE_V1");
    h.update(&COIN_ID.to_le_bytes());
    h.update(&STATE_GENERATION.to_le_bytes());
    *h.finalize().as_bytes()
}

fn handoff_hash() -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC016_RETIRE_HANDOFF_V1");
    h.update(&OLD_EPOCH.to_le_bytes());
    h.update(&NEW_EPOCH.to_le_bytes());
    h.update(&COIN_ID.to_le_bytes());
    h.update(&STATE_GENERATION.to_le_bytes());
    h.update(&stale_state_digest());
    *h.finalize().as_bytes()
}

fn state_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC016_KEY_STATE_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_state(s: KeyState) -> [u8; STATE_RECORD] {
    let mut out = [0u8; STATE_RECORD];
    out[0..8].copy_from_slice(&STATE_MAGIC);
    out[8] = s.stage;
    out[16..24].copy_from_slice(&s.generation.to_le_bytes());
    out[24..56].copy_from_slice(&s.secret);
    out[56..88].copy_from_slice(&s.handoff_hash);
    let c = state_checksum(&out[..88]);
    out[88..120].copy_from_slice(&c);
    out
}

fn decode_state(bytes: &[u8]) -> Result<KeyState, String> {
    if bytes.len() != STATE_RECORD || bytes[0..8] != STATE_MAGIC {
        return Err("bad SEC-016 key-state record".into());
    }
    if bytes[88..120] != state_checksum(&bytes[..88]) {
        return Err("SEC-016 key-state checksum mismatch".into());
    }
    let stage = bytes[8];
    if stage != STAGE_ACTIVE && stage != STAGE_RETIRED {
        return Err("unknown SEC-016 key-state stage".into());
    }
    let generation = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes[24..56]);
    let mut handoff_hash = [0u8; 32];
    handoff_hash.copy_from_slice(&bytes[56..88]);
    Ok(KeyState { stage, generation, secret, handoff_hash })
}

fn write_state(path: &Path, state: KeyState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(&encode_state(state)).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

fn read_state(path: &Path) -> Result<KeyState, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    decode_state(&bytes)
}

fn load_or_create_state(path: &Path) -> Result<KeyState, String> {
    if path.exists() {
        return read_state(path);
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let state = KeyState {
        stage: STAGE_ACTIVE,
        generation: 0,
        secret,
        handoff_hash: [0u8; 32],
    };
    write_state(path, state)?;
    Ok(state)
}

fn advance_secret(secret: &[u8; 32], next_generation: u64, handoff: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC016_ONE_WAY_RETIRE_RATCHET_V1");
    h.update(secret);
    h.update(&next_generation.to_le_bytes());
    h.update(handoff);
    *h.finalize().as_bytes()
}

fn signing_seed(secret: &[u8; 32], epoch: u64, key_generation: u64) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC016_FRESHNESS_SIGNING_SEED_V1");
    h.update(secret);
    h.update(&epoch.to_le_bytes());
    h.update(&key_generation.to_le_bytes());
    *h.finalize().as_bytes()
}

fn freshness_message(epoch: u64, state_digest: &[u8; 32], nonce: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC016_FRESHNESS_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&COIN_ID.to_le_bytes());
    out.extend_from_slice(&STATE_GENERATION.to_le_bytes());
    out.extend_from_slice(state_digest);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out
}

fn old_signing_key_from_secret(secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&signing_seed(secret, OLD_EPOCH, 0))
}

fn public_for_state(state: KeyState) -> VerifyingKey {
    SigningKey::from_bytes(&signing_seed(&state.secret, OLD_EPOCH, state.generation)).verifying_key()
}

fn retire_state(path: &Path, state: &mut KeyState, h: [u8; 32]) -> Result<(), String> {
    if state.stage == STAGE_RETIRED {
        if state.handoff_hash == h {
            return Ok(());
        }
        return Err("already retired under a different handoff".into());
    }
    let next_generation = state.generation + 1;
    let next_secret = advance_secret(&state.secret, next_generation, &h);
    let next = KeyState {
        stage: STAGE_RETIRED,
        generation: next_generation,
        secret: next_secret,
        handoff_hash: h,
    };
    write_state(path, next)?;
    *state = next;
    Ok(())
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

fn run_node(index: usize, port: u16, path: PathBuf) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind node {index}: {e}"))?;
    let mut state = load_or_create_state(&path)?;
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
                let _ = stream.write_all(&[1]);
            }
            OP_PUBLIC => {
                let pk = public_for_state(state).to_bytes();
                let _ = stream.write_all(&[state.stage]);
                let _ = stream.write_all(&state.generation.to_le_bytes());
                let _ = stream.write_all(&pk);
            }
            OP_FRESH => {
                let epoch = match read_u64(&mut stream) { Ok(v) => v, Err(_) => continue };
                let generation = match read_u64(&mut stream) { Ok(v) => v, Err(_) => continue };
                let digest = match read_arr32(&mut stream) { Ok(v) => v, Err(_) => continue };
                let nonce = match read_arr32(&mut stream) { Ok(v) => v, Err(_) => continue };
                if state.stage != STAGE_ACTIVE
                    || state.generation != 0
                    || epoch != OLD_EPOCH
                    || generation != STATE_GENERATION
                    || digest != stale_state_digest()
                {
                    let _ = stream.write_all(&[0]);
                    continue;
                }
                let sk = old_signing_key_from_secret(&state.secret);
                let sig = sk.sign(&freshness_message(epoch, &digest, &nonce, index)).to_bytes();
                let _ = stream.write_all(&[1]);
                let _ = stream.write_all(&sig);
            }
            OP_RETIRE => {
                let h = match read_arr32(&mut stream) { Ok(v) => v, Err(_) => continue };
                match retire_state(&path, &mut state, h) {
                    Ok(()) => { let _ = stream.write_all(&[1]); }
                    Err(_) => { let _ = stream.write_all(&[0]); }
                }
            }
            OP_SHUTDOWN => {
                let _ = stream.write_all(&[1]);
                break;
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

fn wait_ping(port: u16) -> Result<(), String> {
    for _ in 0..100 {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            if s.write_all(&[OP_PING]).is_ok() {
                let mut b = [0u8; 1];
                if s.read_exact(&mut b).is_ok() && b[0] == 1 {
                    return Ok(());
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(format!("node on port {port} did not become ready"))
}

fn spawn_child(exe: &Path, index: usize, port: u16, state: &Path) -> Result<Child, String> {
    Command::new(exe)
        .arg("--node")
        .arg(index.to_string())
        .arg(port.to_string())
        .arg(state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())
}

struct NodeProc {
    index: usize,
    port: u16,
    state_path: PathBuf,
    child: Child,
}

impl NodeProc {
    fn start(exe: &Path, index: usize, root: &Path) -> Result<Self, String> {
        let port = free_port()?;
        let state_path = root.join(format!("node-{index}.state"));
        let child = spawn_child(exe, index, port, &state_path)?;
        wait_ping(port)?;
        Ok(Self { index, port, state_path, child })
    }

    fn restart(&mut self, exe: &Path) -> Result<(), String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.port = free_port()?;
        self.child = spawn_child(exe, self.index, self.port, &self.state_path)?;
        wait_ping(self.port)
    }

    fn stop(&mut self) {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
            let _ = s.write_all(&[OP_SHUTDOWN]);
        }
        let _ = self.child.wait();
    }
}

fn rpc_public(port: u16) -> Result<(u8, u64, VerifyingKey), String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.write_all(&[OP_PUBLIC]).map_err(|e| e.to_string())?;
    let mut stage = [0u8; 1];
    s.read_exact(&mut stage).map_err(|e| e.to_string())?;
    let generation = read_u64(&mut s)?;
    let pk = read_arr32(&mut s)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad public key")?;
    Ok((stage[0], generation, vk))
}

fn rpc_retire(port: u16, h: [u8; 32]) -> Result<bool, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.write_all(&[OP_RETIRE]).map_err(|e| e.to_string())?;
    s.write_all(&h).map_err(|e| e.to_string())?;
    let mut b = [0u8; 1];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b[0] == 1)
}

fn rpc_fresh(port: u16, nonce: [u8; 32]) -> Option<[u8; 64]> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.write_all(&[OP_FRESH]).ok()?;
    s.write_all(&OLD_EPOCH.to_le_bytes()).ok()?;
    s.write_all(&STATE_GENERATION.to_le_bytes()).ok()?;
    s.write_all(&stale_state_digest()).ok()?;
    s.write_all(&nonce).ok()?;
    let mut ok = [0u8; 1];
    s.read_exact(&mut ok).ok()?;
    if ok[0] != 1 { return None; }
    let mut sig = [0u8; 64];
    s.read_exact(&mut sig).ok()?;
    Some(sig)
}

fn nonce(label: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC016_CLIENT_NONCE_V1");
    h.update(label);
    *h.finalize().as_bytes()
}

fn verify_share(vk: &VerifyingKey, index: usize, nonce: &[u8; 32], sig: &[u8; 64]) -> bool {
    vk.verify_strict(
        &freshness_message(OLD_EPOCH, &stale_state_digest(), nonce, index),
        &Signature::from_bytes(sig),
    ).is_ok()
}

fn collect_live(nodes: &[NodeProc], old_pks: &[VerifyingKey], nonce: [u8; 32]) -> usize {
    let mut count = 0;
    for n in nodes {
        if let Some(sig) = rpc_fresh(n.port, nonce) {
            if verify_share(&old_pks[n.index], n.index, &nonce, &sig) {
                count += 1;
            }
        }
    }
    count
}

fn compromised_current_count(nodes: &[NodeProc], old_pks: &[VerifyingKey], nonce: [u8; 32]) -> Result<usize, String> {
    let mut count = 0;
    for n in nodes {
        let st = read_state(&n.state_path)?;
        let sk = old_signing_key_from_secret(&st.secret);
        let sig = sk.sign(&freshness_message(OLD_EPOCH, &stale_state_digest(), &nonce, n.index)).to_bytes();
        if verify_share(&old_pks[n.index], n.index, &nonce, &sig) {
            count += 1;
        }
    }
    Ok(count)
}

fn snapshot_attack_count(snapshot_paths: &[(usize, PathBuf)], nodes: &[NodeProc], old_pks: &[VerifyingKey], nonce: [u8; 32]) -> Result<usize, String> {
    let mut count = 0;
    for (idx, path) in snapshot_paths {
        let st = read_state(path)?;
        let sk = old_signing_key_from_secret(&st.secret);
        let sig = sk.sign(&freshness_message(OLD_EPOCH, &stale_state_digest(), &nonce, *idx)).to_bytes();
        if verify_share(&old_pks[*idx], *idx, &nonce, &sig) { count += 1; }
    }
    for idx in [5usize, 6usize] {
        let st = read_state(&nodes[idx].state_path)?;
        let sk = old_signing_key_from_secret(&st.secret);
        let sig = sk.sign(&freshness_message(OLD_EPOCH, &stale_state_digest(), &nonce, idx)).to_bytes();
        if verify_share(&old_pks[idx], idx, &nonce, &sig) { count += 1; }
    }
    Ok(count)
}

fn run_controller() -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let root = env::temp_dir().join(format!("calibre-sec016-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    let mut nodes = Vec::new();
    for i in 0..N {
        nodes.push(NodeProc::start(&exe, i, &root)?);
    }

    let mut old_pks = Vec::new();
    for n in &nodes {
        let (stage, generation, pk) = rpc_public(n.port)?;
        if stage != STAGE_ACTIVE || generation != 0 {
            return Err(format!("node {} did not start at active generation 0", n.index));
        }
        old_pks.push(pk);
    }

    let snapshots_dir = root.join("pre-retirement-snapshots");
    fs::create_dir_all(&snapshots_dir).map_err(|e| e.to_string())?;
    let mut attack_snapshots = Vec::new();
    for idx in [0usize, 1usize, 2usize] {
        let p = snapshots_dir.join(format!("node-{idx}-old.state"));
        fs::copy(&nodes[idx].state_path, &p).map_err(|e| e.to_string())?;
        attack_snapshots.push((idx, p));
    }

    println!("CALIBRE SECURITY SEC-016 v0.16.0");
    println!("ONE-WAY RETIRED-KEY RATCHET / LATER OLD-COMMITTEE KEY-COMPROMISE ATTACK");
    println!("Old committee epoch {OLD_EPOCH}: N=7 Q=5; nodes 0..4 retire honestly, nodes 5..6 model Byzantine old-key retention");
    println!("Seven separate OS processes use real 127.0.0.1 TCP sockets on one physical host");
    println!("Purpose: test whether compromise of CURRENT retired-node secret state can recreate the OLD epoch freshness signing key");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!("Important: this is a one-way software key-ratchet candidate, NOT a formally proven forward-secure signature scheme");
    println!();

    let n0 = nonce(b"baseline");
    let baseline = collect_live(&nodes, &old_pks, n0);
    if baseline < Q { return Err(format!("baseline freshness quorum failed: {baseline}/7")); }
    println!("BEFORE RETIREMENT: OLD COMMITTEE ANSWERS FRESH NONCE {baseline}/7 -> BASELINE PASS");

    let hh = handoff_hash();
    for idx in 0..5 {
        if !rpc_retire(nodes[idx].port, hh)? {
            return Err(format!("honest node {idx} retirement failed"));
        }
    }
    println!("RETIREMENT: FIVE HONEST OLD SIGNERS RATCHET SECRET STATE FORWARD AND sync_all() BEFORE ACK; TWO BYZANTINE OLD SIGNERS RETAIN OLD KEYS -> APPLIED");

    let n1 = nonce(b"post-retirement-live");
    let stale_live = collect_live(&nodes, &old_pks, n1);
    if stale_live >= Q { return Err(format!("retired committee unexpectedly reached stale freshness quorum: {stale_live}/7")); }
    println!("POST-RETIREMENT LIVE OLD COMMITTEE FRESHNESS: {stale_live}/7 <5 -> STALE CURRENTNESS REJECTED: PASS");

    nodes[2].restart(&exe)?;
    let n2 = nonce(b"restart-check");
    let after_restart = collect_live(&nodes, &old_pks, n2);
    if after_restart >= Q { return Err("restart resurrected old freshness key".into()); }
    println!("RESTARTED HONEST RETIRED SIGNER: RATCHET STATE SURVIVES; OLD FRESHNESS QUORUM REMAINS {after_restart}/7 <5 -> PASS");

    let n3 = nonce(b"later-compromise-current-state");
    let current_compromise = compromised_current_count(&nodes, &old_pks, n3)?;
    if current_compromise >= Q { return Err(format!("later compromise of current states recreated stale quorum: {current_compromise}/7")); }
    println!("LATER COMPROMISE OF ALL CURRENT ON-DISK NODE SECRET STATES: ONLY {current_compromise}/7 SIGNATURES VERIFY UNDER OLD PUBLIC KEYS -> OLD 5/7 FRESHNESS CANNOT BE RECREATED: PASS IN TESTED RATCHET MODEL");

    let old_state = read_state(&attack_snapshots[0].1)?;
    let current_state = read_state(&nodes[0].state_path)?;
    let old_pk = old_signing_key_from_secret(&old_state.secret).verifying_key();
    let attempted_old_pk = old_signing_key_from_secret(&current_state.secret).verifying_key();
    if old_pk == attempted_old_pk { return Err("ratchet did not change old signing key material".into()); }
    println!("ONE-WAY RATCHET CHECK: CURRENT RETIRED SECRET DERIVES A DIFFERENT KEY THAN PRE-RETIREMENT OLD FRESHNESS KEY -> PASS");

    let n4 = nonce(b"pre-retirement-snapshot-attack");
    let snapshot_attack = snapshot_attack_count(&attack_snapshots, &nodes, &old_pks, n4)?;
    if snapshot_attack < Q { return Err(format!("expected pre-retirement snapshot attack witness did not reach quorum: {snapshot_attack}/7")); }
    println!("PRE-RETIREMENT SECRET SNAPSHOT ATTACK: 3 COPIED HONEST OLD SECRETS + 2 BYZANTINE RETAINED OLD SECRETS = {snapshot_attack}/7 VALID STALE FRESHNESS -> ATTACK WITNESS CONFIRMED");

    for n in &mut nodes { n.stop(); }
    let _ = fs::remove_dir_all(&root);

    println!();
    println!("=== SEC-016 DECISION ===");
    println!("SOFTWARE ONE-WAY RETIRED-KEY RATCHET: IMPLEMENTED / PROCESS-RESTART PERSISTENCE TESTED");
    println!("LATER COMPROMISE OF CURRENT RETIRED-NODE SECRET STATE RECREATES OLD FRESHNESS QUORUM: NO IN TESTED MODEL");
    println!("OLD-COMMITTEE STALE FRESHNESS AFTER HONEST RETIREMENT WITH TWO BYZANTINE OLD-KEY HOLDERS: REJECTED BELOW 5/7");
    println!("PRE-RETIREMENT OLD-SECRET SNAPSHOT / EXFILTRATION: SAFETY FAILS; 5/7 STALE FRESHNESS ATTACK CONFIRMED");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("FORMAL FORWARD-SECURE SIGNATURE THEOREM: NOT CLAIMED");
    println!("PHYSICAL KEY ERASURE / SSD FORENSIC REMNANT DELETION: NOT PROVEN");
    println!("MALICIOUS PRE-RETIREMENT STORAGE SNAPSHOT RESISTANCE: NOT SOLVED");
    println!("POWER-LOSS / DISK-CONTROLLER FLUSH SEMANTICS: NOT PROVEN");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--node") {
        if args.len() != 5 {
            Err("usage: --node <index> <port> <state-path>".into())
        } else {
            let index = args[2].parse::<usize>().map_err(|e| e.to_string());
            let port = args[3].parse::<u16>().map_err(|e| e.to_string());
            match (index, port) {
                (Ok(i), Ok(p)) => run_node(i, p, PathBuf::from(&args[4])),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
    } else {
        run_controller()
    };
    if let Err(e) = result {
        eprintln!("SEC-016 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_secret() -> [u8; 32] { [7u8; 32] }

    #[test]
    fn state_checksum_detects_mutation() {
        let s = KeyState { stage: STAGE_ACTIVE, generation: 0, secret: fixed_secret(), handoff_hash: [0u8; 32] };
        let mut rec = encode_state(s);
        assert_eq!(decode_state(&rec).unwrap(), s);
        rec[30] ^= 1;
        assert!(decode_state(&rec).is_err());
    }

    #[test]
    fn ratchet_changes_old_signing_key() {
        let s0 = fixed_secret();
        let s1 = advance_secret(&s0, 1, &handoff_hash());
        assert_ne!(old_signing_key_from_secret(&s0).verifying_key(), old_signing_key_from_secret(&s1).verifying_key());
    }

    #[test]
    fn current_ratchet_secret_signature_does_not_verify_under_old_public_key() {
        let s0 = fixed_secret();
        let s1 = advance_secret(&s0, 1, &handoff_hash());
        let old = old_signing_key_from_secret(&s0);
        let current_attempt = old_signing_key_from_secret(&s1);
        let n = nonce(b"test-current");
        let msg = freshness_message(OLD_EPOCH, &stale_state_digest(), &n, 0);
        let sig = current_attempt.sign(&msg);
        assert!(old.verifying_key().verify_strict(&msg, &sig).is_err());
    }

    #[test]
    fn pre_retirement_snapshot_secret_still_signs_old_key() {
        let s0 = fixed_secret();
        let old = old_signing_key_from_secret(&s0);
        let n = nonce(b"test-old");
        let msg = freshness_message(OLD_EPOCH, &stale_state_digest(), &n, 0);
        let sig = old.sign(&msg);
        assert!(old.verifying_key().verify_strict(&msg, &sig).is_ok());
    }

    #[test]
    fn quorum_boundary_is_five() {
        assert!(4 < Q);
        assert!(5 >= Q);
        assert_eq!(N, 7);
    }
}
