use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NETWORK_ID: u32 = 1;
const MAX_INPUTS: usize = 8;
const CELL_VALUE: u64 = 100;
const EPOCH: u64 = 4;
const N: usize = 7;
const AUTH_Q: usize = 5;
const ANCHOR_Q: usize = 5;
const RECOVERY_Q: usize = 6;
const F: usize = 2;
const WITNESS_MAGIC: [u8; 8] = *b"CALWA004";
const WITNESS_RECORD_SIZE: usize = 192;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cell {
    id: u64,
    value: u64,
    generation: u64,
    owner: [u8; 32],
}

#[derive(Clone, Debug)]
struct SpendTx {
    network_id: u32,
    tx_id: u64,
    inputs: Vec<InputRef>,
    output_id: u64,
    recipient: [u8; 32],
    output_value: u64,
    expiry: u64,
}

#[derive(Clone, Copy)]
struct UserAuthorization {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy)]
struct VerifiedSpend {
    digest: [u8; 32],
    signer: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct LockEvidence {
    certifier: [u8; 32],
    epoch: u64,
    input: InputRef,
    digest: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy)]
struct WitnessAck {
    witness: [u8; 32],
    evidence_fingerprint: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy)]
struct CertifierShare {
    certifier: [u8; 32],
    digest: [u8; 32],
    user_signer: [u8; 32],
    epoch: u64,
    signature: [u8; 64],
}

#[derive(Clone)]
struct ThresholdCertificate {
    digest: [u8; 32],
    user_signer: [u8; 32],
    shares: Vec<CertifierShare>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct EvidenceKey {
    certifier: [u8; 32],
    epoch: u64,
    input: InputRef,
}

struct WitnessStore {
    path: PathBuf,
    file: File,
    evidence: HashMap<EvidenceKey, LockEvidence>,
}

struct WitnessNode {
    sk: SigningKey,
    byzantine: bool,
    store: WitnessStore,
}

struct CertifierNode {
    sk: SigningKey,
    byzantine: bool,
    local_locks: HashMap<InputRef, [u8; 32]>,
}

#[derive(Clone)]
struct CoreState {
    active: HashMap<u64, Cell>,
    committee: Vec<[u8; 32]>,
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn canonical_user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + tx.inputs.len() * 16);
    out.extend_from_slice(b"CALIBRE_SEC004_USER_SPEND_V1");
    out.extend_from_slice(&tx.network_id.to_le_bytes());
    out.extend_from_slice(&tx.tx_id.to_le_bytes());
    out.extend_from_slice(&(tx.inputs.len() as u64).to_le_bytes());
    for input in &tx.inputs {
        out.extend_from_slice(&input.id.to_le_bytes());
        out.extend_from_slice(&input.generation.to_le_bytes());
    }
    out.extend_from_slice(&tx.output_id.to_le_bytes());
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&tx.output_value.to_le_bytes());
    out.extend_from_slice(&tx.expiry.to_le_bytes());
    out
}

fn tx_commitment(tx: &SpendTx, signer: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC004_AUTHORIZED_TX_V1");
    h.update(&canonical_user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn sign_user_spend(tx: &SpendTx, sk: &SigningKey) -> UserAuthorization {
    UserAuthorization {
        signer: sk.verifying_key().to_bytes(),
        signature: sk.sign(&canonical_user_message(tx)).to_bytes(),
    }
}

fn verify_user_authorization(
    tx: &SpendTx,
    auth: &UserAuthorization,
    cells: &HashMap<u64, Cell>,
) -> Result<VerifiedSpend, String> {
    if tx.network_id != NETWORK_ID {
        return Err("wrong network".into());
    }
    if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
        return Err("invalid input count".into());
    }
    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "invalid user key")?;
    let sig = Signature::from_bytes(&auth.signature);
    vk.verify_strict(&canonical_user_message(tx), &sig)
        .map_err(|_| "user signature rejected")?;

    let mut seen = HashSet::new();
    let mut total = 0u64;
    for input in &tx.inputs {
        if !seen.insert(*input) {
            return Err("duplicate input".into());
        }
        let cell = cells.get(&input.id).ok_or("input not active")?;
        if cell.generation != input.generation {
            return Err("generation mismatch".into());
        }
        if cell.owner != auth.signer {
            return Err("owner mismatch".into());
        }
        total = total.checked_add(cell.value).ok_or("value overflow")?;
    }
    if total != tx.output_value {
        return Err("value conservation mismatch".into());
    }
    Ok(VerifiedSpend {
        digest: tx_commitment(tx, &auth.signer),
        signer: auth.signer,
    })
}

fn evidence_message(certifier: &[u8; 32], input: InputRef, digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(120);
    out.extend_from_slice(b"CALIBRE_SEC004_LOCK_EVIDENCE_V1");
    out.extend_from_slice(&EPOCH.to_le_bytes());
    out.extend_from_slice(certifier);
    out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes());
    out.extend_from_slice(digest);
    out
}

fn make_evidence(sk: &SigningKey, input: InputRef, digest: [u8; 32]) -> LockEvidence {
    let certifier = sk.verifying_key().to_bytes();
    LockEvidence {
        certifier,
        epoch: EPOCH,
        input,
        digest,
        signature: sk.sign(&evidence_message(&certifier, input, &digest)).to_bytes(),
    }
}

fn verify_evidence(e: &LockEvidence) -> Result<(), String> {
    if e.epoch != EPOCH {
        return Err("evidence epoch mismatch".into());
    }
    let vk = VerifyingKey::from_bytes(&e.certifier).map_err(|_| "invalid evidence key")?;
    let sig = Signature::from_bytes(&e.signature);
    vk.verify_strict(&evidence_message(&e.certifier, e.input, &e.digest), &sig)
        .map_err(|_| "evidence signature rejected".into())
}

fn evidence_fingerprint(e: &LockEvidence) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC004_EVIDENCE_FINGERPRINT_V1");
    h.update(&e.certifier);
    h.update(&e.epoch.to_le_bytes());
    h.update(&e.input.id.to_le_bytes());
    h.update(&e.input.generation.to_le_bytes());
    h.update(&e.digest);
    h.update(&e.signature);
    *h.finalize().as_bytes()
}

fn ack_message(fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(b"CALIBRE_SEC004_WITNESS_ACK_V1");
    out.extend_from_slice(&EPOCH.to_le_bytes());
    out.extend_from_slice(fingerprint);
    out
}

fn verify_ack(ack: &WitnessAck, trusted: &HashSet<[u8; 32]>, fp: &[u8; 32]) -> Result<(), String> {
    if !trusted.contains(&ack.witness) || &ack.evidence_fingerprint != fp {
        return Err("invalid witness ack membership/content".into());
    }
    let vk = VerifyingKey::from_bytes(&ack.witness).map_err(|_| "invalid witness key")?;
    let sig = Signature::from_bytes(&ack.signature);
    vk.verify_strict(&ack_message(fp), &sig)
        .map_err(|_| "witness ack signature rejected".into())
}

fn record_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC004_WITNESS_RECORD_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_record(e: &LockEvidence) -> [u8; WITNESS_RECORD_SIZE] {
    let mut out = [0u8; WITNESS_RECORD_SIZE];
    out[0..8].copy_from_slice(&WITNESS_MAGIC);
    out[8..40].copy_from_slice(&e.certifier);
    out[40..48].copy_from_slice(&e.epoch.to_le_bytes());
    out[48..56].copy_from_slice(&e.input.id.to_le_bytes());
    out[56..64].copy_from_slice(&e.input.generation.to_le_bytes());
    out[64..96].copy_from_slice(&e.digest);
    out[96..160].copy_from_slice(&e.signature);
    let c = record_checksum(&out[..160]);
    out[160..192].copy_from_slice(&c);
    out
}

fn decode_record(buf: &[u8]) -> Result<LockEvidence, String> {
    if buf.len() != WITNESS_RECORD_SIZE || &buf[0..8] != &WITNESS_MAGIC[..] {
        return Err("witness record format rejected".into());
    }
    if &record_checksum(&buf[..160])[..] != &buf[160..192] {
        return Err("witness record checksum rejected".into());
    }
    let mut certifier = [0u8; 32];
    certifier.copy_from_slice(&buf[8..40]);
    let epoch = u64::from_le_bytes(buf[40..48].try_into().unwrap());
    let input = InputRef {
        id: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
        generation: u64::from_le_bytes(buf[56..64].try_into().unwrap()),
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[64..96]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[96..160]);
    let e = LockEvidence { certifier, epoch, input, digest, signature };
    verify_evidence(&e)?;
    Ok(e)
}

impl WitnessStore {
    fn open(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = OpenOptions::new().read(true).write(true).create(true).open(&path)
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let full = bytes.len() / WITNESS_RECORD_SIZE;
        let valid_len = full * WITNESS_RECORD_SIZE;
        let mut evidence = HashMap::new();
        for i in 0..full {
            let start = i * WITNESS_RECORD_SIZE;
            let e = decode_record(&bytes[start..start + WITNESS_RECORD_SIZE])?;
            let key = EvidenceKey { certifier: e.certifier, epoch: e.epoch, input: e.input };
            if let Some(old) = evidence.insert(key, e) {
                if old.digest != e.digest {
                    return Err("witness durable store contains conflicting evidence".into());
                }
            }
        }
        if bytes.len() != valid_len {
            file.set_len(valid_len as u64).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        Ok(Self { path, file, evidence })
    }

    fn persist(&mut self, e: LockEvidence) -> Result<(), String> {
        verify_evidence(&e)?;
        let key = EvidenceKey { certifier: e.certifier, epoch: e.epoch, input: e.input };
        if let Some(old) = self.evidence.get(&key) {
            if old.digest != e.digest {
                return Err("honest witness refuses conflicting evidence".into());
            }
            return Ok(());
        }
        self.file.write_all(&encode_record(&e)).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.evidence.insert(key, e);
        Ok(())
    }

    fn get(&self, certifier: [u8; 32], input: InputRef) -> Option<LockEvidence> {
        self.evidence.get(&EvidenceKey { certifier, epoch: EPOCH, input }).copied()
    }
}

impl WitnessNode {
    fn open(index: usize, byzantine: bool, root: &Path) -> Result<Self, String> {
        Ok(Self {
            sk: deterministic_key(b"CALIBRE_SEC004_WITNESS_KEY_V1", index as u64),
            byzantine,
            store: WitnessStore::open(root.join(format!("witness-{index}.wal")))?,
        })
    }

    fn public(&self) -> [u8; 32] { self.sk.verifying_key().to_bytes() }

    fn accept(&mut self, e: LockEvidence) -> Result<WitnessAck, String> {
        verify_evidence(&e)?;
        if !self.byzantine {
            self.store.persist(e)?;
        }
        let fp = evidence_fingerprint(&e);
        Ok(WitnessAck {
            witness: self.public(),
            evidence_fingerprint: fp,
            signature: self.sk.sign(&ack_message(&fp)).to_bytes(),
        })
    }

    fn query(&self, certifier: [u8; 32], input: InputRef) -> Option<LockEvidence> {
        if self.byzantine { None } else { self.store.get(certifier, input) }
    }
}

fn open_witnesses(root: &Path) -> Result<Vec<WitnessNode>, String> {
    (0..N).map(|i| WitnessNode::open(i, i < F, root)).collect()
}

fn certifier_share_message(digest: &[u8; 32], user: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC004_CERTIFIER_SHARE_V1");
    out.extend_from_slice(&EPOCH.to_le_bytes());
    out.extend_from_slice(digest);
    out.extend_from_slice(user);
    out
}

impl CertifierNode {
    fn new(index: usize, byzantine: bool) -> Self {
        Self {
            sk: deterministic_key(b"CALIBRE_SEC004_CERTIFIER_KEY_V1", index as u64),
            byzantine,
            local_locks: HashMap::new(),
        }
    }

    fn public(&self) -> [u8; 32] { self.sk.verifying_key().to_bytes() }

    fn rollback_local_state(&mut self) { self.local_locks.clear(); }

    fn recover_input(
        &self,
        input: InputRef,
        witnesses: &[WitnessNode],
        recovery_indices: &[usize],
    ) -> Result<Option<[u8; 32]>, String> {
        let mut unique_responses = HashSet::new();
        let mut found: Option<[u8; 32]> = None;
        for &i in recovery_indices {
            unique_responses.insert(witnesses[i].public());
            if let Some(e) = witnesses[i].query(self.public(), input) {
                verify_evidence(&e)?;
                if e.certifier != self.public() || e.input != input {
                    return Err("recovery evidence mismatch".into());
                }
                if let Some(d) = found {
                    if d != e.digest { return Err("conflicting signed recovery evidence".into()); }
                } else {
                    found = Some(e.digest);
                }
            }
        }
        if unique_responses.len() < RECOVERY_Q {
            return Err("insufficient recovery responses".into());
        }
        Ok(found)
    }

    fn anchor_input(
        &self,
        input: InputRef,
        digest: [u8; 32],
        witnesses: &mut [WitnessNode],
        anchor_indices: &[usize],
    ) -> Result<(), String> {
        let evidence = make_evidence(&self.sk, input, digest);
        let fp = evidence_fingerprint(&evidence);
        let trusted: HashSet<[u8; 32]> = witnesses.iter().map(WitnessNode::public).collect();
        let mut unique = HashSet::new();
        for &i in anchor_indices {
            if let Ok(ack) = witnesses[i].accept(evidence) {
                verify_ack(&ack, &trusted, &fp)?;
                unique.insert(ack.witness);
            }
        }
        if unique.len() < ANCHOR_Q {
            return Err(format!("insufficient witness anchor acks: {}", unique.len()));
        }
        Ok(())
    }

    fn authorize_anchor_and_sign(
        &mut self,
        tx: &SpendTx,
        auth: &UserAuthorization,
        cells: &HashMap<u64, Cell>,
        witnesses: &mut [WitnessNode],
        anchor_indices: &[usize],
        recovery_indices: &[usize],
    ) -> Result<CertifierShare, String> {
        let verified = verify_user_authorization(tx, auth, cells)?;
        if !self.byzantine {
            for input in &tx.inputs {
                if let Some(recovered) = self.recover_input(*input, witnesses, recovery_indices)? {
                    if recovered != verified.digest {
                        return Err("distributed anti-rollback recovery found prior conflicting lock".into());
                    }
                    self.local_locks.insert(*input, recovered);
                }
                if let Some(existing) = self.local_locks.get(input) {
                    if existing != &verified.digest {
                        return Err("local conflict lock rejected".into());
                    }
                }
            }
            for input in &tx.inputs {
                self.anchor_input(*input, verified.digest, witnesses, anchor_indices)?;
            }
            for input in &tx.inputs {
                self.local_locks.insert(*input, verified.digest);
            }
        }
        Ok(CertifierShare {
            certifier: self.public(),
            digest: verified.digest,
            user_signer: verified.signer,
            epoch: EPOCH,
            signature: self.sk.sign(&certifier_share_message(&verified.digest, &verified.signer)).to_bytes(),
        })
    }
}

fn verify_threshold(tx: &SpendTx, cert: &ThresholdCertificate, committee: &[[u8; 32]]) -> Result<(), String> {
    if tx_commitment(tx, &cert.user_signer) != cert.digest {
        return Err("certificate transaction mismatch".into());
    }
    let trusted: HashSet<[u8; 32]> = committee.iter().copied().collect();
    let mut unique = HashSet::new();
    for share in &cert.shares {
        if share.epoch != EPOCH || share.digest != cert.digest || share.user_signer != cert.user_signer {
            return Err("share mismatch".into());
        }
        if !trusted.contains(&share.certifier) || !unique.insert(share.certifier) {
            continue;
        }
        let vk = VerifyingKey::from_bytes(&share.certifier).map_err(|_| "bad certifier key")?;
        let sig = Signature::from_bytes(&share.signature);
        vk.verify_strict(&certifier_share_message(&share.digest, &share.user_signer), &sig)
            .map_err(|_| "bad certifier signature")?;
    }
    if unique.len() < AUTH_Q { return Err("insufficient certifier quorum".into()); }
    Ok(())
}

impl CoreState {
    fn new(active: HashMap<u64, Cell>, committee: Vec<[u8; 32]>) -> Self { Self { active, committee } }

    fn apply(&mut self, tx: &SpendTx, cert: &ThresholdCertificate) -> Result<Cell, String> {
        verify_threshold(tx, cert, &self.committee)?;
        let mut total = 0u64;
        for input in &tx.inputs {
            let cell = self.active.get(&input.id).ok_or("core input inactive")?;
            if cell.generation != input.generation { return Err("core generation mismatch".into()); }
            total += cell.value;
        }
        if total != tx.output_value { return Err("core value mismatch".into()); }
        for input in &tx.inputs { self.active.remove(&input.id); }
        let out = Cell { id: tx.output_id, value: tx.output_value, generation: 0, owner: tx.recipient };
        self.active.insert(out.id, out.clone());
        Ok(out)
    }
}

fn alice_cells(owner: [u8; 32]) -> HashMap<u64, Cell> {
    (0..MAX_INPUTS).map(|i| {
        let id = 1000 + i as u64;
        (id, Cell { id, value: CELL_VALUE, generation: 7, owner })
    }).collect()
}

fn spend_to(recipient: [u8; 32], tx_id: u64, output_id: u64) -> SpendTx {
    SpendTx {
        network_id: NETWORK_ID,
        tx_id,
        inputs: (0..MAX_INPUTS).map(|i| InputRef { id: 1000 + i as u64, generation: 7 }).collect(),
        output_id,
        recipient,
        output_value: CELL_VALUE * MAX_INPUTS as u64,
        expiry: 2_000_000_000,
    }
}

fn unique_temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!("calibre-sec004-{label}-{}-{nanos}-{seq}", process::id()))
}

fn snapshot(path: &Path) -> Vec<u8> { fs::read(path).unwrap_or_default() }

fn restore(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn witness_path(root: &Path, index: usize) -> PathBuf { root.join(format!("witness-{index}.wal")) }

fn main() {
    let alice_sk = deterministic_key(b"CALIBRE_SEC004_USER_KEY_V1", 1);
    let bob_sk = deterministic_key(b"CALIBRE_SEC004_USER_KEY_V1", 2);
    let mallory_sk = deterministic_key(b"CALIBRE_SEC004_USER_KEY_V1", 3);
    let alice = alice_sk.verifying_key().to_bytes();
    let bob = bob_sk.verifying_key().to_bytes();
    let mallory = mallory_sk.verifying_key().to_bytes();
    let cells = alice_cells(alice);
    let tx_a = spend_to(bob, 100, 9000);
    let tx_b = spend_to(mallory, 101, 9001);
    let auth_a = sign_user_spend(&tx_a, &alice_sk);
    let auth_b = sign_user_spend(&tx_b, &alice_sk);

    println!("CALIBRE SECURITY SEC-004 v0.4.0");
    println!("DISTRIBUTED 5-OF-7 LOCK ANCHOR + 6-OF-7 ROLLBACK RECOVERY");
    println!("Purpose: recover an honest certifier's prior conflict decision even if its local SEC-003 WAL is rolled back");
    println!("AUTH_Q={} ANCHOR_Q={} RECOVERY_Q={} N={} F={} | anchor/recovery intersection={} (>F)", AUTH_Q, ANCHOR_Q, RECOVERY_Q, N, F, ANCHOR_Q + RECOVERY_Q - N);
    println!("Performance target: NONE - security semantics only");
    println!();

    let root = unique_temp_root("main");
    fs::create_dir_all(&root).unwrap();
    let mut witnesses = open_witnesses(&root).unwrap();
    let witness_snapshots: Vec<(PathBuf, Vec<u8>)> = [2usize, 3, 4].iter().map(|&i| {
        let p = witness_path(&root, i);
        (p.clone(), snapshot(&p))
    }).collect();
    let mut certifiers: Vec<CertifierNode> = (0..N).map(|i| CertifierNode::new(i, i < F)).collect();
    let committee: Vec<[u8; 32]> = certifiers.iter().map(CertifierNode::public).collect();
    let anchor = [0usize, 1, 2, 3, 4];
    let recovery = [0usize, 1, 2, 3, 5, 6];

    let mut a_shares = Vec::new();
    for i in [0usize, 1, 2, 3, 4] {
        a_shares.push(certifiers[i].authorize_anchor_and_sign(&tx_a, &auth_a, &cells, &mut witnesses, &anchor, &recovery).unwrap());
    }
    let cert_a = ThresholdCertificate { digest: a_shares[0].digest, user_signer: a_shares[0].user_signer, shares: a_shares };
    verify_threshold(&tx_a, &cert_a, &committee).unwrap();
    println!("ALICE -> BOB 5-OF-7 CERTIFICATE WITH WITNESS-ANCHORED HONEST LOCKS: PASS");

    // Roll back local certifier memory for the three honest signers of A. Distributed recovery must restore A.
    for i in [2usize, 3, 4] { certifiers[i].rollback_local_state(); }
    let mut b_shares = Vec::new();
    for i in [0usize, 1, 5, 6, 2, 3, 4] {
        if let Ok(s) = certifiers[i].authorize_anchor_and_sign(&tx_b, &auth_b, &cells, &mut witnesses, &anchor, &recovery) {
            b_shares.push(s);
        }
    }
    assert_eq!(b_shares.len(), 4);
    println!("ROLL BACK 3 HONEST CERTIFIER LOCAL LOCKS: 6-OF-7 RECOVERY FINDS PRIOR A EVIDENCE; B GETS ONLY 4/7 -> REJECTED");

    // Stronger boundary attack: also roll back the three honest witness stores that carried the A anchors.
    drop(witnesses);
    for (path, bytes) in &witness_snapshots { restore(path, bytes); }
    let mut witnesses = open_witnesses(&root).unwrap();
    for i in [2usize, 3, 4] { certifiers[i].rollback_local_state(); }
    let mut b2 = Vec::new();
    for i in [0usize, 1, 2, 3, 4] {
        b2.push(certifiers[i].authorize_anchor_and_sign(&tx_b, &auth_b, &cells, &mut witnesses, &anchor, &recovery).unwrap());
    }
    let cert_b = ThresholdCertificate { digest: b2[0].digest, user_signer: b2[0].user_signer, shares: b2 };
    verify_threshold(&tx_b, &cert_b, &committee).unwrap();
    let mut replica_a = CoreState::new(cells.clone(), committee.clone());
    let mut replica_b = CoreState::new(cells.clone(), committee.clone());
    assert_eq!(replica_a.apply(&tx_a, &cert_a).unwrap().owner, bob);
    assert_eq!(replica_b.apply(&tx_b, &cert_b).unwrap().owner, mallory);
    println!("ROLL BACK LOCAL LOCKS + 3 HONEST WITNESS ANCHOR WALs: TWO VALID 5-OF-7 SUCCESSORS -> ATTACK CONFIRMED");
    println!();

    println!("=== SEC-004 DECISION ===");
    println!("SIGNED LOCK EVIDENCE ANCHORED TO 5-OF-7 WITNESSES BEFORE HONEST SHARE: PASS");
    println!("WITNESS ACKS ARE UNIQUE REAL ED25519 SIGNATURES: PASS");
    println!("6-OF-7 RECOVERY INTERSECTS PRIOR 5-OF-7 ANCHOR IN >=4 NODES: PASS / MATHEMATICAL");
    println!("LOCAL CERTIFIER SNAPSHOT ROLLBACK RECOVERY WITH F<=2: PASS UNDER DURABLE-WITNESS ASSUMPTION");
    println!("SECOND AUTHORIZATION QUORUM AFTER LOCAL-ONLY ROLLBACK: REJECTED");
    println!("COORDINATED ROLLBACK OF 3 HONEST WITNESS STORES: FAIL - ATTACK CONFIRMED");
    println!("TPM / HARDWARE MONOTONIC ANTI-ROLLBACK: NOT YET");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL ORDER: NOT USED");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");

    let _ = fs::remove_dir_all(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_intersection_exceeds_byzantine_bound() {
        assert_eq!(ANCHOR_Q + RECOVERY_Q - N, 4);
        assert!(ANCHOR_Q + RECOVERY_Q - N > F);
    }

    #[test]
    fn witness_record_round_trip_and_signature_check() {
        let sk = deterministic_key(b"CALIBRE_SEC004_CERTIFIER_KEY_V1", 2);
        let e = make_evidence(&sk, InputRef { id: 1, generation: 7 }, [9u8; 32]);
        let decoded = decode_record(&encode_record(&e)).unwrap();
        assert_eq!(decoded.certifier, e.certifier);
        assert_eq!(decoded.input, e.input);
        assert_eq!(decoded.digest, e.digest);
    }

    #[test]
    fn local_rollback_is_recovered_from_witness_quorum() {
        let root = unique_temp_root("test-recovery");
        fs::create_dir_all(&root).unwrap();
        let mut witnesses = open_witnesses(&root).unwrap();
        let mut certifier = CertifierNode::new(2, false);
        let input = InputRef { id: 1000, generation: 7 };
        let digest = [7u8; 32];
        let anchor = [0usize, 1, 2, 3, 4];
        certifier.anchor_input(input, digest, &mut witnesses, &anchor).unwrap();
        certifier.local_locks.insert(input, digest);
        certifier.rollback_local_state();
        let recovered = certifier.recover_input(input, &witnesses, &[0usize, 1, 2, 3, 5, 6]).unwrap();
        assert_eq!(recovered, Some(digest));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn three_honest_witness_rollbacks_erase_software_anchor_boundary() {
        let root = unique_temp_root("test-witness-rollback");
        fs::create_dir_all(&root).unwrap();
        let mut witnesses = open_witnesses(&root).unwrap();
        let snaps: Vec<(PathBuf, Vec<u8>)> = [2usize, 3, 4].iter().map(|&i| {
            let p = witness_path(&root, i);
            (p.clone(), snapshot(&p))
        }).collect();
        let certifier = CertifierNode::new(2, false);
        let input = InputRef { id: 1000, generation: 7 };
        certifier.anchor_input(input, [1u8; 32], &mut witnesses, &[0usize, 1, 2, 3, 4]).unwrap();
        drop(witnesses);
        for (p, b) in &snaps { restore(p, b); }
        let witnesses = open_witnesses(&root).unwrap();
        assert_eq!(certifier.recover_input(input, &witnesses, &[0usize, 1, 2, 3, 5, 6]).unwrap(), None);
        let _ = fs::remove_dir_all(root);
    }
}
