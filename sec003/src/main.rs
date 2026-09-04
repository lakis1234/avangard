use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NETWORK_ID: u32 = 1;
const MAX_INPUTS: usize = 8;
const CELL_VALUE: u64 = 100;
const CERT_EPOCH: u64 = 3;
const N: usize = 7;
const Q: usize = 5;
const LOCK_MAGIC: [u8; 8] = *b"CALLK003";
const LOCK_RECORD_SIZE: usize = 96;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cell {
    id: u64,
    value: u64,
    generation: u64,
    owner: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LockKey {
    epoch: u64,
    input: InputRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SpendTx {
    network_id: u32,
    tx_id: u64,
    inputs: Vec<InputRef>,
    output_id: u64,
    recipient: [u8; 32],
    output_value: u64,
    expiry: u64,
}

#[derive(Clone, Copy, Debug)]
struct UserAuthorization {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct VerifiedSpend {
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct CertifierShare {
    certifier: [u8; 32],
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
    epoch: u64,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct ThresholdCertificate {
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
    epoch: u64,
    shares: Vec<CertifierShare>,
}

struct DurableLockStore {
    path: PathBuf,
    file: File,
    locks: HashMap<LockKey, [u8; 32]>,
}

struct CertifierNode {
    index: usize,
    sk: SigningKey,
    byzantine: bool,
    store: DurableLockStore,
}

#[derive(Clone)]
struct CoreState {
    active: HashMap<u64, Cell>,
    committee: Vec<[u8; 32]>,
    threshold: usize,
}

fn ioerr(context: &str, e: std::io::Error) -> String {
    format!("{context}: {e}")
}

fn deterministic_key(label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC003_DETERMINISTIC_KEY_V1");
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn canonical_user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + tx.inputs.len() * 16);
    out.extend_from_slice(b"CALIBRE_SEC003_USER_SPEND_V1");
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
    h.update(b"CALIBRE_SEC003_AUTHORIZED_TX_COMMITMENT_V1");
    h.update(&canonical_user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn share_message(tx_digest: &[u8; 32], user_signer: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC003_THRESHOLD_SHARE_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(tx_digest);
    out.extend_from_slice(user_signer);
    out
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
        return Err("wrong network/domain".into());
    }
    if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
        return Err("invalid input count".into());
    }

    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "invalid user public key")?;
    let sig = Signature::from_bytes(&auth.signature);
    vk.verify_strict(&canonical_user_message(tx), &sig)
        .map_err(|_| "user signature rejected")?;

    let mut seen = HashSet::with_capacity(tx.inputs.len());
    let mut total = 0u64;
    for input in &tx.inputs {
        if !seen.insert(*input) {
            return Err("duplicate input".into());
        }
        let cell = cells
            .get(&input.id)
            .ok_or_else(|| format!("input {} not active", input.id))?;
        if cell.generation != input.generation {
            return Err(format!("input {} generation mismatch", input.id));
        }
        if cell.owner != auth.signer {
            return Err(format!("input {} owner mismatch", input.id));
        }
        total = total
            .checked_add(cell.value)
            .ok_or_else(|| "input value overflow".to_string())?;
    }

    if total != tx.output_value {
        return Err(format!(
            "value conservation mismatch: inputs={} output={}",
            total, tx.output_value
        ));
    }

    Ok(VerifiedSpend {
        tx_digest: tx_commitment(tx, &auth.signer),
        user_signer: auth.signer,
    })
}

fn lock_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC003_LOCK_RECORD_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_lock_record(key: LockKey, digest: [u8; 32]) -> [u8; LOCK_RECORD_SIZE] {
    let mut out = [0u8; LOCK_RECORD_SIZE];
    out[0..8].copy_from_slice(&LOCK_MAGIC);
    out[8..16].copy_from_slice(&key.epoch.to_le_bytes());
    out[16..24].copy_from_slice(&key.input.id.to_le_bytes());
    out[24..32].copy_from_slice(&key.input.generation.to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    let checksum = lock_checksum(&out[..64]);
    out[64..96].copy_from_slice(&checksum);
    out
}

fn decode_lock_record(buf: &[u8]) -> Result<(LockKey, [u8; 32]), String> {
    if buf.len() != LOCK_RECORD_SIZE {
        return Err("lock record wrong size".into());
    }
    if &buf[0..8] != &LOCK_MAGIC[..] {
        return Err("lock record magic mismatch".into());
    }
    let expected = lock_checksum(&buf[..64]);
    if &buf[64..96] != &expected[..] {
        return Err("lock record checksum mismatch".into());
    }
    let epoch = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let id = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let generation = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[32..64]);
    Ok((
        LockKey {
            epoch,
            input: InputRef { id, generation },
        },
        digest,
    ))
}

impl DurableLockStore {
    fn open(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ioerr("create lock directory", e))?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|e| ioerr("open durable lock WAL", e))?;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| ioerr("seek durable lock WAL", e))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| ioerr("read durable lock WAL", e))?;

        let full_records = bytes.len() / LOCK_RECORD_SIZE;
        let valid_len = full_records * LOCK_RECORD_SIZE;
        let mut locks = HashMap::new();
        for i in 0..full_records {
            let start = i * LOCK_RECORD_SIZE;
            let end = start + LOCK_RECORD_SIZE;
            let (key, digest) = decode_lock_record(&bytes[start..end])?;
            if let Some(existing) = locks.insert(key, digest) {
                if existing != digest {
                    return Err(format!(
                        "durable WAL contains conflicting lock for input {} generation {} epoch {}",
                        key.input.id, key.input.generation, key.epoch
                    ));
                }
            }
        }

        // A partial tail can only originate before sync_all() completed. The certifier signs only
        // after sync_all() succeeds, so truncating an incomplete tail cannot forget a signed share.
        if bytes.len() != valid_len {
            file.set_len(valid_len as u64)
                .map_err(|e| ioerr("truncate torn lock WAL tail", e))?;
            file.sync_all()
                .map_err(|e| ioerr("sync truncated lock WAL", e))?;
        }
        file.seek(SeekFrom::End(0))
            .map_err(|e| ioerr("seek lock WAL end", e))?;

        Ok(Self { path, file, locks })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn lock_inputs_before_signing(
        &mut self,
        inputs: &[InputRef],
        digest: [u8; 32],
    ) -> Result<(), String> {
        let mut pending = Vec::new();
        for input in inputs {
            let key = LockKey {
                epoch: CERT_EPOCH,
                input: *input,
            };
            if let Some(existing) = self.locks.get(&key) {
                if existing != &digest {
                    return Err(format!(
                        "persistent honest conflict lock for input {} generation {} epoch {}",
                        input.id, input.generation, CERT_EPOCH
                    ));
                }
            } else {
                pending.push((key, encode_lock_record(key, digest)));
            }
        }

        if pending.is_empty() {
            return Ok(());
        }

        self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| ioerr("seek lock WAL append", e))?;
        for (_, record) in &pending {
            self.file
                .write_all(record)
                .map_err(|e| ioerr("append lock WAL record", e))?;
        }

        // Safety ordering: durable lock first, signature share second.
        self.file
            .sync_all()
            .map_err(|e| ioerr("sync lock WAL before certifier signature", e))?;

        for (key, _) in pending {
            self.locks.insert(key, digest);
        }
        Ok(())
    }
}

fn certifier_path(root: &Path, index: usize) -> PathBuf {
    root.join(format!("certifier-{index}.lockwal"))
}

impl CertifierNode {
    fn open(index: usize, byzantine: bool, root: &Path) -> Result<Self, String> {
        Ok(Self {
            index,
            sk: deterministic_key(100 + index as u64),
            byzantine,
            store: DurableLockStore::open(certifier_path(root, index))?,
        })
    }

    fn public(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    fn make_share(&self, verified: VerifiedSpend) -> CertifierShare {
        CertifierShare {
            certifier: self.public(),
            tx_digest: verified.tx_digest,
            user_signer: verified.user_signer,
            epoch: CERT_EPOCH,
            signature: self
                .sk
                .sign(&share_message(
                    &verified.tx_digest,
                    &verified.user_signer,
                    CERT_EPOCH,
                ))
                .to_bytes(),
        }
    }

    fn persist_verified_locks(
        &mut self,
        tx: &SpendTx,
        verified: VerifiedSpend,
    ) -> Result<(), String> {
        if self.byzantine {
            return Ok(());
        }
        self.store
            .lock_inputs_before_signing(&tx.inputs, verified.tx_digest)
    }

    fn authorize_and_sign(
        &mut self,
        tx: &SpendTx,
        auth: &UserAuthorization,
        cells: &HashMap<u64, Cell>,
    ) -> Result<CertifierShare, String> {
        let verified = verify_user_authorization(tx, auth, cells)?;
        self.persist_verified_locks(tx, verified)?;
        Ok(self.make_share(verified))
    }

    fn sign_raw_claim(
        &self,
        tx: &SpendTx,
        claimed_user: [u8; 32],
    ) -> Result<CertifierShare, String> {
        if !self.byzantine {
            return Err("honest certifier refuses raw unverified claim".into());
        }
        Ok(self.make_share(VerifiedSpend {
            tx_digest: tx_commitment(tx, &claimed_user),
            user_signer: claimed_user,
        }))
    }
}

fn open_committee(root: &Path, f_byzantine: usize) -> Result<Vec<CertifierNode>, String> {
    assert!(f_byzantine <= N);
    (0..N)
        .map(|i| CertifierNode::open(i, i < f_byzantine, root))
        .collect()
}

fn committee_keys(nodes: &[CertifierNode]) -> Vec<[u8; 32]> {
    nodes.iter().map(CertifierNode::public).collect()
}

fn certificate_from(shares: Vec<CertifierShare>) -> ThresholdCertificate {
    assert!(!shares.is_empty());
    ThresholdCertificate {
        tx_digest: shares[0].tx_digest,
        user_signer: shares[0].user_signer,
        epoch: shares[0].epoch,
        shares,
    }
}

impl CoreState {
    fn new(cells: HashMap<u64, Cell>, committee: Vec<[u8; 32]>, threshold: usize) -> Self {
        Self {
            active: cells,
            committee,
            threshold,
        }
    }

    fn verify_threshold_certificate(
        &self,
        tx: &SpendTx,
        cert: &ThresholdCertificate,
    ) -> Result<(), String> {
        if cert.epoch != CERT_EPOCH {
            return Err("certificate epoch mismatch".into());
        }
        if tx_commitment(tx, &cert.user_signer) != cert.tx_digest {
            return Err("threshold certificate does not bind exact transaction".into());
        }

        let trusted: HashSet<[u8; 32]> = self.committee.iter().copied().collect();
        let mut unique = HashSet::new();
        for share in &cert.shares {
            if share.epoch != cert.epoch
                || share.tx_digest != cert.tx_digest
                || share.user_signer != cert.user_signer
            {
                return Err("share/certificate mismatch".into());
            }
            if !trusted.contains(&share.certifier) {
                return Err("share from untrusted certifier".into());
            }
            if !unique.insert(share.certifier) {
                continue;
            }
            let vk = VerifyingKey::from_bytes(&share.certifier)
                .map_err(|_| "invalid certifier public key")?;
            let sig = Signature::from_bytes(&share.signature);
            vk.verify_strict(
                &share_message(&share.tx_digest, &share.user_signer, share.epoch),
                &sig,
            )
            .map_err(|_| "threshold share signature rejected")?;
        }
        if unique.len() < self.threshold {
            return Err(format!(
                "insufficient threshold shares: have {} need {}",
                unique.len(), self.threshold
            ));
        }
        Ok(())
    }

    fn apply_certified_spend(
        &mut self,
        tx: &SpendTx,
        cert: &ThresholdCertificate,
    ) -> Result<Cell, String> {
        if tx.network_id != NETWORK_ID {
            return Err("core wrong network/domain".into());
        }
        self.verify_threshold_certificate(tx, cert)?;
        if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
            return Err("core invalid input count".into());
        }
        if self.active.contains_key(&tx.output_id) {
            return Err("output id already active".into());
        }

        let mut seen = HashSet::with_capacity(tx.inputs.len());
        let mut total = 0u64;
        for input in &tx.inputs {
            if !seen.insert(*input) {
                return Err("core duplicate input".into());
            }
            let cell = self
                .active
                .get(&input.id)
                .ok_or_else(|| format!("core input {} already spent/not active", input.id))?;
            if cell.generation != input.generation {
                return Err(format!("core input {} generation mismatch", input.id));
            }
            total = total
                .checked_add(cell.value)
                .ok_or_else(|| "core input value overflow".to_string())?;
        }
        if total != tx.output_value {
            return Err("core value conservation mismatch".into());
        }

        for input in &tx.inputs {
            self.active.remove(&input.id);
        }
        let output = Cell {
            id: tx.output_id,
            value: tx.output_value,
            generation: 0,
            owner: tx.recipient,
        };
        self.active.insert(output.id, output.clone());
        Ok(output)
    }
}

fn alice_cells(alice: [u8; 32]) -> HashMap<u64, Cell> {
    (0..MAX_INPUTS)
        .map(|i| {
            let id = 1_000 + i as u64;
            (
                id,
                Cell {
                    id,
                    value: CELL_VALUE,
                    generation: 7,
                    owner: alice,
                },
            )
        })
        .collect()
}

fn spend_to(recipient: [u8; 32], tx_id: u64, output_id: u64) -> SpendTx {
    SpendTx {
        network_id: NETWORK_ID,
        tx_id,
        inputs: (0..MAX_INPUTS)
            .map(|i| InputRef {
                id: 1_000 + i as u64,
                generation: 7,
            })
            .collect(),
        output_id,
        recipient,
        output_value: CELL_VALUE * MAX_INPUTS as u64,
        expiry: 2_000_000_000,
    }
}

fn collect_valid_shares(
    nodes: &mut [CertifierNode],
    indices: &[usize],
    tx: &SpendTx,
    auth: &UserAuthorization,
    cells: &HashMap<u64, Cell>,
) -> Vec<CertifierShare> {
    let mut out = Vec::new();
    for &i in indices {
        if let Ok(share) = nodes[i].authorize_and_sign(tx, auth, cells) {
            out.push(share);
        }
    }
    out
}

fn unique_temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "calibre-sec003-{label}-{}-{nanos}-{seq}",
        process::id()
    ))
}

fn snapshot(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn restore_snapshot(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| ioerr("open snapshot restore target", e))?;
    f.write_all(bytes)
        .map_err(|e| ioerr("restore lock snapshot", e))?;
    f.sync_all()
        .map_err(|e| ioerr("sync restored lock snapshot", e))?;
    Ok(())
}

fn run_child_durable_lock_then_exit(root: &Path) -> ! {
    let alice_sk = deterministic_key(1);
    let bob_sk = deterministic_key(2);
    let alice = alice_sk.verifying_key().to_bytes();
    let bob = bob_sk.verifying_key().to_bytes();
    let cells = alice_cells(alice);
    let tx = spend_to(bob, 700, 97_000);
    let auth = sign_user_spend(&tx, &alice_sk);
    let verified = verify_user_authorization(&tx, &auth, &cells)
        .expect("SEC-003 child authorization must verify");
    let mut node = CertifierNode::open(2, false, root)
        .expect("SEC-003 child certifier store must open");
    node.persist_verified_locks(&tx, verified)
        .expect("SEC-003 child durable lock sync must succeed");
    // Deliberately exit after the durable lock and before producing a certifier share.
    process::exit(77)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--child-durable-lock-exit") {
        let root = PathBuf::from(args.get(2).expect("missing child lock root"));
        run_child_durable_lock_then_exit(&root);
    }

    let alice_sk = deterministic_key(1);
    let bob_sk = deterministic_key(2);
    let mallory_sk = deterministic_key(3);
    let alice = alice_sk.verifying_key().to_bytes();
    let bob = bob_sk.verifying_key().to_bytes();
    let mallory = mallory_sk.verifying_key().to_bytes();
    let cells = alice_cells(alice);
    let tx_a = spend_to(bob, 50, 9_100);
    let tx_b = spend_to(mallory, 51, 9_101);
    let auth_a = sign_user_spend(&tx_a, &alice_sk);
    let auth_b = sign_user_spend(&tx_b, &alice_sk);

    println!("CALIBRE SECURITY SEC-003 v0.3.0");
    println!("DURABLE CONFLICT-LOCK WAL + CRASH/RESTART + STORAGE-ROLLBACK BOUNDARY");
    println!("Purpose: make the SEC-002 honest one-digest lock survive process restart before a certifier share can be issued");
    println!("N={} Q={} f<=2 target | ordering: verify owner -> persist+sync lock -> sign share", N, Q);
    println!("Performance target: NONE - security phase; frozen PERF result remains separate");
    println!();

    // Normal f=2 quorum with durable honest locks.
    let root = unique_temp_root("main");
    fs::create_dir_all(&root).expect("create SEC-003 main root");
    let mut nodes = open_committee(&root, 2).expect("open SEC-003 committee");
    let committee = committee_keys(&nodes);
    let pre_a_snapshots: Vec<(PathBuf, Vec<u8>)> = [2usize, 3, 4]
        .iter()
        .map(|&i| {
            let p = certifier_path(&root, i);
            (p.clone(), snapshot(&p))
        })
        .collect();

    let a_shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &tx_a, &auth_a, &cells);
    assert_eq!(a_shares.len(), Q);
    let cert_a = certificate_from(a_shares);
    let mut core_a = CoreState::new(cells.clone(), committee.clone(), Q);
    assert!(core_a.apply_certified_spend(&tx_a, &cert_a).is_ok());
    println!("VALID ALICE -> BOB WITH DURABLE 5-OF-7 LOCKED SHARES: PASS");

    // Drop/reopen all nodes. The three honest signers of A must still reject B.
    drop(nodes);
    let mut restarted = open_committee(&root, 2).expect("reopen SEC-003 committee after restart");
    let b_attempt = collect_valid_shares(
        &mut restarted,
        &[0, 1, 5, 6, 2, 3, 4],
        &tx_b,
        &auth_b,
        &cells,
    );
    assert_eq!(b_attempt.len(), 4);
    println!("F=2 THREE HONEST A-SIGNERS DROP/REOPEN: CONFLICTING B GETS ONLY 4/7 -> REJECTED");

    // Real second-process exit after durable lock sync but before signature share.
    let crash_root = unique_temp_root("child-crash");
    fs::create_dir_all(&crash_root).expect("create child crash root");
    let status = Command::new(env::current_exe().expect("current SEC-003 executable"))
        .arg("--child-durable-lock-exit")
        .arg(&crash_root)
        .status()
        .expect("spawn SEC-003 crash child");
    assert_eq!(status.code(), Some(77));
    let mut crashed_node = CertifierNode::open(2, false, &crash_root)
        .expect("reopen child-crashed certifier");
    let child_tx_b = spend_to(mallory, 701, 97_001);
    let child_auth_b = sign_user_spend(&child_tx_b, &alice_sk);
    assert!(crashed_node
        .authorize_and_sign(&child_tx_b, &child_auth_b, &cells)
        .is_err());
    println!("ABRUPT CHILD PROCESS EXIT AFTER LOCK SYNC / BEFORE SHARE: RESTART REMEMBERS LOCK -> PASS");

    // Torn partial tail recovery must preserve all earlier synced locks.
    let torn_root = unique_temp_root("torn-tail");
    fs::create_dir_all(&torn_root).expect("create torn-tail root");
    let mut torn_node = CertifierNode::open(2, false, &torn_root).expect("open torn node");
    torn_node
        .authorize_and_sign(&tx_a, &auth_a, &cells)
        .expect("torn-tail setup share");
    let torn_path = torn_node.store.path().to_path_buf();
    drop(torn_node);
    let mut tail = OpenOptions::new()
        .append(true)
        .open(&torn_path)
        .expect("append torn tail");
    tail.write_all(b"INCOMPLETE-LOCK-TAIL")
        .expect("write torn tail bytes");
    drop(tail);
    let mut recovered = CertifierNode::open(2, false, &torn_root)
        .expect("recover torn-tail certifier");
    assert!(recovered.authorize_and_sign(&tx_b, &auth_b, &cells).is_err());
    assert_eq!(fs::metadata(&torn_path).unwrap().len() as usize % LOCK_RECORD_SIZE, 0);
    println!("TORN PARTIAL WAL TAIL: TRUNCATED TO LAST COMPLETE RECORD; PRIOR CONFLICT LOCK PRESERVED -> PASS");

    // Expected limitation: ordinary files are rollbackable. Restore three honest A-signers to
    // their pre-A snapshots. They then forget A and can sign B, recreating a second 5-of-7 cert.
    drop(restarted);
    for (path, bytes) in &pre_a_snapshots {
        restore_snapshot(path, bytes).expect("restore pre-A lock snapshot");
    }
    let mut rolled_back = open_committee(&root, 2).expect("reopen rolled-back committee");
    let b_after_rollback = collect_valid_shares(
        &mut rolled_back,
        &[0, 1, 2, 3, 4],
        &tx_b,
        &auth_b,
        &cells,
    );
    assert_eq!(b_after_rollback.len(), Q);
    let cert_b = certificate_from(b_after_rollback);
    let mut replica_a = CoreState::new(cells.clone(), committee.clone(), Q);
    let mut replica_b = CoreState::new(cells.clone(), committee, Q);
    assert!(replica_a.apply_certified_spend(&tx_a, &cert_a).is_ok());
    assert!(replica_b.apply_certified_spend(&tx_b, &cert_b).is_ok());
    println!("ROLL BACK 3 HONEST CERTIFIER WALs TO PRE-LOCK SNAPSHOT: TWO VALID 5-OF-7 CERTIFICATES -> ATTACK CONFIRMED");
    println!();

    println!("=== SEC-003 DECISION ===");
    println!("DURABLE LOCK WRITTEN+SYNCED BEFORE HONEST CERTIFIER SHARE: PASS");
    println!("PROCESS DROP/REOPEN CONFLICT MEMORY: PASS");
    println!("ABRUPT SEPARATE-PROCESS EXIT AFTER SYNC / BEFORE SHARE: PASS");
    println!("F<=2 CONFLICTING-SUCCESSOR SAFETY AFTER HONEST RESTARTS: PASS UNDER DURABLE-WAL ASSUMPTION");
    println!("TORN PARTIAL WAL TAIL RECOVERY: PASS / FAIL-CLOSED FOR COMPLETE CORRUPT RECORDS");
    println!("STORAGE SNAPSHOT ROLLBACK RESISTANCE: FAIL - ATTACK CONFIRMED");
    println!("POWER-LOSS + DISK-CONTROLLER DURABILITY: NOT PROVEN BY PROCESS-EXIT TEST");
    println!("TPM / MONOTONIC ANTI-ROLLBACK ANCHOR: NOT YET");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PHYSICAL MULTI-MACHINE / WAN PARTITION TEST: NOT YET");

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(crash_root);
    let _ = fs::remove_dir_all(torn_root);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKey, SigningKey, SigningKey, HashMap<u64, Cell>) {
        let alice_sk = deterministic_key(1);
        let bob_sk = deterministic_key(2);
        let mallory_sk = deterministic_key(3);
        let cells = alice_cells(alice_sk.verifying_key().to_bytes());
        (alice_sk, bob_sk, mallory_sk, cells)
    }

    #[test]
    fn durable_lock_survives_drop_and_reopen() {
        let (alice_sk, bob_sk, mallory_sk, cells) = fixture();
        let a = spend_to(bob_sk.verifying_key().to_bytes(), 1, 9000);
        let b = spend_to(mallory_sk.verifying_key().to_bytes(), 2, 9001);
        let auth_a = sign_user_spend(&a, &alice_sk);
        let auth_b = sign_user_spend(&b, &alice_sk);
        let root = unique_temp_root("test-reopen");
        fs::create_dir_all(&root).unwrap();
        {
            let mut node = CertifierNode::open(2, false, &root).unwrap();
            assert!(node.authorize_and_sign(&a, &auth_a, &cells).is_ok());
        }
        {
            let mut node = CertifierNode::open(2, false, &root).unwrap();
            assert!(node.authorize_and_sign(&b, &auth_b, &cells).is_err());
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn f2_second_quorum_stays_impossible_after_three_honest_restarts() {
        let (alice_sk, bob_sk, mallory_sk, cells) = fixture();
        let a = spend_to(bob_sk.verifying_key().to_bytes(), 3, 9100);
        let b = spend_to(mallory_sk.verifying_key().to_bytes(), 4, 9101);
        let auth_a = sign_user_spend(&a, &alice_sk);
        let auth_b = sign_user_spend(&b, &alice_sk);
        let root = unique_temp_root("test-f2-restart");
        fs::create_dir_all(&root).unwrap();
        let mut nodes = open_committee(&root, 2).unwrap();
        let a_shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &a, &auth_a, &cells);
        assert_eq!(a_shares.len(), Q);
        drop(nodes);
        let mut nodes = open_committee(&root, 2).unwrap();
        let b_shares = collect_valid_shares(&mut nodes, &[0, 1, 5, 6, 2, 3, 4], &b, &auth_b, &cells);
        assert_eq!(b_shares.len(), 4);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lock_file_is_synced_before_share_is_returned() {
        let (alice_sk, bob_sk, _, cells) = fixture();
        let a = spend_to(bob_sk.verifying_key().to_bytes(), 5, 9200);
        let auth = sign_user_spend(&a, &alice_sk);
        let root = unique_temp_root("test-order");
        fs::create_dir_all(&root).unwrap();
        let mut node = CertifierNode::open(2, false, &root).unwrap();
        let share = node.authorize_and_sign(&a, &auth, &cells).unwrap();
        assert_eq!(share.tx_digest, tx_commitment(&a, &auth.signer));
        let bytes = fs::read(certifier_path(&root, 2)).unwrap();
        assert_eq!(bytes.len(), MAX_INPUTS * LOCK_RECORD_SIZE);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn torn_partial_tail_is_truncated_without_forgetting_prior_lock() {
        let (alice_sk, bob_sk, mallory_sk, cells) = fixture();
        let a = spend_to(bob_sk.verifying_key().to_bytes(), 6, 9300);
        let b = spend_to(mallory_sk.verifying_key().to_bytes(), 7, 9301);
        let auth_a = sign_user_spend(&a, &alice_sk);
        let auth_b = sign_user_spend(&b, &alice_sk);
        let root = unique_temp_root("test-torn");
        fs::create_dir_all(&root).unwrap();
        let path = certifier_path(&root, 2);
        {
            let mut node = CertifierNode::open(2, false, &root).unwrap();
            node.authorize_and_sign(&a, &auth_a, &cells).unwrap();
        }
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"TORN").unwrap();
        }
        let mut node = CertifierNode::open(2, false, &root).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len() as usize % LOCK_RECORD_SIZE, 0);
        assert!(node.authorize_and_sign(&b, &auth_b, &cells).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn complete_corrupt_record_fails_closed() {
        let root = unique_temp_root("test-corrupt");
        fs::create_dir_all(&root).unwrap();
        let path = certifier_path(&root, 2);
        let mut f = OpenOptions::new().write(true).create(true).open(&path).unwrap();
        f.write_all(&[0xA5; LOCK_RECORD_SIZE]).unwrap();
        f.sync_all().unwrap();
        drop(f);
        assert!(CertifierNode::open(2, false, &root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_rollback_of_three_honest_signers_reenables_second_quorum() {
        let (alice_sk, bob_sk, mallory_sk, cells) = fixture();
        let a = spend_to(bob_sk.verifying_key().to_bytes(), 8, 9400);
        let b = spend_to(mallory_sk.verifying_key().to_bytes(), 9, 9401);
        let auth_a = sign_user_spend(&a, &alice_sk);
        let auth_b = sign_user_spend(&b, &alice_sk);
        let root = unique_temp_root("test-rollback");
        fs::create_dir_all(&root).unwrap();
        let mut nodes = open_committee(&root, 2).unwrap();
        let snapshots: Vec<(PathBuf, Vec<u8>)> = [2usize, 3, 4]
            .iter()
            .map(|&i| {
                let p = certifier_path(&root, i);
                (p.clone(), snapshot(&p))
            })
            .collect();
        let a_shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &a, &auth_a, &cells);
        assert_eq!(a_shares.len(), Q);
        let cert_a = certificate_from(a_shares);
        let committee = committee_keys(&nodes);
        drop(nodes);
        for (p, bytes) in &snapshots {
            restore_snapshot(p, bytes).unwrap();
        }
        let mut nodes = open_committee(&root, 2).unwrap();
        let b_shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &b, &auth_b, &cells);
        assert_eq!(b_shares.len(), Q);
        let cert_b = certificate_from(b_shares);
        let mut core_a = CoreState::new(cells.clone(), committee.clone(), Q);
        let mut core_b = CoreState::new(cells.clone(), committee, Q);
        assert!(core_a.apply_certified_spend(&a, &cert_a).is_ok());
        assert!(core_b.apply_certified_spend(&b, &cert_b).is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_share_cannot_inflate_threshold() {
        let (alice_sk, bob_sk, _, cells) = fixture();
        let tx = spend_to(bob_sk.verifying_key().to_bytes(), 10, 9500);
        let auth = sign_user_spend(&tx, &alice_sk);
        let root = unique_temp_root("test-dup");
        fs::create_dir_all(&root).unwrap();
        let mut nodes = open_committee(&root, 0).unwrap();
        let one = nodes[0].authorize_and_sign(&tx, &auth, &cells).unwrap();
        let cert = certificate_from(vec![one, one, one, one, one]);
        let core = CoreState::new(cells, committee_keys(&nodes), Q);
        assert!(core.verify_threshold_certificate(&tx, &cert).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
