use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NETWORK_ID: u32 = 1;
const EPOCH: u64 = 7;
const N: usize = 7;
const Q: usize = 5;
const F_TARGET: usize = 2;
const MAX_INPUTS: usize = 8;
const CELL_VALUE: u64 = 100;
const WAL_RECORD: usize = 48;

const OP_PING: u8 = 0;
const OP_SIGN: u8 = 1;
const OP_SHUTDOWN: u8 = 255;

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
struct CertifierShare {
    certifier: [u8; 32],
    digest: [u8; 32],
    user_signer: [u8; 32],
    epoch: u64,
    signature: [u8; 64],
}

#[derive(Debug)]
enum NodeReply {
    Share(CertifierShare),
    Rejected(String),
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn user_key(label: u64) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC007_USER_KEY_V1", label)
}

fn certifier_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC007_CERTIFIER_KEY_V1", 100 + index as u64)
}

fn canonical_user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + tx.inputs.len() * 16);
    out.extend_from_slice(b"CALIBRE_SEC007_USER_SPEND_V1");
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
    h.update(b"CALIBRE_SEC007_AUTHORIZED_TX_V1");
    h.update(&canonical_user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn share_message(digest: &[u8; 32], user: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC007_CERTIFIER_SHARE_V1");
    out.extend_from_slice(&EPOCH.to_le_bytes());
    out.extend_from_slice(digest);
    out.extend_from_slice(user);
    out
}

fn sign_user(tx: &SpendTx, sk: &SigningKey) -> UserAuthorization {
    UserAuthorization {
        signer: sk.verifying_key().to_bytes(),
        signature: sk.sign(&canonical_user_message(tx)).to_bytes(),
    }
}

fn alice_cells() -> HashMap<u64, Cell> {
    let alice = user_key(1).verifying_key().to_bytes();
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
        expiry: 2_100_000_000,
    }
}

fn verify_user(tx: &SpendTx, auth: &UserAuthorization) -> Result<[u8; 32], String> {
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

    let cells = alice_cells();
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
    Ok(tx_commitment(tx, &auth.signer))
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
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| format!("read WAL: {e}"))?;
        if bytes.len() % WAL_RECORD != 0 {
            return Err("WAL has incomplete record; fail closed".into());
        }
        let mut locks = HashMap::new();
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let id = u64::from_le_bytes(rec[0..8].try_into().unwrap());
            let generation = u64::from_le_bytes(rec[8..16].try_into().unwrap());
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&rec[16..48]);
            let input = InputRef { id, generation };
            if let Some(old) = locks.insert(input, digest) {
                if old != digest {
                    return Err("WAL contains conflicting honest locks".into());
                }
            }
        }
        Ok(Self { file, locks })
    }

    fn lock_before_sign(&mut self, inputs: &[InputRef], digest: [u8; 32]) -> Result<(), String> {
        let mut pending = Vec::new();
        for input in inputs {
            if let Some(old) = self.locks.get(input) {
                if old != &digest {
                    return Err(format!(
                        "honest conflict lock: input {} generation {} already chose another digest",
                        input.id, input.generation
                    ));
                }
            } else {
                pending.push(*input);
            }
        }
        for input in &pending {
            self.file
                .write_all(&input.id.to_le_bytes())
                .map_err(|e| format!("WAL write id: {e}"))?;
            self.file
                .write_all(&input.generation.to_le_bytes())
                .map_err(|e| format!("WAL write generation: {e}"))?;
            self.file
                .write_all(&digest)
                .map_err(|e| format!("WAL write digest: {e}"))?;
        }
        if !pending.is_empty() {
            self.file.sync_all().map_err(|e| format!("WAL sync: {e}"))?;
            for input in pending {
                self.locks.insert(input, digest);
            }
        }
        Ok(())
    }
}

fn make_share(index: usize, digest: [u8; 32], user: [u8; 32]) -> CertifierShare {
    let sk = certifier_key(index);
    CertifierShare {
        certifier: sk.verifying_key().to_bytes(),
        digest,
        user_signer: user,
        epoch: EPOCH,
        signature: sk.sign(&share_message(&digest, &user)).to_bytes(),
    }
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}

fn put_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn take_u64_le(data: &[u8], off: &mut usize) -> Result<u64, String> {
    if *off + 8 > data.len() {
        return Err("truncated u64".into());
    }
    let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

fn take_u32_le(data: &[u8], off: &mut usize) -> Result<u32, String> {
    if *off + 4 > data.len() {
        return Err("truncated u32".into());
    }
    let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn take_array<const M: usize>(data: &[u8], off: &mut usize) -> Result<[u8; M], String> {
    if *off + M > data.len() {
        return Err("truncated fixed array".into());
    }
    let mut out = [0u8; M];
    out.copy_from_slice(&data[*off..*off + M]);
    *off += M;
    Ok(out)
}

fn encode_sign_request(tx: &SpendTx, auth: &UserAuthorization) -> Vec<u8> {
    let mut out = Vec::with_capacity(320);
    out.push(OP_SIGN);
    out.extend_from_slice(&tx.network_id.to_le_bytes());
    put_u64_le(&mut out, tx.tx_id);
    out.push(tx.inputs.len() as u8);
    for input in &tx.inputs {
        put_u64_le(&mut out, input.id);
        put_u64_le(&mut out, input.generation);
    }
    put_u64_le(&mut out, tx.output_id);
    out.extend_from_slice(&tx.recipient);
    put_u64_le(&mut out, tx.output_value);
    put_u64_le(&mut out, tx.expiry);
    out.extend_from_slice(&auth.signer);
    out.extend_from_slice(&auth.signature);
    out
}

fn decode_sign_request(data: &[u8]) -> Result<(SpendTx, UserAuthorization), String> {
    if data.first().copied() != Some(OP_SIGN) {
        return Err("not a sign request".into());
    }
    let mut off = 1usize;
    let network_id = take_u32_le(data, &mut off)?;
    let tx_id = take_u64_le(data, &mut off)?;
    if off >= data.len() {
        return Err("missing input count".into());
    }
    let count = data[off] as usize;
    off += 1;
    if count == 0 || count > MAX_INPUTS {
        return Err("invalid wire input count".into());
    }
    let mut inputs = Vec::with_capacity(count);
    for _ in 0..count {
        inputs.push(InputRef {
            id: take_u64_le(data, &mut off)?,
            generation: take_u64_le(data, &mut off)?,
        });
    }
    let output_id = take_u64_le(data, &mut off)?;
    let recipient = take_array::<32>(data, &mut off)?;
    let output_value = take_u64_le(data, &mut off)?;
    let expiry = take_u64_le(data, &mut off)?;
    let signer = take_array::<32>(data, &mut off)?;
    let signature = take_array::<64>(data, &mut off)?;
    if off != data.len() {
        return Err("unexpected bytes after request".into());
    }
    Ok((
        SpendTx {
            network_id,
            tx_id,
            inputs,
            output_id,
            recipient,
            output_value,
            expiry,
        },
        UserAuthorization { signer, signature },
    ))
}

fn encode_share_response(share: &CertifierShare) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 32 + 8 + 64);
    out.push(1);
    out.extend_from_slice(&share.certifier);
    out.extend_from_slice(&share.digest);
    out.extend_from_slice(&share.user_signer);
    put_u64_le(&mut out, share.epoch);
    out.extend_from_slice(&share.signature);
    out
}

fn encode_reject_response(msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + msg.len());
    out.push(0);
    out.extend_from_slice(msg.as_bytes());
    out
}

fn decode_node_reply(data: &[u8]) -> Result<NodeReply, String> {
    if data.is_empty() {
        return Err("empty node response".into());
    }
    if data[0] == 0 {
        return Ok(NodeReply::Rejected(String::from_utf8_lossy(&data[1..]).to_string()));
    }
    if data[0] != 1 {
        return Err("unknown node response status".into());
    }
    let mut off = 1usize;
    let certifier = take_array::<32>(data, &mut off)?;
    let digest = take_array::<32>(data, &mut off)?;
    let user_signer = take_array::<32>(data, &mut off)?;
    let epoch = take_u64_le(data, &mut off)?;
    let signature = take_array::<64>(data, &mut off)?;
    if off != data.len() {
        return Err("trailing node response bytes".into());
    }
    Ok(NodeReply::Share(CertifierShare {
        certifier,
        digest,
        user_signer,
        epoch,
        signature,
    }))
}

fn write_frame(stream: &mut TcpStream, body: &[u8]) -> Result<(), String> {
    if body.len() > 4096 {
        return Err("frame too large".into());
    }
    let mut header = Vec::with_capacity(4);
    push_u32(&mut header, body.len() as u32);
    stream.write_all(&header).map_err(|e| format!("write frame header: {e}"))?;
    stream.write_all(body).map_err(|e| format!("write frame body: {e}"))?;
    stream.flush().map_err(|e| format!("flush frame: {e}"))?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(|e| format!("read frame header: {e}"))?;
    let len = read_u32_be(&header) as usize;
    if len > 4096 {
        return Err("incoming frame too large".into());
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).map_err(|e| format!("read frame body: {e}"))?;
    Ok(body)
}

fn send_frame(port: u16, body: &[u8]) -> Result<Vec<u8>, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(700))
        .map_err(|e| format!("connect 127.0.0.1:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set write timeout: {e}"))?;
    write_frame(&mut stream, body)?;
    read_frame(&mut stream)
}

fn send_sign(port: u16, tx: &SpendTx, auth: &UserAuthorization) -> Result<NodeReply, String> {
    decode_node_reply(&send_frame(port, &encode_sign_request(tx, auth))?)
}

fn node_main(index: usize, port: u16, root: PathBuf, byzantine: bool) -> Result<(), String> {
    if index >= N {
        return Err("node index out of range".into());
    }
    let wal_path = root.join(format!("certifier-{index}.wal"));
    let mut store = LockStore::open(&wal_path)?;
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("node {index} bind 127.0.0.1:{port}: {e}"))?;

    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let body = match read_frame(&mut stream) {
            Ok(b) => b,
            Err(_) => continue,
        };
        match body.first().copied() {
            Some(OP_PING) => {
                let _ = write_frame(&mut stream, &[1]);
            }
            Some(OP_SHUTDOWN) => {
                let _ = write_frame(&mut stream, &[1]);
                return Ok(());
            }
            Some(OP_SIGN) => {
                let response = (|| -> Result<Vec<u8>, String> {
                    let (tx, auth) = decode_sign_request(&body)?;
                    let digest = verify_user(&tx, &auth)?;
                    if !byzantine {
                        store.lock_before_sign(&tx.inputs, digest)?;
                    }
                    Ok(encode_share_response(&make_share(index, digest, auth.signer)))
                })();
                let body = match response {
                    Ok(b) => b,
                    Err(e) => encode_reject_response(&e),
                };
                let _ = write_frame(&mut stream, &body);
            }
            _ => {
                let _ = write_frame(&mut stream, &encode_reject_response("unknown opcode"));
            }
        }
    }
    Ok(())
}

fn committee_keys() -> Vec<[u8; 32]> {
    (0..N).map(|i| certifier_key(i).verifying_key().to_bytes()).collect()
}

fn verify_share(tx: &SpendTx, share: &CertifierShare, committee: &HashSet<[u8; 32]>) -> bool {
    if share.epoch != EPOCH || !committee.contains(&share.certifier) {
        return false;
    }
    if tx_commitment(tx, &share.user_signer) != share.digest {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&share.certifier) else {
        return false;
    };
    let sig = Signature::from_bytes(&share.signature);
    vk.verify_strict(&share_message(&share.digest, &share.user_signer), &sig)
        .is_ok()
}

fn unique_valid_count(tx: &SpendTx, shares: &[CertifierShare]) -> usize {
    let committee: HashSet<[u8; 32]> = committee_keys().into_iter().collect();
    let mut unique = HashSet::new();
    for share in shares {
        if verify_share(tx, share, &committee) {
            unique.insert(share.certifier);
        }
    }
    unique.len()
}

fn has_quorum(tx: &SpendTx, shares: &[CertifierShare]) -> bool {
    unique_valid_count(tx, shares) >= Q
}

#[derive(Clone)]
struct CoreState {
    active: HashMap<u64, Cell>,
}

impl CoreState {
    fn new() -> Self {
        Self { active: alice_cells() }
    }

    fn apply(&mut self, tx: &SpendTx, shares: &[CertifierShare]) -> Result<Cell, String> {
        if !has_quorum(tx, shares) {
            return Err("authorization quorum missing".into());
        }
        let mut total = 0u64;
        let mut seen = HashSet::new();
        for input in &tx.inputs {
            if !seen.insert(*input) {
                return Err("core duplicate input".into());
            }
            let cell = self.active.get(&input.id).ok_or("core input inactive")?;
            if cell.generation != input.generation {
                return Err("core generation mismatch".into());
            }
            total += cell.value;
        }
        if total != tx.output_value {
            return Err("core value mismatch".into());
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

struct NodeProc {
    index: usize,
    port: u16,
    byzantine: bool,
    child: Child,
}

struct Cluster {
    root: PathBuf,
    nodes: Vec<NodeProc>,
}

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "calibre-sec007-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn find_port_block() -> Result<u16, String> {
    for base in (42000u16..60000u16).step_by(7) {
        let mut reservations = Vec::new();
        let mut ok = true;
        for i in 0..N {
            match TcpListener::bind(("127.0.0.1", base + i as u16)) {
                Ok(l) => reservations.push(l),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            drop(reservations);
            return Ok(base);
        }
    }
    Err("could not reserve seven loopback ports".into())
}

fn spawn_node(index: usize, port: u16, root: &Path, byzantine: bool) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut child = Command::new(exe)
        .arg("--node")
        .arg(index.to_string())
        .arg(port.to_string())
        .arg(root)
        .arg(if byzantine { "1" } else { "0" })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn node {index}: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("try_wait node {index}: {e}"))? {
            return Err(format!("node {index} exited before ready: {status}"));
        }
        if send_frame(port, &[OP_PING]).is_ok() {
            return Ok(child);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("node {index} did not become ready on port {port}"));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

impl Cluster {
    fn start(label: &str, f_byzantine: usize) -> Result<Self, String> {
        let root = unique_root(label);
        fs::create_dir_all(&root).map_err(|e| format!("create cluster root: {e}"))?;
        let base = find_port_block()?;
        let mut nodes = Vec::with_capacity(N);
        for index in 0..N {
            let byzantine = index < f_byzantine;
            let port = base + index as u16;
            match spawn_node(index, port, &root, byzantine) {
                Ok(child) => nodes.push(NodeProc { index, port, byzantine, child }),
                Err(e) => {
                    for node in &mut nodes {
                        let _ = node.child.kill();
                        let _ = node.child.wait();
                    }
                    let _ = fs::remove_dir_all(&root);
                    return Err(e);
                }
            }
        }
        Ok(Self { root, nodes })
    }

    fn port(&self, index: usize) -> u16 {
        self.nodes[index].port
    }

    fn sign(&self, index: usize, tx: &SpendTx, auth: &UserAuthorization) -> Result<NodeReply, String> {
        send_sign(self.port(index), tx, auth)
    }

    fn restart(&mut self, index: usize) -> Result<(), String> {
        let port = self.nodes[index].port;
        let byzantine = self.nodes[index].byzantine;
        let _ = self.nodes[index].child.kill();
        let _ = self.nodes[index].child.wait();
        thread::sleep(Duration::from_millis(120));
        let child = spawn_node(index, port, &self.root, byzantine)?;
        self.nodes[index].child = child;
        Ok(())
    }

    fn shutdown(&mut self) {
        for node in &mut self.nodes {
            let _ = send_frame(node.port, &[OP_SHUTDOWN]);
        }
        for node in &mut self.nodes {
            let _ = node.child.wait();
        }
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            match node.child.try_wait() {
                Ok(Some(_)) => {}
                _ => {
                    let _ = node.child.kill();
                    let _ = node.child.wait();
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn share_from(reply: NodeReply) -> Option<CertifierShare> {
    match reply {
        NodeReply::Share(s) => Some(s),
        NodeReply::Rejected(_) => None,
    }
}

fn collect(cluster: &Cluster, indices: &[usize], tx: &SpendTx, auth: &UserAuthorization, delay_ms: u64) -> Vec<CertifierShare> {
    let mut out = Vec::new();
    for &index in indices {
        if delay_ms > 0 {
            thread::sleep(Duration::from_millis(delay_ms));
        }
        if let Ok(reply) = cluster.sign(index, tx, auth) {
            if let Some(share) = share_from(reply) {
                out.push(share);
            }
        }
    }
    out
}

fn run_experiment() -> Result<(), String> {
    let alice_sk = user_key(1);
    let bob_sk = user_key(2);
    let mallory_sk = user_key(3);
    let bob = bob_sk.verifying_key().to_bytes();
    let mallory = mallory_sk.verifying_key().to_bytes();
    let tx_a = spend_to(bob, 700, 90_000);
    let tx_b = spend_to(mallory, 701, 90_001);
    let auth_a = sign_user(&tx_a, &alice_sk);
    let auth_b = sign_user(&tx_b, &alice_sk);

    println!("CALIBRE SECURITY SEC-007 v0.7.0");
    println!("REAL TCP LOOPBACK / SEVEN OS PROCESSES / CONFLICT SAFETY + PARTITION LIVENESS");
    println!("Purpose: test one monetary input set under real socket delivery, message reordering, delays, process restart, logical partition, and Byzantine double-signing");
    println!("N={N} Q={Q} target f<={F_TARGET}");
    println!("Network scope: 127.0.0.1 real TCP sockets and seven separate child processes on one Windows/Linux host; NOT physical multi-machine/WAN");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!();

    // 1) Liveness with two unavailable Byzantine processes: all five honest nodes can complete a valid spend.
    let mut liveness = Cluster::start("liveness", 2)?;
    let live_shares = collect(&liveness, &[2, 3, 4, 5, 6], &tx_a, &auth_a, 10);
    if !has_quorum(&tx_a, &live_shares) {
        return Err(format!("two-unavailable liveness failed: {} unique shares", unique_valid_count(&tx_a, &live_shares)));
    }
    let mut live_core = CoreState::new();
    live_core.apply(&tx_a, &live_shares)?;
    println!("TWO BYZANTINE NODES LOGICALLY UNAVAILABLE; FIVE HONEST TCP PROCESSES FINALIZE ALICE -> BOB: PASS (5/7)");

    let duplicate = live_shares[0];
    let dup_count = unique_valid_count(&tx_a, &[duplicate, duplicate, duplicate, duplicate, duplicate]);
    if dup_count != 1 {
        return Err("duplicate share accounting failure".into());
    }
    println!("DUPLICATE TCP DELIVERY / SAME CERTIFIER SHARE REPLAYED 5 TIMES: COUNTS AS 1 -> PASS");
    liveness.shutdown();

    // 2) Reordered conflict race with f=2. Byzantine 0,1 sign both. Honest groups see opposite successors first.
    let mut race = Cluster::start("f2-race", 2)?;
    let mut a_shares = Vec::new();
    let mut b_shares = Vec::new();

    // B reaches honest 5 first, then A reaches honest 2, then B reaches 6, then A reaches 3 and 4.
    if let Some(s) = share_from(race.sign(5, &tx_b, &auth_b)?) { b_shares.push(s); }
    thread::sleep(Duration::from_millis(40));
    if let Some(s) = share_from(race.sign(2, &tx_a, &auth_a)?) { a_shares.push(s); }
    thread::sleep(Duration::from_millis(60));
    if let Some(s) = share_from(race.sign(6, &tx_b, &auth_b)?) { b_shares.push(s); }
    if let Some(s) = share_from(race.sign(3, &tx_a, &auth_a)?) { a_shares.push(s); }
    if let Some(s) = share_from(race.sign(4, &tx_a, &auth_a)?) { a_shares.push(s); }

    // Two Byzantine certifiers deliberately double-sign both conflicts.
    for i in [0usize, 1] {
        if let Some(s) = share_from(race.sign(i, &tx_a, &auth_a)?) { a_shares.push(s); }
        if let Some(s) = share_from(race.sign(i, &tx_b, &auth_b)?) { b_shares.push(s); }
    }
    // B probes the A-locked honest nodes and must be rejected.
    for i in [2usize, 3, 4] {
        if let Some(s) = share_from(race.sign(i, &tx_b, &auth_b)?) { b_shares.push(s); }
    }

    let a_count = unique_valid_count(&tx_a, &a_shares);
    let b_count = unique_valid_count(&tx_b, &b_shares);
    if a_count != 5 || b_count != 4 || !has_quorum(&tx_a, &a_shares) || has_quorum(&tx_b, &b_shares) {
        return Err(format!("f=2 race unexpected counts A={a_count} B={b_count}"));
    }
    let mut core_a = CoreState::new();
    core_a.apply(&tx_a, &a_shares)?;
    let mut core_b = CoreState::new();
    if core_b.apply(&tx_b, &b_shares).is_ok() {
        return Err("f=2 conflicting B unexpectedly committed".into());
    }
    println!("F=2 REORDERED/DELAYED CONFLICT RACE: A GETS 5/7, B GETS 4/7 -> ONE AUTHORIZATION FINALIZES: PASS");

    // 3) Kill and restart honest node 2. Its durable one-digest lock must survive and reject B.
    race.restart(2)?;
    match race.sign(2, &tx_b, &auth_b)? {
        NodeReply::Rejected(_) => println!("HONEST CERTIFIER PROCESS KILL/RESTART: DURABLE A LOCK SURVIVES; CONFLICTING B REJECTED -> PASS"),
        NodeReply::Share(_) => return Err("restarted honest certifier forgot conflict lock".into()),
    }
    race.shutdown();

    // 4) 4/3 logical partition. Neither side reaches Q. After heal, only A can complete.
    let mut partition = Cluster::start("partition", 2)?;
    let mut left_a = collect(&partition, &[0, 2, 3, 4], &tx_a, &auth_a, 15); // 4 nodes
    let mut right_b = collect(&partition, &[1, 5, 6], &tx_b, &auth_b, 15);    // 3 nodes
    if has_quorum(&tx_a, &left_a) || has_quorum(&tx_b, &right_b) {
        return Err("4/3 partition unexpectedly formed quorum".into());
    }
    println!("4/3 LOGICAL NETWORK PARTITION: NEITHER SIDE CAN REACH 5/7 -> SAFETY PASS / LIVENESS PAUSES");

    // Heal: byzantine node 1 can sign A, so A reaches 5. Byzantine 0 can sign B, but B only reaches 4.
    if let Some(s) = share_from(partition.sign(1, &tx_a, &auth_a)?) { left_a.push(s); }
    if let Some(s) = share_from(partition.sign(0, &tx_b, &auth_b)?) { right_b.push(s); }
    for i in [2usize, 3, 4] {
        if let Some(s) = share_from(partition.sign(i, &tx_b, &auth_b)?) { right_b.push(s); }
    }
    let healed_a = unique_valid_count(&tx_a, &left_a);
    let healed_b = unique_valid_count(&tx_b, &right_b);
    if healed_a != 5 || healed_b != 4 || !has_quorum(&tx_a, &left_a) || has_quorum(&tx_b, &right_b) {
        return Err(format!("healed partition unexpected counts A={healed_a} B={healed_b}"));
    }
    let mut healed_core = CoreState::new();
    healed_core.apply(&tx_a, &left_a)?;
    println!("PARTITION HEALED: A REACHES 5/7; CONFLICTING B REMAINS 4/7 -> LIVENESS RECOVERS WITHOUT DUAL FINALITY: PASS");
    partition.shutdown();

    // 5) Expected f=3 boundary. Three Byzantine certifiers can sign both; honest nodes split 2+2.
    let mut boundary = Cluster::start("f3-boundary", 3)?;
    let a3 = collect(&boundary, &[0, 1, 2, 3, 4], &tx_a, &auth_a, 5);
    let b3 = collect(&boundary, &[0, 1, 2, 5, 6], &tx_b, &auth_b, 5);
    if !has_quorum(&tx_a, &a3) || !has_quorum(&tx_b, &b3) {
        return Err("f=3 boundary failed to construct expected dual certificates".into());
    }
    let mut replica_a = CoreState::new();
    let mut replica_b = CoreState::new();
    replica_a.apply(&tx_a, &a3)?;
    replica_b.apply(&tx_b, &b3)?;
    println!("F=3 REAL TCP MULTI-PROCESS BOUNDARY: TWO VALID 5-OF-7 CONFLICTING SUCCESSORS -> ATTACK CONFIRMED / EXPECTED");
    boundary.shutdown();

    println!();
    println!("=== SEC-007 DECISION ===");
    println!("SEVEN SEPARATE CERTIFIER OS PROCESSES + REAL TCP LOOPBACK: PASS");
    println!("OWNER-BOUND USER AUTHORIZATION VERIFIED INSIDE EACH CERTIFIER PROCESS: PASS");
    println!("REAL ED25519 5-OF-7 UNIQUE CERTIFIER SHARES: PASS");
    println!("MESSAGE DELAY + REORDERING + DUPLICATE DELIVERY SAFETY WITH F<=2: PASS IN TESTED SCHEDULES");
    println!("HONEST CERTIFIER PROCESS RESTART WITH DURABLE CONFLICT LOCK: PASS");
    println!("4/3 PARTITION SAFETY: PASS; LIVENESS PAUSES WITHOUT QUORUM, THEN RECOVERS AFTER HEAL");
    println!("CONFLICTING-SUCCESSOR AUTHORIZATION FINALITY WITH F<=2 IN TESTED TCP SCENARIOS: PASS");
    println!("F=3 SAFETY: FAIL - DUAL CERTIFICATES CONFIRMED AT EXPECTED QUORUM BOUNDARY");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PHYSICAL MULTI-MACHINE / WAN NETWORK: NOT YET");
    println!("PACKET LOSS / RANDOMIZED LONG-RUN FAULT FUZZING: NOT YET");
    println!("FULL POWER-LOSS / DISK-CONTROLLER DURABILITY: NOT PROVEN");
    Ok(())
}

fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("byzantine flag must be 0 or 1".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--node") {
        (|| -> Result<(), String> {
            let index = args.get(2).ok_or("missing node index")?.parse::<usize>().map_err(|e| e.to_string())?;
            let port = args.get(3).ok_or("missing node port")?.parse::<u16>().map_err(|e| e.to_string())?;
            let root = PathBuf::from(args.get(4).ok_or("missing node root")?);
            let byzantine = parse_bool(args.get(5).ok_or("missing byzantine flag")?)?;
            node_main(index, port, root, byzantine)
        })()
    } else {
        run_experiment()
    };

    if let Err(e) = result {
        eprintln!("SEC-007 ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_intersection_boundary_is_three() {
        assert_eq!(2 * Q - N, 3);
        assert!(2 * Q - N > F_TARGET);
        assert_eq!(2 * Q - N, 3);
    }

    #[test]
    fn sign_request_round_trip_preserves_exact_transaction_and_signature() {
        let alice = user_key(1);
        let bob = user_key(2).verifying_key().to_bytes();
        let tx = spend_to(bob, 1, 9_000);
        let auth = sign_user(&tx, &alice);
        let wire = encode_sign_request(&tx, &auth);
        let (decoded_tx, decoded_auth) = decode_sign_request(&wire).unwrap();
        assert_eq!(decoded_tx, tx);
        assert_eq!(decoded_auth.signer, auth.signer);
        assert_eq!(decoded_auth.signature, auth.signature);
        assert_eq!(verify_user(&decoded_tx, &decoded_auth).unwrap(), tx_commitment(&tx, &auth.signer));
    }

    #[test]
    fn duplicate_certifier_share_never_inflates_threshold() {
        let alice = user_key(1);
        let bob = user_key(2).verifying_key().to_bytes();
        let tx = spend_to(bob, 2, 9_001);
        let auth = sign_user(&tx, &alice);
        let digest = verify_user(&tx, &auth).unwrap();
        let s = make_share(0, digest, auth.signer);
        assert_eq!(unique_valid_count(&tx, &[s, s, s, s, s]), 1);
        assert!(!has_quorum(&tx, &[s, s, s, s, s]));
    }

    #[test]
    fn durable_lock_reopen_rejects_conflicting_digest() {
        let root = unique_root("unit-wal");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("node.wal");
        let input = InputRef { id: 1000, generation: 7 };
        let a = [1u8; 32];
        let b = [2u8; 32];
        {
            let mut store = LockStore::open(&path).unwrap();
            store.lock_before_sign(&[input], a).unwrap();
        }
        {
            let mut store = LockStore::open(&path).unwrap();
            assert!(store.lock_before_sign(&[input], b).is_err());
            assert!(store.lock_before_sign(&[input], a).is_ok());
        }
        let _ = fs::remove_dir_all(root);
    }
}
