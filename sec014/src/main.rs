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
const E0: u64 = 20;
const E1: u64 = 21;
const E2: u64 = 22;
const COIN_ID: u64 = 0xCA11_BEE0;

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
struct StateRef { coin_id: u64, generation: u64, digest: [u8; 32] }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Finality { epoch: u64, input: StateRef, successor_digest: [u8; 32] }
#[derive(Clone, Copy, Debug)]
struct FinalShare { index: usize, signature: [u8; 64] }
#[derive(Clone, Debug)]
struct FinalCert { finality: Finality, shares: Vec<FinalShare> }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handoff { from_epoch: u64, to_epoch: u64, state: StateRef }
#[derive(Clone, Copy, Debug)]
struct HandoffShare { index: usize, signature: [u8; 64] }
#[derive(Clone, Debug)]
struct HandoffCert { handoff: Handoff, shares: Vec<HandoffShare> }
#[derive(Clone, Copy, Debug)]
struct ActivationShare { index: usize, signature: [u8; 64] }
#[derive(Clone, Debug)]
struct ActivationCert { handoff_hash: [u8; 32], shares: Vec<ActivationShare> }

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new(); h.update(domain); h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}
fn committee_key(epoch: u64, index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC014_COMMITTEE_KEY_V1", epoch * 1000 + index as u64)
}
fn genesis_digest() -> [u8; 32] {
    let mut h = Hasher::new(); h.update(b"CALIBRE_SEC014_GENESIS_ALICE_V1"); h.update(&COIN_ID.to_le_bytes());
    *h.finalize().as_bytes()
}
fn successor_digest(prev: &[u8;32], generation: u64, label: &[u8]) -> [u8;32] {
    let mut h=Hasher::new(); h.update(b"CALIBRE_SEC014_SUCCESSOR_V1"); h.update(&COIN_ID.to_le_bytes()); h.update(&generation.to_le_bytes()); h.update(prev); h.update(label); *h.finalize().as_bytes()
}
fn finality_message(f:&Finality)->Vec<u8>{
    let mut v=Vec::with_capacity(128); v.extend_from_slice(b"CALIBRE_SEC014_FINALITY_V1"); v.extend_from_slice(&f.epoch.to_le_bytes()); v.extend_from_slice(&f.input.coin_id.to_le_bytes()); v.extend_from_slice(&f.input.generation.to_le_bytes()); v.extend_from_slice(&f.input.digest); v.extend_from_slice(&f.successor_digest); v
}
fn final_share_message(f:&Finality,index:usize)->Vec<u8>{let mut v=finality_message(f);v.extend_from_slice(&(index as u64).to_le_bytes());v}
fn handoff_message(h:&Handoff)->Vec<u8>{let mut v=Vec::with_capacity(128);v.extend_from_slice(b"CALIBRE_SEC014_HANDOFF_V1");v.extend_from_slice(&h.from_epoch.to_le_bytes());v.extend_from_slice(&h.to_epoch.to_le_bytes());v.extend_from_slice(&h.state.coin_id.to_le_bytes());v.extend_from_slice(&h.state.generation.to_le_bytes());v.extend_from_slice(&h.state.digest);v}
fn handoff_hash(h:&Handoff)->[u8;32]{*blake3::hash(&handoff_message(h)).as_bytes()}
fn handoff_share_message(h:&Handoff,index:usize)->Vec<u8>{let mut v=handoff_message(h);v.extend_from_slice(&(index as u64).to_le_bytes());v}
fn activation_message(epoch:u64,hash:&[u8;32],index:usize)->Vec<u8>{let mut v=Vec::with_capacity(80);v.extend_from_slice(b"CALIBRE_SEC014_ACTIVATION_V1");v.extend_from_slice(&epoch.to_le_bytes());v.extend_from_slice(&(index as u64).to_le_bytes());v.extend_from_slice(hash);v}

fn verify_final_share(f:&Finality,s:&FinalShare)->bool{
    s.index<N && committee_key(f.epoch,s.index).verifying_key().verify_strict(&final_share_message(f,s.index),&Signature::from_bytes(&s.signature)).is_ok()
}
fn verify_final_cert(c:&FinalCert)->bool{
    let mut u=HashSet::new(); for s in &c.shares{if !verify_final_share(&c.finality,s){return false;}u.insert(s.index);} u.len()>=Q
}
fn verify_handoff_share(h:&Handoff,s:&HandoffShare)->bool{
    s.index<N && committee_key(h.from_epoch,s.index).verifying_key().verify_strict(&handoff_share_message(h,s.index),&Signature::from_bytes(&s.signature)).is_ok()
}
fn verify_handoff_cert(c:&HandoffCert)->bool{
    let mut u=HashSet::new();for s in &c.shares{if !verify_handoff_share(&c.handoff,s){return false;}u.insert(s.index);}u.len()>=Q
}
fn verify_activation_share(epoch:u64,hash:&[u8;32],s:&ActivationShare)->bool{
    s.index<N && committee_key(epoch,s.index).verifying_key().verify_strict(&activation_message(epoch,hash,s.index),&Signature::from_bytes(&s.signature)).is_ok()
}
fn verify_activation_cert(epoch:u64,c:&ActivationCert,h:&HandoffCert)->bool{
    if !verify_handoff_cert(h)||c.handoff_hash!=handoff_hash(&h.handoff){return false;}let mut u=HashSet::new();for s in &c.shares{if !verify_activation_share(epoch,&c.handoff_hash,s){return false;}u.insert(s.index);}u.len()>=Q
}

fn checksum(prefix:&[u8])->[u8;32]{let mut h=Hasher::new();h.update(b"CALIBRE_SEC014_WAL_CHECKSUM_V1");h.update(prefix);*h.finalize().as_bytes()}
fn encode_record(kind:u8,epoch:u64,coin:u64,g:u64,aux:u64,d1:[u8;32],d2:[u8;32])->[u8;WAL_RECORD]{
    let mut r=[0u8;WAL_RECORD];r[0..8].copy_from_slice(&WAL_MAGIC);r[8]=kind;r[16..24].copy_from_slice(&epoch.to_le_bytes());r[24..32].copy_from_slice(&coin.to_le_bytes());r[32..40].copy_from_slice(&g.to_le_bytes());r[40..48].copy_from_slice(&aux.to_le_bytes());r[48..80].copy_from_slice(&d1);r[80..112].copy_from_slice(&d2);let c=checksum(&r[..112]);r[112..144].copy_from_slice(&c);r
}
fn decode_record(r:&[u8])->Result<(u8,u64,u64,u64,u64,[u8;32],[u8;32]),String>{
    if r.len()!=WAL_RECORD||r[0..8]!=WAL_MAGIC{return Err("bad WAL record".into());}if r[112..144]!=checksum(&r[..112]){return Err("WAL checksum mismatch".into());}let kind=r[8];if !matches!(kind,K_ACTIVE|K_TRANSFER|K_RETIRED|K_ACTIVATION){return Err("unknown WAL kind".into());}let epoch=u64::from_le_bytes(r[16..24].try_into().unwrap());let coin=u64::from_le_bytes(r[24..32].try_into().unwrap());let g=u64::from_le_bytes(r[32..40].try_into().unwrap());let aux=u64::from_le_bytes(r[40..48].try_into().unwrap());let mut d1=[0u8;32];d1.copy_from_slice(&r[48..80]);let mut d2=[0u8;32];d2.copy_from_slice(&r[80..112]);Ok((kind,epoch,coin,g,aux,d1,d2))
}

struct Store{
    file:File,epoch:u64,active:HashMap<u64,(u64,[u8;32])>,transfer:HashMap<(u64,u64),[u8;32]>,retired:HashMap<(u64,u64),[u8;32]>,activation:HashMap<(u64,u64,u64),[u8;32]>
}
impl Store{
    fn open(path:&Path,epoch:u64)->Result<Self,String>{
        if let Some(p)=path.parent(){fs::create_dir_all(p).map_err(|e|e.to_string())?;}let mut file=OpenOptions::new().read(true).write(true).create(true).open(path).map_err(|e|e.to_string())?;file.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;let mut bytes=Vec::new();file.read_to_end(&mut bytes).map_err(|e|e.to_string())?;if bytes.len()%WAL_RECORD!=0{return Err("incomplete WAL; fail closed".into());}
        let mut s=Self{file,epoch,active:HashMap::new(),transfer:HashMap::new(),retired:HashMap::new(),activation:HashMap::new()};
        for r in bytes.chunks_exact(WAL_RECORD){let(kind,re,coin,g,aux,d1,d2)=decode_record(r)?;if re!=epoch{return Err("WAL epoch mismatch".into());}match kind{K_ACTIVE=>{s.active.insert(coin,(g,d1));},K_TRANSFER=>{if let Some(old)=s.transfer.insert((coin,g),d2){if old!=d2{return Err("conflicting transfer choice".into());}}},K_RETIRED=>{if let Some(old)=s.retired.insert((coin,g),d1){if old!=d1{return Err("conflicting handoff choice".into());}}},K_ACTIVATION=>{if let Some(old)=s.activation.insert((aux,coin,g),d1){if old!=d1{return Err("conflicting activation".into());}}s.active.insert(coin,(g,d2));},_=>unreachable!()}}
        s.file.seek(SeekFrom::End(0)).map_err(|e|e.to_string())?;Ok(s)
    }
    fn append(&mut self,r:[u8;WAL_RECORD])->Result<(),String>{self.file.seek(SeekFrom::End(0)).map_err(|e|e.to_string())?;self.file.write_all(&r).map_err(|e|e.to_string())?;self.file.sync_all().map_err(|e|e.to_string())?;Ok(())}
    fn bootstrap(&mut self,s:StateRef)->Result<(),String>{if self.active.contains_key(&s.coin_id){return Ok(());}self.append(encode_record(K_ACTIVE,self.epoch,s.coin_id,s.generation,0,s.digest,[0u8;32]))?;self.active.insert(s.coin_id,(s.generation,s.digest));Ok(())}
    fn active_matches(&self,s:StateRef)->bool{self.active.get(&s.coin_id)==Some(&(s.generation,s.digest))}
    fn record_transfer(&mut self,f:&Finality)->Result<bool,String>{
        if self.retired.contains_key(&(f.input.coin_id,f.input.generation))||!self.active_matches(f.input){return Ok(false);}let k=(f.input.coin_id,f.input.generation);if let Some(old)=self.transfer.get(&k){return Ok(old==&f.successor_digest);}self.append(encode_record(K_TRANSFER,self.epoch,f.input.coin_id,f.input.generation,0,f.input.digest,f.successor_digest))?;self.transfer.insert(k,f.successor_digest);Ok(true)
    }
    fn commit(&mut self,c:&FinalCert)->Result<bool,String>{
        if c.finality.epoch!=self.epoch||!verify_final_cert(c)||!self.active_matches(c.finality.input){return Ok(false);}let n=StateRef{coin_id:c.finality.input.coin_id,generation:c.finality.input.generation+1,digest:c.finality.successor_digest};self.append(encode_record(K_ACTIVE,self.epoch,n.coin_id,n.generation,0,n.digest,[0u8;32]))?;self.active.insert(n.coin_id,(n.generation,n.digest));Ok(true)
    }
    fn record_handoff(&mut self,h:&Handoff)->Result<bool,String>{
        if h.from_epoch!=self.epoch||h.to_epoch!=self.epoch+1||!self.active_matches(h.state){return Ok(false);}let k=(h.state.coin_id,h.state.generation);let hh=handoff_hash(h);if let Some(old)=self.retired.get(&k){return Ok(old==&hh);}self.append(encode_record(K_RETIRED,self.epoch,h.state.coin_id,h.state.generation,h.to_epoch,hh,h.state.digest))?;self.retired.insert(k,hh);Ok(true)
    }
    fn activate(&mut self,c:&HandoffCert)->Result<bool,String>{
        let h=c.handoff;if h.to_epoch!=self.epoch||h.from_epoch+1!=self.epoch||!verify_handoff_cert(c){return Ok(false);}let k=(h.from_epoch,h.state.coin_id,h.state.generation);let hh=handoff_hash(&h);if let Some(old)=self.activation.get(&k){return Ok(old==&hh);}if let Some((g,d))=self.active.get(&h.state.coin_id){if *g!=h.state.generation||*d!=h.state.digest{return Ok(false);}}self.append(encode_record(K_ACTIVATION,self.epoch,h.state.coin_id,h.state.generation,h.from_epoch,hh,h.state.digest))?;self.activation.insert(k,hh);self.active.insert(h.state.coin_id,(h.state.generation,h.state.digest));Ok(true)
    }
}

fn write_u64(s:&mut TcpStream,v:u64)->Result<(),String>{s.write_all(&v.to_le_bytes()).map_err(|e|e.to_string())}
fn read_u64(s:&mut TcpStream)->Result<u64,String>{let mut b=[0u8;8];s.read_exact(&mut b).map_err(|e|e.to_string())?;Ok(u64::from_le_bytes(b))}
fn read32(s:&mut TcpStream)->Result<[u8;32],String>{let mut b=[0u8;32];s.read_exact(&mut b).map_err(|e|e.to_string())?;Ok(b)}
fn read64(s:&mut TcpStream)->Result<[u8;64],String>{let mut b=[0u8;64];s.read_exact(&mut b).map_err(|e|e.to_string())?;Ok(b)}
fn write_state(s:&mut TcpStream,x:&StateRef)->Result<(),String>{write_u64(s,x.coin_id)?;write_u64(s,x.generation)?;s.write_all(&x.digest).map_err(|e|e.to_string())}
fn read_state(s:&mut TcpStream)->Result<StateRef,String>{Ok(StateRef{coin_id:read_u64(s)?,generation:read_u64(s)?,digest:read32(s)?})}
fn write_finality(s:&mut TcpStream,f:&Finality)->Result<(),String>{write_u64(s,f.epoch)?;write_state(s,&f.input)?;s.write_all(&f.successor_digest).map_err(|e|e.to_string())}
fn read_finality(s:&mut TcpStream)->Result<Finality,String>{Ok(Finality{epoch:read_u64(s)?,input:read_state(s)?,successor_digest:read32(s)?})}
fn write_final_cert(s:&mut TcpStream,c:&FinalCert)->Result<(),String>{write_finality(s,&c.finality)?;s.write_all(&[c.shares.len() as u8]).map_err(|e|e.to_string())?;for sh in &c.shares{s.write_all(&[sh.index as u8]).map_err(|e|e.to_string())?;s.write_all(&sh.signature).map_err(|e|e.to_string())?;}Ok(())}
fn read_final_cert(s:&mut TcpStream)->Result<FinalCert,String>{let f=read_finality(s)?;let mut n=[0u8;1];s.read_exact(&mut n).map_err(|e|e.to_string())?;if n[0] as usize>N{return Err("oversized final cert".into());}let mut shares=Vec::new();for _ in 0..n[0]{let mut i=[0u8;1];s.read_exact(&mut i).map_err(|e|e.to_string())?;shares.push(FinalShare{index:i[0] as usize,signature:read64(s)?});}Ok(FinalCert{finality:f,shares})}
fn write_handoff(s:&mut TcpStream,h:&Handoff)->Result<(),String>{write_u64(s,h.from_epoch)?;write_u64(s,h.to_epoch)?;write_state(s,&h.state)}
fn read_handoff(s:&mut TcpStream)->Result<Handoff,String>{Ok(Handoff{from_epoch:read_u64(s)?,to_epoch:read_u64(s)?,state:read_state(s)?})}
fn write_handoff_cert(s:&mut TcpStream,c:&HandoffCert)->Result<(),String>{write_handoff(s,&c.handoff)?;s.write_all(&[c.shares.len() as u8]).map_err(|e|e.to_string())?;for sh in &c.shares{s.write_all(&[sh.index as u8]).map_err(|e|e.to_string())?;s.write_all(&sh.signature).map_err(|e|e.to_string())?;}Ok(())}
fn read_handoff_cert(s:&mut TcpStream)->Result<HandoffCert,String>{let h=read_handoff(s)?;let mut n=[0u8;1];s.read_exact(&mut n).map_err(|e|e.to_string())?;if n[0] as usize>N{return Err("oversized handoff cert".into());}let mut shares=Vec::new();for _ in 0..n[0]{let mut i=[0u8;1];s.read_exact(&mut i).map_err(|e|e.to_string())?;shares.push(HandoffShare{index:i[0] as usize,signature:read64(s)?});}Ok(HandoffCert{handoff:h,shares})}

fn run_node(epoch:u64,index:usize,port:u16,wal:PathBuf,byz:bool,bootstrap:bool)->Result<(),String>{
    let listener=TcpListener::bind(("127.0.0.1",port)).map_err(|e|format!("bind e{epoch} n{index}: {e}"))?;let mut store=Store::open(&wal,epoch)?;if bootstrap{store.bootstrap(StateRef{coin_id:COIN_ID,generation:0,digest:genesis_digest()})?;}let sk=committee_key(epoch,index);
    for conn in listener.incoming(){let mut stream=match conn{Ok(s)=>s,Err(_)=>continue};let mut op=[0u8;1];if stream.read_exact(&mut op).is_err(){continue;}match op[0]{
        OP_PING=>{let _=stream.write_all(&[0xAA]);},
        OP_SHUTDOWN=>{let _=stream.write_all(&[0x55]);break;},
        OP_FINALIZE=>{let f=read_finality(&mut stream)?;let allowed=if byz{f.epoch==epoch}else{f.epoch==epoch&&store.record_transfer(&f)?};if !allowed{let _=stream.write_all(&[0]);continue;}let sig=sk.sign(&final_share_message(&f,index)).to_bytes();stream.write_all(&[1,index as u8]).map_err(|e|e.to_string())?;stream.write_all(&sig).map_err(|e|e.to_string())?;},
        OP_COMMIT=>{let c=read_final_cert(&mut stream)?;let ok=store.commit(&c)?;stream.write_all(&[if ok{1}else{0}]).map_err(|e|e.to_string())?;},
        OP_HANDOFF=>{let h=read_handoff(&mut stream)?;let allowed=if byz{h.from_epoch==epoch}else{store.record_handoff(&h)?};if !allowed{let _=stream.write_all(&[0]);continue;}let sig=sk.sign(&handoff_share_message(&h,index)).to_bytes();stream.write_all(&[1,index as u8]).map_err(|e|e.to_string())?;stream.write_all(&sig).map_err(|e|e.to_string())?;},
        OP_ACTIVATE=>{let c=read_handoff_cert(&mut stream)?;let valid=c.handoff.to_epoch==epoch&&c.handoff.from_epoch+1==epoch&&verify_handoff_cert(&c);let allowed=if valid{store.activate(&c)?}else{byz};if !allowed{let _=stream.write_all(&[0]);continue;}let hh=handoff_hash(&c.handoff);let sig=sk.sign(&activation_message(epoch,&hh,index)).to_bytes();stream.write_all(&[1,index as u8]).map_err(|e|e.to_string())?;stream.write_all(&sig).map_err(|e|e.to_string())?;},
        _=>{let _=stream.write_all(&[0]);}
    }}Ok(())
}

fn free_port()->Result<u16,String>{let l=TcpListener::bind(("127.0.0.1",0)).map_err(|e|e.to_string())?;Ok(l.local_addr().map_err(|e|e.to_string())?.port())}
struct NodeProc{epoch:u64,index:usize,port:u16,wal:PathBuf,byz:bool,bootstrap:bool,child:Child}
impl NodeProc{
    fn spawn(exe:&Path,epoch:u64,index:usize,wal:PathBuf,byz:bool,bootstrap:bool)->Result<Self,String>{let port=free_port()?;let child=Command::new(exe).arg("--node").arg(epoch.to_string()).arg(index.to_string()).arg(port.to_string()).arg(&wal).arg(if byz{"1"}else{"0"}).arg(if bootstrap{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|e.to_string())?;let mut n=Self{epoch,index,port,wal,byz,bootstrap,child};n.wait_ready()?;Ok(n)}
    fn wait_ready(&mut self)->Result<(),String>{for _ in 0..400{if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_PING]);let mut b=[0u8;1];if s.read_exact(&mut b).is_ok()&&b[0]==0xAA{return Ok(());}}thread::sleep(Duration::from_millis(5));}Err(format!("node e{} n{} not ready",self.epoch,self.index))}
    fn restart(&mut self,exe:&Path)->Result<(),String>{let _=self.child.kill();let _=self.child.wait();self.port=free_port()?;self.child=Command::new(exe).arg("--node").arg(self.epoch.to_string()).arg(self.index.to_string()).arg(self.port.to_string()).arg(&self.wal).arg(if self.byz{"1"}else{"0"}).arg(if self.bootstrap{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|e.to_string())?;self.wait_ready()}
    fn stop(&mut self){if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_SHUTDOWN]);}let _=self.child.wait();}
}
fn connect(port:u16)->Option<TcpStream>{let addr:SocketAddr=format!("127.0.0.1:{port}").parse().ok()?;let s=TcpStream::connect_timeout(&addr,Duration::from_millis(1000)).ok()?;s.set_read_timeout(Some(Duration::from_millis(1000))).ok();s.set_write_timeout(Some(Duration::from_millis(1000))).ok();Some(s)}
fn rpc_finalize(port:u16,f:&Finality)->Option<FinalShare>{let mut s=connect(port)?;s.write_all(&[OP_FINALIZE]).ok()?;write_finality(&mut s,f).ok()?;let mut st=[0u8;1];s.read_exact(&mut st).ok()?;if st[0]==0{return None;}let mut i=[0u8;1];s.read_exact(&mut i).ok()?;let sh=FinalShare{index:i[0] as usize,signature:read64(&mut s).ok()?};if verify_final_share(f,&sh){Some(sh)}else{None}}
fn rpc_commit(port:u16,c:&FinalCert)->bool{let Some(mut s)=connect(port)else{return false;};if s.write_all(&[OP_COMMIT]).is_err()||write_final_cert(&mut s,c).is_err(){return false;}let mut st=[0u8;1];s.read_exact(&mut st).is_ok()&&st[0]==1}
fn rpc_handoff(port:u16,h:&Handoff)->Option<HandoffShare>{let mut s=connect(port)?;s.write_all(&[OP_HANDOFF]).ok()?;write_handoff(&mut s,h).ok()?;let mut st=[0u8;1];s.read_exact(&mut st).ok()?;if st[0]==0{return None;}let mut i=[0u8;1];s.read_exact(&mut i).ok()?;let sh=HandoffShare{index:i[0] as usize,signature:read64(&mut s).ok()?};if verify_handoff_share(h,&sh){Some(sh)}else{None}}
fn rpc_activate(port:u16,epoch:u64,c:&HandoffCert)->Option<ActivationShare>{let mut s=connect(port)?;s.write_all(&[OP_ACTIVATE]).ok()?;write_handoff_cert(&mut s,c).ok()?;let mut st=[0u8;1];s.read_exact(&mut st).ok()?;if st[0]==0{return None;}let mut i=[0u8;1];s.read_exact(&mut i).ok()?;let sh=ActivationShare{index:i[0] as usize,signature:read64(&mut s).ok()?};let hh=handoff_hash(&c.handoff);if verify_activation_share(epoch,&hh,&sh){Some(sh)}else{None}}
fn collect_final(nodes:&[NodeProc],f:&Finality,idx:&[usize])->Vec<FinalShare>{let mut m=HashMap::new();for &i in idx{if let Some(s)=rpc_finalize(nodes[i].port,f){m.entry(s.index).or_insert(s);}}m.into_values().collect()}
fn collect_handoff(nodes:&[NodeProc],h:&Handoff,idx:&[usize])->Vec<HandoffShare>{let mut m=HashMap::new();for &i in idx{if let Some(s)=rpc_handoff(nodes[i].port,h){m.entry(s.index).or_insert(s);}}m.into_values().collect()}
fn collect_activation(nodes:&[NodeProc],epoch:u64,c:&HandoffCert,idx:&[usize])->Vec<ActivationShare>{let mut m=HashMap::new();for &i in idx{if let Some(s)=rpc_activate(nodes[i].port,epoch,c){m.entry(s.index).or_insert(s);}}m.into_values().collect()}
fn final_cert(nodes:&[NodeProc],f:Finality)->Result<FinalCert,String>{let idx:Vec<usize>=(0..N).collect();let c=FinalCert{finality:f,shares:collect_final(nodes,&f,&idx)};if verify_final_cert(&c){Ok(c)}else{Err(format!("finality only {}/7",c.shares.len()))}}
fn commit_all(nodes:&[NodeProc],c:&FinalCert)->usize{nodes.iter().filter(|n|rpc_commit(n.port,c)).count()}
fn synth_handoff_share(h:&Handoff,index:usize)->HandoffShare{HandoffShare{index,signature:committee_key(h.from_epoch,index).sign(&handoff_share_message(h,index)).to_bytes()}}

fn controller()->Result<(),String>{
    let exe=env::current_exe().map_err(|e|e.to_string())?;let root=env::temp_dir().join(format!("calibre-sec014-{}",std::process::id()));let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).map_err(|e|e.to_string())?;
    println!("CALIBRE SECURITY SEC-014 v0.14.0");println!("MULTI-GENERATION MONETARY LINEAGE ACROSS ZERO-OVERLAP COMMITTEE ROTATIONS");println!("Epochs 20 -> 21 -> 22; each N=7 Q=5; 21 separate OS processes over real 127.0.0.1 TCP");println!("Owner authorization is abstracted as pre-authorized state digests; this test isolates lineage/rotation semantics");println!("Global blockchain / universal transaction order: NOT USED");println!("Per-monetary-state generation/epoch lineage: USED");println!();
    let mut c0=Vec::new();let mut c1=Vec::new();let mut c2=Vec::new();for i in 0..N{c0.push(NodeProc::spawn(&exe,E0,i,root.join(format!("e20-{i}.wal")),i<2,true)?);c1.push(NodeProc::spawn(&exe,E1,i,root.join(format!("e21-{i}.wal")),i<2,false)?);c2.push(NodeProc::spawn(&exe,E2,i,root.join(format!("e22-{i}.wal")),i<2,false)?);}
    let all:Vec<usize>=(0..N).collect();let honest:Vec<usize>=vec![2,3,4,5,6];
    let d0=genesis_digest();let d1=successor_digest(&d0,1,b"BOB");let d2=successor_digest(&d1,2,b"CAROL");let d3=successor_digest(&d2,3,b"DAVE");let d4=successor_digest(&d3,4,b"EVE");let m1=successor_digest(&d1,2,b"MALLORY-CONFLICT");let stale=successor_digest(&d0,1,b"MALLORY-STALE");
    let s0=StateRef{coin_id:COIN_ID,generation:0,digest:d0};let c01=final_cert(&c0,Finality{epoch:E0,input:s0,successor_digest:d1})?;if commit_all(&c0,&c01)<Q{return Err("epoch20 g0->g1 commit failed".into());}println!("GENERATION 0->1 / EPOCH 20: ALICE-STATE -> BOB-STATE FINALIZES -> PASS");
    let s1=StateRef{coin_id:COIN_ID,generation:1,digest:d1};let h20=Handoff{from_epoch:E0,to_epoch:E1,state:s1};let hc20=HandoffCert{handoff:h20,shares:collect_handoff(&c0,&h20,&[0,1,2,3,4])};if !verify_handoff_cert(&hc20){return Err("20->21 handoff missing".into());}
    let partial20=HandoffCert{handoff:h20,shares:hc20.shares.iter().take(4).copied().collect()};if !collect_activation(&c1,E1,&partial20,&honest).is_empty(){return Err("4/7 handoff activated honest e21".into());}println!("INSUFFICIENT 20->21 HANDOFF 4/7: HONEST EPOCH-21 ACTIVATION=0 -> PASS");
    let hskip=Handoff{from_epoch:E0,to_epoch:E2,state:s1};let skip=collect_handoff(&c0,&hskip,&all);if skip.len()>2{return Err(format!("20->22 skipped handoff got {}/7",skip.len()));}println!("SKIPPED-EPOCH HANDOFF 20->22: {}/7 ONLY, NO QC -> PASS",skip.len());
    let old_conf=Finality{epoch:E0,input:s1,successor_digest:m1};let old_votes=collect_final(&c0,&old_conf,&all);if old_votes.len()>=Q{return Err("old committee finalized post-handoff conflict".into());}println!("OLD EPOCH-20 POST-HANDOFF CONFLICT: {}/7 <5 -> PASS",old_votes.len());
    let acts21=collect_activation(&c1,E1,&hc20,&all);let ac21=ActivationCert{handoff_hash:handoff_hash(&h20),shares:acts21};if !verify_activation_cert(E1,&ac21,&hc20){return Err("e21 activation QC missing".into());}println!("EPOCH 21 DIRECT-PREDECESSOR ACTIVATION 5/7 -> PASS");
    let c12=final_cert(&c1,Finality{epoch:E1,input:s1,successor_digest:d2})?;if commit_all(&c1,&c12)<Q{return Err("epoch21 g1->g2 commit failed".into());}println!("GENERATION 1->2 / EPOCH 21: BOB-STATE -> CAROL-STATE FINALIZES -> PASS");
    let s2=StateRef{coin_id:COIN_ID,generation:2,digest:d2};let h21=Handoff{from_epoch:E1,to_epoch:E2,state:s2};let hc21=HandoffCert{handoff:h21,shares:collect_handoff(&c1,&h21,&[0,1,2,3,4])};if !verify_handoff_cert(&hc21){return Err("21->22 handoff missing".into());}
    if !collect_activation(&c2,E2,&hc20,&honest).is_empty(){return Err("e22 accepted stale 20->21 handoff".into());}println!("STALE 20->21 HANDOFF REPLAY AGAINST EPOCH 22: HONEST ACTIVATION=0 -> PASS");
    let acts22=collect_activation(&c2,E2,&hc21,&all);let ac22=ActivationCert{handoff_hash:handoff_hash(&h21),shares:acts22};if !verify_activation_cert(E2,&ac22,&hc21){return Err("e22 activation QC missing".into());}println!("EPOCH 22 ACTIVATES ONLY DIRECT 21->22 HANDOFF 5/7 -> PASS");
    let c23=final_cert(&c2,Finality{epoch:E2,input:s2,successor_digest:d3})?;if commit_all(&c2,&c23)<Q{return Err("epoch22 g2->g3 commit failed".into());}println!("GENERATION 2->3 / EPOCH 22: CAROL-STATE -> DAVE-STATE FINALIZES -> PASS");
    c2[4].restart(&exe)?;let s3=StateRef{coin_id:COIN_ID,generation:3,digest:d3};let c34=final_cert(&c2,Finality{epoch:E2,input:s3,successor_digest:d4})?;if commit_all(&c2,&c34)<Q{return Err("restart continuity g3->g4 failed".into());}println!("EPOCH-22 HONEST RESTART + GENERATION 3->4 DAVE->EVE FINALIZES -> PASS");
    let stale_votes=collect_final(&c2,&Finality{epoch:E2,input:s0,successor_digest:stale},&all);let honest_stale=stale_votes.iter().filter(|s|s.index>=2).count();if honest_stale!=0||stale_votes.len()>=Q{return Err("stale generation replay reached honest/quorum support".into());}println!("STALE GENERATION-0 REPLAY AFTER GENERATION-4: HONEST=0, TOTAL {}/7 <5 -> PASS",stale_votes.len());
    c0[2].restart(&exe)?;let old_again=collect_final(&c0,&old_conf,&all);if old_again.len()>=Q{return Err("restarted old signer forgot retirement".into());}println!("RESTARTED EPOCH-20 HONEST HANDOFF SIGNER REMEMBERS RETIREMENT: CONFLICT {}/7 <5 -> PASS",old_again.len());
    let ba=Handoff{from_epoch:E0,to_epoch:E1,state:StateRef{coin_id:COIN_ID+99,generation:7,digest:[1u8;32]}};let bb=Handoff{from_epoch:E0,to_epoch:E1,state:StateRef{coin_id:COIN_ID+99,generation:7,digest:[2u8;32]}};let ca=HandoffCert{handoff:ba,shares:[0,1,2,3,4].into_iter().map(|i|synth_handoff_share(&ba,i)).collect()};let cb=HandoffCert{handoff:bb,shares:[0,1,2,5,6].into_iter().map(|i|synth_handoff_share(&bb,i)).collect()};if !verify_handoff_cert(&ca)||!verify_handoff_cert(&cb){return Err("f=3 boundary witness failed".into());}println!("F=3 EXPECTED BOUNDARY: TWO CRYPTOGRAPHIC 5/7 CONFLICTING HANDOFF CERTIFICATES -> ATTACK WITNESS CONFIRMED");
    for n in &mut c0{n.stop();}for n in &mut c1{n.stop();}for n in &mut c2{n.stop();}let _=fs::remove_dir_all(&root);
    println!();println!("=== SEC-014 DECISION ===");println!("MULTI-GENERATION MONETARY LINEAGE g0->g4 ACROSS EPOCHS 20->21->22: PASS IN TESTED LOCAL SCENARIO");println!("ZERO-OVERLAP DIRECT-PREDECESSOR MULTI-EPOCH HANDOFF CONTINUITY: PASS");println!("OLD COMMITTEE POST-HANDOFF SUCCESSOR FENCING WITH f<=2: PASS IN TESTED SCENARIO");println!("INSUFFICIENT 4/7 + SKIPPED-EPOCH + STALE-HANDOFF REPLAY REJECTION: PASS");println!("STALE MONETARY GENERATION REPLAY AFTER MULTIPLE SUCCESSORS: PASS");println!("PROCESS-RESTART PERSISTENCE OF CURRENT STATE + OLD RETIREMENT: PASS");println!("F=3 HANDOFF SAFETY BOUNDARY: TWO 5/7 CERTIFICATES REACHABLE / EXPECTED");println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");println!("PER-MONETARY-STATE GENERATION/EPOCH LINEAGE USED: YES");println!("OFFLINE-CLIENT LONG-RANGE BOOTSTRAP / PRODUCTION MEMBERSHIP SELECTION / SYBIL RESISTANCE: NOT PROVEN");println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");Ok(())
}

fn main(){let a:Vec<String>=env::args().collect();let r=if a.get(1).map(String::as_str)==Some("--node"){if a.len()!=8{Err("node usage: --node <epoch> <index> <port> <wal> <byz> <bootstrap>".into())}else{let e=a[2].parse::<u64>().map_err(|x|x.to_string());let i=a[3].parse::<usize>().map_err(|x|x.to_string());let p=a[4].parse::<u16>().map_err(|x|x.to_string());match(e,i,p){(Ok(e),Ok(i),Ok(p))=>run_node(e,i,p,PathBuf::from(&a[5]),a[6]=="1",a[7]=="1"),(Err(x),_,_)|(_,Err(x),_)|(_,_,Err(x))=>Err(x)}}}else{controller()};if let Err(e)=r{eprintln!("SEC-014 ERROR: {e}");std::process::exit(1);}}

#[cfg(test)]mod tests{use super::*;
#[test]fn epoch_key_domains_are_disjoint(){assert_ne!(committee_key(E0,2).verifying_key().to_bytes(),committee_key(E1,2).verifying_key().to_bytes());assert_ne!(committee_key(E1,2).verifying_key().to_bytes(),committee_key(E2,2).verifying_key().to_bytes());}
#[test]fn generation_binding_changes_digest(){let d=genesis_digest();assert_ne!(successor_digest(&d,1,b"BOB"),successor_digest(&d,2,b"BOB"));}
#[test]fn four_handoff_shares_fail(){let h=Handoff{from_epoch:E0,to_epoch:E1,state:StateRef{coin_id:COIN_ID,generation:1,digest:[7u8;32]}};let c=HandoffCert{handoff:h,shares:(0..4).map(|i|synth_handoff_share(&h,i)).collect()};assert!(!verify_handoff_cert(&c));}
#[test]fn five_handoff_shares_pass(){let h=Handoff{from_epoch:E0,to_epoch:E1,state:StateRef{coin_id:COIN_ID,generation:1,digest:[9u8;32]}};let c=HandoffCert{handoff:h,shares:(0..5).map(|i|synth_handoff_share(&h,i)).collect()};assert!(verify_handoff_cert(&c));}
#[test]fn f3_boundary_constructs_two_q5(){let a=Handoff{from_epoch:E0,to_epoch:E1,state:StateRef{coin_id:COIN_ID+1,generation:3,digest:[1u8;32]}};let b=Handoff{from_epoch:E0,to_epoch:E1,state:StateRef{coin_id:COIN_ID+1,generation:3,digest:[2u8;32]}};let ca=HandoffCert{handoff:a,shares:[0,1,2,3,4].into_iter().map(|i|synth_handoff_share(&a,i)).collect()};let cb=HandoffCert{handoff:b,shares:[0,1,2,5,6].into_iter().map(|i|synth_handoff_share(&b,i)).collect()};assert!(verify_handoff_cert(&ca)&&verify_handoff_cert(&cb));}}
