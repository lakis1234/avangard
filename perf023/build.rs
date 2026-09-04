use std::env;
use std::fs;
use std::path::PathBuf;

mod perf022_builder {
    include!("../perf022/build.rs");
    pub fn run() {
        main();
    }
}

fn replace_once(src: &mut String, from: &str, to: &str, label: &str) {
    let n = src.matches(from).count();
    assert_eq!(n, 1, "PERF-023 transform expected exactly one {label}, found {n}");
    *src = src.replacen(from, to, 1);
}

fn main() {
    println!("cargo:rerun-if-changed=../perf022/build.rs");
    println!("cargo:rerun-if-changed=../perf021/build.rs");
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    // Generate the proven PERF-022 BLAKE3 certified engine first, then add a diagnostic mode
    // that isolates live content hashing from Ed25519 batch-certificate verification.
    perf022_builder::run();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let generated = out_dir.join("generated.rs");
    let mut src = fs::read_to_string(&generated).expect("read PERF-022-generated source");

    src = src.replace("PERF-022", "PERF-023");
    src = src.replace("_0022", "_0023");
    src = src.replace("v2.2.0", "v2.3.0");

    replace_once(
        &mut src,
        "struct BatchCert {\n    public: [u8; 32],\n    signature: [u8; 64],\n}",
        "struct BatchCert {\n    public: [u8; 32],\n    signature: [u8; 64],\n    digest: [u8; 32],\n}",
        "BatchCert digest field",
    );

    replace_once(
        &mut src,
        "            out.push(BatchCert { public, signature });",
        "            out.push(BatchCert { public, signature, digest });",
        "BatchCert digest construction",
    );

    replace_once(
        &mut src,
        "    let total_inputs = txs * arity as u64;\n    let batches = ((txs as usize) + batch_size - 1) / batch_size;",
        "    let total_inputs = txs * arity as u64;\n    let batches = ((txs as usize) + batch_size - 1) / batch_size;\n    // Diagnostic only: BOTH is the real PERF-022 gate. HASH-ONLY and CERT-ONLY deliberately\n    // disable one half so we can measure where the remaining throughput loss comes from.\n    let gate_mode: u8 = match env::var(\"CALIBRE_PERF023_MODE\")\n        .unwrap_or_else(|_| \"both\".to_string())\n        .to_ascii_lowercase()\n        .as_str()\n    {\n        \"both\" => 0,\n        \"hash-only\" => 1,\n        \"cert-only\" => 2,\n        other => panic!(\"PERF-023 unknown CALIBRE_PERF023_MODE: {other}\"),\n    };",
        "diagnostic gate mode",
    );

    replace_once(
        &mut src,
        "                    let cert = batch_certs[batch * streams + s];\n                    let vk = VerifyingKey::from_bytes(&cert.public)\n                        .expect(\"PERF-023 invalid certificate public key\");\n                    let sig = Signature::from_bytes(&cert.signature);\n                    vk.verify_strict(&cert_message(batch, s, &digest), &sig)\n                        .expect(\"PERF-023 batch authorization certificate rejected\");",
        "                    let cert = batch_certs[batch * streams + s];\n                    let effective_digest = if gate_mode == 2 { cert.digest } else { digest };\n                    if gate_mode != 1 {\n                        let vk = VerifyingKey::from_bytes(&cert.public)\n                            .expect(\"PERF-023 invalid certificate public key\");\n                        let sig = Signature::from_bytes(&cert.signature);\n                        vk.verify_strict(&cert_message(batch, s, &effective_digest), &sig)\n                            .expect(\"PERF-023 batch authorization certificate rejected\");\n                    }",
        "conditional certificate verification",
    );

    let digest_pattern = "let digest = *std::mem::replace(&mut batch_hasher, Blake3Hasher::new()).finalize().as_bytes();";
    let digest_replacement = "let digest = if gate_mode == 2 { [0u8; 32] } else { *std::mem::replace(&mut batch_hasher, Blake3Hasher::new()).finalize().as_bytes() };";
    let n = src.matches(digest_pattern).count();
    assert!(n >= 2, "PERF-023 expected at least two receiver digest-finalize sites, found {n}");
    src = src.replace(digest_pattern, digest_replacement);

    replace_once(
        &mut src,
        "                    batch_hasher.update(&record[..96]);",
        "                    if gate_mode != 2 { batch_hasher.update(&record[..96]); }",
        "conditional live BLAKE3 update",
    );

    src = src.replace(
        "BLAKE3 VERIFIED AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE",
        "DIGEST/CERTIFICATE COST DECOMPOSITION -> SPSC OWNER-LOCAL ATOMIC ENGINE",
    );
    src = src.replace(
        "Change vs PERF-021: replace BLAKE3 stream-batch content digest with BLAKE3 while retaining the same Ed25519 certificate gate",
        "Change vs PERF-022: diagnostic A/B isolation of live BLAKE3 hashing versus Ed25519 batch-certificate verification",
    );
    src = src.replace(
        "Target: preserve the ~5M PERF-015 core while cryptographically gating each stream-batch before execution",
        "Target: identify whether remaining PERF-022 loss is dominated by live BLAKE3 hashing or certificate verification",
    );
    src = src.replace(
        "BLAKE3 STREAM-BATCH CONTENT DIGEST INCLUDED: YES",
        "BLAKE3 STREAM-BATCH CONTENT DIGEST: CONDITIONAL BY CALIBRE_PERF023_MODE",
    );
    src = src.replace(
        "ED25519 STREAM-BATCH CERTIFICATE VERIFICATION INCLUDED: YES",
        "ED25519 STREAM-BATCH CERTIFICATE VERIFICATION: CONDITIONAL BY CALIBRE_PERF023_MODE",
    );

    replace_once(
        &mut src,
        "    let args: Vec<String> = env::args().collect();",
        "    let args: Vec<String> = env::args().collect();\n    let diagnostic_mode = env::var(\"CALIBRE_PERF023_MODE\").unwrap_or_else(|_| \"both\".to_string());",
        "main diagnostic mode label",
    );
    replace_once(
        &mut src,
        "    println!(\"DIGEST/CERTIFICATE COST DECOMPOSITION -> SPSC OWNER-LOCAL ATOMIC ENGINE\");",
        "    println!(\"DIGEST/CERTIFICATE COST DECOMPOSITION -> SPSC OWNER-LOCAL ATOMIC ENGINE\");\n    println!(\"DIAGNOSTIC GATE MODE: {}\", diagnostic_mode);\n    println!(\"hash-only and cert-only are measurement modes, NOT secure production protocol modes\");",
        "diagnostic mode print",
    );

    fs::write(&generated, src).expect("write PERF-023 generated source");
}
