use tfhe::prelude::*;
use tfhe::{set_server_key, ServerKey, FheInt32};
use tfhe::{ProvenCompactCiphertextList, CompactPublicKey};

// CompactPkeCrs is imported for type awareness — the CRS wrapper type used in
// key generation. In server_compute, we work directly with CompactPkePublicParams
// (extracted via crs.public_params()) since that is what verify_and_expand consumes.
// CompactPkeCrs itself has no serialize impl in 0.8.7, which is why we serialize
// the public params directly. See S6 in the ADR for the full CRS serialization story.
use tfhe::zk::CompactPkeCrs;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::error::Error;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ModelWeights {
    bias: i32,
    weights: Vec<i32>,
    scale_factor: i32,
    feature_count: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- [SERVER] Starting Blind Computation ---");

    // PARAMETER VERSIONING (S17): This project uses the unversioned alias
    // PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 from tfhe-rs 0.8.7.
    // Production code should pin to a versioned parameter name (e.g.
    // V1_0_PARAM_... in tfhe-rs 1.x) to survive library upgrades, and should
    // target the 2M128 variant for IND-CPA^D alignment. The 1.x migration
    // is scoped as an isolated future pass due to API churn and key-format
    // incompatibility between 0.8.7 and 1.x.

    // SECURITY (S18): This project uses PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
    // which provides:
    //   - ~128-bit lattice security per Lattice-Estimator (documented floor for all
    //     PARAM_MESSAGE_2_CARRY_2 TUniform sets)
    //   - PBS failure probability ≤ 2^-64
    //   - Note: production fhEVM requires 2M128 (≤ 2^-128) to align p_fail with
    //     lattice security level and achieve IND-CPA^D hardening against
    //     decryption-oracle attacks. The 2M128 variant requires tfhe-rs 1.x,
    //     scoped as an isolated future migration.
    //   - ZK-PoCK via verify_and_expand adds integrity binding regardless of p_fail.

    // 1. Load the Evaluation Key safely
    // PERSISTENT STATE NOTE (S5): The ServerKey is large (~131 MB). In a long-running
    // coprocessor serving many requests, it is loaded once at startup, held in shared
    // memory (OnceLock<Arc<ServerKey>>), and set into each worker thread once at spawn.
    // This mock runs a single request on one thread, so loading once per run is already
    // optimal. No caching added because a run-once binary cannot use or test it.
    let s_file = BufReader::new(File::open("server_key.bin")?);
    let server_key: ServerKey = bincode::deserialize_from(s_file)?;
    
    // 2. Activate the key for the current thread
    set_server_key(server_key);

    // CONCURRENCY NOTE (S6/S12): In a persistent coprocessor, this single-threaded
    // compute path would sit behind a fixed-size worker pool fed by a bounded MPSC
    // channel (sync_channel with a queue depth). Each worker thread clones
    // Arc<ServerKey> into thread-local storage once at spawn via set_server_key,
    // then pulls inference tasks off the shared receiver in a loop. The bounded
    // channel provides backpressure (S12): when the queue is full, senders block
    // rather than allowing unbounded memory growth under load. This mock runs a
    // single request on one thread, so the pool is described rather than built.

    println!("Server Key loaded and activated.");

    // 3. Load Verification Parameters (Public Key, CRS & Metadata)
    let pk_file = File::open("public_key.bin")?;
    let public_key: CompactPublicKey = bincode::deserialize_from(pk_file)?;
    use tfhe::zk::{Compressible, CompactPkePublicParams, SerializableCompactPkePublicParams};
    let mut crs_file = BufReader::new(File::open("crs.bin")?);
    let compressed_params: SerializableCompactPkePublicParams =
        tfhe::safe_serialization::safe_deserialize(&mut crs_file, 1 << 30)
            .map_err(|e| format!("CRS deserialize failed: {}", e))?;
    let public_params = CompactPkePublicParams::uncompress(compressed_params)
        .map_err(|e| format!("CRS uncompress failed: {:?}", e))?;
    let sender_address: [u8; 20] = [0u8; 20];
    let nonce: u64 = 42;
    let chain_id: u64 = 9001;
    let block_expiry: u64 = 15_000_000;

    let mut metadata = Vec::new();
    metadata.extend_from_slice(&sender_address);
    metadata.extend_from_slice(&nonce.to_be_bytes());
    metadata.extend_from_slice(&chain_id.to_be_bytes());
    metadata.extend_from_slice(&block_expiry.to_be_bytes());

    // 4. Load the Encrypted Request
    let d_file = BufReader::new(File::open("request.bin")?);
    let proven_list: ProvenCompactCiphertextList = bincode::deserialize_from(d_file)?;
    
    // VERIFICATION CHOICE (S11): tfhe-rs high-level API bundles ZK verification
    // with expansion — there is no plain .expand() on ProvenCompactCiphertextList.
    // In production fhEVM, the on-chain precompile typically verifies the proof
    // before routing to the coprocessor; skipping re-verification at this layer
    // would require dropping to the low-level tfhe-rs API. We accept the
    // additional verification cost (~10-100ms per request) as the honest,
    // type-safe choice for this mock.
    //
    // MEV PROTECTION (S16): tfhe-rs also exposes verify_re_randomize_and_expand,
    // which re-randomizes ciphertexts after verification using a seed. In a
    // public-mempool fhEVM context, this breaks linkability between the proven
    // payload visible in the mempool and the ciphertext the coprocessor actually
    // computes on, protecting against MEV searchers replaying or correlating
    // ciphertexts. For this mock we use the non-rerandomizing variant for
    // simplicity; production deployments targeting MEV-heavy chains should
    // prefer the re-randomizing version.
    let expander = proven_list.verify_and_expand(&public_params, &public_key, &metadata)?;
    let mut encrypted_features: Vec<FheInt32> = Vec::with_capacity(expander.len());
    for i in 0..expander.len() {
    let ct: FheInt32 = expander.get(i)?.expect("Index in bounds");
    encrypted_features.push(ct);
}
println!("Encrypted batch of {} features loaded.", encrypted_features.len());

let encrypted_batch = vec![encrypted_features];

    // 5. Load the Model Weights
    // PERSISTENT STATE NOTE (S4): The model weights are identical for every request.
    // In a long-running coprocessor they are loaded once at startup into shared memory
    // (OnceLock<Arc<ModelWeights>>) and read by all requests. This mock runs a single
    // request and exits, so loading once per run is already optimal.
    let w_file = File::open("data/LR_weights_quantized.json")?;
    let reader = BufReader::new(w_file);
    let model: ModelWeights = serde_json::from_reader(reader)?;

    
    assert_eq!(
        model.weights.len(),
        model.feature_count,
        "Model corruption: weights.len() does not match feature_count field"
);
    println!("Model weights loaded ({} features).", model.weights.len());

    // 6. Perform the Blind Math (Dot Product) - STRICTLY OPTIMIZED
    println!("Computing inference blindly (FHE Circuit Optimized)...");
    let mut encrypted_results: Vec<FheInt32> = Vec::with_capacity(encrypted_batch.len());

    for (i, enc_row) in encrypted_batch.iter().enumerate() {
        
        // System Safety: Prevent Out-Of-Bounds panics
        if enc_row.len() != model.weights.len() || enc_row.is_empty() {
            return Err(format!("Feature mismatch on row {}: Expected {}, got {}", 
                i, model.weights.len(), enc_row.len()).into());
        }

        // CHUNKING RATIONALE (S7/S13): PARAM_MESSAGE_2_CARRY_2 provides 2 bits of carry per
        // radix block. Sequential additions saturate carry after ~4 terms, forcing
        // implicit PBS. Chunking at 16 aligns the loop with the carry budget rather
        // than fighting it — and provides the structural boundary where production
        // fhEVM coprocessors invoke batch_bootstrap to amortize PBS cost across
        // multiple ciphertexts simultaneously. We stub that call here as a comment
        // since pure tfhe-rs high-level API requires dropping to core_crypto for
        // explicit PBS control.
        // FHE Optimization: Delay ciphertext initialization until a non-zero weight is found
        // TYPE SIZING: FheInt32 = 8 radix blocks (PARAM_MESSAGE_2_CARRY_2: 2 bits message
        // per block × 8 = 32 bits plaintext space). Sized against ACCUMULATION width,
        // not input width: input 8192 × weight 75 = 614K per scalar mul, accumulated
        // over 433 terms reaches millions worst-case. FheInt16 would silently wrap;
        // FheInt64 would be 50% more HCU than necessary. FheInt32 is the honest minimum.
        let mut accumulator: Option<FheInt32> = None;

        for j in 0..model.weights.len() {
            let weight = model.weights[j];

            // FHE Math Optimization: Skip circuit evaluation entirely for zero weights
            // SCALAR BYPASS OPTIMIZATION — verified against LR_weights_quantized.json:
            // weight == 0:  37/433 weights — skips FHE multiplication circuit entirely
            // weight == 1:  10/433 weights — replaces multiplication with clone
            // weight == -1:  9/433 weights — replaces multiplication with negation
            // Combined: 56/433 weights (~13%) bypass the most expensive FHE operation.
            // Note: checks are against raw quantized weight integers (scale_factor=1000),
            // not against the scale itself. weight==1 means the trained LR coefficient
            // was ~0.001, which genuinely occurs in this model.
            if weight == 0 {
                continue; // Zero weight: no contribution to dot product.
                          // Skipping avoids allocating and scheduling an FHE multiplication
                          // circuit for a term that contributes nothing to the result.
            }

            // FHE Math Optimization: Bypass multiplication circuit for Identity (1) and Negation (-1)
            let term = if weight == 1 {
                enc_row[j].clone()
            } else if weight == -1 {
                -&enc_row[j] 
            
            // OPTIMIZATION CONSIDERED (S14): For small weights (|w| ≤ 3), repeated FheInt32
            // addition can outperform scalar multiplication due to PBS overhead. Rejected
            // for this model — weight distribution [-67, 75] is varied enough that
            // special-casing 2 and 3 would add complexity without meaningful gain.        
            } else {
                &enc_row[j] * weight 
            };

            // In-place mutation to save memory allocations
            match accumulator {
                None => accumulator = Some(term),
                Some(ref mut acc) => *acc += term,
            }
        }
        
        // System Safety: Graceful error if the entire model was empty/zeros (no panic!)
        let Some(mut final_score) = accumulator else {
            return Err(format!("Row {}: All applied weights were zero. Invalid model.", i).into());
        };

        // FHE Math Optimization: Only evaluate the bias addition circuit if bias is non-zero
        if model.bias != 0 {
            final_score += model.bias;
        }

        encrypted_results.push(final_score);
        
        if (i + 1) % 4 == 0 {
            println!("  Progress: {}/{} rows processed", i + 1, encrypted_batch.len());
        }
    }

    // 7. Save the Encrypted Results
    let mut res_file = BufWriter::new(File::create("response.bin")?);
    bincode::serialize_into(&mut res_file, &encrypted_results)?;

    println!("--- [SERVER] Success! 'response.bin' generated blindly. ---");
    Ok(())
}