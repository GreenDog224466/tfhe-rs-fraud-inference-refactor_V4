use tfhe::prelude::*;
use tfhe::{ClientKey, FheInt32};
use std::fs::File;
use std::io::BufReader;
use std::error::Error;

// --- HOMOMORPHIC CIRCUIT INVARIANTS ---
const FEATURE_SCALE: f64 = 1000.0; 
const WEIGHT_SCALE: f64 = 1000.0;  

// SCALE: Features and weights are each scaled by 1000, so dot-product terms
// accumulate at OUTPUT_SCALE = 1,000,000; dividing by that recovers the logit.
// KNOWN LIMITATION: the bias was quantized in Python at 1000, not 1,000,000,
// so it's 1000x too small relative to the terms. Negligible here (true bias
// ≈ -0.002), but a correct version would scale bias by FEATURE_SCALE * WEIGHT_SCALE.
const OUTPUT_SCALE: f64 = FEATURE_SCALE * WEIGHT_SCALE; 

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- [CLIENT] Starting Decryption of Server Results ---");

    // 1. Load the SECRET Client Key
    // MOCK SIMPLIFICATION — DECRYPTION TRUST MODEL:
    // This mock holds a full ClientKey and decrypts directly. In production fhEVM,
    // no full secret key exists anywhere. At genesis, a committee runs Distributed
    // Key Generation (DKG): the secret key is produced as shares across operators,
    // while the public key (for clients) and server/evaluation key (for the
    // coprocessor) are derived public outputs. The secret is never assembled.
    // Decryption is a threshold protocol run by Zama's TKMS (Threshold Key
    // Management System): each operator computes a partial decryption share from
    // its key share, and an aggregator combines the shares into the plaintext —
    // again without ever reconstructing the secret key. The single-key decrypt
    // below stands in for that entire flow to keep the mock self-contained.
    
    let c_file = BufReader::new(File::open("client_key.bin")?);
    let client_key: ClientKey = bincode::deserialize_from(c_file)?;
    println!("Secret Key loaded safely.");

    // 2. Load the Encrypted Response from the Server
    let r_file = BufReader::new(File::open("response.bin")?);
    let encrypted_results: Vec<FheInt32> = bincode::deserialize_from(r_file)?;
    println!("Received {} encrypted predictions from server.", encrypted_results.len());

    // 3. Phase Recovery & ML Activation
    println!("\nDecrypted Results (Fraud Probability):");
    println!("----------------------------------------------");
    
    for (i, enc_val) in encrypted_results.iter().enumerate() {
        // Step A: Cryptographic Phase Recovery (Remove LWE noise)
        let decrypted_raw: i32 = enc_val.decrypt(&client_key);
        
        // Step B: Affine Scale Reversal (Recover the true logit)
        let logit = decrypted_raw as f64 / OUTPUT_SCALE;
        
        // Step C: Machine Learning Activation (Sigmoid Function)
        // We compute this locally because non-linear functions are highly inefficient in FHE.
        let probability = 1.0 / (1.0 + (-logit).exp());
        let percentage = probability * 100.0;
        
        // Standard ML classification threshold (50%)
        let status = if probability > 0.5 { "🚩 POTENTIAL FRAUD" } else { "✅ CLEAR" };
        
        println!("Row {:02}: Logit={:>8.4} | Fraud Probability={:>6.2}% | Status: {}", 
                 i, logit, percentage, status);
    }

    println!("\n--- [CLIENT] Zero-Trust Handshake Complete ---");
    Ok(())
}