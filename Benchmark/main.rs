use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::error::Error;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt64};
use polars::prelude::*; 
use rayon::prelude::*; 

// --- Constants ---
const HOURLY_COST_USD: f64 = 0.78; 

// --- 1. Data Structures ---
#[derive(Debug, Deserialize)]
struct ModelWeights {
    #[allow(dead_code)] 
    scale_factor: i64, 
    bias: i64,
    weights: Vec<i64>,
}

#[derive(Debug)]
struct TestStage {
    features: usize,
    rows: usize,
    category: &'static str,    
    description: &'static str,
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("=========================================================================================");
    println!("🔐 FHE FRAUD DETECTION: THE VALIDATION PYRAMID");
    println!("   Target Infrastructure: GCP N2-Standard-16 (AVX-512)");
    println!("=========================================================================================\n");

    // --- 2. Setup & Key Gen ---
    println!("[Init] Generating Cryptographic Parameters (tfhe-rs default)...");
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    // Main thread needs it too
    set_server_key(server_key.clone());
    println!("   -> Keys Active.\n");

    // --- 3. Resource Loading ---
    let weight_path = "/mnt/pv/data/LR_weights_quantized.json";
    let data_path = "/mnt/pv/data/processed/scaled_features.parquet";

    let file = File::open(weight_path)?;
    let reader = BufReader::new(file);
    let full_model: ModelWeights = serde_json::from_reader(reader)?;
    let max_features = full_model.weights.len();
    println!("[Init] Model Loaded. Max Features: {}", max_features);

    let df = LazyFrame::scan_parquet(data_path, ScanArgsParquet::default())?
        .collect()?;
    let total_rows_available = df.height();
    println!("[Init] Dataset Loaded. Available Rows: {}\n", total_rows_available);

    // --- 4. THE VALIDATION PYRAMID ---
    let stages = vec![
        TestStage { features: 5, rows: 5, category: "SANITY", description: "I/O Pipeline Check" },
        TestStage { features: max_features, rows: 1, category: "CRYPTO", description: "Noise Budget (Max Depth)" },
        TestStage { features: max_features, rows: 16, category: "SATURATION", description: "1:1 Core Mapping (16 vCPU)" },
        TestStage { features: max_features, rows: 32,  category: "OPTIMIZE", description: "Batch 32 (2x Overcommit)" },
        TestStage { features: max_features, rows: 64,  category: "OPTIMIZE", description: "Batch 64 (4x Overcommit)" },
        TestStage { features: max_features, rows: 128, category: "OPTIMIZE", description: "Batch 128 (8x Overcommit)" },
        TestStage { features: max_features, rows: 100, category: "SOAK", description: "Reliability Test (Batch 100)" },
    ];

    // --- 5. Execution Engine ---
    println!("{:<12} | {:<28} | {:<10} | {:<10} | {:<12} | {:<10}", 
        "CATEGORY", "TEST SCENARIO", "TIME (s)", "ROWS/SEC", "COST ($)", "STATUS");
    println!("{}", "-".repeat(100));

    for stage in stages {
        if stage.features > max_features { continue; }

        // Data Slicing
        let current_weights = &full_model.weights[0..stage.features];
        let current_bias = full_model.bias;
        let mut batch_plain_inputs: Vec<Vec<i64>> = Vec::new();
        let rows_to_process = std::cmp::min(stage.rows, total_rows_available);
        
        for r in 0..rows_to_process {
            let mut row_vec = Vec::new();
            let row_series = df.get_row(r).unwrap(); 
            for c in 0..stage.features {
                if let AnyValue::Int64(val) = row_series.0[c] { row_vec.push(val); } else { row_vec.push(0); }
            }
            batch_plain_inputs.push(row_vec);
        }

        let start_total = Instant::now();

        // A. Encryption (Parallel)
        // Encryption only needs client_key (passed explicitly), so no set_server_key needed here usually, 
        // but passing it is safe.
        let encrypted_batch: Vec<Vec<FheInt64>> = batch_plain_inputs.par_iter()
            .map(|row| {
                row.iter().map(|&val| FheInt64::encrypt(val, &client_key)).collect()
            })
            .collect();

        // B. Compute Dot Product (Parallel) -- CRITICAL FIX HERE
        // We capture server_key for the closure
        let server_key_handle = server_key.clone();
        
        let encrypted_results: Vec<FheInt64> = encrypted_batch.par_iter()
            .map(|enc_row| {
                // FIX: Initialize the key for this specific worker thread
                set_server_key(server_key_handle.clone());
                
                let mut accumulator = FheInt64::encrypt(current_bias, &client_key);
                for (w, enc_val) in current_weights.iter().zip(enc_row.iter()) {
                    accumulator = accumulator + (enc_val * *w);
                }
                accumulator
            })
            .collect();

        // C. Decrypt & Verify
        let mut success_count = 0;
        for (i, result_cipher) in encrypted_results.iter().enumerate() {
            let decrypted: i64 = result_cipher.decrypt(&client_key);
            let input_row = &batch_plain_inputs[i];
            let expected: i64 = input_row.iter().zip(current_weights.iter())
                .map(|(a, b)| a * b)
                .sum::<i64>() + current_bias;
            
            if decrypted == expected { success_count += 1; }
        }

        let duration = start_total.elapsed();
        let seconds = duration.as_secs_f64();
        let throughput = rows_to_process as f64 / seconds; 
        let cost_estimate = (HOURLY_COST_USD / 3600.0) * seconds;
        let status = if success_count == rows_to_process { "✅ PASS" } else { "❌ FAIL" };

        println!("{:<12} | {:<28} | {:<10.2} | {:<10.2} | ${:<11.6} | {}", 
            stage.category, stage.description, seconds, throughput, cost_estimate, status
        );

        if success_count != rows_to_process && stage.category == "CRYPTO" {
            println!("\n🚨 CRITICAL FAILURE: Noise Budget exceeded. Halting.");
            break;
        }
    }
    println!("{}", "-".repeat(100));
    println!("Report generated for stakeholder review.");
    Ok(())
}
