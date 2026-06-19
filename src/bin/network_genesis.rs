use tfhe::{generate_keys, ConfigBuilder, CompactPublicKey};
use std::fs::File;
use std::io::BufWriter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Network Genesis (Mock DKG)...");

    // 1. Configure the FHE parameters with a BOUNDED distribution for ZK-Proofs
    let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let config = ConfigBuilder::with_custom_parameters(params).build();

    // 2. Generate the Master Keys (Simulating the Validator Network)
    let (client_key, server_key) = generate_keys(config);
    
    // 3. Extract the Public Key (The Padlock for the users)
    let public_key = CompactPublicKey::try_new(&client_key)?; 

    // --- SAVE ALL ARTIFACTS --- //

    // 4. Save the Public Key (For the Client)
    let pk_file = File::create("public_key.bin")?;
    bincode::serialize_into(BufWriter::new(pk_file), &public_key)?;
    println!("Saved: public_key.bin");

    // 5. Save the Server Key (For the Coprocessor)
    let sk_file = File::create("server_key.bin")?;
    bincode::serialize_into(BufWriter::new(sk_file), &server_key)?;
    println!("Saved: server_key.bin");

    // 6. Save the Client Key (For the Mock Network Decryption)
    let ck_file = File::create("client_key.bin")?;
    bincode::serialize_into(BufWriter::new(ck_file), &client_key)?;
    println!("Saved: client_key.bin");

    println!("Genesis Complete. The network is ready.");
    Ok(())
}


