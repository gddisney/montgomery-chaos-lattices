use sha3::{Digest, Sha3_256, Sha3_512};
use std::collections::HashMap;
use rand::Rng;

/// Generates a strong perturbation based on the current state and step using SHA3-256.
pub fn enhanced_perturbation(state: u64, step: u64) -> u64 {
    let input = format!("{}-{}", state, step);
    let hash = Sha3_256::digest(input.as_bytes());
    let perturbation = u64::from_be_bytes(hash[0..8].try_into().unwrap());
    std::cmp::max(perturbation, 1_000_000) // Ensure perturbation has a minimum value
}

/// Generates a chaotic sequence using modular arithmetic and deterministic perturbation.
pub fn chaotic_sequence(n: usize, seed: u64) -> Vec<usize> {
    let mut chaos_seq: Vec<usize> = (0..n).collect();
    let mut current_state = seed;

    for i in 0..n {
        let perturbation = enhanced_perturbation(current_state, i as u64);
        let mod_pi = (current_state % ((std::f64::consts::PI * 1e8) as u64)) as f64 / 1e8;
        let trig_transform = (mod_pi.sin() * mod_pi.cos()).abs();
        let chaotic_index = ((trig_transform * n as f64) as u64 + perturbation) as usize % n;

        chaos_seq.swap(i, chaotic_index);
        current_state = (current_state + perturbation) % n as u64;
    }

    chaos_seq
}

/// Compress data using a chaotic sequence.
pub fn compress(data: &[u8], chaos_seq: &[usize], value_to_index: &HashMap<u8, usize>) -> Vec<usize> {
    data.iter()
        .map(|&byte| {
            *value_to_index
                .get(&byte)
                .expect(&format!("Byte value {} not found in chaos sequence.", byte))
        })
        .collect()
}

/// Decompress data using a chaotic sequence.
pub fn decompress(compressed_data: &[usize], chaos_seq: &[usize]) -> Vec<u8> {
    compressed_data
        .iter()
        .map(|&index| {
            if index < chaos_seq.len() {
                chaos_seq[index] as u8
            } else {
                panic!("Index {} is out of bounds for the chaotic sequence.", index);
            }
        })
        .collect()
}

/// Converts a list of integers to a hexadecimal string.
pub fn list_to_hex(int_list: &[usize]) -> String {
    int_list.iter().map(|&num| format!("{:02x}", num)).collect()
}

/// Converts a hexadecimal string back to a list of integers.
pub fn hex_to_list(hex_string: &str) -> Vec<usize> {
    (0..hex_string.len())
        .step_by(2)
        .map(|i| usize::from_str_radix(&hex_string[i..i + 2], 16).unwrap())
        .collect()
}

/// Generate an HMAC using SHA3-512.
pub fn generate_hmac_sha3(data: &str, key: &[u8]) -> String {
    let mut hasher = Sha3_512::new_with_prefix(key);
    hasher.update(data.as_bytes());
    let hash_result = hasher.finalize();
    hash_result.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Verify an HMAC using SHA3-512.
pub fn verify_hmac_sha3(data: &str, hmac: &str, key: &[u8]) -> bool {
    let calculated_hmac = generate_hmac_sha3(data, key);
    calculated_hmac == hmac
}

/// Encode data with a given seed and generate HMAC for integrity.
pub fn encode_with_seed(seed: u64, data: &[u8], hmac_key: &[u8]) -> String {
    let chaos_seq = chaotic_sequence(256, seed);
    let value_to_index: HashMap<u8, usize> = chaos_seq
        .iter()
        .enumerate()
        .map(|(idx, &value)| (value as u8, idx))
        .collect();
    let compressed_data = compress(data, &chaos_seq, &value_to_index);
    let seed_hex = format!("{:04x}", seed); // Adjust based on seed range
    let data_hex = list_to_hex(&compressed_data);
    let hmac = generate_hmac_sha3(&data_hex, hmac_key);
    format!("{}{}{}", seed_hex, data_hex, hmac)
}

/// Decode data from an encoded hex string with HMAC verification.
pub fn decode_with_seed(encoded_str: &str, hmac_key: &[u8]) -> Vec<u8> {
    if encoded_str.len() < 4 + 128 {
        panic!("Encoded string is too short to contain a valid seed or HMAC.");
    }
    let seed_hex = &encoded_str[..4];
    let data_hex = &encoded_str[4..encoded_str.len() - 128];
    let hmac = &encoded_str[encoded_str.len() - 128..];
    let seed = u64::from_str_radix(seed_hex, 16).unwrap();

    if !verify_hmac_sha3(data_hex, hmac, hmac_key) {
        panic!("HMAC verification failed. The data may have been tampered with.");
    }

    let compressed_data = hex_to_list(data_hex);
    let chaos_seq = chaotic_sequence(256, seed);
    decompress(&compressed_data, &chaos_seq)
}
