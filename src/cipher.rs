use crate::chaos_hmac::*;
use crate::hyper_prime::*;
use crate::ortho::*;
use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;
use num_bigint::BigUint;
use sha3::{Digest, Sha3_256};

/// Encrypt data using the S-Box and ChaCha20 cipher.
pub fn encrypt_with_sbox(
    data: &[u8],
    sbox: &[u8; 256],
    key: &[u8],
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut substituted_data = data
        .iter()
        .map(|&byte| sbox[byte as usize])
        .collect::<Vec<u8>>();

    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(&mut substituted_data);
    substituted_data
}

/// Decrypt data using the inverse S-Box and ChaCha20 cipher.
pub fn decrypt_with_sbox(
    encrypted_data: &[u8],
    inverse_sbox: &[u8; 256],
    key: &[u8],
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut decrypted_data = encrypted_data.to_vec();

    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(&mut decrypted_data);

    decrypted_data
        .iter()
        .map(|&byte| inverse_sbox[byte as usize])
        .collect()
}

/// Full pipeline: Chaos  Lattice  S-Box  Encrypt  Chaos
pub fn encrypt_pipeline(
    data: &[u8],
    seed: u64,
    hmac_key: &[u8],
    sbox: &[u8; 256],
    key: &[u8],
    nonce: &[u8; 12],
) -> String {
    // Chaos Encoding
    let chaos_encoded = encode_with_seed(seed, data, hmac_key);

    // Encrypt with S-Box and ChaCha20
    let encrypted_data = encrypt_with_sbox(chaos_encoded.as_bytes(), sbox, key, nonce);

    // Final Chaos Encoding
    let final_encoded = encode_with_seed(seed, &encrypted_data, hmac_key);
    final_encoded
}

/// Full pipeline: Chaos  Decrypt  S-Box  Lattice  Chaos
pub fn decrypt_pipeline(
    encrypted_data: &str,
    seed: u64,
    hmac_key: &[u8],
    inverse_sbox: &[u8; 256],
    key: &[u8],
    nonce: &[u8; 12],
) -> Vec<u8> {
    // Decode Chaos
    let chaos_decoded = decode_with_seed(encrypted_data, hmac_key);

    // Decrypt with S-Box and ChaCha20
    let decrypted_data = decrypt_with_sbox(&chaos_decoded, inverse_sbox, key, nonce);

    // Decode Final Chaos
    decode_with_seed(&String::from_utf8(decrypted_data).unwrap(), hmac_key)
}

/// Generate a random nonce.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).expect("Failed to generate random nonce");
    nonce
}

