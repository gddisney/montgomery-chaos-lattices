use sha3::{Digest, Sha3_256, Sha3_512};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use rand::rngs::OsRng;
use std::env;
use std::fs::{read_to_string, write};
use std::process;
use hex;

/// Generate a list of small primes up to a given limit using the Sieve of Eratosthenes
fn small_prime_sieve(limit: usize) -> Vec<u64> {
    let mut sieve = vec![true; limit + 1];
    let mut p = 2;
    while p * p <= limit {
        if sieve[p] {
            let mut multiple = p * p;
            while multiple <= limit {
                sieve[multiple] = false;
                multiple += p;
            }
        }
        p += 1;
    }
    let mut primes = Vec::new();
    for i in 2..=limit {
        if sieve[i] {
            primes.push(i as u64);
        }
    }
    primes
}

/// Quick check using small primes to eliminate trivial composites
#[inline(always)]
fn passes_small_prime_check(n: &BigUint, small_primes: &[u64]) -> bool {
    for &prime in small_primes {
        let prime_big = BigUint::from(prime);
        if n % &prime_big == BigUint::zero() {
            return *n == prime_big;
        }
    }
    true
}

/// Miller-Rabin primality test with a chosen number of rounds.
/// This function assumes n has passed small prime checks.
#[inline(always)]
fn miller_rabin(rng: &mut OsRng, n: &BigUint, k: usize) -> bool {
    if *n <= BigUint::one() {
        return false;
    }
    if *n == BigUint::from(2u64) {
        return true;
    }
    if n % 2u64 == BigUint::zero() {
        return false;
    }

    let one = BigUint::one();
    let two = &one + &one;
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0;
    while &d % &two == BigUint::zero() {
        d >>= 1;
        s += 1;
    }

    'outer: for _ in 0..k {
        let a = rng.gen_biguint_range(&two, n);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 0..(s - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// Combined check: first small primes, then Miller-Rabin
#[inline(always)]
fn is_probably_prime(rng: &mut OsRng, n: &BigUint, small_primes: &[u64], rounds: usize) -> bool {
    if !passes_small_prime_check(n, small_primes) {
        return false;
    }
    miller_rabin(rng, n, rounds)
}

/// Generate a large "hyper" prime by quickly filtering out composites with small primes,
/// then using Miller-Rabin for final checks. This uses OsRng for cryptographically
/// secure random bytes when constructing the candidate.
#[inline(always)]
fn generate_hyper_prime(rng: &mut OsRng, bits: usize, small_primes: &[u64], rounds: usize) -> BigUint {
    loop {
        let candidate = rng.gen_biguint(bits.try_into().unwrap());
        if is_probably_prime(rng, &candidate, small_primes, rounds) {
            return candidate;
        }
    }
}

/// Structure for a lattice point
#[derive(Debug, Clone)]
struct LatticePoint {
    coordinates: Vec<BigUint>, // Coordinates in the lattice
}

/// Structure for the lattice
#[derive(Debug)]
struct Lattice {
    points: Vec<LatticePoint>,    // Lattice points
    dimensions: usize,            // Number of dimensions
    prime_anchors: Vec<BigUint>,  // Prime anchors derived from rows
    sbox: [u8; 256],              // Substitution box
    inverse_sbox: [u8; 256],      // Inverse substitution box
}

impl Lattice {
    /// Create the genesis lattice
    fn new(dimensions: usize, size: usize, prime_bits: usize, small_primes: &[u64], rounds: usize) -> Self {
        let mut points = Vec::new();
        let mut rng = OsRng;

        for _ in 0..size {
            let mut coordinates = Vec::new();
            for _ in 0..dimensions {
                let prime = generate_hyper_prime(&mut rng, prime_bits, small_primes, rounds);
                coordinates.push(prime);
            }
            points.push(LatticePoint { coordinates });
        }

        Self {
            points,
            dimensions,
            prime_anchors: Vec::new(),
            sbox: [0u8; 256],
            inverse_sbox: [0u8; 256],
        }
    }

    /// Get coordinates of all lattice points
    fn get_coordinates(&self) -> Vec<Vec<BigUint>> {
        self.points
            .iter()
            .map(|point| point.coordinates.clone())
            .collect()
    }

    /// Bind lattice rows using Montgomery ladder and chaos transformations
    fn bind_with_chaos(&mut self, scalar: &BigUint, chaos_seq: &[usize]) {
        for point in &mut self.points {
            let mut r0 = point.coordinates.clone();
            let mut r1 = point.coordinates.clone();

            for (bit, chaos_val) in scalar
                .to_bytes_be()
                .iter()
                .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
                .zip(chaos_seq)
            {
                if bit == 0 {
                    for i in 0..self.dimensions {
                        r1[i] = r0[i].clone() + &r1[i] + BigUint::from(*chaos_val as u64);
                        r0[i] = r0[i].clone() * BigUint::from(2u32);
                    }
                } else {
                    for i in 0..self.dimensions {
                        r0[i] = r0[i].clone() + &r1[i] + BigUint::from(*chaos_val as u64);
                        r1[i] = r1[i].clone() * BigUint::from(2u32);
                    }
                }
                Self::orthogonalize(&mut r0, &mut r1);
            }
            point.coordinates = r0;
        }
    }

    /// Ensure orthogonality between two vectors
    fn orthogonalize(v1: &mut Vec<BigUint>, v2: &mut Vec<BigUint>) {
        let mut dot_product = BigUint::zero();
        let mut magnitude_squared = BigUint::zero();

        for (x1, x2) in v1.iter().zip(v2.iter()) {
            dot_product = dot_product + (x1 * x2);
            magnitude_squared = magnitude_squared + (x2 * x2);
        }

        if magnitude_squared.is_zero() {
            return;
        }

        let projection_scalar = &dot_product / &magnitude_squared;
        for (x1, x2) in v1.iter_mut().zip(v2.iter()) {
            *x1 = x1.clone() - &(x2 * &projection_scalar);
        }
    }

    /// Generate S-Box and inverse S-Box using the chaos seed
    fn generate_sbox(&mut self, chaos_seed: u64) {
        let mut hasher = Sha3_256::new();
        hasher.update(&chaos_seed.to_be_bytes());
        for anchor in &self.prime_anchors {
            hasher.update(&anchor.to_bytes_be());
        }
        let seed = hasher.finalize();

        let mut sbox = [0u8; 256];
        for i in 0..256 {
            sbox[i] = i as u8;
        }

        let chaos_seed_u64 = u64::from_be_bytes(seed[0..8].try_into().unwrap());
        let chaos_seq = chaotic_sequence(256, chaos_seed_u64);
        for i in 0..256 {
            sbox.swap(i, chaos_seq[i % chaos_seq.len()]);
        }

        for (i, &byte) in sbox.iter().enumerate() {
            self.inverse_sbox[byte as usize] = i as u8;
        }

        self.sbox = sbox;
    }

    /// Encrypt a message using the S-Box and chaotic sequence
    fn encrypt(&self, plaintext: &[u8], chaos_seed: u64) -> Vec<u8> {
        let chaos_seq = chaotic_sequence(plaintext.len(), chaos_seed);
        plaintext
            .iter()
            .enumerate()
            .map(|(i, &byte)| self.sbox[(byte ^ chaos_seq[i] as u8) as usize])
            .collect()
    }

    /// Decrypt a message using the inverse S-Box and chaotic sequence
    fn decrypt(&self, ciphertext: &[u8], chaos_seed: u64) -> Vec<u8> {
        let chaos_seq = chaotic_sequence(ciphertext.len(), chaos_seed);
        ciphertext
            .iter()
            .enumerate()
            .map(|(i, &byte)| {
                let index = self.inverse_sbox[byte as usize];
                index ^ chaos_seq[i] as u8
            })
            .collect()
    }
}

/// Chaos utility functions

fn enhanced_perturbation(state: u64, step: u64) -> u64 {
    let input = format!("{}-{}", state, step);
    let hash = Sha3_256::digest(input.as_bytes());
    u64::from_be_bytes(hash[0..8].try_into().unwrap())
}

fn chaotic_sequence(n: usize, seed: u64) -> Vec<usize> {
    let mut chaos_seq: Vec<usize> = (0..n).collect();
    let mut current_state = seed;

    for i in 0..n {
        let perturbation = enhanced_perturbation(current_state, i as u64);
        let mod_pi = (current_state % ((std::f64::consts::PI * 1e8) as u64)) as f64 / 1e8;
        let trig_transform = (mod_pi.sin() * mod_pi.cos()).abs();
        let chaotic_index = ((trig_transform * n as f64) as u64 + perturbation) as usize % n;

        chaos_seq.swap(i, chaotic_index);
        current_state = current_state.wrapping_add(perturbation) % n as u64;
    }

    chaos_seq
}

/// HMAC Utility Functions

/// Generate an HMAC using SHA3-256
fn generate_hmac_sha3(data: &str, key: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(data.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

/// Verify HMAC using SHA3-256
fn verify_hmac_sha3(data_hex: &str, hmac: &str, key: &[u8]) -> bool {
    let recalculated_hmac = generate_hmac_sha3(data_hex, key);
    recalculated_hmac == hmac
}

/// Wrap the key or ciphertext in PEM-like format with line breaks every 64 characters
fn wrap_in_pem_format(label: &str, key: &str) -> String {
    let wrapped_key: String = key
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("\n");

    format!(
        "--- BEGIN {} ---\n{}\n--- END {} ---",
        label, wrapped_key, label
    )
}

/// Generate the chaos key
fn generate_chaos_key(bits: usize, small_prime_limit: usize) -> String {
    // Generate the nonce (seed)
    let nonce = generate_nonce(bits, small_prime_limit);

    // Generate the HMAC key prime
    let hmac_key_prime = generate_hyper_prime(&mut OsRng, bits.try_into().unwrap(), &small_prime_sieve(small_prime_limit), 40);

    // Generate the chaotic sequence using the nonce
    let chaos_seq = chaotic_sequence(256, nonce);

    // Serialize the chaotic sequence to a hex string
    let data_string: String = chaos_seq.iter().map(|&num| format!("{:02x}", num)).collect();

    // Generate the HMAC value using the HMAC key
    let hmac_value = generate_hmac_sha3(&data_string, &hmac_key_prime.to_bytes_be());

    // Encode nonce and hmac_key as hex
    let nonce_hex = hex::encode(nonce.to_be_bytes());
    let hmac_key_hex = hex::encode(hmac_key_prime.to_bytes_be());

    // Concatenate nonce_hex + hmac_key_hex + data_string + hmac_value
    let encoded_data = format!("{}{}{}{}", nonce_hex, hmac_key_hex, data_string, hmac_value);

    // Wrap the key in PEM-like format
    wrap_in_pem_format("CHAOS KEY", &encoded_data)
}

/// Generate a 64-bit nonce (seed)
fn generate_nonce(bits: usize, small_prime_limit: usize) -> u64 {
    let small_primes = small_prime_sieve(small_prime_limit);
    let mut rng = OsRng;
    let rounds = 40;
    let prime_bits = bits;
    let chaos_seed_big = generate_hyper_prime(&mut rng, prime_bits.try_into().unwrap(), &small_primes, rounds);
    let mut hasher = Sha3_512::new();
    hasher.update(chaos_seed_big.to_bytes_be());
    let chaos_seed_bytes = hasher.finalize();
    u64::from_be_bytes(chaos_seed_bytes[0..8].try_into().unwrap())
}

/// Save a chaos key to a file
fn save_chaos_key(filename: &str, key: &str) -> std::io::Result<()> {
    write(filename, key)
}

/// Decode a chaos key from PEM-like format
fn decode_chaos_key(bits: usize, filename: &str) -> Result<(u64, BigUint, String), String> {
    let content = read_to_string(filename).map_err(|e| e.to_string())?;
    if !content.starts_with("--- BEGIN CHAOS KEY ---") || !content.ends_with("--- END CHAOS KEY ---") {
        return Err("Invalid Chaos Key format.".to_string());
    }

    // Extract the encoded data between the markers
    let encoded_data = content
        .lines()
        .skip(1)
        .take_while(|line| *line != "--- END CHAOS KEY ---")
        .collect::<Vec<&str>>()
        .join("");

    // Calculate seed (nonce), hmac_key, data, and hmac_value lengths in hex
    let seed_hex_length = 16; // 64-bit nonce = 16 hex characters
    let hmac_key_bits = bits;
    let hmac_key_bytes = hmac_key_bits / 8;
    let hmac_key_hex_length = hmac_key_bytes * 2;
    let data_hex_length = 512; // 256-byte chaos sequence = 512 hex characters
    let hmac_value_hex_length = 64; // SHA3-256 = 256 bits = 64 hex characters

    let expected_length = seed_hex_length + hmac_key_hex_length + data_hex_length + hmac_value_hex_length;

    if encoded_data.len() != expected_length {
        return Err(format!(
            "Encoded data length mismatch. Expected {}, found {}.",
            expected_length,
            encoded_data.len()
        ));
    }

    // Extract seed_hex, hmac_key_hex, data_hex, hmac_value
    let seed_hex = &encoded_data[0..seed_hex_length];
    let hmac_key_hex = &encoded_data[seed_hex_length..seed_hex_length + hmac_key_hex_length];
    let data_hex = &encoded_data[seed_hex_length + hmac_key_hex_length..seed_hex_length + hmac_key_hex_length + data_hex_length];
    let hmac_value = &encoded_data[seed_hex_length + hmac_key_hex_length + data_hex_length..];

    // Convert hex to bytes
    let seed_bytes = hex::decode(seed_hex).map_err(|_| "Invalid nonce hex encoding.".to_string())?;
    let hmac_key_bytes_vec = hex::decode(hmac_key_hex).map_err(|_| "Invalid HMAC key hex encoding.".to_string())?;
    let _data_bytes = hex::decode(data_hex).map_err(|_| "Invalid data hex encoding.".to_string())?;

    // Convert seed bytes to u64
    let seed_array: [u8; 8] = seed_bytes.try_into().map_err(|_| "Invalid nonce byte length.".to_string())?;
    let seed = u64::from_be_bytes(seed_array);

    // Convert hmac_key bytes to BigUint
    let hmac_key_prime = BigUint::from_bytes_be(&hmac_key_bytes_vec);

    // Generate the chaotic sequence using the seed (nonce)
    let chaos_seq = chaotic_sequence(256, seed);

    // Serialize the chaotic sequence to a hex string
    let data_string: String = chaos_seq.iter().map(|&num| format!("{:02x}", num)).collect();

    // Generate the HMAC value using the HMAC key
    let recalculated_hmac = generate_hmac_sha3(&data_string, &hmac_key_prime.to_bytes_be());

    // Verify HMAC
    if recalculated_hmac != hmac_value {
        return Err("HMAC verification failed. The data may have been tampered with.".to_string());
    }

    Ok((seed, hmac_key_prime, recalculated_hmac))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} <command> [arguments]", args[0]);
        eprintln!("Commands:");
        eprintln!("  gen <bits> <output_file>");
        eprintln!("  verify <bits> <input_file>");
        eprintln!("  encrypt <bits> <input_file> <plaintext_file> <ciphertext_file>");
        eprintln!("  decrypt <bits> <input_file> <ciphertext_file> <decrypted_file>");
        process::exit(1);
    }

    let command = args[1].as_str();

    match command {
        "gen" => {
            if args.len() != 4 {
                eprintln!("Usage: {} gen <bits> <output_file>", args[0]);
                process::exit(1);
            }

            let bits: usize = match args[2].parse() {
                Ok(num) => num,
                Err(_) => {
                    eprintln!("Invalid bits argument. Must be a positive integer.");
                    process::exit(1);
                }
            };

            let output_file = &args[3];

            // Validate that bits is divisible by 64 and >= 64
            if bits < 64 || bits % 64 != 0 {
                eprintln!("Bits must be a multiple of 64 and at least 64.");
                process::exit(1);
            }

            // Generate the chaos key
            let chaos_key = generate_chaos_key(bits, 10_000);

            // Save the chaos key to the file
            if let Err(e) = save_chaos_key(output_file, &chaos_key) {
                eprintln!("Failed to save chaos key: {}", e);
                process::exit(1);
            }

            println!("Chaos key successfully saved to {}", output_file);
        }
        "verify" => {
            if args.len() != 4 {
                eprintln!("Usage: {} verify <bits> <input_file>", args[0]);
                process::exit(1);
            }

            let bits: usize = match args[2].parse() {
                Ok(num) => num,
                Err(_) => {
                    eprintln!("Invalid bits argument. Must be a positive integer.");
                    process::exit(1);
                }
            };

            let input_file = &args[3];

            // Validate that bits is divisible by 64 and >= 64
            if bits < 64 || bits % 64 != 0 {
                eprintln!("Bits must be a multiple of 64 and at least 64.");
                process::exit(1);
            }

            // Decode the chaos key
            match decode_chaos_key(bits, input_file) {
                Ok((_seed, _hmac_key_prime, _hmac_value)) => {
                    println!("Chaos key verification successful. HMAC is valid.");
                }
                Err(e) => {
                    eprintln!("Chaos key verification failed: {}", e);
                    process::exit(1);
                }
            }
        }
        "encrypt" => {
            if args.len() != 6 {
                eprintln!("Usage: {} encrypt <bits> <input_file> <plaintext_file> <ciphertext_file>", args[0]);
                process::exit(1);
            }

            let bits: usize = match args[2].parse() {
                Ok(num) => num,
                Err(_) => {
                    eprintln!("Invalid bits argument. Must be a positive integer.");
                    process::exit(1);
                }
            };

            let input_file = &args[3];
            let plaintext_file = &args[4];
            let ciphertext_file = &args[5];

            // Validate that bits is divisible by 64 and >= 64
            if bits < 64 || bits % 64 != 0 {
                eprintln!("Bits must be a multiple of 64 and at least 64.");
                process::exit(1);
            }

            // Decode the chaos key
            let (seed, hmac_key_prime, _hmac_value) = match decode_chaos_key(bits, input_file) {
                Ok((s, k, v)) => (s, k, v),
                Err(e) => {
                    eprintln!("Failed to decode chaos key: {}", e);
                    process::exit(1);
                }
            };

            // Load plaintext
            let plaintext = match read_to_string(plaintext_file) {
                Ok(content) => content.into_bytes(),
                Err(e) => {
                    eprintln!("Failed to read plaintext file: {}", e);
                    process::exit(1);
                }
            };

            // Initialize lattice using the chaos seed and HMAC key
            let dimensions = 256;
            let size = 3;
            let prime_bits = 256;
            let small_primes = small_prime_sieve(10_000);
            let scalar = BigUint::from(2u64);
            let rounds = 40; // Increased for better security

            let mut lattice = Lattice::new(dimensions, size, prime_bits, &small_primes, rounds);

            // Bind lattice with chaos
            lattice.bind_with_chaos(&scalar, &chaotic_sequence(dimensions, seed));

            // Generate S-Box
            lattice.generate_sbox(seed);

            // Encrypt the plaintext
            let ciphertext = lattice.encrypt(&plaintext, seed);

            // Generate HMAC over the ciphertext for AEAD
            let ciphertext_hex = hex::encode(&ciphertext);
            let hmac_value = generate_hmac_sha3(&ciphertext_hex, &hmac_key_prime.to_bytes_be());

            // Encode ciphertext and HMAC in PEM-like format
            let encoded_ciphertext = format!("{}{}", ciphertext_hex, hmac_value);
            let wrapped_ciphertext = wrap_in_pem_format("CIPHERTEXT", &encoded_ciphertext);

            // Save the ciphertext to the file
            if let Err(e) = write(ciphertext_file, wrapped_ciphertext) {
                eprintln!("Failed to write ciphertext to file: {}", e);
                process::exit(1);
            }

            println!("Encryption successful. Ciphertext saved to {}", ciphertext_file);
        }
        "decrypt" => {
            if args.len() != 6 {
                eprintln!("Usage: {} decrypt <bits> <input_file> <ciphertext_file> <decrypted_file>", args[0]);
                process::exit(1);
            }

            let bits: usize = match args[2].parse() {
                Ok(num) => num,
                Err(_) => {
                    eprintln!("Invalid bits argument. Must be a positive integer.");
                    process::exit(1);
                }
            };

            let input_file = &args[3];
            let ciphertext_file = &args[4];
            let decrypted_file = &args[5];

            // Validate that bits is divisible by 64 and >= 64
            if bits < 64 || bits % 64 != 0 {
                eprintln!("Bits must be a multiple of 64 and at least 64.");
                process::exit(1);
            }

            // Decode the chaos key
            let (seed, hmac_key_prime, _hmac_value) = match decode_chaos_key(bits, input_file) {
                Ok((s, k, v)) => (s, k, v),
                Err(e) => {
                    eprintln!("Failed to decode chaos key: {}", e);
                    process::exit(1);
                }
            };

            // Load ciphertext (assumed to be in PEM-like format)
            let wrapped_ciphertext = match read_to_string(ciphertext_file) {
                Ok(content) => content.trim().to_string(),
                Err(e) => {
                    eprintln!("Failed to read ciphertext file: {}", e);
                    process::exit(1);
                }
            };

            // Extract encoded ciphertext data
            if !wrapped_ciphertext.starts_with("--- BEGIN CIPHERTEXT ---") || !wrapped_ciphertext.ends_with("--- END CIPHERTEXT ---") {
                eprintln!("Invalid Ciphertext format.");
                process::exit(1);
            }

            let encoded_data = wrapped_ciphertext
                .lines()
                .skip(1)
                .take_while(|line| *line != "--- END CIPHERTEXT ---")
                .collect::<Vec<&str>>()
                .join("");

            // Separate ciphertext_hex and hmac_value
            let ciphertext_hex_length = encoded_data.len() - 64; // Assuming HMAC is 64 hex characters
            let ciphertext_hex = &encoded_data[0..ciphertext_hex_length];
            let received_hmac = &encoded_data[ciphertext_hex_length..];

            // Verify HMAC
            let recalculated_hmac = generate_hmac_sha3(ciphertext_hex, &hmac_key_prime.to_bytes_be());
            if recalculated_hmac != received_hmac {
                eprintln!("HMAC verification failed. The ciphertext may have been tampered with.");
                process::exit(1);
            }

            // Decode ciphertext from hex
            let ciphertext = match hex::decode(ciphertext_hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("Failed to decode ciphertext from hex: {}", e);
                    process::exit(1);
                }
            };

            // Initialize lattice using the chaos seed and HMAC key
            let dimensions = 256;
            let size = 3;
            let prime_bits = 256;
            let small_primes = small_prime_sieve(10_000);
            let scalar = BigUint::from(2u64);
            let rounds = 40; // Increased for better security

            let mut lattice = Lattice::new(dimensions, size, prime_bits, &small_primes, rounds);

            // Bind lattice with chaos
            lattice.bind_with_chaos(&scalar, &chaotic_sequence(dimensions, seed));

            // Generate S-Box
            lattice.generate_sbox(seed);

            // Decrypt the ciphertext
            let decrypted = lattice.decrypt(&ciphertext, seed);

            // Save the decrypted plaintext to the file
            if let Err(e) = write(decrypted_file, &decrypted) {
                eprintln!("Failed to write decrypted plaintext to file: {}", e);
                process::exit(1);
            }

            println!("Decryption successful. Plaintext saved to {}", decrypted_file);
        }
        _ => {
            eprintln!("Invalid command: {}", command);
            eprintln!("Available commands: gen, verify, encrypt, decrypt");
            process::exit(1);
        }
    }
}

