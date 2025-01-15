use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

/// Structure for a lattice point
#[derive(Debug, Clone)]
pub struct LatticePoint {
    pub coordinates: Vec<BigUint>, // Coordinates in the lattice
}

/// Structure for the lattice
#[derive(Debug)]
pub struct Lattice {
    points: Vec<LatticePoint>,    // Lattice points
    dimensions: usize,            // Number of dimensions
    prime_anchors: Vec<BigUint>,  // Prime anchors derived from rows
    sbox: [u8; 256],              // Substitution box
    inverse_sbox: [u8; 256],      // Inverse substitution box
}

impl Lattice {
    /// Create a new lattice with random points
    pub fn new(dimensions: usize, size: usize, prime_bits: usize, small_primes: &[u64], rounds: usize) -> Self {
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

    /// Print the lattice points
    pub fn print(&self) {
        println!("\nLattice Points ({}D):", self.dimensions);
        for (i, point) in self.points.iter().enumerate() {
            let coords: Vec<String> = point
                .coordinates
                .iter()
                .map(|c| c.to_str_radix(10))
                .collect();
            println!("Row {}: [{}]", i + 1, coords.join(", "));
        }
    }

    /// Perform Montgomery ladder binding on rows
    pub fn bind_rows_with_ladder(&mut self, scalar: &BigUint) {
        for point in &mut self.points {
            let mut r0 = point.coordinates.clone(); // Initialize R0
            let mut r1 = point.coordinates.clone(); // Initialize R1

            for bit in scalar.to_bytes_be().iter().flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1)) {
                if bit == 0 {
                    for i in 0..self.dimensions {
                        r1[i] = r0[i].clone() + &r1[i]; // Addition
                        r0[i] = r0[i].clone() * BigUint::from(2u32); // Doubling
                    }
                } else {
                    for i in 0..self.dimensions {
                        r0[i] = r0[i].clone() + &r1[i]; // Addition
                        r1[i] = r1[i].clone() * BigUint::from(2u32); // Doubling
                    }
                }
                Self::orthogonalize(&mut r0, &mut r1);
            }
            point.coordinates = r0; // Final result is in R0
        }
    }

    /// Orthogonalize two vectors
    fn orthogonalize(v1: &mut Vec<BigUint>, v2: &mut Vec<BigUint>) {
        let mut dot_product = BigUint::zero();
        let mut magnitude_squared = BigUint::zero();

        // Compute the dot product and magnitude squared of v1
        for (x1, x2) in v1.iter().zip(v2.iter()) {
            dot_product = &dot_product + &(x1 * x2);
            magnitude_squared = &magnitude_squared + &(x2 * x2);
        }

        // If magnitude squared is zero, v2 is already orthogonal
        if magnitude_squared.is_zero() {
            return;
        }

        // Compute the scalar projection factor
        let projection_scalar = &dot_product / &magnitude_squared;

        // Adjust v1 to make it orthogonal to v2
        for (x1, x2) in v1.iter_mut().zip(v2.iter()) {
            *x1 = x1.clone() - &(x2 * &projection_scalar);
        }
    }

    /// Generate prime anchors
    pub fn generate_prime_anchors(&mut self) {
        self.prime_anchors.clear();

        for (i, point) in self.points.iter().enumerate() {
            let row_sum = point
                .coordinates
                .iter()
                .fold(BigUint::zero(), |acc, x| acc + x);

            let prime_anchor = Lattice::next_prime(&row_sum);
            self.prime_anchors.push(prime_anchor.clone());

            println!(
                "Row {}: Sum = {}, Prime Anchor = {}",
                i + 1,
                row_sum.to_str_radix(10),
                prime_anchor.to_str_radix(10)
            );
        }
    }

    /// Find the next prime number
    fn next_prime(n: &BigUint) -> BigUint {
        let mut candidate = n.clone();
        let mut rng = OsRng;

        loop {
            if is_probably_prime(&mut rng, &candidate, &small_prime_sieve(10_000), 40) {
                return candidate;
            }
            candidate += BigUint::one();
        }
    }

    /// Generate S-Box and inverse S-Box using ChaCha20
    pub fn generate_sbox(&mut self) {
        let mut anchor_bytes = Vec::new();
        for anchor in &self.prime_anchors {
            anchor_bytes.extend_from_slice(&anchor.to_bytes_be());
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&anchor_bytes);
        let seed = hasher.finalize();

        let key = &seed[..32];
        let nonce = &[0u8; 12];
        let mut cipher = ChaCha20::new(key.into(), nonce.into());

        let mut sbox = [0u8; 256];
        for i in 0..256 {
            sbox[i] = i as u8;
        }

        cipher.apply_keystream(&mut sbox);

        for (i, &byte) in sbox.iter().enumerate() {
            self.inverse_sbox[byte as usize] = i as u8;
        }

        self.sbox = sbox;
    }
}

