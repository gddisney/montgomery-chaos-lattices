//extern crate hyperprime;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::Rng;
use std::time::Instant;
use std::env;
use std::str::FromStr;
use num_traits::ToPrimitive;
/// Generate a list of small primes up to a given limit using the Sieve of Eratosthenes
pub fn small_prime_sieve(limit: usize) -> Vec<u64> {
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
pub fn passes_small_prime_check(n: &BigUint, small_primes: &[u64]) -> bool {
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
pub fn miller_rabin(rng: &mut OsRng, n: &BigUint, k: usize) -> bool {
    if *n <= BigUint::one() {
        return false;
    }
    if *n == BigUint::from(2_u64) {
        return true;
    }
    if n % 2_u64 == BigUint::zero() {
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
pub fn is_probably_prime(rng: &mut OsRng, n: &BigUint, small_primes: &[u64], rounds: usize) -> bool {
    if !passes_small_prime_check(n, small_primes) {
        return false;
    }
    miller_rabin(rng, n, rounds)
}

/// Generate a large "hyper" prime by quickly filtering out composites with small primes,
/// then using Miller-Rabin for final checks. This uses OsRng for cryptographically
/// secure random bytes when constructing the candidate.
#[inline(always)]
pub fn generate_hyper_prime(rng: &mut OsRng, bits: usize, small_primes: &[u64], rounds: usize) -> BigUint {
    loop {
        let candidate = rng.gen_biguint(bits.try_into().unwrap())
            | BigUint::one() // Ensure it's odd
            | (BigUint::one() << (bits - 1)); // Ensure the highest bit is set
        if is_probably_prime(rng, &candidate, small_primes, rounds) {
            return candidate;
        }
    }
}

/// Generate a Safe Prime: p = 2q + 1, where q is also prime
pub fn generate_safe_prime(rng: &mut OsRng, bits: usize, small_primes: &[u64], rounds: usize) -> BigUint {
    loop {
        // Generate q with bits-1 bits to ensure p has the desired bit length
        let q = generate_hyper_prime(rng, bits - 1, small_primes, rounds);
        let p = &q * 2u32 + 1u32;
        if is_probably_prime(rng, &p, small_primes, rounds) {
            return p;
        }
    }
}

/// Generate a Sophie Germain Prime: q, where p = 2q + 1 is also prime
pub fn generate_germain_prime(rng: &mut OsRng, bits: usize, small_primes: &[u64], rounds: usize) -> BigUint {
    loop {
        let q = generate_hyper_prime(rng, bits, small_primes, rounds);
        let p = &q * 2u32 + 1u32;
        if is_probably_prime(rng, &p, small_primes, rounds) {
            return q;
        }
    }
}

/// Generate a Mersenne Prime: p = 2^n - 1, where n is prime
pub fn generate_mersenne_prime(rng: &mut OsRng, exponent_bits: usize, small_primes: &[u64], rounds: usize) -> Option<BigUint> {
    // Due to the rarity of Mersenne primes, limit the number of attempts
    let max_attempts = 1000;
    for _ in 0..max_attempts {
        let n = generate_hyper_prime(rng, exponent_bits, small_primes, rounds);
        // Ensure that n fits into a u32 for the pow function
        if let Some(exp) = n.to_u32() {
            let two = BigUint::from(2u32);
            let mersenne_candidate = two.pow(exp) - BigUint::one();
            if is_probably_prime(rng, &mersenne_candidate, small_primes, rounds) {
                return Some(mersenne_candidate);
            }
        } else {
            eprintln!("Exponent too large to handle.");
            continue;
        }
    }
    None
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} <number_of_bits> <prime_type>", program);
    eprintln!("Prime types: prime, safe, germain, mersenne");
}

fn main() {
    let start = Instant::now();
    let args: Vec<String> = env::args().collect();
    let small_prime_limit = 10_000;

    if args.len() < 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    // Parse number_of_bits
    let bits: usize = match args[1].parse() {
        Ok(value) => value,
        Err(_) => {
            eprintln!("Error: '{}' is not a valid number of bits.", args[1]);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    };

    // Parse prime_type
    let prime_type = args[2].to_lowercase();
    let valid_prime_types = vec!["prime", "safe", "germain", "mersenne"];

    if !valid_prime_types.contains(&prime_type.as_str()) {
        eprintln!("Error: '{}' is not a supported prime type.", args[2]);
        print_usage(&args[0]);
        std::process::exit(1);
    }

    println!("Generating a '{}' prime with {} bits.", prime_type, bits);

    let small_primes = small_prime_sieve(small_prime_limit);
    let mut rng = OsRng;
    let rounds = 40; // Increased for better security

    let hyper_prime = match prime_type.as_str() {
        "prime" => generate_hyper_prime(&mut rng, bits, &small_primes, rounds),
        "safe" => generate_safe_prime(&mut rng, bits, &small_primes, rounds),
        "germain" => generate_germain_prime(&mut rng, bits, &small_primes, rounds),
        "mersenne" => {
            // For Mersenne primes, bits correspond to the exponent
            // Mersenne primes have the form 2^n - 1, where n is prime
            // Note: Generating large Mersenne primes is computationally intensive
            match generate_mersenne_prime(&mut rng, bits, &small_primes, rounds) {
                Some(p) => p,
                None => {
                    eprintln!("Failed to generate a Mersenne prime after multiple attempts.");
                    std::process::exit(1);
                }
            }
        },
        _ => {
            // This should never happen due to earlier validation
            eprintln!("Unsupported prime type: {}", prime_type);
            std::process::exit(1);
        }
    };

    let duration = start.elapsed();

    println!("Generated {} prime ({} bits): {}", prime_type, bits, hyper_prime);
    println!("Time taken: {:?}", duration);
}

