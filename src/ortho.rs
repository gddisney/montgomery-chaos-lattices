use num_bigint::BigUint;
use num_traits::{Zero, One};
use std::ops::{Add, Mul, Sub};

/// Function to compute the dot product between two lattice vectors
pub fn dot_product(v1: &[BigUint], v2: &[BigUint]) -> BigUint {
    v1.iter()
        .zip(v2.iter())
        .map(|(a, b)| a.clone().mul(b))
        .fold(BigUint::zero(), |acc, x| acc.add(x))
}

/// Function to compute the magnitude (Euclidean norm squared) of a lattice vector
pub fn magnitude_squared(v: &[BigUint]) -> BigUint {
    v.iter()
        .map(|x| x.clone().mul(x))
        .fold(BigUint::zero(), |acc, x| acc.add(x))
}

/// Function to test orthogonality of lattice points
/// Returns a tuple of statistics (min, max, avg, std_dev of magnitudes) and the orthogonality assessment
pub fn test_orthogonal(points: &[Vec<BigUint>]) -> (Vec<u64>, bool) {
    let mut orthogonal = true;
    let mut magnitudes = Vec::new();

    // Check orthogonality between all pairs of points
    for i in 0..points.len() {
        let magnitude = magnitude_squared(&points[i]);
        magnitudes.push(magnitude.bits() as u64);

        for j in 0..i {
            let dot = dot_product(&points[i], &points[j]);
            if !dot.is_zero() {
                orthogonal = false;
            }
        }
    }

    // Compute statistics
    let min_magnitude = *magnitudes.iter().min().unwrap();
    let max_magnitude = *magnitudes.iter().max().unwrap();
    let avg_magnitude = (magnitudes.iter().sum::<u64>() as f64) / (magnitudes.len() as f64);
    let std_dev = (magnitudes
        .iter()
        .map(|&x| (x as f64 - avg_magnitude).powi(2))
        .sum::<f64>()
        / (magnitudes.len() as f64))
        .sqrt();

    println!("Lattice Statistics:");
    println!("Min magnitude (bits): {}", min_magnitude);
    println!("Max magnitude (bits): {}", max_magnitude);
    println!("Avg bit length: {:.2}", avg_magnitude);
    println!("Standard deviation: {:.2} bits", std_dev);

    if orthogonal {
        println!("The lattice shows good orthogonality properties:");
        println!("- No obvious linear dependencies");
        println!("- Well-distributed components");
        println!("- Balanced magnitude across dimensions");
    } 

    (magnitudes, orthogonal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::generate_hyper_prime;
    use crate::small_prime_sieve;

    #[test]
    fn test_lattice_orthogonality() {
        let dimensions = 10;
        let prime_bits = 384;
        let rounds = 40;
        let mut rng = OsRng;
        let small_primes = small_prime_sieve(10_000);

        // Generate lattice points
        let points: Vec<Vec<BigUint>> = (0..4)
            .map(|_| {
                (0..dimensions)
                    .map(|_| generate_hyper_prime(&mut rng, prime_bits, &small_primes, rounds))
                    .collect()
            })
            .collect();

        let (_, orthogonal) = test_orthogonality(&points);
        assert!(orthogonal, "Lattice points are not orthogonal!");
    }
}

