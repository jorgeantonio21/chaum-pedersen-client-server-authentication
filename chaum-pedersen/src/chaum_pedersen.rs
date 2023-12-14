//! # Chaum-Pedersen Protocol Implementation
//!
//! This module provides an implementation of the Chaum-Pedersen cryptographic protocol.
//! It includes structures and methods for generating random values, committing to values,
//! solving challenges, and verifying the validity of responses in cryptographic operations.
//!
//! ## Usage
//!
//! To use this module, create an instance of the `ChaumPedersen` struct and utilize its methods
//! to perform cryptographic operations as per the Chaum-Pedersen protocol.
use anyhow::{anyhow, Result};
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use rand::{rngs::StdRng, SeedableRng};

use crate::{Parameters, DEFAULT_PARAMS};

pub type RandomValue = BigInt;
pub type Solution = BigInt;

pub struct ChaumPedersenExponents {
    pub(crate) r1: BigInt,
    pub(crate) r2: BigInt,
}

impl ChaumPedersenExponents {
    pub fn get_first_exponent(&self) -> &BigInt {
        &self.r1
    }

    pub fn get_second_exponent(&self) -> &BigInt {
        &self.r2
    }
}

/// Defines the interface for the Chaum-Pedersen protocol.
pub trait ChaumPedersenInterface {
    /// Generates a random value for cryptographic operations.
    fn generate_random(&self) -> RandomValue;

    /// Creates a commitment using a given value.
    ///
    /// # Arguments
    /// * `k`: The value to commit.
    ///
    /// # Returns
    /// A `ChaumPedersenExponents` instance containing the commitment exponentiation values.
    fn commit(&self, k: &BigInt) -> ChaumPedersenExponents;

    /// Solves a cryptographic challenge.
    ///
    /// # Arguments
    /// * `x`: A secret value.
    /// * `k`: The committed value.
    /// * `c`: The challenge value.
    ///
    /// # Returns
    /// The solution as a `Solution` type.
    fn solve_challenge(&self, x: &BigInt, k: &BigInt, c: &BigInt) -> Solution;

    /// Verifies the validity of a cryptographic operation.
    ///
    /// # Arguments
    /// * `y1`, `y2`: Committed values.
    /// * `r1`, `r2`: Response exponents.
    /// * `s`: The solution to the challenge.
    /// * `c`: The challenge value.
    ///
    /// # Returns
    /// A `Result` indicating success or an error message.
    fn verify(
        &self,
        y1: &BigInt,
        y2: &BigInt,
        r1: &BigInt,
        r2: &BigInt,
        s: &BigInt,
        c: &BigInt,
    ) -> Result<()>;
}

/// Main structure for the Chaum-Pedersen protocol operations.
pub struct ChaumPedersen {
    // Cryptographic parameters
    parameters: Parameters,
}

impl ChaumPedersen {
    #[allow(dead_code)]
    fn new(parameters: Parameters) -> Self {
        Self { parameters }
    }
}

impl Default for ChaumPedersen {
    fn default() -> Self {
        Self {
            parameters: Parameters {
                bit_size: DEFAULT_PARAMS.bit_size,
                p: DEFAULT_PARAMS.p.clone(),
                q: DEFAULT_PARAMS.q.clone(),
                g: DEFAULT_PARAMS.g.clone(),
                h: DEFAULT_PARAMS.h.clone(),
            },
        }
    }
}

impl ChaumPedersenInterface for ChaumPedersen {
    fn generate_random(&self) -> RandomValue {
        let mut rng = StdRng::from_entropy();
        BigInt::from_biguint(
            num_bigint::Sign::Plus,
            rng.gen_biguint(self.parameters.bit_size),
        )
    }

    fn commit(&self, k: &BigInt) -> ChaumPedersenExponents {
        ChaumPedersenExponents {
            r1: self.parameters.g.modpow(k, &self.parameters.p),
            r2: self.parameters.h.modpow(k, &self.parameters.p),
        }
    }

    fn solve_challenge(&self, x: &BigInt, k: &BigInt, c: &BigInt) -> Solution {
        // the solution `s` needs to be considered (mod q), as it is part of
        let mut s = (k - (c * x)) % &self.parameters.q;
        if s < 0.to_bigint().unwrap() {
            s += &self.parameters.q;
        }
        s
    }

    fn verify(
        &self,
        y1: &BigInt,
        y2: &BigInt,
        r1: &BigInt,
        r2: &BigInt,
        s: &BigInt,
        c: &BigInt,
    ) -> Result<()> {
        let true_r1 = (self.parameters.g.modpow(s, &self.parameters.p)
            * y1.modpow(c, &self.parameters.p))
            % &self.parameters.p;
        let true_r2 = (self.parameters.h.modpow(s, &self.parameters.p)
            * y2.modpow(c, &self.parameters.p))
            % &self.parameters.p;

        if (r1 != &true_r1) || (r2 != &true_r2) {
            return Err(anyhow!(
                "Failed to verify challenge, invalid authentication attempt"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaum_pedersen_algorithm_in_success_case() {
        let cp = ChaumPedersen::default();

        let client_secret = cp.generate_random();
        let y1 = &cp.parameters.g.modpow(&client_secret, &DEFAULT_PARAMS.p);
        let y2 = &cp.parameters.h.modpow(&client_secret, &DEFAULT_PARAMS.p);
        let k = cp.generate_random();
        let ChaumPedersenExponents { r1, r2 } = cp.commit(&k);
        let challenge = cp.generate_random();
        let solution = cp.solve_challenge(&client_secret, &k, &challenge);
        assert!(cp.verify(y1, y2, &r1, &r2, &solution, &challenge).is_ok());
    }

    #[test]
    fn test_chaum_pedersen_algorithm_if_mismatched_secret() {
        let cp = ChaumPedersen::default();

        let client_secret1 = cp.generate_random();
        let client_secret2 = cp.generate_random();
        let y1 = &cp.parameters.g.modpow(&client_secret1, &DEFAULT_PARAMS.p);
        let y2 = &cp.parameters.h.modpow(&client_secret2, &DEFAULT_PARAMS.p);
        let k = cp.generate_random();
        let ChaumPedersenExponents { r1, r2 } = cp.commit(&k);
        let challenge = cp.generate_random();
        let solution = cp.solve_challenge(&client_secret1, &k, &challenge);
        assert!(cp.verify(y1, y2, &r1, &r2, &solution, &challenge).is_err());
    }
}
