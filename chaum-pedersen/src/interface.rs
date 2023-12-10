use anyhow::Result;
use num_bigint::BigInt;

pub type RandomValue = BigInt;
pub type Solution = BigInt;

pub struct ChaumPedersenCommitment {
    pub(crate) r1: BigInt,
    pub(crate) r2: BigInt,
}

pub trait ChaumPedersen {
    fn generate_random(&mut self) -> RandomValue;
    fn commit(&self, k: &BigInt) -> ChaumPedersenCommitment;
    fn solve_challenge(&self, x: &BigInt, k: &BigInt, c: &BigInt) -> Solution;
    fn verify(&self, y1: &BigInt, y2: &BigInt, s: &BigInt, c: &BigInt) -> Result<()>;
}
