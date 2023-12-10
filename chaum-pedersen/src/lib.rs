use once_cell::sync::Lazy;
use std::str::FromStr;

use num_bigint::BigInt;

pub mod interface;

pub struct Parameters {
    bit_size: u64,
    p: BigInt,
    q: BigInt,
    g: BigInt,
    h: BigInt,
}

static DEFAULT_PARAMS: Lazy<Parameters> = Lazy::new(|| Parameters {
    bit_size: 256,
    p: BigInt::from_str(
        "42765216643065397982265462252423826320512529931694366715111734768493812630447",
    )
    .unwrap(),
    q: BigInt::from_str(
        "21382608321532698991132731126211913160256264965847183357555867384246906315223",
    )
    .unwrap(),
    g: BigInt::from_str("4").unwrap(),
    h: BigInt::from_str("9").unwrap(),
});
