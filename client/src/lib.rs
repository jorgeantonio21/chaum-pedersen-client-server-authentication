use num_bigint::BigInt;
use zeroize::Zeroize;

pub mod client;

pub mod client_auth {
    tonic::include_proto!("zkp_auth");
}

#[doc(hidden)]
pub fn calculate_password_hash<T: ToString + Zeroize>(mut password: T) -> BigInt {
    let secret_bytes = blake3::hash(password.to_string().as_bytes());
    // zeroize pass
    password.zeroize();
    // blake3's `Hash` bytes representation is big endian
    let secret_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, secret_bytes.as_bytes());
    secret_bigint
}
