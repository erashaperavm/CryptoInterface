use zeroize::ZeroizeOnDrop;
use crate::core::Output;
use crate::error::CryptoError;
use crate::rng::CryptoRng;

pub trait Kem {
    type PublicKey: Output;
    type PrivateKey: Output + ZeroizeOnDrop;
    type Ciphertext: Output;
    type SharedSecret: Output + ZeroizeOnDrop;

    /// 生成密钥对，必须注入随机源
    fn generate_keypair(rng: &mut impl CryptoRng) -> (Self::PrivateKey, Self::PublicKey);

    fn encapsulate(pk: &Self::PublicKey, rng: &mut impl CryptoRng)
                   -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError>;

    fn decapsulate(sk: &Self::PrivateKey, ct: &Self::Ciphertext)
                   -> Result<Self::SharedSecret, CryptoError>;
}