use zeroize::ZeroizeOnDrop;
use crate::core::Output;
use crate::error::CryptoError;
use crate::rng::CryptoRng;

pub trait KeyAgreement {
    type PublicKey: Output;
    type PrivateKey: Output + ZeroizeOnDrop;
    type SharedSecret: Output + ZeroizeOnDrop;

    fn generate_keypair(rng: &mut impl CryptoRng) -> (Self::PrivateKey, Self::PublicKey);

    fn agree(sk: &Self::PrivateKey, pk: &Self::PublicKey)
             -> Result<Self::SharedSecret, CryptoError>;
}