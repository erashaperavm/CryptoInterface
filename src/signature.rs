use zeroize::ZeroizeOnDrop;
use crate::core::{ConstantTimeEq, Output};
use crate::error::CryptoError;
use crate::rng::CryptoRng;

pub trait Signature {
    
    type PublicKey: Output;
    type PrivateKey: Output + ZeroizeOnDrop;
    type Sig: Output + ConstantTimeEq;

    fn generate_keypair(rng: &mut impl CryptoRng) -> (Self::PrivateKey, Self::PublicKey);

    fn sign(sk: &Self::PrivateKey, msg: &[u8], rng: &mut impl CryptoRng)
            -> Self::Sig;

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Sig)
              -> Result<(), CryptoError>;
}