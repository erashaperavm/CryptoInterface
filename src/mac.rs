use zeroize::ZeroizeOnDrop;
use crate::core::{ConstantTimeEq, Output};
use crate::error::CryptoError;

pub trait Mac {
    type Key: Output + ZeroizeOnDrop;
    type Tag: Output + ConstantTimeEq;

    fn compute(key: &Self::Key, data: &[u8]) -> Self::Tag;

    fn verify(key: &Self::Key, data: &[u8], tag: &Self::Tag) -> Result<(), CryptoError>;
}