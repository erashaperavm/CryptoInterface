use zeroize::ZeroizeOnDrop;
use crate::core::Output;
use crate::error::CryptoError;

pub trait Hkdf {
    type Prk: Output + ZeroizeOnDrop;       // 伪随机密钥
    type Okm: Output;                       // 输出密钥材料

    fn extract(salt: &[u8], ikm: &[u8]) -> Self::Prk;
    fn expand(prk: &Self::Prk, info: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
}