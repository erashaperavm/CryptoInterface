use zeroize::ZeroizeOnDrop;
use crate::core::{ConstantTimeEq, Output};
use crate::error::CryptoError;
use crate::rng::CryptoRng;

pub trait AeadEnc {
    type Key: Output + ZeroizeOnDrop;
    type Nonce: Output;
    type Tag: Output + ConstantTimeEq;

    /// 加密并返回 tag；ciphertext 缓冲区长度必须 >= plaintext.len()
    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        rng: &mut impl CryptoRng,       // 某些模式需要随机 nonce 或随机 padding
    ) -> Result<Self::Tag, CryptoError>;

    /// 解密前先验证 tag，验证失败不清空 plaintext
    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &Self::Tag,
        plaintext: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// 产生一个 nonce（使用 rng 填充默认长度）
    fn generate_nonce(rng: &mut impl CryptoRng) -> Self::Nonce;
}