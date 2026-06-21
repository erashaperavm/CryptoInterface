use zeroize::ZeroizeOnDrop;
use crate::core::Output;
use crate::error::CryptoError;
use crate::rng::CryptoRng;

/// 公钥加密算法 trait。
///
/// 实现者应提供固定长度的密文（`Ciphertext` 实现 `Output`），
/// 而明文长度可变（由实现决定最大长度）。解密时返回 `Vec<u8>`，
/// 调用者可根据需要零化内存。
pub trait Pke {
    /// 公钥类型，固定长度。
    type PublicKey: Output;

    /// 私钥类型，固定长度，并在 Drop 时自动零化。
    type PrivateKey: Output + ZeroizeOnDrop;

    /// 密文类型，固定长度（通常等于密钥模长或群元素大小）。
    type Ciphertext: Output;

    /// 生成密钥对，使用密码学安全的随机数生成器。
    fn generate_keypair(rng: &mut impl CryptoRng) -> (Self::PrivateKey, Self::PublicKey);

    /// 使用公钥加密明文，返回密文。
    ///
    /// # 参数
    /// - `pk`：接收者的公钥
    /// - `plaintext`：要加密的消息。长度必须不大于 `max_plaintext_len(pk)`。
    /// - `rng`：随机源，用于填充或随机化（如 OAEP 的随机数）。
    ///
    /// # 错误
    /// - 若 `plaintext` 过长，返回 `CryptoError::BufferTooSmall`。
    /// - 若内部发生错误（如 RNG 失败），返回 `CryptoError::InternalError`。
    fn encrypt(
        pk: &Self::PublicKey,
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Self::Ciphertext, CryptoError>;

    /// 使用私钥解密密文，返回明文。
    ///
    /// # 错误
    /// - 若密文格式无效或解密失败，返回 `CryptoError::DecryptionFailed`。
    /// - 若密钥不匹配，也可能返回上述错误。
    fn decrypt(
        sk: &Self::PrivateKey,
        ct: &Self::Ciphertext,
    ) -> Result<Vec<u8>, CryptoError>;

    /// 返回给定公钥下可加密的最大明文长度（字节数）。
    ///
    /// 不同密钥对（如不同模长）可能返回不同值。
    fn max_plaintext_len(pk: &Self::PublicKey) -> usize;
}