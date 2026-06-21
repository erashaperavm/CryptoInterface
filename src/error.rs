/// 错误码枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTag,
    DecryptionFailed,
    VerificationFailed,
    BufferTooSmall { needed: usize, provided: usize },
    InternalError,
    UnsupportedAlgorithm,
}