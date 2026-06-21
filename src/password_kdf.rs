use crate::error::CryptoError;
use crate::rng::CryptoRng;

/// 专门为 Password KDF（如 Argon2、bcrypt、scrypt、PBKDF2）设计的 Trait
pub trait PasswordKdf {
    /// 算法特定的代价参数（包含迭代次数、内存大小、并行度等）。
    /// 例如：Argon2 的 `Params { m_cost, t_cost, p_cost, output_len }`
    type Params: Clone + core::fmt::Debug;

    /// 编码后的哈希字符串（用于存储和验证，如 `$argon2id$v=19$...`）。
    /// 通常为 UTF-8 字符串，但用 `AsRef<[u8]>` 更通用。
    type EncodedHash: AsRef<[u8]>;

    /// ------------------- 1. 原始密钥派生（适用于加密密钥生成） -------------------
    /// 将低熵密码（password）和盐（salt）派生出任意长度的密钥材料。
    /// 输出长度由 `out.len()` 决定，派生结果写入 `out` 缓冲区。
    ///
    /// # 安全注意
    /// - `salt` 应至少为 16 字节且对于同一密码唯一（推荐使用 `CryptoRng` 生成）。
    /// - 调用者应确保 `password` 在使用后尽快零化（例如使用 `Zeroizing<Vec<u8>>`）。
    /// - 若 `out` 长度不合法（例如超出算法支持的最大值），返回 `CryptoError::InvalidKeyLength`。
    fn derive_into(
        params: &Self::Params,
        password: &[u8],
        salt: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// ------------------- 2. 存储与验证（适用于用户密码校验） -------------------
    /// 对密码进行哈希处理，生成包含**随机盐**和**算法参数**的编码字符串。
    /// 该方法会使用 `rng` 生成安全的盐，并自动根据 `params` 执行哈希。
    ///
    /// 返回的 `EncodedHash` 可直接存储到数据库中。
    fn hash(
        params: &Self::Params,
        password: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Self::EncodedHash, CryptoError>;

    /// 验证密码是否匹配给定的编码哈希字符串。
    /// 若匹配返回 `Ok(())`，否则返回 `CryptoError::VerificationFailed`。
    ///
    /// 该实现必须使用**常量时间比较**来比对派生的哈希值，以抵御时序攻击。
    fn verify(
        encoded_hash: &Self::EncodedHash,
        password: &[u8],
    ) -> Result<(), CryptoError>;
}