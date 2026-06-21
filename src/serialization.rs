use crate::error::CryptoError;
use std::io::{Read, Write};

/// 可序列化与反序列化的类型。
///
/// 该 trait 提供了将类型转换为字节流（`serialize`）和从字节流恢复（`deserialize`）
/// 的基本能力。所有实现都应确保序列化格式是自描述的（或事先约定），
/// 并且能够处理潜在的格式错误（返回 `CryptoError`）。
///
/// 对于固定长度的类型（如实现了 `Output` 的类型），实现者可以自行保证
/// `to_bytes()` 返回的向量长度固定，但本 trait 不作强制。
pub trait Serializable: Sized {
    /// 将自身序列化并写入 `writer`。
    ///
    /// # 错误
    /// 若写入失败（如磁盘满）或序列化格式异常，返回 `CryptoError`。
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), CryptoError>;

    /// 从 `reader` 读取并反序列化为自身。
    ///
    /// # 错误
    /// 若读取失败、数据格式不正确或长度不匹配，返回 `CryptoError`。
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, CryptoError>;

    /// 将自身序列化为 `Vec<u8>`。
    ///
    /// 默认实现基于 `serialize`，将数据写入内存缓冲区。
    fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut vec = Vec::new();
        self.serialize(&mut vec)?;
        Ok(vec)
    }

    /// 从字节切片反序列化。
    ///
    /// 默认实现使用 `Cursor` 将切片包装为 `Read` 并调用 `deserialize`。
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cursor = std::io::Cursor::new(bytes);
        Self::deserialize(&mut cursor)
    }
}

/// 密钥对象的序列化扩展，包含类型标识和可选的元数据。
///
/// 此 trait 用于需要区分不同算法或密钥类型的存储场景。
/// 实现者应在序列化数据中嵌入版本或算法标识符，以便反序列化时正确选择类型。
pub trait KeySerializable: Serializable {
    /// 返回密钥类型/算法的标识符（如字符串或枚举整数）。
    ///
    /// 该标识符可用于在反序列化时验证密钥类型与预期是否一致。
    fn key_type_identifier(&self) -> &'static [u8];

    /// 返回与密钥关联的额外元数据（可选），如创建时间、用途等。
    ///
    /// 若不使用元数据，可返回空切片。
    fn metadata(&self) -> &[u8] {
        &[]
    }
}

/// 密钥对的序列化 trait（公钥 + 私钥捆绑）。
///
/// 用于存储或传输完整的密钥对，通常需要额外的加密保护。
pub trait KeyPairSerializable {
    /// 公钥类型。
    type PubKey: Serializable;
    /// 私钥类型（敏感）。
    type PrivKey: Serializable + crate::core::ZeroizeOnDrop;

    /// 将公钥序列化到 writer。
    fn serialize_public<W: Write>(&self, writer: &mut W) -> Result<(), CryptoError>;

    /// 将私钥序列化到 writer（通常应加密后再序列化）。
    fn serialize_private<W: Write>(&self, writer: &mut W) -> Result<(), CryptoError>;

    /// 从 reader 反序列化公钥。
    fn deserialize_public<R: Read>(reader: &mut R) -> Result<Self::PubKey, CryptoError>;

    /// 从 reader 反序列化私钥（通常需要先解密）。
    fn deserialize_private<R: Read>(reader: &mut R) -> Result<Self::PrivKey, CryptoError>;
}

/// 密钥标识符 trait，用于在存储中引用特定密钥。
///
/// 标识符可以是 UUID、指纹、或任意字节序列。
pub trait KeyIdentifier: AsRef<[u8]> + Sized {
    /// 从字节构造标识符，可校验长度或格式。
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}