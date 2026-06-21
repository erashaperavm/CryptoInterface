use crate::error::CryptoError;

/// 输出类型 trait：固定长度 + 序列化
pub trait Output: AsRef<[u8]> + Sized {
    const LEN: usize;

    /// 从字节切片构造；长度不匹配返回错误
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// 以固定长度字节返回
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// 固定长度字节数组（编译期保证长度）
// 注意：没有 derive(Default)，因为对于泛型 N 无法实现 Default
#[derive(Clone)]
pub struct FixedBytes<const N: usize>([u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// 创建全零的固定长度字节数组（代替 Default::default）
    #[inline]
    pub fn new_zeroed() -> Self {
        FixedBytes([0u8; N])
    }

    /// 从切片构造
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != N {
            Err(CryptoError::BufferTooSmall {
                needed: N,
                provided: bytes.len(),
            })
        } else {
            let mut arr = [0u8; N];
            arr.copy_from_slice(bytes);
            Ok(FixedBytes(arr))
        }
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for FixedBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Output for FixedBytes<N> {
    const LEN: usize = N;

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Self::from_bytes(bytes)
    }
}

/// 常量时间比较 trait，实现必须恒定时间
pub trait ConstantTimeEq {
    fn ct_eq(&self, other: &Self) -> bool;
}

/// 零化内存标记 trait
// 实现者应在自己的 Drop 实现中调用 as_mut().fill(0)
pub trait ZeroizeOnDrop: AsMut<[u8]> {}