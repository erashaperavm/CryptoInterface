use crate::core::{ConstantTimeEq, Output};

pub trait Digest {
    type Output: Output + ConstantTimeEq;   // 添加常量时间比较便于签名校验
    fn digest(data: &[u8]) -> Self::Output;
}

pub trait DigestState {
    type Output: Output + ConstantTimeEq;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;     // #[must_use] 由调用者负责
}