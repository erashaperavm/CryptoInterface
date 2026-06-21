/// 任何密码学安全的随机数生成器
pub trait CryptoRng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}