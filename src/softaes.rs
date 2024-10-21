use softaes::unprotected::{Block, SoftAes};

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct AesBlock(Block);

impl AesBlock {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> AesBlock {
        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(bytes);
        AesBlock(Block::from_bytes(&tmp))
    }

    #[inline]
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0.to_bytes()
    }

    #[inline]
    pub fn xor(&self, other: AesBlock) -> AesBlock {
        AesBlock(self.0.xor(&other.0))
    }

    #[inline]
    pub fn round(&self, rk: AesBlock) -> AesBlock {
        AesBlock(SoftAes::block_encrypt(&self.0, &rk.0))
    }
}
