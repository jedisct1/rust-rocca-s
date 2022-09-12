#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
mod aes_crate;
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
use aes_crate::AesBlock;

#[cfg(all(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
mod aes_ni;
#[cfg(all(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
use aes_ni::AesBlock;

use core::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidTag,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Invalid tag"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

mod rocca {
    use crate::AesBlock;
    pub use crate::Error;

    /// ROCCA authentication tag
    pub type Tag = [u8; 32];

    /// ROCCA key
    pub type Key = [u8; 32];

    /// ROCCA nonce
    pub type Nonce = [u8; 16];

    #[repr(transparent)]
    #[derive(Debug, Clone, Copy)]
    struct State {
        blocks: [AesBlock; 7],
    }

    const ROUNDS: usize = 16;

    impl State {
        fn update(&mut self, x0: AesBlock, x1: AesBlock) {
            let blocks = &mut self.blocks;
            let next: [AesBlock; 7] = [
                blocks[6].xor(blocks[1]),
                blocks[0].round(x0),
                blocks[1].round(blocks[0]),
                blocks[2].round(blocks[6]),
                blocks[3].round(x1),
                blocks[4].round(blocks[3]),
                blocks[5].round(blocks[4]),
            ];
            self.blocks = next;
        }

        pub fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
            let z0 = AesBlock::from_bytes(&[
                205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66,
            ]);
            let z1 = AesBlock::from_bytes(&[
                188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181,
            ]);
            let k0 = AesBlock::from_bytes(&key[0..16]);
            let k1 = AesBlock::from_bytes(&key[16..32]);
            let zero = AesBlock::from_bytes(&[0; 16]);
            let nonce_block = AesBlock::from_bytes(nonce);

            let blocks: [AesBlock; 7] = [k1, nonce_block, z0, k0, z1, nonce_block.xor(k1), zero];
            let mut state = State { blocks };
            for _ in 0..ROUNDS {
                state.update(z0, z1);
            }
            state
        }

        fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let msg0 = AesBlock::from_bytes(&src[0..16]);
            let msg1 = AesBlock::from_bytes(&src[16..32]);
            let tmp0 = blocks[3].xor(blocks[5]).round(blocks[0]).xor(msg0);
            let tmp1 = blocks[4].xor(blocks[6]).round(blocks[2]).xor(msg1);
            dst[..16].copy_from_slice(&tmp0.as_bytes());
            dst[16..32].copy_from_slice(&tmp1.as_bytes());
            self.update(msg0, msg1);
        }

        fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let c0 = AesBlock::from_bytes(&src[0..16]);
            let c1 = AesBlock::from_bytes(&src[16..32]);
            let msg0 = blocks[3].xor(blocks[5]).round(blocks[0]).xor(c0);
            let msg1 = blocks[4].xor(blocks[6]).round(blocks[2]).xor(c1);
            dst[..16].copy_from_slice(&msg0.as_bytes());
            dst[16..32].copy_from_slice(&msg1.as_bytes());
            self.update(msg0, msg1);
        }

        fn dec_partial(&mut self, dst: &mut [u8], src: &[u8; 32]) {
            let blocks = &self.blocks;
            let c0 = AesBlock::from_bytes(&src[0..16]);
            let c1 = AesBlock::from_bytes(&src[16..32]);
            let msg0 = blocks[3].xor(blocks[5]).round(blocks[0]).xor(c0);
            let msg1 = blocks[4].xor(blocks[6]).round(blocks[2]).xor(c1);
            let mut padded = [0u8; 32];
            padded[..16].copy_from_slice(&msg0.as_bytes());
            padded[16..32].copy_from_slice(&msg1.as_bytes());
            padded[dst.len()..].fill(0);
            dst.copy_from_slice(&padded[..dst.len()]);
            self.update(
                AesBlock::from_bytes(&padded[0..16]),
                AesBlock::from_bytes(&padded[16..32]),
            );
        }

        fn mac(&mut self, adlen: usize, mlen: usize) -> Tag {
            let adlen_bytes = (adlen as u128 * 8).to_le_bytes();
            let mlen_bytes = (mlen as u128 * 8).to_le_bytes();
            let adlen_block = AesBlock::from_bytes(&adlen_bytes);
            let mlen_block = AesBlock::from_bytes(&mlen_bytes);
            for _ in 0..ROUNDS {
                self.update(adlen_block, mlen_block);
            }
            let blocks = &self.blocks;
            let tmp0 = blocks[0].xor(blocks[1]).xor(blocks[2]).xor(blocks[3]);
            let tmp1 = blocks[4].xor(blocks[5]).xor(blocks[6]);
            let mut tag = [0u8; 32];
            tag[..16].copy_from_slice(&tmp0.as_bytes());
            tag[16..32].copy_from_slice(&tmp1.as_bytes());
            tag
        }
    }

    #[repr(transparent)]
    pub struct Rocca(State);

    impl Rocca {
        /// Create a new AEAD instance.
        /// `key` and `nonce` must be 16 bytes long.
        pub fn new(nonce: &Nonce, key: &Key) -> Self {
            Rocca(State::new(key, nonce))
        }

        /// Encrypts a message using ROCCA
        /// # Arguments
        /// * `m` - Message
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        #[cfg(feature = "std")]
        pub fn encrypt(mut self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag) {
            let state = &mut self.0;
            let mlen = m.len();
            let adlen = ad.len();
            let mut c = Vec::with_capacity(mlen);
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= mlen {
                src.copy_from_slice(&m[i..][..32]);
                state.enc(&mut dst, &src);
                c.extend_from_slice(&dst);
                i += 32;
            }
            if mlen % 32 != 0 {
                src.fill(0);
                src[..mlen % 32].copy_from_slice(&m[i..]);
                state.enc(&mut dst, &src);
                c.extend_from_slice(&dst[..mlen % 32]);
            }
            let tag = state.mac(adlen, mlen);
            (c, tag)
        }

        /// Encrypts a message in-place using ROCCA
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `ad` - Associated data
        /// # Returns
        /// Encrypted message and authentication tag.
        pub fn encrypt_in_place(mut self, mc: &mut [u8], ad: &[u8]) -> Tag {
            let state = &mut self.0;
            let mclen = mc.len();
            let adlen = ad.len();
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= mclen {
                src.copy_from_slice(&mc[i..][..32]);
                state.enc(&mut dst, &src);
                mc[i..][..32].copy_from_slice(&dst);
                i += 32;
            }
            if mclen % 32 != 0 {
                src.fill(0);
                src[..mclen % 32].copy_from_slice(&mc[i..]);
                state.enc(&mut dst, &src);
                mc[i..].copy_from_slice(&dst[..mclen % 32]);
            }

            state.mac(adlen, mclen)
        }

        /// Decrypts a message using ROCCA
        /// # Arguments
        /// * `c` - Ciphertext
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        /// # Returns
        /// Decrypted message.
        #[cfg(feature = "std")]
        pub fn decrypt(mut self, c: &[u8], tag: &Tag, ad: &[u8]) -> Result<Vec<u8>, Error> {
            let state = &mut self.0;
            let clen = c.len();
            let adlen = ad.len();
            let mut m = Vec::with_capacity(clen);
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= clen {
                src.copy_from_slice(&c[i..][..32]);
                state.dec(&mut dst, &src);
                m.extend_from_slice(&dst);
                i += 32;
            }
            if clen % 32 != 0 {
                src.fill(0);
                src[..clen % 32].copy_from_slice(&c[i..]);
                state.dec_partial(&mut dst[..clen % 32], &src);
                m.extend_from_slice(&dst[..clen % 32]);
            }
            let tag2 = state.mac(adlen, clen);
            let mut acc = 0;
            for (a, b) in tag.iter().zip(tag2.iter()) {
                acc |= a ^ b;
            }
            if acc != 0 {
                m.fill(0xaa);
                return Err(Error::InvalidTag);
            }
            Ok(m)
        }

        /// Decrypts a message in-place using ROCCA
        /// # Arguments
        /// * `mc` - Input and output buffer
        /// * `tag` - Authentication tag
        /// * `ad` - Associated data
        pub fn decrypt_in_place(
            mut self,
            mc: &mut [u8],
            tag: &Tag,
            ad: &[u8],
        ) -> Result<(), Error> {
            let state = &mut self.0;
            let mclen = mc.len();
            let adlen = ad.len();
            let mut src = [0u8; 32];
            let mut dst = [0u8; 32];
            let mut i = 0;
            while i + 32 <= adlen {
                src.copy_from_slice(&ad[i..][..32]);
                state.enc(&mut dst, &src);
                i += 32;
            }
            if adlen % 32 != 0 {
                src.fill(0);
                src[..adlen % 32].copy_from_slice(&ad[i..]);
                state.enc(&mut dst, &src);
            }
            i = 0;
            while i + 32 <= mclen {
                src.copy_from_slice(&mc[i..][..32]);
                state.dec(&mut dst, &src);
                mc[i..][..32].copy_from_slice(&dst);
                i += 32;
            }
            if mclen % 32 != 0 {
                src.fill(0);
                src[..mclen % 32].copy_from_slice(&mc[i..]);
                state.dec_partial(&mut dst[..mclen % 32], &src);
                mc[i..].copy_from_slice(&dst[..mclen % 32]);
            }
            let tag2 = state.mac(adlen, mclen);
            let mut acc = 0;
            for (a, b) in tag.iter().zip(tag2.iter()) {
                acc |= a ^ b;
            }
            if acc != 0 {
                mc.fill(0xaa);
                return Err(Error::InvalidTag);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rocca::Rocca;

    use ct_codecs::{Decoder, Hex};

    #[test]
    #[cfg(feature = "std")]
    fn test_rocca() {
        let m = [0u8; 64];
        let ad = [0u8; 32];
        let key = [0u8; 32];
        let nonce = [0u8; 16];

        let (c, tag) = Rocca::new(&nonce, &key).encrypt(&m, &ad);
        let expected_c = Hex::decode_to_vec("9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb", None).unwrap();
        let expected_tag = Hex::decode_to_vec(
            "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386",
            None,
        )
        .unwrap();
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag[..tag.len()]);

        let m2 = Rocca::new(&nonce, &key).decrypt(&c, &tag, &ad).unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_rocca_small() {
        let m = [0u8; 6];
        let ad = [0u8; 32];
        let key = [0u8; 32];
        let nonce = [0u8; 16];

        let (c, tag) = Rocca::new(&nonce, &key).encrypt(&m, &ad);
        let m2 = Rocca::new(&nonce, &key).decrypt(&c, &tag, &ad).unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_rocca_in_place() {
        let m = [0u8; 64];
        let ad = [0u8; 32];
        let key = [0u8; 32];
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Rocca::new(&nonce, &key).encrypt_in_place(&mut mc, &ad);
        let expected_mc = Hex::decode_to_vec("9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb", None).unwrap();
        let expected_tag = Hex::decode_to_vec(
            "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386",
            None,
        )
        .unwrap();
        assert_eq!(mc, expected_mc);
        assert_eq!(tag, expected_tag[..tag.len()]);

        Rocca::new(&nonce, &key)
            .decrypt_in_place(&mut mc, &tag, &ad)
            .unwrap();
        assert_eq!(mc, &m);
    }

    #[test]
    fn test_rocca_in_place_small() {
        let m = [0u8; 6];
        let ad = [0u8; 32];
        let key = [0u8; 32];
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Rocca::new(&nonce, &key).encrypt_in_place(&mut mc, &ad);
        Rocca::new(&nonce, &key)
            .decrypt_in_place(&mut mc, &tag, &ad)
            .unwrap();
        assert_eq!(mc, &m);
    }
}

pub use self::rocca::*;
