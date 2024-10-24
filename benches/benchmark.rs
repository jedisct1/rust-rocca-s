use aegis::aegis128l::Aegis128L;
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
use aegis::{aegis128x2::Aegis128X2, aegis128x4::Aegis128X4};
use aes_gcm::{aead::AeadInPlace as _, aead::KeyInit as _, Aes128Gcm, Aes256Gcm};
use benchmark_simple::*;
use chacha20poly1305::ChaCha20Poly1305;
use rocca::Rocca;

fn test_aes256gcm(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes256Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_aes128gcm(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&[0u8; 16]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
fn test_aes128gcm_boringssl(m: &mut [u8]) {
    use boring::symm;
    use symm::Cipher;

    let cipher = Cipher::aes_128_gcm();
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let _ = symm::encrypt_aead(cipher, &key, Some(&nonce), &[], m, &mut tag).unwrap();
}

fn test_aegis128l(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::<32>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
fn test_aegis128x2(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X2::<32>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
fn test_aegis128x4(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X4::<32>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_rocca_s(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let state = Rocca::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_chacha20poly1305(m: &mut [u8]) {
    let key = chacha20poly1305::Key::from_slice(&[0u8; 32]);
    let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]);
    let state = ChaCha20Poly1305::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 10_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!(
        "aes256-gcm (rust-crypto) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128gcm(&mut m));
    println!(
        "aes128-gcm (rust-crypto) : {}",
        res.throughput(m.len() as _)
    );

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    {
        let res = bench.run(options, || test_aes128gcm_boringssl(&mut m));
        println!(
            "aes128-gcm (boringssl)   : {}",
            res.throughput(m.len() as _)
        );
    }

    let res = bench.run(options, || test_chacha20poly1305(&mut m));
    println!(
        "chacha20-poly1305        : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128l(&mut m));
    println!(
        "aegis128l                : {}",
        res.throughput(m.len() as _)
    );

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    {
        let res = bench.run(options, || test_aegis128x2(&mut m));
        println!(
            "aegis128x2               : {}",
            res.throughput(m.len() as _)
        );
    }

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    {
        let res = bench.run(options, || test_aegis128x4(&mut m));
        println!(
            "aegis128x4               : {}",
            res.throughput(m.len() as _)
        );
    }

    let res = bench.run(options, || test_rocca_s(&mut m));
    println!(
        "rocca-s                  : {}",
        res.throughput(m.len() as _)
    );
}
