# ROCCA-S for Rust

This is a Rust implementation of the [ROCCA-S: an efficient AES-based encryption scheme for beyond 5G](https://www.ietf.org/archive/id/draft-nakano-rocca-s-03.html) authenticated cipher, ported from
[the Zig implementation](https://github.com/jedisct1/zig-rocca).

ROCCA-S is has a 256 bit key size, a 128 bit nonce, processes 256 bit message blocks and outputs a 256 bit authentication tag.

# Cargo flags

- `std`: allow dynamic allocations

`std` is the default.

**IMPORTANT:** In order to get decent code on x86 and x86_64 CPUs, you should set
additional `rustc` flags prior to compiling that crate or a project using it:

```sh
export RUSTFLAGS="-Ctarget-feature=+aes,+sse4.1"
```

A benchmark can be run that way:

```sh
export RUSTFLAGS="-C target-cpu=native -Ctarget-feature=+aes,+pclmulqdq,+sse4.1"
cargo bench
```

# Benchmarks

Benchmarks take a 16384 bytes input block. Results are in bytes per second.

## Rust implementations

Crates:

- `aes-gcm`
- `chacha20poly1305`
- `aegis128l`
- `rocca`

Scaleway EPYC 7543 instance, `RUSTFLAGS` set.

| cipher                | speed    |
| --------------------- | -------- |
| aes256-gcm            | 1.18 G/s |
| aes128-gcm            | 1.24 G/s |
| chacha20-poly1305     | 1.62 G/s |
| aegis128l (pure rust) | 5.08 G/s |
| rocca-s               | 5.09 G/s |

WebAssembly (Wasmtime, Apple M1)

| cipher                   | speed      |
| ------------------------ | ---------- |
| aes256-gcm (rust-crypto) | 47.75 M/s  |
| aes128-gcm (rust-crypto) | 58.41 M/s  |
| chacha20-poly1305        | 158.37 M/s |
| aegis128l (protected)    | 528.98 M/s |
| rocca-s (unprotected)    | 615.84 M/s |