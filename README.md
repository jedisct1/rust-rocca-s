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