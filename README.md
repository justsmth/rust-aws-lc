# aws-lc

[![crates.io](https://img.shields.io/crates/v/aws-lc.svg)](https://crates.io/crates/aws-lc)

AWS-LC bindings for the Rust programming language and TLS adapters for [tokio](https://github.com/tokio-rs/tokio)
and [hyper](https://github.com/hyperium/hyper) built on top of it.

[Documentation](https://docs.rs/aws-lc).

## Release Support

By default, the crate statically links with the latest AWS-LC master branch.

## Support for pre-built binaries

While this crate can build AWS-LC on its own, you may want to provide pre-built binaries instead.
To do so, specify the environment variable `AWS_LC_BIN_PATH` with the path to the binaries.

You can also provide specific headers by setting `AWS_LC_INCLUDE_PATH`.

_Notes_: The crate will look for headers in the `$AWS_LC_INCLUDE_PATH` folder, make sure to place your headers there.

_Warning_: When providing a different version of AWS-LC make sure to use a compatible one, the crate relies on the presence of certain functions.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [boring](https://github.com/cloudflare/boring), which is a fork of [rust-openssl](https://github.com/sfackler/rust-openssl).
