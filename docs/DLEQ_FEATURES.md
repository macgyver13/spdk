# DLEQ Implementation Features

This document explains how to switch between different DLEQ proof implementations in the SPDK project or projects using spdk-core.

## Overview

SPDK now integrates with [rust-dleq](https://github.com/macgyver13/rust-dleq) for BIP-374 DLEQ (Discrete Log Equality) proof generation and verification. The `rust-dleq` library provides two implementation options:

1. **`dleq-standalone`** (default): Pure Rust implementation using rust-secp256k1 for elliptic curve operations
   - Portable across all platforms
   - No external dependencies beyond Rust ecosystem
   - Suitable for most use cases

2. **`dleq-native`**: Direct FFI to libsecp256k1 (PR #1651)
   - Uses native C library for better performance
   - Requires secp256k1 git submodule
   - May offer performance benefits on certain workloads

## Architecture

### Default Build (native)

By default, SPDK uses the native libsecp256k1 implementation via `dleq-native` feature:

```bash
cd spdk
cargo build
cargo test
```

This is equivalent to:
```bash
cargo build --features dleq-native
```

### Building with rust (standalone)

```bash
# To build with standalone feature
cargo build --no-default-features --features dleq-standalone,async,parallel
```

**Note**: When using `--no-default-features`, you need to explicitly enable other features you want:
- `async`: Enable async APIs
- `parallel`: Enable CPU parallelization with rayon
- `sync`: For sync-only mode (mutually exclusive with `async`)

### Building spdk-core Only

If you're working directly with the `spdk-core` crate:

```bash
cd spdk-core

# Standalone (default)
cargo build

# Native
cargo build --no-default-features --features dleq-native
```

## Feature Comparison

| Feature | dleq-standalone | dleq-native |
|---------|-----------------|-------------|
| **Implementation** | Pure Rust + rust-secp256k1 | Direct FFI to libsecp256k1 |
| **Dependencies** | Rust ecosystem only | Requires C compiler, secp256k1 submodule |
| **Portability** | ✅ All platforms | ⚠️ Requires native build setup |
| **Performance** | Good | Potentially better |
| **Setup complexity** | Simple | Moderate (submodules, C toolchain) |
| **Default** | ✅ Yes | ❌ No |

## Testing

Run tests with specific feature:

```bash
# Test with native (default)
cargo test -p spdk-core

# Test with standalone
cargo test -p spdk-core --no-default-features --features dleq-standalone

# Test crypto module specifically
cargo test -p spdk-core --lib crypto::dleq
```

## Example Code

## Switching Features in Cargo.toml

If you're depending on `spdk-core` from another crate:

```toml
# Use default (standalone)
[dependencies]
spdk-core = { path = "../spdk/spdk-core" }

# native explicitly
[dependencies]
spdk-core = { path = "../spdk/spdk-core", default-features = true }

# Use standalone
[dependencies]
spdk-core = { path = "../spdk/spdk-core", default-features = false, features = ["dleq-standalone"] }
```

## Troubleshooting

### Error: "Cannot enable both 'standalone' and 'native' features"

Make sure you're not enabling both features simultaneously. Use `--no-default-features` when switching to `dleq-native`:

```bash
cargo build --no-default-features --features dleq-native,async,parallel
```

### Verification: Check Which Feature is Active

You can verify which feature is being used by examining the build output or by adding a test:

```bash
# Verbose build shows feature resolution
cargo build -vv 2>&1 | grep dleq
```