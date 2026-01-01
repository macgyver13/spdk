# Silent Payments Dev Kit

SPDK is a library that can be used to build silent payment wallets.
It builds on top of [rust-silentpayments](https://github.com/cygnet3/rust-silentpayments).

Whereas rust-silentpayments concerns itself with cryptography (it is essentially a wrapper around secp256k1 for some silent payments logic), SPDK can be used for more high-level operations that are required for wallets, such as scanning for payments from a chain backend, or creating and signing transactions.

SPDK is used as a backend for the silent payment wallet [Dana wallet](https://github.com/cygnet3/danawallet).

## Features

### DLEQ Proof Implementation

SPDK integrates with [rust-dleq](https://github.com/macgyver13/rust-dleq) for BIP-374 DLEQ proof generation and verification. You can choose between two implementations:

- **`dleq-standalone`** (default): Pure Rust implementation using rust-secp256k1
- **`dleq-native`**: Direct FFI to libsecp256k1 for better performance

See [DLEQ_FEATURES.md](docs/DLEQ_FEATURES.md) for detailed information about switching between implementations.

### Building

```bash
# Default build (dleq-standalone)
cargo build

# With native DLEQ implementation
cargo build --no-default-features --features dleq-native,async,parallel
```

### Development Workflows

This project includes a [`justfile`](justfile) with common development tasks. Install [just](https://github.com/casey/just) and run:

```bash
# Show available commands
just

# Common tasks
just check    # Check spdk-core
just build    # Build spdk-core
just test     # Run tests
just fmt      # Format code
just lint     # Run clippy

# DLEQ examples
just run-dleq               # Run with default features
just run-dleq-standalone    # Run with standalone implementation
```


