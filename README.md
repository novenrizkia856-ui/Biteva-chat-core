# Bitevachat

Decentralized peer-to-peer chat system built in Rust. Every user holds a local cryptographic wallet (BIP39 mnemonic → Ed25519 keypair). Messages are end-to-end encrypted with ephemeral X25519 ECDH and transported over libp2p. No central server — nodes communicate directly via Kademlia DHT discovery and QUIC transport.

## Architecture

Bitevachat is a **Cargo workspace monorepo** with modular crates. Each subsystem is isolated into its own crate with a clean dependency graph and zero circular dependencies.

All shared types live exclusively in `bitevachat-types`.

### Crate Dependency Graph

```
bitevachat-types          (core shared types, zero external heavy deps)
  └─► bitevachat-crypto   (Ed25519, X25519, XChaCha20, SHA3-256, Argon2id, BIP39)
       ├─► bitevachat-wallet   (wallet creation, encryption, backup, key rotation)
       └─► bitevachat-protocol (canonical CBOR, message signing, E2E encryption)
            └─► bitevachat-storage  (encrypted sled DB, message store, pending queue)
                 └─► bitevachat-network (libp2p, Kademlia, gossipsub, QUIC, NAT traversal)
                      └─► bitevachat-node [bin] (event loop, integrates all components)
                           └─► bitevachat-rpc (gRPC local server via tonic)
                                ├─► bitevachat-cli [bin] (command-line client)
                                └─► bitevachat-gui [bin] (desktop GUI via egui/Tauri)
```

### Crate Roles

| Crate | Type | Purpose |
|---|---|---|
| `bitevachat-types` | lib | Address, MessageId, NodeId, Timestamp, errors, config |
| `bitevachat-crypto` | lib | All cryptographic operations (signing, ECDH, AEAD, KDF, BIP39) |
| `bitevachat-wallet` | lib | Wallet lifecycle: create, lock, unlock, backup, rotate |
| `bitevachat-protocol` | lib | Message format, canonical CBOR, signing, E2E encryption |
| `bitevachat-storage` | lib | Encrypted database layer, message store, pending queue |
| `bitevachat-network` | lib | libp2p transport, peer discovery, message routing |
| `bitevachat-rpc` | lib | gRPC server for UI and external integration |
| `bitevachat-node` | bin | Node runtime: event loop, component orchestration |
| `bitevachat-cli` | bin | Command-line interface client |
| `bitevachat-gui` | bin | Desktop graphical interface |

## Build

```bash
# Check all crates compile
cargo check --workspace

# Build all crates (debug)
cargo build --workspace

# Build release binaries
cargo build --workspace --release
```

## Test

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p bitevachat-types
```

## Lint

```bash
# Format check
cargo fmt --all -- --check

# Clippy
cargo clippy --workspace --all-targets -- -D warnings
```

## Project Structure

```
bitevachat/
├── Cargo.toml                 # Workspace root
├── rust-toolchain.toml        # Pinned stable toolchain
├── README.md
├── .cargo/
│   └── config.toml            # Build optimizations
├── .github/
│   └── workflows/
│       └── ci.yml             # CI: check, fmt, clippy, test
└── crates/
    ├── bitevachat-types/      # Core shared types
    ├── bitevachat-crypto/     # Cryptographic primitives
    ├── bitevachat-wallet/     # Wallet management
    ├── bitevachat-storage/    # Encrypted storage engine
    ├── bitevachat-protocol/   # Message protocol & E2E
    ├── bitevachat-network/    # P2P networking (libp2p)
    ├── bitevachat-rpc/        # Local gRPC server
    ├── bitevachat-node/       # Node binary (orchestrator)
    ├── bitevachat-cli/        # CLI binary
    └── bitevachat-gui/        # GUI binary
```

## Design Principles

- All shared types in `bitevachat-types` only — no cross-crate type leakage
- No circular dependencies
- No `unwrap()`, no `todo!()`, no `panic!()` without justification
- All data at rest encrypted with XChaCha20-Poly1305
- All messages canonically serialized (sorted-key CBOR) before signing
- Production-grade from day one
