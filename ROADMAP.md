# Bitevachat — 20 Tahapan Coding

**Decentralized Chat System Development Roadmap**
**Architecture: BIP39 Wallet + Ed25519 + E2E Encryption + libp2p P2P Network**

---

## Tahap 1: Project Scaffolding & Workspace Setup

**Tujuan:** Membangun fondasi workspace Rust multi-crate (Cargo workspace) dengan struktur modular yang mendukung seluruh subsystem Bitevachat. Semua crate didefinisikan sejak awal agar dependency graph jelas dan tidak ada circular dependency di kemudian hari.

**Deskripsi:** Inisialisasi Cargo workspace dengan layout monorepo. Setiap subsystem (crypto, wallet, network, storage, protocol, rpc, cli, gui) menjadi crate terpisah. Definisikan shared types di crate `bitevachat-types` (address, message ID, timestamp wrapper, error enum). Setup CI pipeline dasar (cargo check, cargo clippy, cargo test). Tambahkan `rust-toolchain.toml` untuk pin nightly/stable, dan `.cargo/config.toml` untuk build optimization.

**Yang dibuat:**

- `Cargo.toml` (workspace root) — definisi members: `crates/bitevachat-types`, `crates/bitevachat-crypto`, `crates/bitevachat-wallet`, `crates/bitevachat-storage`, `crates/bitevachat-protocol`, `crates/bitevachat-network`, `crates/bitevachat-rpc`, `crates/bitevachat-node`, `crates/bitevachat-cli`, `crates/bitevachat-gui`
- `crates/bitevachat-types/src/lib.rs` — `Address` (newtype `[u8; 32]`), `MessageId` (newtype `[u8; 32]`), `NodeId`, `Timestamp` (wrapper UTC ISO8601), `BitevachatError` enum, `Result<T>` type alias
- `crates/bitevachat-types/src/config.rs` — `AppConfig` struct dengan default values (pending_ttl: 5 days, db_retention: 1500, rate_limit: 10/min, pending_max: 500, nonce_cache: 10_000)
- `rust-toolchain.toml` — pin Rust edition 2021, toolchain version
- `.cargo/config.toml` — target-specific optimizations
- `.github/workflows/ci.yml` — basic CI: check, clippy, test, fmt
- `README.md` — project overview

**File yang diubah:** Tidak ada (semua baru)

---

## Tahap 2: Cryptographic Primitives Layer

**Tujuan:** Implementasi seluruh fungsi kriptografi dasar yang akan digunakan oleh semua crate lain — Ed25519 signing/verification, X25519 ECDH, XChaCha20-Poly1305 AEAD, SHA3-256 hashing, dan Argon2id KDF. Semua operasi di-wrap dalam API yang ergonomis dan type-safe.

**Deskripsi:** Crate `bitevachat-crypto` menjadi satu-satunya tempat operasi kriptografi. Gunakan `ring` atau `ed25519-dalek` + `x25519-dalek` untuk keypair operations, `chacha20poly1305` crate untuk AEAD, `sha3` crate untuk hashing, dan `argon2` crate untuk KDF. Setiap fungsi harus memiliki unit test dengan known-answer vectors (test vectors dari RFC/standard). Private keys di-handle dengan `zeroize` crate untuk secure memory cleanup.

**Yang dibuat:**

- `crates/bitevachat-crypto/Cargo.toml` — dependencies: `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `sha3`, `argon2`, `rand`, `zeroize`
- `crates/bitevachat-crypto/src/lib.rs` — module re-exports
- `crates/bitevachat-crypto/src/signing.rs` — `Keypair` struct (wraps Ed25519), `sign(message: &[u8]) -> Signature`, `verify(pubkey, message, signature) -> Result<()>`, `pubkey_to_address(pubkey) -> Address` (SHA3-256 + checksum)
- `crates/bitevachat-crypto/src/ecdh.rs` — `EphemeralSecret`, `ecdh_derive_shared(our_secret: &X25519Secret, their_public: &X25519Public) -> SharedSecret`, `ed25519_to_x25519()` conversion functions
- `crates/bitevachat-crypto/src/aead.rs` — `encrypt_xchacha20(key, nonce, plaintext, aad) -> CiphertextWithTag`, `decrypt_xchacha20(key, nonce, ciphertext, aad) -> Plaintext`, nonce generation (96-bit random)
- `crates/bitevachat-crypto/src/hash.rs` — `sha3_256(data) -> [u8; 32]`, `compute_message_id(sender, timestamp, nonce) -> MessageId`
- `crates/bitevachat-crypto/src/kdf.rs` — `argon2id_derive_key(password, salt, params) -> DerivedKey`, `Argon2Params` struct (configurable m_cost, t_cost, p_cost)
- `crates/bitevachat-crypto/src/checksum.rs` — `append_checksum(hash) -> AddressWithChecksum`, `verify_checksum(address_bytes) -> Result<()>`, Bech32 encoding/decoding for address display
- `crates/bitevachat-crypto/tests/` — test vectors untuk setiap modul

**File yang diubah:** `crates/bitevachat-types/src/lib.rs` (tambah trait `Signable`, `Verifiable`)

---

## Tahap 3: BIP39 Mnemonic & HD Key Derivation

**Tujuan:** Implementasi BIP39 mnemonic generation (24 kata) dan deterministic key derivation dari mnemonic → master seed → Ed25519 keypair, lengkap dengan validasi wordlist dan checksum mnemonic.

**Deskripsi:** Generate 256-bit entropy → 24-word BIP39 mnemonic menggunakan English wordlist standard. Dari mnemonic + optional passphrase, derive master seed via PBKDF2-HMAC-SHA512 (per BIP39 spec). Dari master seed, derive Ed25519 keypair menggunakan SLIP-0010 (Ed25519 HD derivation) atau simple HKDF. Sediakan API untuk: generate new mnemonic, restore from mnemonic, validate mnemonic, derive keypair from seed. Semua sensitive data (seed, entropy) di-zeroize setelah digunakan.

**Yang dibuat:**

- `crates/bitevachat-crypto/src/mnemonic.rs` — `generate_mnemonic() -> Mnemonic` (24 words), `validate_mnemonic(words: &str) -> Result<()>`, `mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Seed` (PBKDF2-HMAC-SHA512, 2048 rounds per BIP39)
- `crates/bitevachat-crypto/src/hd_derive.rs` — `derive_ed25519_keypair(seed: &Seed, path: &str) -> Keypair` (SLIP-0010 compatible), `derive_x25519_keypair(ed25519_keypair) -> X25519Keypair`
- `crates/bitevachat-crypto/src/wordlist.rs` — embedded BIP39 English 2048-word list, binary search lookup, `word_to_index()`, `index_to_word()`
- `crates/bitevachat-crypto/tests/bip39_vectors.rs` — test vectors dari BIP39 reference (known mnemonic → known seed → known keypair)

**File yang diubah:** `crates/bitevachat-crypto/src/lib.rs` (tambah module declarations), `crates/bitevachat-crypto/Cargo.toml` (tambah `hmac`, `sha2`, `pbkdf2` dependencies)

---

## Tahap 4: Wallet Creation, Encryption & Storage

**Tujuan:** Membangun wallet system lengkap — create wallet dari mnemonic, encrypt private key ke disk sebagai `wallet.dat`, decrypt saat unlock, support passphrase protection, dan backup/restore flow.

**Deskripsi:** `wallet.dat` berisi encrypted private key + metadata (address, creation time, version, Argon2 params, salt, nonce). Format: header (magic bytes + version) → Argon2id salt → nonce → encrypted payload (XChaCha20-Poly1305). Wallet manager handle lifecycle: create, open (decrypt), lock (zeroize in-memory key), unlock, backup (export mnemonic — tampilkan sekali, wajibkan konfirmasi), dan import (restore dari mnemonic). Sediakan juga key rotation: generate new keypair, sign migration statement dengan old key, re-encrypt.

**Yang dibuat:**

- `crates/bitevachat-wallet/Cargo.toml` — depends on `bitevachat-crypto`, `bitevachat-types`, `serde`, `bincode`
- `crates/bitevachat-wallet/src/lib.rs` — re-exports
- `crates/bitevachat-wallet/src/wallet.rs` — `Wallet` struct (address, public_key, encrypted_private_key status), `WalletState` enum (Locked, Unlocked), `create_wallet(mnemonic, passphrase) -> Wallet`, `unlock(passphrase) -> UnlockedWallet`, `lock()`, `get_keypair() -> &Keypair` (only when unlocked)
- `crates/bitevachat-wallet/src/wallet_file.rs` — `WalletFileHeader` struct (magic: `BTVC`, version: u8, argon2_params, salt: [u8;32], nonce: [u8;24]), `write_wallet_file(path, header, encrypted_payload)`, `read_wallet_file(path) -> (Header, EncryptedPayload)`, file format serialization/deserialization
- `crates/bitevachat-wallet/src/backup.rs` — `BackupFlow` (state machine: ShowMnemonic → ConfirmMnemonic → Complete), `export_backup(wallet, passphrase) -> BackupFile`, `import_from_mnemonic(words, passphrase) -> Wallet`
- `crates/bitevachat-wallet/src/rotation.rs` — `rotate_key(old_wallet, new_mnemonic) -> (NewWallet, MigrationStatement)`, `MigrationStatement` struct (old_address, new_address, timestamp, signature_by_old_key)
- `crates/bitevachat-wallet/tests/` — test create/lock/unlock cycle, backup/restore round-trip, invalid passphrase rejection, wallet file corruption detection

**File yang diubah:** Workspace `Cargo.toml` (sudah ada member), `crates/bitevachat-types/src/lib.rs` (tambah `WalletStatus` enum jika diperlukan)

---

## Tahap 5: Message Protocol & Canonical Serialization

**Tujuan:** Definisikan format pesan canonical yang deterministik (sorted-key CBOR), message ID generation, signing, dan verification pipeline. Ini menjadi kontrak data yang digunakan seluruh sistem.

**Deskripsi:** Pesan menggunakan CBOR dengan sorted keys (canonical CBOR per RFC 8949 deterministic encoding). Setiap pesan memiliki field: sender (address), recipient (address), payload_type (enum: Text, File, System), payload_ciphertext (bytes), node_id, nonce (96-bit), timestamp (ISO8601 UTC), message_id (SHA3-256 dari sender||timestamp||nonce). Signature Ed25519 menandatangani seluruh serialized CBOR payload (termasuk ciphertext, timestamp, nonce, message_id). Verification pipeline: deserialize → verify signature → check timestamp skew → check nonce uniqueness → baru decrypt.

**Yang dibuat:**

- `crates/bitevachat-protocol/Cargo.toml` — depends on `bitevachat-types`, `bitevachat-crypto`, `ciborium` (CBOR), `serde`, `chrono`
- `crates/bitevachat-protocol/src/lib.rs` — re-exports
- `crates/bitevachat-protocol/src/message.rs` — `Message` struct (semua field), `PayloadType` enum, `MessageEnvelope` (Message + Signature), implementasi `Serialize`/`Deserialize` dengan CBOR sorted keys
- `crates/bitevachat-protocol/src/canonical.rs` — `to_canonical_cbor(message: &Message) -> Vec<u8>` (deterministic), `from_canonical_cbor(bytes: &[u8]) -> Result<Message>`, unit test: serialize → deserialize → re-serialize harus menghasilkan bytes identik
- `crates/bitevachat-protocol/src/signing.rs` — `sign_message(keypair: &Keypair, message: &Message) -> MessageEnvelope`, `verify_envelope(envelope: &MessageEnvelope) -> Result<VerifiedMessage>`
- `crates/bitevachat-protocol/src/validation.rs` — `validate_timestamp(ts: &Timestamp, max_skew: Duration) -> Result<()>`, `validate_message_id(msg: &Message) -> Result<()>` (recompute dan compare), schema validation (semua required fields present, field types correct)
- `crates/bitevachat-protocol/src/nonce.rs` — `NonceCache` struct (LRU cache, configurable size default 10k), `check_and_insert(sender: &Address, nonce: &[u8]) -> Result<()>` (reject duplicate)
- `crates/bitevachat-protocol/tests/` — canonical serialization determinism test, signature round-trip, replay rejection, timestamp skew rejection, malformed message rejection

**File yang diubah:** `crates/bitevachat-types/src/lib.rs` (tambah `PayloadType` enum, `Nonce` type)

---

## Tahap 6: End-to-End Encryption (Ephemeral X25519)

**Tujuan:** Implementasi E2E encryption layer menggunakan ephemeral X25519 ECDH per message, yang memberikan forward secrecy ringan. Setiap pesan menghasilkan shared secret baru.

**Deskripsi:** Sender: (1) generate ephemeral X25519 keypair, (2) ECDH dengan recipient's X25519 public key (derived dari Ed25519 pubkey), (3) derive symmetric key dari shared secret via HKDF-SHA256, (4) encrypt plaintext dengan XChaCha20-Poly1305, (5) sertakan ephemeral public key dalam payload. Recipient: (1) extract ephemeral pubkey, (2) ECDH dengan own X25519 private key, (3) derive same symmetric key, (4) decrypt. Untuk group chat (tahap nanti), gunakan group symmetric key yang di-wrap ke setiap member.

**Yang dibuat:**

- `crates/bitevachat-protocol/src/e2e.rs` — `encrypt_message(sender_keypair, recipient_pubkey, plaintext) -> EncryptedPayload`, `decrypt_message(recipient_keypair, sender_pubkey, encrypted: &EncryptedPayload) -> Plaintext`, `EncryptedPayload` struct (ephemeral_pubkey, nonce, ciphertext, tag)
- `crates/bitevachat-protocol/src/session.rs` — `SessionKey` struct (derived symmetric key + metadata), `derive_session_key(shared_secret, context_info) -> SessionKey` via HKDF-SHA256
- `crates/bitevachat-crypto/src/hkdf.rs` — `hkdf_sha256(ikm, salt, info, output_len) -> DerivedKey`
- `crates/bitevachat-protocol/tests/e2e_tests.rs` — encrypt/decrypt round-trip antara dua keypair, wrong key rejection, tampered ciphertext rejection, ephemeral key uniqueness per message

**File yang diubah:** `crates/bitevachat-crypto/Cargo.toml` (tambah `hkdf` dependency), `crates/bitevachat-crypto/src/lib.rs` (tambah hkdf module), `crates/bitevachat-protocol/src/lib.rs` (tambah e2e, session modules)

---

## Tahap 7: Storage Engine — Encrypted Database Layer

**Tujuan:** Membangun storage engine terenkripsi untuk message store, conversation index, dan metadata. Semua data at-rest dienkripsi, dengan HMAC untuk tamper detection.

**Deskripsi:** Gunakan `sled` (embedded Rust DB) sebagai backend utama (opsional RocksDB via feature flag). Buat encryption wrapper yang encrypt/decrypt setiap value sebelum write/after read menggunakan XChaCha20-Poly1305 dengan key derived dari wallet secret + local passphrase. HMAC-SHA256 pada setiap record untuk tamper detection. Sediakan trees/column families: `messages` (by conversation), `conversations` (index), `contacts` (address → alias), `settings`, `nonce_cache`. Default retention 1500 messages per conversation (configurable), auto-prune oldest saat limit tercapai.

**Yang dibuat:**

- `crates/bitevachat-storage/Cargo.toml` — depends on `sled`, `bitevachat-crypto`, `bitevachat-types`, `serde`, `bincode`
- `crates/bitevachat-storage/src/lib.rs` — re-exports
- `crates/bitevachat-storage/src/engine.rs` — `StorageEngine` struct, `open(path, encryption_key) -> Result<Self>`, `close()`, internal sled DB handle
- `crates/bitevachat-storage/src/encrypted_tree.rs` — `EncryptedTree<T>` wrapper, `get(key) -> Result<Option<T>>`, `insert(key, value: &T) -> Result<()>`, `delete(key)`, `iter()` — semua auto-encrypt/decrypt + HMAC verify
- `crates/bitevachat-storage/src/messages.rs` — `MessageStore`, `store_message(convo_id, envelope: &MessageEnvelope)`, `get_messages(convo_id, limit, offset) -> Vec<MessageEnvelope>`, `pin_message(msg_id)`, `star_message(msg_id)`, `prune_old(convo_id, retention_limit)`, `export_archive(convo_id) -> Vec<u8>`
- `crates/bitevachat-storage/src/conversations.rs` — `ConversationIndex`, `create_conversation(peer_address) -> ConvoId`, `list_conversations() -> Vec<ConvoSummary>`, `delete_conversation(convo_id)`
- `crates/bitevachat-storage/src/contacts.rs` — `ContactStore`, `set_alias(address, alias)`, `get_alias(address) -> Option<String>`, `list_contacts()`, `blocklist_add(address)`, `blocklist_check(address) -> bool`
- `crates/bitevachat-storage/src/settings.rs` — `SettingsStore`, key-value untuk user preferences (retention, encryption toggle, rate limits)
- `crates/bitevachat-storage/tests/` — encrypted round-trip, tamper detection (flip byte → HMAC fail), retention pruning, concurrent access

**File yang diubah:** `crates/bitevachat-types/src/lib.rs` (tambah `ConvoId`, `ConvoSummary` types)

---

## Tahap 8: Pending Queue & Offline Delivery System

**Tujuan:** Membangun pending message queue untuk pesan ke node offline, dengan retry logic, backoff, TTL expiry, dan size limits untuk anti-DoS.

**Deskripsi:** Saat recipient node offline, pesan disimpan di `pending.dat` (file terenkripsi terpisah dari main DB). Setiap pending entry: message envelope + retry_count + last_attempt + created_at. Retry scheduler: exponential backoff (1min, 2min, 4min, 8min, ... cap 1 jam) dengan network reachability check sebelum retry. Default TTL 5 hari; expired entries di-purge otomatis. Limits: max 500 messages per recipient, global cap configurable. Background task (Tokio) menjalankan retry loop.

**Yang dibuat:**

- `crates/bitevachat-storage/src/pending.rs` — `PendingQueue`, `PendingEntry` struct (envelope, retry_count, last_attempt, created_at, recipient), `enqueue(entry) -> Result<()>` (cek limits sebelum insert), `dequeue_ready() -> Vec<PendingEntry>` (entries yang siap retry), `mark_delivered(msg_id)`, `mark_failed(msg_id)` (increment retry_count + update last_attempt), `purge_expired(ttl: Duration)`, `count_for_recipient(address) -> usize`, `total_count() -> usize`
- `crates/bitevachat-storage/src/pending_file.rs` — `PendingFile`, encrypted file I/O untuk pending.dat, `load(path, key) -> Vec<PendingEntry>`, `save(path, key, entries)`, atomic write (write tmp → rename)
- `crates/bitevachat-node/src/pending_scheduler.rs` — (placeholder, implementasi penuh di tahap 12) `PendingScheduler`, Tokio interval task, backoff calculation, integration dengan network layer
- `crates/bitevachat-storage/tests/pending_tests.rs` — enqueue/dequeue cycle, TTL expiry, per-recipient limit enforcement, backoff timing calculation

**File yang diubah:** `crates/bitevachat-storage/src/lib.rs` (tambah pending module), `crates/bitevachat-types/src/config.rs` (tambah pending-related config fields)

---

## Tahap 9: libp2p Network Layer — Transport & Peer Discovery

**Tujuan:** Setup fondasi networking menggunakan libp2p: QUIC transport, Kademlia DHT untuk peer discovery, peer identity dari Ed25519 keypair, dan basic connection management.

**Deskripsi:** Crate `bitevachat-network` menggunakan `libp2p` dengan transport QUIC (performance + built-in encryption). Peer identity: Ed25519 keypair dari wallet langsung digunakan sebagai libp2p identity. Kademlia DHT untuk peer discovery — setiap node publish address-nya ke DHT, dan query DHT untuk menemukan peer berdasarkan address. Connection manager: max connections, idle timeout, dial policy. Bootstrap nodes: configurable list of known peers untuk initial DHT join.

**Yang dibuat:**

- `crates/bitevachat-network/Cargo.toml` — depends on `libp2p` (features: quic, kademlia, gossipsub, relay, identify, noise), `bitevachat-crypto`, `bitevachat-types`, `tokio`
- `crates/bitevachat-network/src/lib.rs` — re-exports
- `crates/bitevachat-network/src/transport.rs` — `build_transport(keypair: &Keypair) -> libp2p::Transport` (QUIC + Noise fallback), configure multiplexing
- `crates/bitevachat-network/src/identity.rs` — `wallet_keypair_to_libp2p(keypair) -> libp2p::identity::Keypair`, `peer_id_from_address(address) -> PeerId`
- `crates/bitevachat-network/src/discovery.rs` — `DiscoveryBehaviour` (wraps Kademlia), `publish_address(address, peer_id)`, `find_peer(address) -> Option<PeerId>`, `add_bootstrap_nodes(nodes: Vec<Multiaddr>)`, DHT configuration (replication factor, query timeout)
- `crates/bitevachat-network/src/swarm.rs` — `BitevachatSwarm` struct, `new(config, keypair) -> Self`, `start_listening(addr: Multiaddr)`, `dial_peer(peer_id, addr)`, event loop skeleton
- `crates/bitevachat-network/src/config.rs` — `NetworkConfig` (listen_addr, bootstrap_nodes, max_connections, idle_timeout, dial_timeout)
- `crates/bitevachat-network/tests/` — two-node discovery test (spawn 2 nodes, verify mereka bisa saling temukan via DHT)

**File yang diubah:** `crates/bitevachat-types/src/config.rs` (tambah `NetworkConfig` defaults)

---

## Tahap 10: P2P Message Routing & Delivery

**Tujuan:** Implementasi direct message delivery antar peers — routing pesan dari sender ke recipient via libp2p, termasuk message handling, acknowledgement, dan integration dengan pending queue.

**Deskripsi:** Buat custom libp2p protocol `/bitevachat/msg/1.0.0` untuk point-to-point messaging. Sender: lookup recipient di DHT → dial → send MessageEnvelope via protocol stream. Recipient: handler menerima stream → verify signature → check timestamp/nonce → decrypt → store ke DB → send ACK. Jika recipient unreachable, enqueue ke pending queue. Implement gossipsub subscription untuk metadata broadcast (online status, profile updates). Event system: `NetworkEvent` enum yang di-emit ke node layer.

**Yang dibuat:**

- `crates/bitevachat-network/src/protocol.rs` — `MessageProtocol` (implements `libp2p::core::UpgradeInfo`), protocol negotiation `/bitevachat/msg/1.0.0`, codec untuk MessageEnvelope serialization over stream
- `crates/bitevachat-network/src/handler.rs` — `MessageHandler`, `on_message_received(peer_id, envelope) -> HandlerResult`, verification pipeline (signature → timestamp → nonce → pass to node), ACK/NACK response
- `crates/bitevachat-network/src/routing.rs` — `Router`, `send_message(recipient_address, envelope) -> Result<DeliveryStatus>`, `DeliveryStatus` enum (Delivered, Queued, Failed), DHT lookup → dial → send → await ACK
- `crates/bitevachat-network/src/gossip.rs` — `GossipBehaviour` (wraps gossipsub), `publish_metadata(topic, data)`, `subscribe(topic)`, topics: `presence`, `profile-updates`
- `crates/bitevachat-network/src/events.rs` — `NetworkEvent` enum (MessageReceived, PeerConnected, PeerDisconnected, DeliveryAck, DeliveryFailed, GossipMessage)
- `crates/bitevachat-network/tests/` — two-node message delivery test, offline → pending → online → delivery test

**File yang diubah:** `crates/bitevachat-network/src/swarm.rs` (integrate MessageProtocol + GossipBehaviour into combined behaviour), `crates/bitevachat-network/src/lib.rs`

---

## Tahap 11: NAT Traversal — STUN/TURN & Relay

**Tujuan:** Menjamin konektivitas di balik NAT dengan STUN hole-punching, TURN fallback, dan libp2p relay circuit — critical untuk real-world usability.

**Deskripsi:** Integrasikan libp2p-relay untuk circuit relay (peers bisa relay traffic untuk NAT-ed peers). Tambahkan STUN client untuk external address discovery dan hole punching. TURN fallback jika direct connection gagal. Implementasi AutoNAT (libp2p) untuk detect NAT status. Sediakan mode "relay only" untuk user yang mau privasi. Relay node operators bisa opt-in untuk serve sebagai public relay.

**Yang dibuat:**

- `crates/bitevachat-network/src/nat.rs` — `NatTraversal`, `detect_nat_status() -> NatStatus` (enum: Public, BehindNat, Symmetric), `configure_stun(servers: Vec<String>)`, `get_external_address() -> Option<Multiaddr>`
- `crates/bitevachat-network/src/relay.rs` — `RelayConfig`, `enable_relay_client()` (use relay for outgoing), `enable_relay_server()` (serve as relay), relay reservation management, `relay_only_mode(enabled: bool)`
- `crates/bitevachat-network/src/hole_punch.rs` — `HolePuncher`, DCUtR (Direct Connection Upgrade through Relay) integration, `attempt_hole_punch(peer_id) -> Result<()>`, fallback chain: direct → hole punch → relay
- `crates/bitevachat-network/src/turn.rs` — TURN client wrapper (via `stun-rs` atau equivalent), `TurnClient`, `allocate() -> TurnAllocation`, credential management

**File yang diubah:** `crates/bitevachat-network/src/swarm.rs` (tambah relay + AutoNAT + DCUtR ke combined behaviour), `crates/bitevachat-network/src/config.rs` (tambah NAT/relay config fields), `crates/bitevachat-network/src/routing.rs` (update send flow: direct → hole punch → relay fallback)

---

## Tahap 12: Node Core — Event Loop & Component Integration

**Tujuan:** Membangun node core yang mengintegrasikan semua komponen (wallet, network, storage, protocol, pending) ke dalam satu event-driven runtime.

**Deskripsi:** Crate `bitevachat-node` adalah orchestrator. Saat startup: load wallet → unlock → init storage → init network (swarm) → start listening → join DHT → start pending scheduler. Main event loop (Tokio select!) menangani: network events, RPC commands, timer events (pending retry, nonce cache cleanup, DB prune). Setiap incoming message: verify → decrypt → store → notify UI. Setiap outgoing message: encrypt → sign → canonical serialize → route. Node state machine: Initializing → Running → Shutting Down.

**Yang dibuat:**

- `crates/bitevachat-node/Cargo.toml` — depends on semua crates
- `crates/bitevachat-node/src/lib.rs` — re-exports
- `crates/bitevachat-node/src/node.rs` — `Node` struct (wallet, storage, network, config), `Node::new(config) -> Self`, `start() -> JoinHandle`, `shutdown()`, `NodeState` enum
- `crates/bitevachat-node/src/event_loop.rs` — main `run()` async fn, `tokio::select!` over: `swarm.next()` (network), `rpc_rx.recv()` (RPC commands), `pending_tick.tick()` (scheduler), `maintenance_tick.tick()` (cleanup)
- `crates/bitevachat-node/src/incoming.rs` — `handle_incoming_message(envelope)`: verify signature → check nonce → decrypt → store → emit event to UI channel
- `crates/bitevachat-node/src/outgoing.rs` — `send_message(recipient, plaintext)`: encrypt → build Message → sign → canonical CBOR → route via network → fallback to pending
- `crates/bitevachat-node/src/pending_scheduler.rs` — (complete implementation) `PendingScheduler`, `tick()`: load ready entries → attempt delivery → update status, exponential backoff logic, `purge_expired()`
- `crates/bitevachat-node/src/maintenance.rs` — periodic tasks: nonce cache cleanup, DB retention pruning, DHT refresh, stale connection cleanup

**File yang diubah:** `crates/bitevachat-types/src/lib.rs` (tambah `NodeEvent` enum untuk UI notification channel)

---

## Tahap 13: Local RPC Server (gRPC over Unix Socket)

**Tujuan:** Expose node functionality ke UI dan external tools via local gRPC server — hanya accessible dari localhost, dengan authentication untuk remote access.

**Deskripsi:** Gunakan `tonic` untuk gRPC server di Unix socket (Linux/macOS) atau named pipe (Windows) / localhost TCP fallback. Definisikan protobuf service: `WalletService` (create, unlock, lock, get_address, backup), `MessageService` (send, list, get, pin, delete), `ContactService` (add_alias, list, block, unblock), `NodeService` (status, peers, config). Default: hanya localhost; jika remote RPC diaktifkan, wajib mTLS + API token. External message injection: harus supply full signed canonical payload; node verif sebelum inject.

**Yang dibuat:**

- `crates/bitevachat-rpc/Cargo.toml` — depends on `tonic`, `prost`, `tokio`, `bitevachat-node`, `bitevachat-types`
- `crates/bitevachat-rpc/proto/bitevachat.proto` — protobuf definitions: `WalletService`, `MessageService`, `ContactService`, `NodeService`, semua request/response messages
- `crates/bitevachat-rpc/build.rs` — tonic-build compile protobuf
- `crates/bitevachat-rpc/src/lib.rs` — re-exports
- `crates/bitevachat-rpc/src/server.rs` — `RpcServer`, `start(node_handle, bind_config) -> JoinHandle`, Unix socket binding, graceful shutdown
- `crates/bitevachat-rpc/src/wallet_service.rs` — implements `WalletService` trait → delegates ke Node
- `crates/bitevachat-rpc/src/message_service.rs` — implements `MessageService` → delegates ke Node
- `crates/bitevachat-rpc/src/contact_service.rs` — implements `ContactService` → delegates ke Node
- `crates/bitevachat-rpc/src/node_service.rs` — implements `NodeService` → delegates ke Node (status, connected peers, config)
- `crates/bitevachat-rpc/src/auth.rs` — `AuthInterceptor`, local API token check, mTLS setup for remote
- `crates/bitevachat-rpc/src/inject.rs` — `inject_external_message(signed_payload)`: verify signature + timestamp → inject ke network
- `crates/bitevachat-rpc/tests/` — gRPC client test: send message via RPC, query status

**File yang diubah:** `crates/bitevachat-node/src/node.rs` (expose methods yang dipanggil RPC), `crates/bitevachat-node/src/lib.rs`

---

## Tahap 14: Anti-Spam, Rate Limiting & Proof-of-Work

**Tujuan:** Implementasi multi-layer spam protection: per-sender rate limits, queue limits, trust scoring, blocklist/whitelist, dan optional lightweight PoW.

**Deskripsi:** Rate limiter: token bucket per sender (default 10 msg/min, configurable). Per-recipient pending queue limit (default 500). Global pending size limit. PoW: optional hashcash-style challenge (SHA3-256 leading zeros, difficulty configurable) yang harus disertakan di message header — hanya untuk pesan dari unknown peers. Trust scoring: known peers (pernah bertukar pesan, stable profile) mendapat higher quota. Blocklist/whitelist di storage layer. Scoring via DHT metadata (opt-in, future).

**Yang dibuat:**

- `crates/bitevachat-node/src/rate_limiter.rs` — `RateLimiter`, `check_rate(sender: &Address) -> Result<()>`, token bucket implementation, configurable limits per sender
- `crates/bitevachat-node/src/spam_filter.rs` — `SpamFilter`, orchestrates: rate limit check → blocklist check → trust score check → PoW check → pass/reject, `filter_incoming(envelope) -> FilterResult` (Accept, RateLimit, Blocked, PowRequired, Reject)
- `crates/bitevachat-protocol/src/pow.rs` — `ProofOfWork` struct (nonce, difficulty, hash), `generate_pow(message_hash, difficulty) -> ProofOfWork`, `verify_pow(pow, message_hash) -> Result<()>`, hashcash-style: find nonce where SHA3-256(message_hash || nonce) has `difficulty` leading zero bits
- `crates/bitevachat-node/src/trust.rs` — `TrustManager`, `get_trust_score(address) -> TrustScore` (enum: Unknown, Seen, Trusted), `record_interaction(address)`, trust increases with successful message exchange
- `crates/bitevachat-storage/src/blocklist.rs` — (jika belum ada, extend contacts.rs) `BlocklistStore`, `add(address)`, `remove(address)`, `contains(address) -> bool`, `whitelist_add(address)`
- `crates/bitevachat-node/tests/` — rate limit enforcement, PoW validation, blocklist rejection, trust score progression

**File yang diubah:** `crates/bitevachat-node/src/incoming.rs` (tambah spam_filter check sebelum process message), `crates/bitevachat-types/src/config.rs` (tambah spam/rate limit config)

---

## Tahap 15: Profile System & Public Data Sync

**Tujuan:** Implementasi signed profile (name, avatar, bio) yang di-broadcast via gossipsub dan di-verify oleh receiving nodes, dengan avatar storage via CID (content-addressed).

**Deskripsi:** Profile JSON: { address, name, avatar_cid (optional), bio, timestamp, version (incrementing) }. Profile selalu di-sign dengan Ed25519 key. Publish profile update via gossipsub topic `profile-updates`. Receiving node: verify signature terhadap address, check version > cached version, update local cache. Avatar: hash content → CID, store blob lokal atau optional IPFS, hanya broadcast CID. Profile caching dengan TTL. Revocation: publish signed revocation statement.

**Yang dibuat:**

- `crates/bitevachat-protocol/src/profile.rs` — `Profile` struct (address, name, avatar_cid, bio, timestamp, version), `SignedProfile` (profile + signature), `create_profile(keypair, name, bio, avatar) -> SignedProfile`, `verify_profile(signed: &SignedProfile) -> Result<()>`, `ProfileRevocation` struct
- `crates/bitevachat-node/src/profile_manager.rs` — `ProfileManager`, `update_profile(name, bio, avatar_bytes) -> SignedProfile`, `broadcast_profile()` (via gossipsub), `on_profile_received(signed_profile)` (verify → check version → cache), profile cache (HashMap<Address, CachedProfile> with TTL)
- `crates/bitevachat-storage/src/profiles.rs` — `ProfileStore`, `save_profile(address, signed_profile)`, `get_profile(address) -> Option<SignedProfile>`, `save_avatar_blob(cid, bytes)`, `get_avatar(cid) -> Option<Vec<u8>>`
- `crates/bitevachat-protocol/src/cid.rs` — `compute_cid(data: &[u8]) -> Cid` (SHA3-256 based content addressing), CID encoding/decoding
- `crates/bitevachat-node/tests/` — profile broadcast & receive between nodes, stale profile rejection (lower version), signature verification failure, avatar CID resolution

**File yang diubah:** `crates/bitevachat-network/src/gossip.rs` (tambah profile topic handler), `crates/bitevachat-node/src/event_loop.rs` (handle profile gossip events), `crates/bitevachat-rpc/proto/bitevachat.proto` (tambah ProfileService RPCs)

---

## Tahap 16: Group Chat — Symmetric Key & Membership

**Tujuan:** Implementasi group chat v1 dengan group symmetric key, creator-managed membership, key rotation saat membership berubah, dan encrypted group messaging via gossipsub.

**Deskripsi:** Group = group_id + group_symmetric_key + membership_list. Creator: generate group_id (random) + group_key, sign membership list, encrypt group_key ke setiap member (wrap dengan masing-masing member's X25519 pubkey). Member join: creator re-encrypt new group_key ke semua members. Member leave/remove: creator generate new group_key, re-distribute. Messages: encrypt dengan group_key via XChaCha20-Poly1305, broadcast via gossipsub topic `group/{group_id}`. Setiap group message tetap di-sign oleh sender untuk authenticity.

**Yang dibuat:**

- `crates/bitevachat-protocol/src/group.rs` — `GroupInfo` struct (group_id, creator, members, version), `SignedGroupInfo` (info + creator signature), `GroupKeyPackage` struct (group_id, encrypted_keys: HashMap<Address, EncryptedGroupKey>), `encrypt_group_key(group_key, member_pubkeys) -> GroupKeyPackage`, `decrypt_group_key(package, my_keypair) -> GroupKey`
- `crates/bitevachat-protocol/src/group_message.rs` — `GroupMessage` struct (extends Message with group_id), `encrypt_group_message(group_key, sender_keypair, plaintext) -> GroupMessageEnvelope`, `decrypt_group_message(group_key, envelope) -> Plaintext`
- `crates/bitevachat-node/src/group_manager.rs` — `GroupManager`, `create_group(name, members) -> GroupInfo`, `add_member(group_id, new_member)` (rotate key), `remove_member(group_id, member)` (rotate key), `send_group_message(group_id, plaintext)`, `on_group_message_received(envelope)`, `on_group_key_received(package)`
- `crates/bitevachat-storage/src/groups.rs` — `GroupStore`, `save_group(info, key)`, `get_group(group_id)`, `list_groups()`, `save_group_messages(group_id, envelopes)`
- `crates/bitevachat-network/src/gossip.rs` — tambah dynamic topic subscription per group (`group/{group_id}`), publish/receive group messages
- `crates/bitevachat-node/tests/` — create group, member join/leave key rotation, group message encrypt/decrypt, unauthorized member rejection

**File yang diubah:** `crates/bitevachat-node/src/event_loop.rs` (handle group events), `crates/bitevachat-rpc/proto/bitevachat.proto` (tambah GroupService RPCs), `crates/bitevachat-types/src/lib.rs` (tambah `GroupId` type)

---

## Tahap 17: CLI Client

**Tujuan:** Membangun command-line client yang fully functional untuk testing, automation, dan power users — semua operasi bisa dilakukan via CLI.

**Deskripsi:** CLI menggunakan `clap` dengan subcommands. Berkomunikasi dengan node via gRPC (connect ke local RPC). Support semua operasi: wallet management, send/receive messages, contact management, group operations, node status. Output format: human-readable default, `--json` flag untuk machine-readable. Interactive mode untuk chat session (read-eval-print loop).

**Yang dibuat:**

- `crates/bitevachat-cli/Cargo.toml` — depends on `clap`, `tonic`, `tokio`, `serde_json`, `colored`
- `crates/bitevachat-cli/src/main.rs` — CLI entry point, clap App definition
- `crates/bitevachat-cli/src/commands/mod.rs` — subcommand modules
- `crates/bitevachat-cli/src/commands/wallet.rs` — `wallet create`, `wallet unlock`, `wallet lock`, `wallet address`, `wallet backup`, `wallet import`
- `crates/bitevachat-cli/src/commands/message.rs` — `msg send <address> <text>`, `msg list [address]`, `msg get <msg_id>`, `msg pin <msg_id>`, `msg delete <msg_id>`
- `crates/bitevachat-cli/src/commands/contact.rs` — `contact add <address> [alias]`, `contact list`, `contact block <address>`, `contact unblock <address>`
- `crates/bitevachat-cli/src/commands/group.rs` — `group create <name> <member1> <member2>...`, `group list`, `group send <group_id> <text>`, `group add-member`, `group remove-member`
- `crates/bitevachat-cli/src/commands/node.rs` — `node status`, `node peers`, `node config [set key value]`
- `crates/bitevachat-cli/src/interactive.rs` — interactive chat REPL: select conversation → type messages → receive in real-time, `Ctrl+C` to exit
- `crates/bitevachat-cli/src/rpc_client.rs` — gRPC client wrapper, connect to node's Unix socket/localhost
- `crates/bitevachat-cli/src/output.rs` — formatter: human-readable tables (colored) vs JSON output

**File yang diubah:** Tidak ada (semua baru), tapi pastikan `bitevachat-rpc` proto sudah lengkap dari tahap 13

---

## Tahap 18: Desktop GUI (egui + Tauri)

**Tujuan:** Membangun desktop GUI yang user-friendly menggunakan egui (immediate-mode GUI), dengan optional Tauri packaging untuk cross-platform distribution.

**Deskripsi:** GUI berkomunikasi dengan node via gRPC (sama seperti CLI). Layout: sidebar (conversation list + contacts) → main panel (chat view) → top bar (status + settings). Flows: onboarding (create wallet / import seed), chat (send/receive real-time), settings (retention, encryption, network config). "Easy mode": password-only wallet tanpa expose seed. "Advanced mode": full seed backup, key rotation, manual config. Show address short form di UI, full di detail. Responsive real-time updates via gRPC streaming atau polling.

**Yang dibuat:**

- `crates/bitevachat-gui/Cargo.toml` — depends on `eframe` (egui), `tonic`, `tokio`, `image`
- `crates/bitevachat-gui/src/main.rs` — eframe app entry, Tokio runtime setup
- `crates/bitevachat-gui/src/app.rs` — `BitevachatApp` struct (implements `eframe::App`), `update()` main render loop, state management
- `crates/bitevachat-gui/src/views/onboarding.rs` — seed creation wizard (generate → show words → confirm backup checklist → set passphrase → done), import flow (enter 24 words → passphrase → restore)
- `crates/bitevachat-gui/src/views/chat.rs` — conversation list sidebar, message bubbles, input field, send button, real-time message display, pin/star controls
- `crates/bitevachat-gui/src/views/contacts.rs` — contact list, alias editing, block/unblock, add by address (dengan checksum validation UI)
- `crates/bitevachat-gui/src/views/groups.rs` — create group dialog, member management, group chat view
- `crates/bitevachat-gui/src/views/settings.rs` — retention slider, encryption info, network config, relay mode toggle, passphrase change, backup export
- `crates/bitevachat-gui/src/views/profile.rs` — edit name/bio/avatar, preview signed profile
- `crates/bitevachat-gui/src/rpc_bridge.rs` — async gRPC client, channels for UI ↔ network thread communication
- `crates/bitevachat-gui/src/theme.rs` — color scheme, fonts, spacing constants
- `Tauri.toml` / `tauri/` — (optional) Tauri wrapper config untuk cross-platform packaging (Windows, macOS, Linux)

**File yang diubah:** Workspace `Cargo.toml` (pastikan gui member), `crates/bitevachat-rpc/proto/bitevachat.proto` (tambah streaming RPCs untuk real-time updates jika belum)

---

## Tahap 19: Metadata Privacy — Tor Integration & Relay Routing

**Tujuan:** Mitigasi metadata leakage (IP, connection timing) dengan optional Tor integration, relay-based routing, dan connection obfuscation.

**Deskripsi:** Tor: optional SOCKS5 proxy mode — route libp2p traffic via Tor (arti crate for Rust Tor client, atau external tor daemon via SOCKS5). Relay routing: multi-hop relay forwarding (pesan di-route melalui 2-3 relay nodes sebelum sampai recipient) — opt-in karena latency tradeoff. Connection obfuscation: randomized timing for gossipsub broadcasts (jitter ±random delay), padding dummy messages. Minimal telemetry enforcement: semua telemetry opt-in, anonymized (no PII).

**Yang dibuat:**

- `crates/bitevachat-network/src/tor.rs` — `TorTransport`, `configure_tor_socks5(proxy_addr: SocketAddr)`, wrap libp2p transport through SOCKS5, `TorMode` enum (Disabled, SocksProxy, EmbeddedArti)
- `crates/bitevachat-network/src/onion_routing.rs` — `OnionRouter`, `route_via_relays(message, relay_chain: Vec<PeerId>) -> Result<()>`, multi-hop encryption (encrypt in layers: innermost = recipient, each layer = relay), relay node handler: unwrap one layer → forward
- `crates/bitevachat-network/src/obfuscation.rs` — `TimingObfuscator`, `add_jitter(base_delay) -> Duration` (random ±30% delay), `DummyTrafficGenerator` (periodic dummy messages to cover real traffic patterns), `PaddingManager` (pad message sizes to fixed buckets)
- `crates/bitevachat-node/src/telemetry.rs` — `TelemetryManager`, `opt_in(enabled: bool)`, `collect_metric(name, value)` (aggregated, non-PII), `export_metrics() -> AggregatedReport`
- `crates/bitevachat-network/tests/` — Tor SOCKS5 connectivity test (mock), relay forwarding multi-hop test, timing jitter distribution test

**File yang diubah:** `crates/bitevachat-network/src/swarm.rs` (integrate Tor transport option), `crates/bitevachat-network/src/config.rs` (privacy config: tor_enabled, relay_hops, jitter settings), `crates/bitevachat-gui/src/views/settings.rs` (privacy settings UI)

---

## Tahap 20: Logging, Auditing, Testing & Production Hardening

**Tujuan:** Final hardening — encrypted logging, audit trail, comprehensive test suite (unit + integration + fuzz + adversarial), documentation, dan production configuration.

**Deskripsi:** Logging: semua logs disimpan terenkripsi di disk (XChaCha20-Poly1305 dengan key dari wallet), structured logging via `tracing` crate. Log export: requires user consent + signature. Audit trail: hash chain of delivered messages (hashes only, tidak plaintext) — setiap entry = SHA3-256(prev_hash || message_id || timestamp). Comprehensive tests: unit tests per module, integration tests (multi-node scenarios), fuzz tests (libfuzzer untuk CBOR parsing, message handling, crypto), adversarial tests (replay attack, spam flood, NAT scenario, malformed messages). Documentation: rustdoc untuk semua public APIs, architecture docs, threat model doc.

**Yang dibuat:**

- `crates/bitevachat-node/src/logging.rs` — `EncryptedLogger`, `init(log_dir, encryption_key, level)`, `tracing` subscriber yang encrypt sebelum write, `export_logs(consent_signature) -> EncryptedLogBundle`, log rotation (size-based)
- `crates/bitevachat-node/src/audit.rs` — `AuditTrail`, `record_delivery(message_id, timestamp)` → append ke hash chain, `verify_chain() -> Result<()>`, `export_audit(consent_signature) -> AuditReport` (hashes only)
- `tests/integration/two_node_chat.rs` — spawn 2 full nodes, create wallets, exchange messages, verify E2E
- `tests/integration/group_chat.rs` — spawn 3+ nodes, create group, exchange group messages, member add/remove
- `tests/integration/offline_delivery.rs` — sender sends while recipient offline → recipient comes online → receives pending
- `tests/integration/nat_relay.rs` — simulate NAT scenario, verify relay-mediated delivery
- `tests/adversarial/replay_attack.rs` — send same signed message twice → verify second rejected
- `tests/adversarial/spam_flood.rs` — send > rate limit from one peer → verify rate limiting kicks in
- `tests/adversarial/malformed_messages.rs` — send corrupt CBOR, wrong signatures, future timestamps → verify all rejected
- `fuzz/fuzz_targets/cbor_parser.rs` — libfuzzer target untuk CBOR deserialization
- `fuzz/fuzz_targets/message_handler.rs` — fuzz incoming message handler
- `fuzz/fuzz_targets/wallet_file.rs` — fuzz wallet.dat parsing
- `docs/ARCHITECTURE.md` — system architecture overview, component diagram, data flow
- `docs/THREAT_MODEL.md` — threat matrix, mitigations per threat, residual risks
- `docs/API.md` — gRPC API reference (generated dari proto + manual examples)
- `docs/DEPLOYMENT.md` — build instructions, config guide, bootstrap node setup, relay operator guide

**File yang diubah:** `Cargo.toml` (workspace — tambah `[profile.release]` optimizations, LTO, codegen-units=1), `crates/bitevachat-node/src/lib.rs` (tambah logging + audit modules), `.github/workflows/ci.yml` (tambah integration test job, fuzz job schedule)

---

## Dependency Graph Antar Tahap

```
Tahap 1 (Scaffolding)
  └─► Tahap 2 (Crypto Primitives)
       ├─► Tahap 3 (BIP39 + HD Keys)
       │    └─► Tahap 4 (Wallet)
       └─► Tahap 5 (Protocol + Canonical)
            └─► Tahap 6 (E2E Encryption)
                 └─► Tahap 7 (Storage Engine)
                      └─► Tahap 8 (Pending Queue)
                           └─► Tahap 9 (libp2p Network)
                                ├─► Tahap 10 (P2P Routing)
                                │    └─► Tahap 11 (NAT Traversal)
                                └─► Tahap 12 (Node Core) ◄── integrates 4,7,8,10
                                     ├─► Tahap 13 (RPC Server)
                                     │    ├─► Tahap 17 (CLI)
                                     │    └─► Tahap 18 (GUI)
                                     ├─► Tahap 14 (Anti-Spam)
                                     ├─► Tahap 15 (Profile System)
                                     ├─► Tahap 16 (Group Chat)
                                     ├─► Tahap 19 (Privacy/Tor)
                                     └─► Tahap 20 (Hardening/Testing)
```

---

## Summary of Operational Defaults

| Parameter | Default | Configurable |
|---|---|---|
| Pending TTL | 5 days | Yes |
| DB retention | 1500 messages/convo | Yes |
| Rate limit | 10 msgs/min/sender | Yes |
| Pending max | 500/recipient | Yes |
| Nonce cache | 10,000 entries | Yes |
| Timestamp skew | ±5 minutes | Yes |
| PoW difficulty | 16 bits (optional) | Yes |
| Relay mode | Disabled | Yes |
| Tor mode | Disabled | Yes |
| Telemetry | Opt-in only | Yes |