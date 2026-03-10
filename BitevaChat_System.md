# Bitevachat — Sistem Chat Terdesentralisasi

**Versi:** 0.2.0
**Bahasa:** Rust
**Tanggal:** Maret 2026
**Penulis:** Noven / Biteva Capital

---

## 1. Ringkasan

Bitevachat adalah aplikasi chat peer-to-peer (P2P) yang sepenuhnya terdesentralisasi. Tidak ada server pusat — setiap pengguna menjalankan node ringan yang berkomunikasi langsung dengan node lain melalui jaringan libp2p. Identitas pengguna berbasis kriptografi: sebuah wallet menghasilkan keypair Ed25519, dan alamat (address) diturunkan dari public key melalui hashing SHA3-256. Pesan diverifikasi dengan digital signature dan dilindungi oleh enkripsi end-to-end (E2E) menggunakan ephemeral X25519 ECDH + XChaCha20-Poly1305, serta enkripsi transport Noise Protocol.

Pengguna dapat sepenuhnya anonim — tidak diperlukan nomor telepon, email, atau informasi pribadi apapun. Yang dibutuhkan hanya seed phrase (BIP39) untuk membuat wallet.

---

## 2. Arsitektur Keseluruhan

```
┌──────────────────────────────────────────────────────────────────┐
│                        Bitevachat Node                           │
│                                                                  │
│  ┌───────────┐  ┌──────────────┐  ┌───────────────────────────┐ │
│  │  Wallet    │  │   Storage    │  │      Network Swarm        │ │
│  │ (Ed25519)  │  │  (LMDB)     │  │  (libp2p + relay + DHT)   │ │
│  └─────┬──────┘  └──────┬───────┘  └────────────┬──────────────┘ │
│        │               │                       │                 │
│        └───────────────┼───────────────────────┘                 │
│                        │                                         │
│               ┌────────┴────────┐                                │
│               │   Event Loop    │                                │
│               │  tokio::select! │                                │
│               └───┬─────────┬───┘                                │
│                   │         │                                    │
│            ┌──────┘         └──────┐                             │
│            ▼                       ▼                             │
│       Incoming                 Outgoing                          │
│       Handler                  Builder                           │
│    (verify+store)          (sign+encrypt)                        │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
│  │ Pending Queue   │  │  Spam Filter   │  │ Profile Manager    │ │
│  │ (pending.dat)   │  │ (trust+PoW)    │  │ (gossip pubsub)   │ │
│  └────────────────┘  └────────────────┘  └────────────────────┘ │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    RPC Server (gRPC)                      │   │
│  │              Port 50051 (localhost only)                   │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
       ▲ NodeCommand                              │ NodeEvent
       │                                          ▼
    ┌──────────────────────────────────────────────────────────┐
    │              GUI (eframe/egui) atau CLI                   │
    └──────────────────────────────────────────────────────────┘
```

### 2.1. Crate Structure

Bitevachat terdiri dari beberapa Rust crate yang saling terhubung:

- **bitevachat-types** — tipe data shared: Address, MessageId, ConvoId, NodeId, Nonce, Timestamp, Signature, PayloadType, NodeEvent, AppConfig, dan error types (BitevachatError).
- **bitevachat-crypto** — kriptografi: Ed25519 keypair (signing, verification), SHA3-256 hashing, pubkey-to-address derivation, message ID computation, KDF (Argon2id), X25519 ECDH key agreement (ephemeral + static), XChaCha20-Poly1305 AEAD, HKDF-SHA256 key derivation.
- **bitevachat-protocol** — wire protocol: MessageEnvelope, Message struct, canonical CBOR serialization (RFC 8949), nonce cache (replay detection), proof-of-work, profile serialization, E2E encryption/decryption (ephemeral ECDH + XChaCha20-Poly1305), session key derivation.
- **bitevachat-wallet** — wallet management: BIP39 mnemonic, keypair derivation, unlock/lock, encrypted private key storage (XChaCha20-Poly1305 + Argon2id KDF).
- **bitevachat-storage** — persistence: LMDB-backed message database, contact store, pending queue (pending.dat), encrypted at rest.
- **bitevachat-network** — libp2p networking: swarm, discovery (Kademlia DHT), relay (Circuit Relay v2), gossipsub, mDNS, AutoNAT, DCUtR hole punching, DNS seed discovery, mailbox (store-and-forward), handler (message validation), routing.
- **bitevachat-node** — node runtime: event loop, incoming/outgoing message processing, spam filter, trust scoring, rate limiter, profile manager, maintenance, pending scheduler.
- **bitevachat-daemon** — headless CLI daemon untuk server/VPS.
- **bitevachat-gui** — desktop GUI dengan eframe/egui.

---

## 3. Wallet dan Identitas

### 3.1. Pembuatan Wallet

Saat pengguna pertama kali membuka aplikasi, mereka diminta untuk membuat wallet baru atau mengimpor seed phrase yang sudah ada.

Alur pembuatan wallet:

1. Generate mnemonic BIP39 (24 kata).
2. Turunkan master key dari mnemonic.
3. Generate keypair Ed25519 dari master key.
4. Pengguna memasukkan passphrase untuk mengenkripsi private key.
5. Private key (mnemonic) dienkripsi dengan XChaCha20-Poly1305 menggunakan key yang diturunkan dari passphrase via Argon2id KDF.
6. File `wallet.json` disimpan ke disk, berisi: public key (hex), encrypted private key (hex), salt (32 byte, hex), nonce (24 byte, hex). Tidak ada plaintext secret yang ditulis ke disk.

### 3.2. Address

Address adalah identitas unik pengguna di jaringan Bitevachat:

```
Address = SHA3-256(Ed25519_Public_Key)
```

Menghasilkan 32 byte (64 karakter hex). Contoh: `2dfdf1319517c98c6885a3e2cb8c14fed0b768be265b558d320a998a5d22ba28`.

Address digunakan untuk: mengirim dan menerima chat, identifikasi node di jaringan, routing pesan, dan sebagai conversation ID (deterministic).

### 3.3. Unlock dan Lock

Wallet dalam kondisi locked secara default saat pertama kali dimuat dari disk. Pengguna harus memasukkan passphrase untuk unlock. Saat unlock, passphrase di-hash dengan Argon2id menggunakan salt yang tersimpan, lalu digunakan untuk mendekripsi private key. Wallet bisa di-lock kembali untuk keamanan.

### 3.4. File Wallet

Format file `wallet.json`:

```json
{
  "version": 1,
  "public_key": "hex_encoded_32_bytes",
  "encrypted_private_key": "hex_encoded_ciphertext",
  "salt": "hex_encoded_32_bytes",
  "nonce": "hex_encoded_24_bytes"
}

```

Penulisan file menggunakan atomic write (write ke `.tmp` lalu rename) untuk mencegah korupsi.

### 3.5. Persistent Keypair dan PeerId

Konversi wallet keypair ke libp2p identity bersifat **deterministic**: wallet yang sama selalu menghasilkan PeerId yang sama. Fungsi `wallet_keypair_to_libp2p()` mengkonversi Ed25519 keypair Bitevachat ke format libp2p secara idempotent.

Implikasi penting:
- Selama file `wallet.json` di-persist dan di-load ulang saat restart, PeerId node stabil antar restart.
- DHT records (Address → PeerId) tetap valid.
- Relay reservations dan peer connections tetap konsisten.
- DNS seed bootstrap tanpa PeerId (peerless) tetap bisa menemukan node yang sama.

PeerId dan Address adalah dua derivasi deterministik dari public key yang sama, menggunakan hashing berbeda:
- `Address = SHA3-256(public_key)` — identitas Bitevachat.
- `PeerId = Multihash(protobuf(public_key))` — identitas libp2p.

### 3.6. Public Key Book

Node menyimpan mapping `Address → Ed25519 Public Key` di `pubkey_book` (in-memory HashMap). Mapping ini dibangun dari dua sumber:
- **WireMessage** — setiap pesan yang diterima membawa `sender_pubkey` (32 bytes). Pubkey ini di-register untuk address pengirim.
- **Identify handshake** — saat koneksi baru terjalin, Identify protocol mengungkapkan public key peer. Pubkey ini di-register untuk address peer.

Public key book digunakan untuk:
- E2E encryption: sender perlu recipient's Ed25519 pubkey untuk melakukan ECDH.
- Verifikasi identitas: memastikan pubkey → address binding valid.

---

## 4. Protokol Pesan

### 4.1. Struktur Message

Setiap pesan yang dikirim melalui jaringan Bitevachat memiliki struktur berikut:

```
Message {
    sender:              Address (32 bytes)
    recipient:           Address (32 bytes)
    payload_type:        PayloadType (Text | File | System)
    payload_ciphertext:  Vec<u8> (isi pesan)
    node_id:             NodeId (32 bytes)
    nonce:               Nonce (12 bytes, random)
    timestamp:           Timestamp (millisecond precision)
    message_id:          MessageId (32 bytes, deterministic)
}
```

### 4.2. Message ID

Message ID dihitung secara deterministic:

```
message_id = SHA3-256(sender || timestamp || nonce)
```

Ini memungkinkan dedup di seluruh jaringan tanpa koordinasi sentral.

### 4.3. MessageEnvelope

Message dibungkus dalam envelope yang berisi signature:

```
MessageEnvelope {
    message:   Message
    signature: Ed25519 Signature (64 bytes)
}
```

### 4.4. Alur Pengiriman Pesan

1. Pengguna mengetik pesan dan menekan Send.
2. GUI mengirim `NodeCommand::SendMessage` ke event loop via channel.
3. Node membuat `Message` struct dengan nonce random (12 byte dari OS RNG).
4. **Pubkey lookup**: node cek `pubkey_book` untuk Ed25519 public key recipient.
5. **E2E encryption** (jika pubkey ditemukan):
   - Generate ephemeral X25519 keypair (fresh per message → forward secrecy).
   - Convert recipient Ed25519 pubkey → X25519 pubkey (birational map Edwards → Montgomery).
   - ECDH: `shared_secret = ephemeral_secret × recipient_x25519_pubkey`.
   - HKDF-SHA256: `session_key = HKDF(shared_secret, salt="Bitevachat-E2E", info=sender_pk||recipient_pk)`.
   - XChaCha20-Poly1305: `ciphertext = Encrypt(session_key, random_nonce, plaintext)`.
   - Serialize: `[0xE2][0xE0][0x01][ephemeral_pk_32][nonce_24][ciphertext+tag]`.
6. Jika pubkey **tidak** ditemukan → payload tetap plaintext (backward compatible).
7. Message ID dihitung: `SHA3-256(sender || timestamp || nonce)`.
8. Message (dengan encrypted payload) di-serialize ke canonical CBOR (RFC 8949 §4.2).
9. Canonical bytes di-sign dengan Ed25519 private key pengirim. **Signature covers encrypted payload** — relay nodes bisa verify tanpa decrypt.
10. `MessageEnvelope` terbentuk (message + signature).
11. Envelope disimpan ke database lokal pengirim **sebagai plaintext** (untuk history chat sendiri).
12. Envelope (dengan encrypted payload) di-enqueue ke pending queue.
13. Node mencoba delivery langsung ke recipient (lihat §5 Routing).

### 4.5. Alur Penerimaan Pesan

Saat node menerima `WireMessage` dari jaringan, validation pipeline berjalan:

1. Register `sender_pubkey` ke `pubkey_book` (untuk E2E encryption pada reply nanti).
2. Verify `SHA3-256(sender_pubkey) == envelope.message.sender` (pubkey-address binding).
3. Verify Ed25519 signature atas canonical CBOR bytes (**sebelum** dekripsi — signature covers encrypted payload).
4. Validasi timestamp skew: asimetris — strict untuk timestamp masa depan (max 10 menit), lenient untuk masa lalu (max 30 menit, mengakomodasi relay delay).
5. Cek nonce replay detection (bounded FIFO cache, 10.000 entries).
6. **E2E decryption** (jika payload memiliki magic header `[0xE2, 0xE0]`):
   - Parse header: extract ephemeral pubkey (32 bytes), nonce (24 bytes), ciphertext.
   - Convert recipient Ed25519 keypair → X25519 static secret.
   - ECDH: `shared_secret = recipient_x25519_secret × ephemeral_pubkey`.
   - HKDF-SHA256: `session_key = HKDF(shared_secret, same salt, same info)`.
   - XChaCha20-Poly1305: `plaintext = Decrypt(session_key, nonce, ciphertext)`.
   - Jika decryption gagal → store raw bytes (GUI tampilkan `[encrypted: N bytes]`).
7. Jika payload **tidak** memiliki magic header → treated as plaintext (backward compatible).
8. Jika semua lolos → emit `NetworkEvent::MessageReceived`.
9. Store **plaintext** ke database (bukan ciphertext).
10. Return `Ack::Ok` ke pengirim.

Jika validasi gagal, ACK yang sesuai dikembalikan: `InvalidSignature`, `InvalidNonce`, `InvalidTimestamp`, atau `DecryptionFailed`.

### 4.6. Wire Protocol

Komunikasi antar node menggunakan libp2p request-response dengan CBOR codec:

- Protocol ID: `/bitevachat/msg/1.0.0`
- Request: `WireMessage { envelope: MessageEnvelope, sender_pubkey: [u8; 32] }`
- Response: `Ack` (Ok | InvalidSignature | InvalidNonce | InvalidTimestamp | DecryptionFailed)

### 4.7. Enkripsi End-to-End (E2E)

Bitevachat mengimplementasikan enkripsi end-to-end berbasis ephemeral X25519 ECDH dengan XChaCha20-Poly1305 AEAD. Relay node yang meneruskan pesan **tidak dapat membaca isi pesan** — mereka hanya melihat opaque ciphertext.

#### 4.7.1. Arsitektur Kriptografi

```
Sender (Alice)                              Recipient (Bob)
    │                                           │
    │ 1. ephemeral = X25519.generate()          │
    │ 2. bob_x25519 = Ed25519→Montgomery(bob_pk)│
    │ 3. shared = ECDH(ephemeral, bob_x25519)   │
    │ 4. session_key = HKDF-SHA256(             │
    │      IKM=shared,                          │
    │      salt="Bitevachat-E2E",               │
    │      info=alice_pk||bob_pk)               │
    │ 5. nonce = random 24 bytes                │
    │ 6. ciphertext = XChaCha20-Poly1305(       │
    │      key=session_key, nonce, plaintext)    │
    │ 7. payload = [magic][ver][eph_pk][nonce][ct]│
    │ 8. sign(canonical_cbor(Message{payload}))  │
    │                                           │
    │── WireMessage(encrypted payload) ────────▶│
    │                                           │
    │                1. verify signature          │
    │                2. detect magic [0xE2][0xE0] │
    │                3. bob_x25519 = Ed25519→X25519(bob_kp)
    │                4. shared = ECDH(bob_x25519, eph_pk)
    │                5. session_key = HKDF(same params)
    │                6. plaintext = Decrypt(session_key, nonce, ct)
    │                7. store plaintext to DB     │
```

#### 4.7.2. E2E Payload Binary Format

Saat E2E aktif, field `payload_ciphertext` dalam `Message` berisi:

```
Offset  Bytes  Field
──────  ─────  ─────────────────────────────────
 0      2      Magic header: [0xE2, 0xE0]
 2      1      Version: 0x01
 3      32     Sender's ephemeral X25519 public key
35      24     XChaCha20-Poly1305 nonce
59      N+16   Ciphertext (N bytes plaintext + 16 bytes Poly1305 tag)
```

Total overhead: 59 bytes header + 16 bytes auth tag = 75 bytes per pesan.

Saat magic header tidak ada, payload diperlakukan sebagai plaintext legacy.

#### 4.7.3. Security Properties

- **Forward secrecy per-message**: setiap pesan menggunakan ephemeral X25519 keypair yang di-generate dan di-discard. Compromise long-term key tidak mengungkapkan pesan yang sudah dikirim.
- **Context binding**: HKDF `info` parameter berisi `sender_pk || recipient_pk`, mengikat session key ke pasangan komunikasi spesifik.
- **Authenticated encryption**: Poly1305 tag mendeteksi tampering pada ciphertext.
- **Relay opacity**: relay node memverifikasi signature (yang covers encrypted payload) tanpa bisa membaca isi pesan.
- **Deterministic nonce domain**: 24-byte nonce space (XChaCha20) membuat collision probability negligible bahkan tanpa nonce counter.

#### 4.7.4. Backward Compatibility

- Pesan lama (plaintext, tanpa magic header) tetap bisa dibaca oleh semua node.
- Jika recipient pubkey belum diketahui (pesan pertama ke kontak baru), pesan dikirim sebagai plaintext. Setelah recipient membalas (atau Identify handshake terjadi), pubkey dipelajari dan enkripsi aktif untuk pesan berikutnya.
- Old nodes yang kirim plaintext → new nodes terima normal.
- New nodes yang kirim encrypted → old nodes melihat `[encrypted: N bytes]` di GUI.

#### 4.7.5. Pubkey Learning

Agar E2E bisa berfungsi, sender harus mengetahui Ed25519 public key recipient. Pubkey dipelajari dari:

1. **WireMessage.sender_pubkey** — setiap pesan masuk membawa pubkey pengirim.
2. **Identify handshake** — setiap koneksi baru mengungkapkan pubkey peer.

Mapping disimpan di `pubkey_book` (in-memory HashMap). Implikasi: pesan pertama ke kontak yang belum pernah berkomunikasi dikirim sebagai plaintext. Setelah kontak membalas atau terkoneksi ke jaringan yang sama, E2E aktif otomatis.

#### 4.7.6. Enkripsi Transport (Layer Tambahan)

Selain E2E, semua koneksi peer-to-peer juga dienkripsi oleh Noise Protocol (terintegrasi di libp2p). Ini memberikan perlindungan ganda:

- **Noise Protocol** — melindungi dari eavesdropping di level transport (antara dua node yang connected langsung atau via relay circuit).
- **E2E (X25519+XChaCha20)** — melindungi dari relay node yang meneruskan pesan dan dari siapapun yang mengakses database node perantara.

---

## 5. Jaringan dan Routing

### 5.1. Libp2p Stack

Bitevachat menggunakan libp2p sebagai networking layer dengan behaviour gabungan:

- **Kademlia DHT** — peer routing dan record storage (Address → PeerId mapping).
- **Request-Response** — direct messaging (WireMessage/Ack).
- **Gossipsub** — pub/sub untuk metadata broadcasting (presence, profile updates).
- **mDNS** — LAN peer discovery (automatic, tanpa internet).
- **Relay Client** — connect melalui relay node saat di belakang NAT.
- **Relay Server** — (opsional) melayani relay circuit untuk node lain.
- **AutoNAT** — deteksi otomatis apakah node publicly reachable atau behind NAT.
- **DCUtR** — Direct Connection Upgrade through Relay (hole punching).
- **Identify** — exchange metadata (public key, listen addresses, protocol support) saat koneksi baru.

### 5.2. Routing dan Delivery

Saat node ingin mengirim pesan ke address tertentu, terdapat fallback chain bertingkat:

**Strategi 1: Direct Delivery**
Node cek address book (HashMap Address → PeerId). Jika recipient ditemukan DAN sedang connected, kirim langsung via request-response.

**Strategi 2: Relay Dial**
Jika recipient dikenal tapi tidak connected, node mencoba dial melalui relay circuit. Pesan akan di-retry dari pending queue setelah connection established.

**Strategi 3: Store-and-Forward (Relay Forward)**
Jika direct delivery dan relay dial gagal, node mengirim pesan ke connected relay/public node. Relay node menerima pesan, validasi signature, lalu:
- Jika recipient connected ke relay → forward langsung.
- Jika recipient offline → simpan di mailbox in-memory.
- Cross-relay forward → kirim ke relay node lain yang mungkin punya recipient.

### 5.3. Store-and-Forward Mailbox

Public/relay node memiliki mailbox in-memory untuk menyimpan pesan yang belum bisa dikirim:

```
Node B (NAT)      Public C      Public F      Node A (NAT)
    │                │             │               │
    │── msg(to=A) ──▶│             │               │
    │  ◀── Ack::Ok ──│             │               │
    │                │ A connected? NO             │
    │                │ mailbox.store(A, msg)       │
    │                │── cross-relay ──▶│           │
    │                │             │ A connected? YES
    │                │             │── msg(to=A) ──▶│ ✓
```

Spesifikasi mailbox:
- Per-recipient FIFO queue, max 256 pesan per recipient (configurable).
- Global max 10.000 pesan total (configurable).
- TTL 1 jam — pesan expired di-purge saat maintenance tick (configurable).
- FIFO eviction saat per-recipient limit tercapai.
- In-memory only — bukan persistent storage. Sender's pending queue yang handle durable retry.

### 5.4. Cross-Relay Forwarding

Jika dua node private menggunakan relay yang berbeda, pesan tetap bisa terkirim melalui cross-relay forwarding:

Saat relay node C tidak bisa deliver (recipient tidak connected), ia:
1. Simpan di mailbox lokal.
2. Forward ke semua relay node lain yang connected (kecuali source peer, untuk mencegah bounce-back).
3. Relay node F menerima → cek ForwardCache (dedup) → cek apakah recipient connected → deliver atau mailbox.

**ForwardCache** mencegah infinite forwarding loop: bounded HashSet + FIFO eviction (10.000 entries), keyed by message_id. Jika message ID sudah ada di cache → silently drop.

### 5.5. Auto-Relay Discovery

Node tidak perlu mengetahui relay node sebelumnya. Saat Identify handshake selesai, node otomatis:
1. Cek apakah peer advertise relay hop protocol (`/libp2p/circuit/relay/0.2.0/hop`).
2. Cek apakah peer memiliki IP publik (bukan private/loopback/link-local/CGNAT).
3. Jika kedua syarat terpenuhi → otomatis register sebagai relay node + listen relay circuit.

Ini memungkinkan node publik baru yang join jaringan langsung membantu relay untuk semua node private yang connected.

### 5.6. DNS Seed Discovery

Bootstrap node discovery menggunakan DNS SRV records, menggantikan hardcoded IP list:

1. Node query `_bitevachat._tcp.seed.bitevacapital.id` untuk SRV records.
2. Setiap SRV target di-resolve ke A/AAAA records.
3. Build multiaddr `/ip4/<ip>/tcp/39812` dari hasil resolusi.
4. Sort by SRV priority (ascending) lalu weight (descending).
5. Merge dengan fallback hardcoded nodes + config bootstrap_nodes.
6. Dedup dan cap di 64 entries.

Fallback chain: DNS SRV → bare domain A/AAAA → hardcoded FALLBACK_BOOTSTRAP_NODES → user config. DNS failure tidak pernah fatal — node tetap bisa start.

Semua node di jaringan Bitevachat menggunakan port standar **39812/TCP**.

Setup DNS zone:
```
_bitevachat._tcp.seed.bitevacapital.id.  SRV  10 10 39812 node1.seed.bitevacapital.id.
node1.seed.bitevacapital.id.              A    82.25.62.154
```

### 5.7. Peerless Bootstrap

Multiaddr bootstrap tanpa `/p2p/<peer_id>` (peerless) didukung penuh:
1. Node dial alamat IP langsung tanpa mengetahui PeerId.
2. Setelah TCP connected, Noise handshake → Identify protocol.
3. Identify mengungkapkan PeerId + public key peer.
4. PeerId ditambahkan ke Kademlia routing table secara otomatis.
5. Kademlia bootstrap di-trigger.

Ini memungkinkan DNS seed bekerja tanpa menyimpan PeerId di DNS records (yang bisa berubah saat node restart).

### 5.8. Self-Dial Prevention

Node publik yang juga ada di fallback bootstrap list diproteksi dari self-dial:
- Filter by PeerId (jika ada `/p2p/` component).
- Filter by IP address match (bandingkan dengan listener IPs, port-agnostic).
- libp2p sendiri juga reject self-dial di level transport ("tried to dial local peer id").

### 5.9. NAT Traversal

Strategi NAT traversal berlapis:

1. **AutoNAT** — detect apakah node publicly reachable. Confidence max 3 probes.
2. **Relay Client** — listen pada relay circuit (`/p2p-circuit`). Relay server menerima reservation.
3. **DCUtR** — hole punching: setelah relay circuit established, DCUtR otomatis upgrade ke direct connection jika memungkinkan.
4. **TURN** — fallback terakhir (stub, belum diimplementasi).

---

## 6. Anti-Spam dan Trust

### 6.1. Spam Filter Pipeline

Setiap pesan masuk melewati filter bertingkat:

1. **Blocklist** — address yang di-block oleh user ditolak langsung.
2. **Rate Limiter** — batas jumlah pesan per sender per window waktu.
3. **Trust Score** — sender dikategorikan: Unknown, Low, Medium, High.
4. **Proof-of-Work** — sender Unknown tanpa PoW ditolak. Sender yang sudah verified oleh network (signature + timestamp + nonce) otomatis dipromosikan melewati requirement PoW.

### 6.2. Trust Promotion

Sender otomatis dipromosikan dari Unknown ke level yang lebih tinggi jika:
- Sender adalah known contact (user secara eksplisit menambahkan).
- Sender sudah diverifikasi oleh network layer (Ed25519 signature, pubkey→address binding, timestamp skew, nonce replay — semua check sudah passed sebelum sampai ke spam filter).

### 6.3. Filter Results

- `Accept` — pesan diterima dan diproses.
- `RateLimit` — sender di-rate limit, pesan ditolak.
- `Blocked` — sender di blocklist.
- `PowRequired` — sender Unknown, PoW diperlukan.
- `Reject { reason }` — ditolak dengan alasan spesifik.

---

## 7. Penyimpanan (Storage)

### 7.1. Message Database

Pesan disimpan di LMDB (Lightning Memory-Mapped Database), dienkripsi at rest. Setiap pesan tersimpan sebagai `StoredMessage`:

```
StoredMessage {
    sender:              [u8; 32]
    recipient:           [u8; 32]
    message_id:          [u8; 32]
    convo_id:            [u8; 32]
    timestamp_millis:    i64
    payload_type:        u8 (0=Text, 1=File, 2=System)
    payload_ciphertext:  Vec<u8>
    nonce:               [u8; 12]
    signature:           Vec<u8>
}
```

### 7.2. Conversation ID

Conversation ID dihitung secara deterministic dari kedua address:

```
ConvoId = SHA3-256(min(A, B) || max(A, B))
```

Ini memastikan kedua peserta menghitung ConvoId yang sama, terlepas dari siapa sender dan siapa recipient.

### 7.3. Contact Store

Menyimpan daftar kontak pengguna: address, alias (opsional), status blocked. Tersimpan di LMDB.

### 7.4. Pending Queue (pending.dat)

Pesan yang belum terkirim disimpan di file `pending.dat`, terenkripsi di disk:

- Setiap entry berisi: `MessageEnvelope`, retry count, last attempt timestamp, created_at, recipient address.
- Retry dengan exponential backoff (cap 60 menit).
- Pesan expired setelah 7 hari otomatis di-purge.
- Global max 5.000 entries.
- Pending scheduler tick setiap 30 detik, mengecek pesan yang ready untuk retry.

---

## 8. Profil Pengguna

### 8.1. Informasi Profil

Pengguna bisa mengatur profil publik:
- Nama (display name)
- Bio
- Avatar (foto profil)

Semua informasi ini opsional — pengguna bisa tetap anonim. Jika tidak diset, yang tampil di GUI hanya address.

### 8.2. Distribusi Profil

Profil didistribusikan melalui Gossipsub:
- Topic: `profile-updates`
- Profil di-sign oleh pemilik (Ed25519 signature) untuk mencegah pemalsuan.
- Profil di-cache oleh node lain di `ProfileManager`.
- Saat node online, profil disebarkan via gossip. Saat offline, node lain hanya melihat address.

### 8.3. Presence

Status online/offline dibroadcast melalui gossip topic `presence`. Node yang connected ke jaringan dianggap online.

---

## 9. GUI Desktop

### 9.1. Arsitektur GUI

```
┌──────────────┐  UiCommand   ┌───────────┐    ┌──────────────────┐
│  eframe UI   │ ────────────▶│ RPC Bridge │───▶│  Embedded Node   │
│ (main thread) │ ◀──────────── │            │    │  + RPC Server    │
└──────────────┘  UiEvent     └───────────┘    └──────────────────┘
```

- GUI berjalan di main thread (eframe/egui).
- Node dan RPC bridge berjalan di background thread (tokio runtime, 4 worker threads).
- Komunikasi via bounded mpsc channels: `UiCommand` (GUI→Node) dan `UiEvent` (Node→GUI).

### 9.2. Tampilan Onboarding

Saat pertama kali buka (belum ada wallet):
1. **Detect** — cek apakah file wallet sudah ada.
2. **Create** — generate seed phrase baru (24 kata BIP39), tampilkan ke user, minta passphrase.
3. **Import** — user memasukkan seed phrase yang sudah ada + passphrase.

Jika wallet sudah ada, langsung ke tampilan **Unlock** — masukkan passphrase.

### 9.3. Tampilan Utama

Setelah wallet unlocked dan node started:

**Navigation Bar (atas):**
- Tab: Chat, Contacts, Profile, Settings
- Status indicator: connected/disconnected, pending message count

**Chat View:**
- Sidebar kiri (260px): daftar conversation (avatar, nama/alias, address truncated), tombol "+ New" untuk memulai chat baru, own address dengan tombol Copy.
- Panel kanan: header (nama + address recipient), area pesan (scroll, bubble chat kiri/kanan), input bar (textbox + tombol Send).
- Optimistic send: pesan langsung muncul di UI saat dikirim, tanpa menunggu server roundtrip.

**Contacts View:**
- Daftar kontak dengan avatar, alias, address.
- Tombol Add, Block/Unblock, Chat (langsung buka chat dengan kontak tersebut).

**Profile View:**
- Edit nama, bio, avatar.
- Disimpan dan dibroadcast via gossip.

**Settings View:**
- Data directory, RPC endpoint.

### 9.4. Penanganan Pesan di GUI

- Pesan ditampilkan dalam urutan database insertion (urutan diterima), bukan timestamp asli pengirim. Ini mencegah pesan delayed via relay menggeser posisi pesan yang sudah tampil.
- Polling setiap 3 detik untuk update, dengan dedup (hanya re-render jika ada perubahan).
- Smart merge: optimistic messages digabungkan dengan server-confirmed messages. Optimistic message yang sudah confirmed otomatis dihapus.
- Scroll otomatis ke bawah hanya saat ada pesan baru, bukan saat polling refresh.

---

## 10. Daemon (Headless)

Node bisa dijalankan tanpa GUI sebagai daemon untuk server/VPS:

```bash
# Pertama kali: buat wallet
bitevachat-daemon --new-wallet --listen /ip4/0.0.0.0/tcp/39812

# VPS relay node
bitevachat-daemon --relay-server --no-mdns --listen /ip4/0.0.0.0/tcp/39812

# Dengan config file
bitevachat-daemon --config /etc/bitevachat/daemon.json
```

Config file (JSON):
```json
{
  "data_dir": "/opt/bitevachat/data",
  "listen_addr": "/ip4/0.0.0.0/tcp/39812",
  "rpc_port": 50051,
  "relay_server": true,
  "enable_mdns": false,
  "passphrase": "my-secure-passphrase"
}
```

Passphrase juga bisa diset via environment variable `BITEVACHAT_PASSPHRASE`.

---

## 11. Event Loop

Node digerakkan oleh unified event loop menggunakan `tokio::select!`:

1. **Network Swarm** — `poll_next()` drives libp2p event processing.
2. **Network Events** — MessageReceived, DeliveryAck, PeerConnected, PeerAddressResolved, GossipMessage, NatStatusChanged, HolePunchSucceeded.
3. **Commands** — dari GUI/CLI: SendMessage, ListMessages, GetStatus, AddContact, Shutdown, dll.
4. **Pending Tick** (30 detik) — retry pesan yang belum terkirim dari pending queue.
5. **Maintenance Tick** (5 menit) — flush storage, DHT refresh, re-publish Address→PeerId, re-listen on relays, purge expired mailbox entries, log network health.
6. **Relay Listen Delay** — one-shot 5 detik setelah startup untuk attempt relay listen.
7. **Shutdown Signal** — graceful exit via watch channel.

### 11.1. Maintenance Tick Actions

- Flush storage ke disk.
- Re-publish Address→PeerId mapping ke DHT.
- Re-bootstrap Kademlia jika ada bootstrap nodes.
- Re-listen on relays jika reservation expired.
- Purge expired mailbox entries.
- Log network health: connected peers, relay status, relay node count, mailbox stats, forward cache size.

### 11.2. Shutdown Sequence

1. Stop accepting new commands.
2. Flush storage.
3. Log pending message count.
4. Exit event loop task.

---

## 12. Konfigurasi Jaringan

### 12.1. NetworkConfig

Parameter jaringan yang bisa dikonfigurasi:

| Parameter | Default | Deskripsi |
|-----------|---------|-----------|
| listen_addr | `/ip6/::/tcp/39812` | Alamat listen |
| dns_seed_domain | `seed.bitevacapital.id` | Domain DNS seed |
| dns_seed_enabled | `true` | Aktifkan DNS seeding |
| bootstrap_nodes | `[]` | Bootstrap tambahan |
| max_connections | 128 | Max koneksi simultan |
| idle_timeout_secs | 60 | Timeout koneksi idle |
| dial_timeout_secs | 10 | Timeout dial outbound |
| kad_protocol | `/bitevachat/kad/1.0.0` | Protocol Kademlia |
| kad_replication_factor | 20 | Faktor replikasi DHT |
| kad_query_timeout_secs | 30 | Timeout query DHT |
| enable_mdns | `true` | Aktifkan mDNS LAN |
| enable_autonat | `true` | Aktifkan AutoNAT |
| autonat_confidence_max | 3 | Probes sebelum confident |
| enable_relay_client | `true` | Mode relay client |
| enable_relay_server | `true` | Mode relay server |
| relay_only | `false` | Hanya via relay |
| mailbox_max_per_recipient | 256 | Max pesan/recipient di mailbox |
| mailbox_max_total | 10.000 | Max total pesan di mailbox |
| mailbox_ttl_secs | 3600 | TTL mailbox entry (1 jam) |

### 12.2. Fallback Bootstrap Nodes

Hardcoded sebagai fallback saat DNS seed gagal:

```
/ip4/82.25.62.154/tcp/39812
```

---

## 13. Keamanan

### 13.1. Verifikasi Pesan

Setiap pesan diverifikasi melalui 4 tahap sebelum diterima:
1. Pubkey→Address binding: `SHA3-256(sender_pubkey) == sender_address`.
2. Ed25519 signature verification atas canonical CBOR encoding (signature covers **encrypted** payload, sehingga relay bisa verify tanpa decrypt).
3. Timestamp skew validation (asimetris: 10 menit future, 30 menit past).
4. Nonce replay detection (FIFO cache 10.000 entries).

### 13.2. Enkripsi End-to-End

Pesan dienkripsi sebelum meninggalkan node pengirim dan hanya bisa didekripsi oleh recipient:
- Ephemeral X25519 ECDH per-message (forward secrecy).
- Session key via HKDF-SHA256 dengan context binding (sender_pk || recipient_pk).
- XChaCha20-Poly1305 AEAD dengan 24-byte random nonce.
- Relay node meneruskan opaque ciphertext — tidak bisa membaca isi.
- Database lokal menyimpan **plaintext** (setelah dekripsi) untuk kenyamanan user.

### 13.3. Relay Forwarding Security

Relay/public node yang forward pesan melakukan:
- Validasi signature (steps 1-2 di §13.1) — mencegah spam dan pesan invalid diteruskan.
- **Tidak** melakukan timestamp/nonce validation — diserahkan ke recipient akhir.
- **Tidak** bisa membaca payload — hanya melihat E2E encrypted bytes.

### 13.4. Enkripsi Transport

Semua koneksi peer-to-peer dienkripsi oleh Noise Protocol (terintegrasi di libp2p). Ini berlaku untuk TCP dan relay circuit connections. Memberikan perlindungan ganda di atas E2E.

### 13.5. Enkripsi At Rest

- Wallet: private key dienkripsi dengan XChaCha20-Poly1305 + Argon2id KDF.
- Pending queue: file `pending.dat` dienkripsi di disk.
- Storage: LMDB database dienkripsi.

### 13.6. Persistent Identity

- Wallet keypair → libp2p identity adalah deterministic.
- Selama wallet.json di-persist, PeerId stabil antar restart.
- DHT records dan relay registrations tetap valid.

### 13.7. Anonimitas

- Identitas hanya berupa keypair — tidak diperlukan informasi pribadi.
- Profil sepenuhnya opsional.
- Address tidak bisa di-trace ke identitas nyata tanpa informasi tambahan.
- Relay node tidak bisa membaca isi pesan yang diteruskan (E2E encrypted).

---

## 14. Glossary

| Istilah | Definisi |
|---------|----------|
| Address | SHA3-256 hash dari Ed25519 public key, 32 bytes |
| ConvoId | Deterministic conversation ID: SHA3-256(min(A,B) \|\| max(A,B)) |
| MessageId | SHA3-256(sender \|\| timestamp \|\| nonce) |
| NodeId | Identitas node di jaringan |
| PeerId | Identitas libp2p, diturunkan deterministik dari wallet keypair |
| Nonce | 12-byte random value untuk replay detection |
| AeadNonce | 24-byte random value untuk XChaCha20-Poly1305 (berbeda dari Nonce) |
| WireMessage | Envelope + sender_pubkey, format wire-level |
| Ack | Response: Ok, InvalidSignature, InvalidNonce, InvalidTimestamp, DecryptionFailed |
| E2E | End-to-end encryption: ephemeral X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 |
| E2E Magic | Header bytes [0xE2, 0xE0] yang mengidentifikasi payload terenkripsi E2E |
| Ephemeral Key | X25519 keypair yang di-generate fresh per-message (forward secrecy) |
| Session Key | 32-byte symmetric key dari HKDF, digunakan untuk AEAD per-message |
| Pubkey Book | In-memory mapping Address → Ed25519 pubkey untuk E2E encryption |
| Mailbox | In-memory store-and-forward buffer di relay node |
| ForwardCache | Dedup cache untuk cross-relay forwarding (10K, FIFO) |
| DHT | Distributed Hash Table (Kademlia) |
| DCUtR | Direct Connection Upgrade through Relay (hole punching) |
| AutoNAT | Automatic NAT status detection |
| Gossipsub | Pub/sub protocol untuk metadata broadcasting |
| mDNS | Multicast DNS untuk LAN peer discovery |
| HKDF | HMAC-based Key Derivation Function (SHA-256) |
| ECDH | Elliptic-Curve Diffie-Hellman key agreement (X25519) |