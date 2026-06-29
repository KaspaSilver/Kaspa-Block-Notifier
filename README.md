# Kaspa-Block-Notifier

A Dockerized watcher that sends you a private encrypted **KaChat message** every time your Kaspa node finds a block reward.

Built on the [Kasia protocol](https://github.com/K-Kluster/Kasia) — messages are end-to-end encrypted using ephemeral ECDH + ChaCha20-Poly1305. Only you can read them.

---

## How it works

1. Connects to your local `kaspad` node via gRPC and subscribes to UTXO changes on your mining address
2. When a block reward arrives it encrypts a message using the Kasia protocol
3. Broadcasts a self-spend Kaspa transaction with the encrypted message as the payload
4. KaChat on your phone decrypts and displays the notification

Cost per notification: ~0.002 KAS in transaction fees (pure self-spend, no KAS sent anywhere).

---

## Prerequisites

- Docker + Docker Compose
- `kaspad` running with `--utxoindex` flag
- [KaChat](https://github.com/vsmirn0v/KaChat) installed on your phone
- A **bot wallet** (separate from your mining wallet) funded with ~2 KAS
- A **handshake** already completed between your bot wallet and your KaChat phone wallet

---

## Setup

### 1. Get the proto files

Download from rusty-kaspa:

```bash
mkdir proto
wget https://raw.githubusercontent.com/kaspanet/rusty-kaspa/master/rpc/grpc/core/proto/messages.proto -P proto/
wget https://raw.githubusercontent.com/kaspanet/rusty-kaspa/master/rpc/grpc/core/proto/rpc.proto -P proto/
```

### 2. Configure your environment

```bash
cp .env.example .env
nano .env
```

Fill in:
- `MINING_ADDRESS` — your kaspa mining address
- `PRIVATE_KEY_HEX` — private key of the bot wallet (not your mining wallet)
- `RECEIVER_ALIAS` — see below
- `RECEIVER_PUBKEY_X` — derive automatically:

```bash
python3 scripts/derive_pubkey.py kaspa:your_kachat_phone_address
```

#### Finding RECEIVER_ALIAS

1. Send a message **from your KaChat phone** to the bot wallet address
2. Look up that transaction on [explorer.kaspa.org](https://explorer.kaspa.org)
3. The payload will be: `ciph_msg:1:comm:{RECEIVER_ALIAS}:...`
4. Copy the alias (12 hex characters) into your `.env`

### 3. Enable `--utxoindex` on kaspad

Check your kaspad startup command:
```bash
docker inspect kaspad --format '{{json .Args}}'
```

If `--utxoindex` is missing, restart kaspad with it added.

### 4. Start the notifier

```bash
docker compose up -d
docker logs -f kaspa-block-notifier
```

---

## Bot wallet setup

The bot wallet needs:
- At least **2 KAS** to cover transaction fees
- A completed **KaChat handshake** with your phone wallet

To do the handshake: open KaChat, add the bot wallet address as a contact, and send it a message. This establishes the shared secret needed for encrypted messaging.

---

## Auto-start on boot

`restart: always` in `docker-compose.yml` handles this automatically as long as Docker starts on boot:

```bash
sudo systemctl is-enabled docker  # should say "enabled"
```

---

## Configuration reference

| Variable | Required | Description |
|---|---|---|
| `MINING_ADDRESS` | ✅ | Your mining wallet address |
| `PRIVATE_KEY_HEX` | ✅ | Bot wallet private key (hex) |
| `RECEIVER_ALIAS` | ✅ | KaChat alias for your phone |
| `RECEIVER_PUBKEY_X` | ✅ | Phone wallet public key x-coord |
| `KASPA_NETWORK` | — | `mainnet` (default) or `testnet-10` |
| `MIN_REWARD_KAS` | — | Minimum reward to trigger alert (default: 0) |
| `NODE_GRPC` | — | Override kaspad gRPC address |
| `NODE_WRPC` | — | Override kaspad wRPC websocket address |

---

## Encryption details

Messages use the [Kasia protocol](https://github.com/K-Kluster/Kasia):
- Ephemeral secp256k1 key pair generated per message
- ECDH between ephemeral private key + recipient public key
- HKDF-SHA256 (empty salt, empty info) → 32-byte ChaCha20 key
- ChaCha20-Poly1305 authenticated encryption
- Payload format: `ciph_msg:1:comm:{alias}:{base64(nonce+ephPubKey+ciphertext)}`
