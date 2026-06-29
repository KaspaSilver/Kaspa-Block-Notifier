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

# Setup

Download file and run
```
cd ~/kaspa-block-notifier
docker compose up -d --build
docker logs -f kaspa-block-notifier
```
