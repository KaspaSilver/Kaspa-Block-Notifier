"""
kaspa-block-notifier / watcher.py
──────────────────────────────────
Sends encrypted KaChat messages on block found events.
Pure self-spend — only pays the transaction fee.
Connects to kaspad via host-gateway (Docker host).
"""

import os
import sys
import time
import logging
import asyncio
import base64
import secrets

import grpc
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, EllipticCurvePublicNumbers, generate_private_key, SECP256K1
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import messages_pb2 as pb
import messages_pb2_grpc as pb_grpc

from kaspa import (
    PrivateKey,
    Address,
    PaymentOutput,
    create_transactions,
    RpcClient,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("kaspa-notifier")

# ── Config (all from .env) ────────────────────────────────────────────────────
MINING_ADDRESS    = os.environ["MINING_ADDRESS"]
PRIVATE_KEY_HEX   = os.environ["PRIVATE_KEY_HEX"]
NODE_GRPC         = os.environ.get("NODE_GRPC", "host-gateway:16110")
NODE_WRPC         = os.environ.get("NODE_WRPC", "ws://host-gateway:17110")
NETWORK           = os.environ.get("KASPA_NETWORK", "mainnet")
MIN_REWARD_KAS    = float(os.environ.get("MIN_REWARD_KAS", "0"))
RECEIVER_ALIAS    = os.environ["RECEIVER_ALIAS"]
RECEIVER_PUBKEY_X = os.environ["RECEIVER_PUBKEY_X"]


def sompi_to_kas(sompi: int) -> float:
    return sompi / 1e8


# ── KaChat encryption (Kasia protocol) ───────────────────────────────────────

def kachat_encrypt(plaintext: str, receiver_x_hex: str) -> bytes:
    """
    Encrypt using the Kasia/KaChat protocol:
      1. Generate ephemeral secp256k1 key pair
      2. ECDH(ephemeral_private, recipient_public) → x-coordinate
      3. HKDF-SHA256(x, salt=b'', info=b'') → 32-byte key
      4. ChaCha20-Poly1305 encrypt
      5. Return: nonce(12) + compressed_ephemeral_pubkey(33) + ciphertext+tag
    """
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int(receiver_x_hex, 16)
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != 0:
        y = p - y  # KaChat always uses 0x02 (even y)
    recv_pub   = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256K1()).public_key(default_backend())
    eph_priv   = generate_private_key(SECP256K1(), default_backend())
    eph_pub_b  = eph_priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    shared     = eph_priv.exchange(ECDH(), recv_pub)
    x_coord    = shared[1:33] if len(shared) == 33 else shared[:32]
    key        = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"",
                      backend=default_backend()).derive(x_coord)
    nonce      = secrets.token_bytes(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + eph_pub_b + ciphertext


def build_payload_hex(message: str) -> str:
    encrypted   = kachat_encrypt(message, RECEIVER_PUBKEY_X)
    b64         = base64.b64encode(encrypted).decode("utf-8")
    payload_str = f"ciph_msg:1:comm:{RECEIVER_ALIAS}:{b64}"
    return payload_str.encode("utf-8").hex()


# ── Notification sender ───────────────────────────────────────────────────────

async def get_balance(rpc: RpcClient, address: str) -> float:
    try:
        resp    = await rpc.get_utxos_by_addresses({"addresses": [address]})
        entries = resp.get("entries", [])
        total   = sum(e["utxoEntry"]["amount"] for e in entries)
        return sompi_to_kas(total)
    except Exception:
        return 0.0


async def send_kachat_notification(kas_amount: float, reward_txid: str):
    try:
        private_key = PrivateKey(PRIVATE_KEY_HEX)
        public_key  = private_key.to_public_key()
        bot_address = public_key.to_address(NETWORK).to_string()

        log.info("Connecting SDK to node for notification send...")
        rpc = RpcClient(url=NODE_WRPC)
        await rpc.connect()

        balance     = await get_balance(rpc, MINING_ADDRESS)
        message     = (
            f"⛏️ Kaspa Block Found\n"
            f"Reward: {kas_amount:.8f} KAS\n"
            f"Balance: {balance:.8f} KAS"
        )
        log.info("Message: %s", message.replace("\n", " | "))
        payload_hex = build_payload_hex(message)

        utxo_resp = await rpc.get_utxos_by_addresses({"addresses": [bot_address]})
        entries   = utxo_resp.get("entries", [])
        if not entries:
            log.warning("Bot wallet empty. Fund %s with ~2 KAS.", bot_address)
            await rpc.disconnect()
            return

        spendable = [e for e in entries if not e["utxoEntry"]["isCoinbase"]]
        if not spendable:
            log.warning("No spendable UTXOs (all coinbase). Waiting for maturity.")
            await rpc.disconnect()
            return

        best_utxo  = max(spendable, key=lambda e: e["utxoEntry"]["amount"])
        input_amt  = best_utxo["utxoEntry"]["amount"]
        output_amt = max(input_amt - 200_000, input_amt // 2)

        result = create_transactions(
            network_id=NETWORK,
            entries=[best_utxo],
            outputs=[PaymentOutput(Address(bot_address), output_amt)],
            change_address=Address(bot_address),
            priority_fee=183300,
            payload=payload_hex,
        )

        for tx in result["transactions"]:
            tx.sign([private_key])
            txid = await tx.submit(rpc)
            log.info("KaChat notification sent! Fee: %d sompi  TX: %s",
                     tx.fee_amount, txid)

        await rpc.disconnect()

    except Exception as exc:
        log.error("Failed to send KaChat notification: %s", exc, exc_info=True)


# ── gRPC subscription ─────────────────────────────────────────────────────────

def subscribe_requests():
    req = pb.KaspadRequest()
    req.notifyUtxosChangedRequest.addresses.extend([MINING_ADDRESS])
    yield req
    while True:
        time.sleep(3600)


def run_watcher():
    log.info("Connecting to kaspad at %s", NODE_GRPC)
    log.info("Watching address : %s", MINING_ADDRESS)
    log.info("Min reward filter: %s KAS", MIN_REWARD_KAS)

    channel = grpc.insecure_channel(
        NODE_GRPC,
        options=[
            ("grpc.max_receive_message_length", 64 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
        ],
    )
    stub = pb_grpc.RPCStub(channel)
    log.info("Subscribed. Waiting for block rewards...")

    seen_txids       = set()
    last_notify_time = 0.0

    for resp in stub.MessageStream(subscribe_requests()):
        if resp.WhichOneof("payload") != "utxosChangedNotification":
            continue

        for entry in resp.utxosChangedNotification.added:
            amount_sompi = entry.utxoEntry.amount
            if amount_sompi == 0:
                continue

            kas = sompi_to_kas(amount_sompi)
            if kas < MIN_REWARD_KAS:
                continue

            txid = entry.outpoint.transactionId if entry.HasField("outpoint") else "unknown"
            if txid in seen_txids:
                continue
            seen_txids.add(txid)

            now = time.time()
            if now - last_notify_time < 10:
                log.info("Cooldown active, skipping duplicate block event.")
                continue
            last_notify_time = now

            log.info("Block found! +%.4f KAS  (TX: %s)", kas, txid)

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(send_kachat_notification(kas, txid))
            finally:
                loop.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    for var in ("MINING_ADDRESS", "PRIVATE_KEY_HEX", "RECEIVER_ALIAS", "RECEIVER_PUBKEY_X"):
        if not os.environ.get(var):
            log.error("Required environment variable %s is not set.", var)
            sys.exit(1)

    retry_delay = 5
    while True:
        try:
            run_watcher()
        except grpc.RpcError as exc:
            log.error("gRPC error: %s — reconnecting in %ds...", exc.details(), retry_delay)
        except Exception as exc:
            log.error("Unexpected error: %s — reconnecting in %ds...", exc, retry_delay)
        time.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, 60)


if __name__ == "__main__":
    main()
