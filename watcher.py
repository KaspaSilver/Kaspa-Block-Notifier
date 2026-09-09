"""
kaspa-block-notifier / watcher.py
──────────────────────────────────
Sends encrypted KaChat messages on block found events.
Pure self-spend — only pays the transaction fee.
Connects to kaspad via host-gateway (Docker host).
"""

from datetime import datetime
import os
import sys
import time
import logging
import asyncio
import base64
import json
import secrets
import urllib.request

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
# The stratum bridge's stats, for the {hashrate} placeholder. Same host the
# control panel reads. Absent/unreachable simply leaves the hashrate "unknown".
BRIDGE_STATS_URL  = os.environ.get("BRIDGE_STATS_URL", "http://bridge:3030/api/stats")

# What the notification says. The default now carries a hashrate line too.
#
# An env file cannot carry a real newline -- every value is one line -- so a
# literal \n in the template becomes one here.
DEFAULT_MESSAGE   = "Reward: {reward} KAS\nBalance: {balance} KAS\nHashrate: {hashrate}"
MESSAGE_TEMPLATE  = (os.environ.get("MESSAGE_TEMPLATE") or DEFAULT_MESSAGE).replace("\\n", "\n")


def sompi_to_kas(sompi: int) -> float:
    return sompi / 1e8


def format_hashrate(ghs: float) -> str:
    th = ghs / 1000.0
    if th >= 1000:
        return f"{th / 1000:.2f} PH/s"
    if th >= 1:
        return f"{th:.2f} TH/s"
    return f"{ghs:.1f} GH/s"


def fetch_pool_hashrate() -> str:
    """Total hashrate of all connected miners, read from the stratum bridge.

    The bridge reports per-worker hashrate in GH/s, so the pool total is their
    sum. Best effort: an unreachable bridge (mining off, say) yields "unknown"
    rather than holding up the notification.
    """
    try:
        with urllib.request.urlopen(BRIDGE_STATS_URL, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        workers = data.get("workers") or []
        total_ghs = sum(float(w.get("hashrate") or 0) for w in workers)
        return format_hashrate(total_ghs)
    except Exception as exc:
        log.warning("Could not read hashrate from the bridge: %s", exc)
        return "unknown"


def render_message(kas_amount: float, balance: float, reward_txid: str, hashrate: str = "unknown") -> str:
    """Fills MESSAGE_TEMPLATE in.

    A template with a placeholder this does not know would raise at the one
    moment that matters -- a block has just been found -- and the notification
    would be lost rather than late. So a bad template falls back to the default
    and says so in the log, and the message still goes out.
    """
    fields = {
        "reward": f"{kas_amount:.8f}",
        "balance": f"{balance:.8f}",
        "hashrate": hashrate,
        "txid": reward_txid,
        "address": MINING_ADDRESS,
        "network": NETWORK,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        return MESSAGE_TEMPLATE.format(**fields)
    except (KeyError, IndexError, ValueError) as exc:
        log.warning("MESSAGE_TEMPLATE could not be used (%s); sending the default message.", exc)
        return DEFAULT_MESSAGE.format(**fields)


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
    # KaChat's own on-chain identifier is `kchat:`, its own network -- not the
    # Kasia `ciph_msg:` prefix this used to write. The op name (comm) and the
    # encryption are unchanged; only the prefix moves. The indexer still reads
    # the old prefix, so this is forward-only.
    encrypted   = kachat_encrypt(message, RECEIVER_PUBKEY_X)
    b64         = base64.b64encode(encrypted).decode("utf-8")
    payload_str = f"kchat:1:comm:{RECEIVER_ALIAS}:{b64}"
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
        hashrate    = fetch_pool_hashrate()
        message     = render_message(kas_amount, balance, reward_txid, hashrate)
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


async def send_raw_message(text: str):
    """Send an arbitrary KaChat message from the wallet to the receiver.

    Used by `--send`, which the control panel drives for alerts that are not
    tied to a block (a hashrate drop, say). Same wallet, receiver and payload
    format as a block notification; only the text is different.
    """
    try:
        private_key = PrivateKey(PRIVATE_KEY_HEX)
        bot_address = private_key.to_public_key().to_address(NETWORK).to_string()

        rpc = RpcClient(url=NODE_WRPC)
        await rpc.connect()
        try:
            payload_hex = build_payload_hex(text)

            utxo_resp = await rpc.get_utxos_by_addresses({"addresses": [bot_address]})
            entries   = utxo_resp.get("entries", [])
            if not entries:
                log.warning("Bot wallet empty. Fund %s with ~2 KAS.", bot_address)
                return
            spendable = [e for e in entries if not e["utxoEntry"]["isCoinbase"]]
            if not spendable:
                log.warning("No spendable UTXOs (all coinbase). Waiting for maturity.")
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
                log.info("Message sent! Fee: %d sompi  TX: %s", tx.fee_amount, txid)
        finally:
            await rpc.disconnect()

    except Exception as exc:
        log.error("Failed to send message: %s", exc, exc_info=True)


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

    # --test sends one notification right now, with sample figures, then exits.
    # It is a real on-chain KaChat message from the funded wallet, so it proves
    # the whole setup end to end: the control panel runs it on the Setup tab.
    if "--test" in sys.argv:
        log.info("Sending a TEST notification with sample figures...")
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                send_kachat_notification(1.23456789, "test-notification-no-real-block")
            )
        finally:
            loop.close()
        log.info("Test finished. If the wallet was funded, the message is on its way to your KaChat alias.")
        return

    # --send delivers one arbitrary message and exits. The text is the argument
    # after --send, or the ALERT_MESSAGE env var. The control panel uses this to
    # send hashrate-drop alerts it detects itself.
    if "--send" in sys.argv:
        idx = sys.argv.index("--send")
        text = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else os.environ.get("ALERT_MESSAGE", "")
        if not text.strip():
            log.error("--send needs a message (an argument after it, or ALERT_MESSAGE).")
            sys.exit(1)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(send_raw_message(text))
        finally:
            loop.close()
        return

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
