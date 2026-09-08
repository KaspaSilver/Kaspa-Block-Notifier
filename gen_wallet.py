#!/usr/bin/env python3
"""
Generate (or derive) a Kaspa wallet with the very same SDK watcher.py uses to
send, so the address always matches the one the bot will spend from.

  python gen_wallet.py --network mainnet
      -> {"privateKeyHex": "<64 hex>", "address": "kaspa:...", "network": "..."}

  python gen_wallet.py --network mainnet --from-key <64 hex>
      -> {"address": "kaspa:...", "network": "..."}   (derive only, no key echoed)

One line of JSON on stdout. Errors go to stderr with a non-zero exit, so the
caller can tell "no wallet" from "the SDK rejected this".
"""
import argparse
import json
import re
import secrets
import sys

from kaspa import PrivateKey


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or derive a Kaspa wallet.")
    parser.add_argument("--network", default="mainnet", help="mainnet or testnet-10")
    parser.add_argument("--from-key", dest="from_key", default=None, help="derive the address for this key instead of generating one")
    args = parser.parse_args()

    generated = args.from_key is None
    key = args.from_key if args.from_key is not None else secrets.token_hex(32)

    if not re.fullmatch(r"[0-9a-fA-F]{64}", key or ""):
        print("private key must be 64 hexadecimal characters", file=sys.stderr)
        return 1

    try:
        address = PrivateKey(key).to_public_key().to_address(args.network).to_string()
    except Exception as exc:  # surface the SDK's own message verbatim
        print(f"could not derive an address: {exc}", file=sys.stderr)
        return 1

    result = {"address": address, "network": args.network}
    if generated:
        result["privateKeyHex"] = key
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
