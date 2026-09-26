"""Signs, sends, and times the transactions of one campaign phase (script/measure_l2.sh).

Usage: l2_send.py <steps.json> <results.jsonl>
Environment: L2_RPC_URL, OWNER_KEY_FILE, APPLICANT_KEY_FILE. Neither the URL nor a key is printed.

Each step of contracts/script/L2Campaign.s.sol is signed with `cast mktx` (nonce, fees, and gas limit
from the node), sent with eth_sendRawTransaction, and polled every 50 ms. Base serves receipts of
preconfirmed transactions (Flashblocks) before their block is sealed, so two times are recorded:
tReceiptMs, from sending to the first receipt, and tInclMs (t_incl), from sending until the block
named in the receipt can be read with the same hash. Steps are sent one after another, each after
the previous one's inclusion. A step with a failed receipt, or a contract created at an unexpected address, stops
the campaign.
"""

import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request

POLL_S = 0.05
RECEIPT_TIMEOUT_S = 180
# Statements carry t_att from the block the phase was simulated on; a node behind it estimates gas at
# an earlier timestamp and sees AttestationFromFuture. Signing is retried at one-second intervals.
MKTX_ATTEMPTS = 10


class RpcError(Exception):
    pass


def ssl_context():
    """Certificate verification stays on. A Python without a CA bundle of its own (python.org builds
    on macOS) falls back to the system bundle."""
    ctx = ssl.create_default_context()
    if not ssl.get_default_verify_paths().cafile and os.path.exists("/etc/ssl/cert.pem"):
        ctx.load_verify_locations("/etc/ssl/cert.pem")
    return ctx


SSL = ssl_context()


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(os.environ["L2_RPC_URL"], data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": "pprev-measure"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=SSL) as resp:
            out = json.load(resp)
    except Exception as e:  # the exception text may carry the URL
        raise RpcError(f"{method}: {type(e).__name__}") from None
    if "error" in out:
        raise RpcError(f"{method}: {out['error'].get('message', 'error')}")
    return out["result"]


def key(role):
    return open(os.environ[f"{role.upper()}_KEY_FILE"]).read().strip()


def mktx(step):
    # Options go first: `--create` is a subcommand and takes what follows as its arguments.
    cmd = ["cast", "mktx", "--value", step["value"], "--private-key", key(step["from"]),
           "--rpc-url", os.environ["L2_RPC_URL"]]
    if step["to"] is None:
        cmd += ["--create", step["data"]]
    else:
        cmd.append(step["to"])
        if step["data"] != "0x":
            cmd.append(step["data"])
    for attempt in range(1, MKTX_ATTEMPTS + 1):
        done = subprocess.run(cmd, capture_output=True, text=True)
        if done.returncode == 0:
            return done.stdout.strip(), attempt
        time.sleep(1)
    # cast's message may include the URL; report only the step.
    sys.exit(f"cast mktx failed for {step['label']} after {MKTX_ATTEMPTS} attempts (exit {done.returncode})")


def calldata_gas(data):
    return sum(4 if b == 0 else 16 for b in data)


def latest_timestamp():
    return int(rpc("eth_getBlockByNumber", ["latest", False])["timestamp"], 16)


def main():
    plan = json.load(open(sys.argv[1]))
    out = open(sys.argv[2], "a")
    if "notBefore" in plan:
        while latest_timestamp() < plan["notBefore"]:
            time.sleep(1)
    for step in plan["steps"]:
        raw, attempts = mktx(step)
        sent_unix_ms = int(time.time() * 1000)
        t0 = time.perf_counter()
        tx_hash = rpc("eth_sendRawTransaction", [raw])
        receipt = None
        while receipt is None:
            if time.perf_counter() - t0 > RECEIPT_TIMEOUT_S:
                sys.exit(f"{step['label']}: no receipt within {RECEIPT_TIMEOUT_S} s")
            time.sleep(POLL_S)
            receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        t_receipt_ms = (time.perf_counter() - t0) * 1000
        block = None
        while block is None or block.get("hash") != receipt["blockHash"]:
            if time.perf_counter() - t0 > RECEIPT_TIMEOUT_S:
                sys.exit(f"{step['label']}: block {receipt['blockNumber']} not readable within {RECEIPT_TIMEOUT_S} s")
            block = rpc("eth_getBlockByNumber", [receipt["blockNumber"], False])
            if block is None or block.get("hash") != receipt["blockHash"]:
                time.sleep(POLL_S)
                # A preconfirmed receipt can change if the block is rebuilt; take the final one.
                receipt = rpc("eth_getTransactionReceipt", [tx_hash]) or receipt
        t_incl_ms = (time.perf_counter() - t0) * 1000
        data = bytes.fromhex(step["data"][2:])
        record = {
            "label": step["label"], "from": step["from"], "hash": tx_hash,
            "blockNumber": int(receipt["blockNumber"], 16), "blockTimestamp": int(block["timestamp"], 16),
            "status": int(receipt["status"], 16), "gasUsed": int(receipt["gasUsed"], 16),
            "effectiveGasPrice": int(receipt["effectiveGasPrice"], 16),
            "l1": {k: (int(v, 16) if isinstance(v, str) and v.startswith("0x") else v)
                   for k, v in receipt.items() if k.startswith("l1")},
            "daFootprintGasScalar": int(receipt.get("daFootprintGasScalar", "0x0"), 16),
            "blobGasUsed": int(receipt.get("blobGasUsed", "0x0"), 16),
            "contractAddress": receipt.get("contractAddress"),
            "rawTransactionBytes": (len(raw) - 2) // 2, "calldataBytes": len(data),
            "calldataGas": calldata_gas(data), "tReceiptMs": round(t_receipt_ms, 3), "tInclMs": round(t_incl_ms, 3),
            "sentAtUnixMs": sent_unix_ms, "signingAttempts": attempts,
        }
        out.write(json.dumps(record) + "\n")
        out.flush()
        if record["status"] != 1:
            sys.exit(f"{step['label']} failed on-chain: {tx_hash}")
        expected = step.get("expectCreate")
        if expected and (record["contractAddress"] or "").lower() != expected.lower():
            sys.exit(f"{step['label']}: created {record['contractAddress']}, expected {expected}")
        print(f"{step['label']}: block {record['blockNumber']}, gas {record['gasUsed']}, t_incl {record['tInclMs']:.0f} ms",
              file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except RpcError as e:
        sys.exit(f"RPC error: {e}")
