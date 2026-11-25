"""Verify a downloaded report OFFLINE, with only the public key. No server, no database.

    python -m scripts.verify_report report-abc123.json
    python -m scripts.verify_report report-abc123.json --pub keys/report_signing_pub.pem
"""
import argparse
import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--pub", help="PEM public key (default: the one embedded in the file)")
    a = ap.parse_args()

    doc = json.load(open(a.report))
    pem = open(a.pub).read() if a.pub else doc["public_key"]
    pub = serialization.load_pem_public_key(pem.encode())
    try:
        pub.verify(base64.b64decode(doc["signature"]), canonical_json(doc["report"]))
    except InvalidSignature:
        print("INVALID: report was modified or not signed by this key")
        sys.exit(1)
    r = doc["report"]
    print(f"VALID  {r['course']['code']} session {r['session_id']} closed {r['closed_at']}")
    print(f"       {r['counts']['present']} present, {r['counts']['absent']} absent; chain head #{r['chain_head_id']}")


if __name__ == "__main__":
    main()
