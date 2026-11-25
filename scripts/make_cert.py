"""Self-signed TLS certificate for HTTPS on the LAN.

Phones only allow camera access + WebCrypto on HTTPS pages, so we need TLS even for a demo.
Covers localhost, 127.0.0.1 and this laptop's Wi-Fi IP. Regenerates when the IP changes.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import config

CERT = config.KEYS_DIR / "tls_cert.pem"
KEY = config.KEYS_DIR / "tls_key.pem"
IP_FILE = config.KEYS_DIR / "tls_ip.txt"


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the outgoing interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def make_cert(force: bool = False) -> None:
    ip = lan_ip()
    if not force and CERT.exists() and IP_FILE.exists() and IP_FILE.read_text() == ip:
        return
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureAttend local")])
    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    if ip != "127.0.0.1":
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    KEY.chmod(0o600)
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    IP_FILE.write_text(ip)
    print(f"TLS certificate created for localhost, {ip}")


if __name__ == "__main__":
    import sys

    if "--ip" in sys.argv:
        print(lan_ip())
    else:
        make_cert(force="--force" in sys.argv)
