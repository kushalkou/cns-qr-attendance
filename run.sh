#!/usr/bin/env bash
# One command to set up and start the server over HTTPS.
#   ./run.sh            start (creates venv, installs, seeds, makes TLS cert on first run)
#   ./run.sh --reset    wipe the database and re-seed first
set -e
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if [ ! -d .venv ]; then
  echo "Creating virtualenv…"
  "$PY" -m venv .venv
fi
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

if [ "$1" == "--reset" ]; then
  python -m scripts.seed --reset
else
  python -m scripts.seed
fi
python -m scripts.make_cert

IP=$(python -m scripts.make_cert --ip)
PORT="${PORT:-8443}"
echo
echo "  Laptop:  https://localhost:$PORT"
echo "  Phones:  https://$IP:$PORT   (same Wi-Fi; accept the certificate warning once)"
echo
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT" \
  --ssl-keyfile keys/tls_key.pem --ssl-certfile keys/tls_cert.pem
