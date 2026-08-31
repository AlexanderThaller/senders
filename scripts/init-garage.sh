#!/usr/bin/env bash
# One-time setup for the local Garage node: form a cluster of one, create the
# bucket, and mint an access key. Writes deploy/garage.env for docker compose.
set -euo pipefail

cd "$(dirname "$0")/.."
BUCKET=${BUCKET:-senders}
KEY_NAME=${KEY_NAME:-senders-dev}
garage() { docker compose exec -T garage /garage "$@"; }

echo "waiting for garage to accept commands…"
for _ in $(seq 1 30); do
  if garage status >/dev/null 2>&1; then break; fi
  sleep 1
done

NODE_ID=$(garage node id -q | cut -d@ -f1)
echo "node ${NODE_ID}"

if ! garage layout show | grep -q "$NODE_ID"; then
  garage layout assign -z dev -c 5G "$NODE_ID"
  # Garage prints the exact command to enact staged changes; take the version
  # from there rather than guessing at it.
  VERSION=$(garage layout show | grep -oE 'apply --version [0-9]+' | tail -1 | awk '{print $3}')
  garage layout apply --version "${VERSION:-1}"
fi

garage bucket create "$BUCKET" 2>/dev/null || true

if ! garage key list | grep -q "$KEY_NAME"; then
  garage key create "$KEY_NAME" >/dev/null
fi
garage bucket allow --read --write --owner "$BUCKET" --key "$KEY_NAME" >/dev/null

INFO=$(garage key info --show-secret "$KEY_NAME")
ACCESS_KEY=$(echo "$INFO" | grep -oE 'GK[0-9a-f]+' | head -1)
SECRET_KEY=$(echo "$INFO" | grep -i 'Secret key:' | awk '{print $3}')

mkdir -p deploy
cat > deploy/garage.env <<ENV
AWS_ACCESS_KEY_ID=${ACCESS_KEY}
AWS_SECRET_ACCESS_KEY=${SECRET_KEY}
ENV
chmod 600 deploy/garage.env

echo "wrote deploy/garage.env for bucket '${BUCKET}'"
