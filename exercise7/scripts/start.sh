#!/usr/bin/env bash
set -euo pipefail

# Start script for exercise7: starts gunicorn, ensures SSL, installs nginx site and restarts nginx.
# Usage: run inside WSL with your pyenv/venv activated so `gunicorn` is available in PATH.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$REPO_ROOT/app"
SSL_DIR="$REPO_ROOT/ssl"
NGINX_CONF_SRC="$REPO_ROOT/nginx/exercise7.conf"
NGINX_CONF_DST="/etc/nginx/sites-available/exercise7.conf"
LOG_DIR="$REPO_ROOT/logs"
WORKERS=2
BIND="127.0.0.1:8000"

echo "repo: $REPO_ROOT"

GUNICORN_CMD="$(command -v gunicorn || true)"
if [ -z "$GUNICORN_CMD" ]; then
  echo "gunicorn not found in PATH. Activate your pyenv/venv first (or install gunicorn)." >&2
  exit 1
fi

# Generate SSL if missing and helper script exists
if [ ! -f "$SSL_DIR/selfsigned.crt" ] || [ ! -f "$SSL_DIR/selfsigned.key" ]; then
  if [ -x "$REPO_ROOT/generateSSL.sh" ]; then
    echo "Generating self-signed cert..."
    "$REPO_ROOT/generateSSL.sh"
  else
    echo "SSL certs missing and generateSSL.sh not found. Please create $SSL_DIR/selfsigned.crt and .key or add generateSSL.sh." >&2
  fi
fi

mkdir -p "$LOG_DIR"
touch "$LOG_DIR/gunicorn-access.log" "$LOG_DIR/gunicorn-error.log"
chmod 640 "$LOG_DIR"/*.log || true

cd "$APP_DIR"

echo "Checking if something listens on $BIND..."
if ss -ltn 2>/dev/null | grep -q "${BIND//./\.}"; then
  echo "A process already listens on $BIND. Skipping gunicorn start."
else
  echo "Starting gunicorn (daemon)..."
  # start gunicorn as daemon and store logs under logs/
  gunicorn --workers "$WORKERS" --bind "$BIND" wsgi:app \
    --access-logfile "$LOG_DIR/gunicorn-access.log" \
    --error-logfile "$LOG_DIR/gunicorn-error.log" --daemon
  sleep 1
fi

if [ -f "$NGINX_CONF_SRC" ]; then
  echo "Installing nginx site config (requires sudo)..."
  # Copy SSL files into a path without spaces so nginx can read them reliably
  SSL_DST_DIR="/etc/ssl/exercise7"
  sudo mkdir -p "$SSL_DST_DIR"
  if [ -f "$SSL_DIR/selfsigned.crt" ]; then
    sudo cp "$SSL_DIR/selfsigned.crt" "$SSL_DST_DIR/selfsigned.crt"
  fi
  if [ -f "$SSL_DIR/selfsigned.key" ]; then
    sudo cp "$SSL_DIR/selfsigned.key" "$SSL_DST_DIR/selfsigned.key"
    sudo chmod 600 "$SSL_DST_DIR/selfsigned.key"
  fi

  # Create a safe nginx config by replacing ssl paths with copied ones
  TMP_CONF="/tmp/exercise7_nginx.conf"
  sed -e "s|ssl_certificate[[:space:]]\+.*;|ssl_certificate $SSL_DST_DIR/selfsigned.crt;|" \
      -e "s|ssl_certificate_key[[:space:]]\+.*;|ssl_certificate_key $SSL_DST_DIR/selfsigned.key;|" \
      "$NGINX_CONF_SRC" > "$TMP_CONF"

  sudo cp "$TMP_CONF" "$NGINX_CONF_DST"
  sudo ln -sfn "$NGINX_CONF_DST" /etc/nginx/sites-enabled/exercise7.conf
  echo "Testing nginx config..."
  sudo nginx -t
  echo "Restarting nginx..."
  sudo service nginx restart || sudo systemctl restart nginx || true
else
  echo "Nginx config not found at $NGINX_CONF_SRC; skipping nginx install/restart."
fi

echo "Start script finished. Check logs: $LOG_DIR/gunicorn-*.log"
echo "Test endpoints (from WSL): curl -vk https://localhost/status -k"
