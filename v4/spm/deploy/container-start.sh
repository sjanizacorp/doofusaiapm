#!/bin/sh
set -eu
set -- --db /data/posture.sqlite serve --listen-address 0.0.0.0
if [ -f /etc/doofusai/issuer.json ]; then
  set -- "$@" --issuer-config /etc/doofusai/issuer.json
fi
if [ -f /etc/doofusai/metrics.token ]; then
  set -- "$@" --metrics-token-file /etc/doofusai/metrics.token
fi
if [ -f /etc/doofusai/gateway.json ]; then
  set -- "$@" --chat-gateway-config /etc/doofusai/gateway.json
fi
if [ -f /etc/doofusai/relay.json ]; then
  set -- "$@" --relay-config /etc/doofusai/relay.json
fi
if [ -f /etc/doofusai/sso.json ]; then
  set -- "$@" --sso-config /etc/doofusai/sso.json
fi
exec python3 /opt/doofusai/app.py "$@"
