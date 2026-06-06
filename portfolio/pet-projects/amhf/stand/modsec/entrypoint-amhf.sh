#!/bin/sh
# AMHF ModSec entrypoint.
#
# Strategy: replace the upstream default.conf with our amhf-rendered server
# block. This way upstream init scripts that sed on default.conf still see a
# file. The upstream entrypoint runs first (via this script's exec at the end)
# and renders /etc/nginx/templates/* — so we render our template AFTER its
# templates have been copied / updated, just before launching nginx.
#
# Easiest mechanism: drop our own /docker-entrypoint.d/99-amhf-config.sh into
# the upstream entrypoint pipeline. That script runs after all 0X / 9X scripts.
set -eu

: "${BACKEND_HOST:?BACKEND_HOST must be set (e.g. dvwa or flag-app)}"
: "${BACKEND_PORT:?BACKEND_PORT must be set (e.g. 80 or 5000)}"

# We intentionally do NOT delete amhf.conf.template here — leaving it in
# /etc/nginx/templates/ also makes the upstream envsubst render it to
# /etc/nginx/amhf.conf, but no nginx.conf includes /etc/nginx/*.conf so that
# file is harmless. Our 99 hook is the file nginx actually reads.

exec /docker-entrypoint.sh nginx -g "daemon off;"
