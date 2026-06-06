#!/bin/sh
# Final AMHF config hook — runs at the tail of /docker-entrypoint.d/.
# By this point the upstream image has rendered its templates, generated TLS
# certs, copied modsec config, and (importantly) updated /etc/nginx/conf.d/default.conf.
# We now overwrite default.conf with our own amhf-rendered server block so
# nginx actually proxies to ${BACKEND_HOST}:${BACKEND_PORT} with ModSecurity on.
set -eu

: "${BACKEND_HOST:?BACKEND_HOST must be set (e.g. dvwa or flag-app)}"
: "${BACKEND_PORT:?BACKEND_PORT must be set (e.g. 80 or 5000)}"

mkdir -p /etc/nginx/conf.d
envsubst '${BACKEND_HOST} ${BACKEND_PORT}' \
    < /etc/nginx/templates/amhf.conf.template \
    > /etc/nginx/conf.d/default.conf

echo "[99-amhf-config] rendered default.conf for backend=${BACKEND_HOST}:${BACKEND_PORT}"
