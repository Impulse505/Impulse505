#!/bin/sh
set -eu

: "${BACKEND_HOST:?BACKEND_HOST must be set (e.g. dvwa or flag-app)}"
: "${BACKEND_PORT:?BACKEND_PORT must be set}"

mkdir -p /etc/nginx/conf.d
envsubst '${BACKEND_HOST} ${BACKEND_PORT}' \
    < /etc/nginx/templates/amhf.conf.template \
    > /etc/nginx/conf.d/amhf.conf

exec nginx -g "daemon off;"
