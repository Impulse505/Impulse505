#!/bin/sh
# AMHF NAXSI entrypoint — render the amhf.conf template, then exec nginx.
set -eu

: "${BACKEND_HOST:?BACKEND_HOST must be set (e.g. dvwa or flag-app)}"
: "${BACKEND_PORT:?BACKEND_PORT must be set (e.g. 80 or 5000)}"

mkdir -p /etc/nginx/conf.d
envsubst '${BACKEND_HOST} ${BACKEND_PORT}' \
    < /etc/nginx/templates/amhf.conf.template \
    > /etc/nginx/conf.d/amhf.conf

exec /usr/local/sbin/nginx -g "daemon off;"
