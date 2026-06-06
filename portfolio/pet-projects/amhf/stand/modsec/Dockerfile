# AMHF ModSecurity stand image.
# Base: official OWASP CRS image with nginx + libmodsecurity v3 + connector + CRS v4.
# We override the upstream config with a small nginx template that selects the
# backend by env var BACKEND_HOST (set to "dvwa" or "flag-app" at compose time).
FROM owasp/modsecurity-crs:4.25.0-nginx-alpine-lts

USER root

# envsubst is in gettext (upstream ships it); curl for the docker healthcheck.
RUN apk add --no-cache gettext curl

# Custom server block: listen 8080, proxy_pass to ${BACKEND_HOST} on its own port.
# /etc/nginx/templates/*.template are processed by the upstream entrypoint via envsubst.
COPY nginx-amhf.conf.template /etc/nginx/templates/amhf.conf.template
COPY entrypoint-amhf.sh /usr/local/bin/entrypoint-amhf.sh
# 99-amhf-config.sh runs at the very end of /docker-entrypoint.d/ — after all
# upstream init scripts have populated their files — and overwrites default.conf
# with our amhf server block (proxy + modsecurity on).
COPY 99-amhf-config.sh /docker-entrypoint.d/99-amhf-config.sh

RUN chmod +x /usr/local/bin/entrypoint-amhf.sh /docker-entrypoint.d/99-amhf-config.sh

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint-amhf.sh"]
