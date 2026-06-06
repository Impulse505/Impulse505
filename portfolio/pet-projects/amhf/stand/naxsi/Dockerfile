# AMHF NAXSI stand image.
#
# Multi-stage:
#   1. builder — alpine:3.19, fetch nginx 1.26.2 source + NAXSI 1.6 source,
#      compile nginx with NAXSI as a static module.
#   2. runtime — alpine:3.19, install just enough libs to run nginx + envsubst
#      + curl (healthcheck). Copy the compiled binary and the NAXSI core rules.
#
# Pinned versions (state in stand/README.md):
#   nginx 1.26.2
#   naxsi tag 1.6 (https://github.com/wargio/naxsi)
#
# NAXSI's modern fork (after the original NBS-System project archived) lives at
# wargio/naxsi. We pin a release tag for reproducibility.

ARG NGINX_VERSION=1.26.2
ARG NAXSI_VERSION=1.6

FROM alpine:3.19 AS builder

ARG NGINX_VERSION
ARG NAXSI_VERSION

RUN apk add --no-cache \
        build-base \
        pcre-dev \
        zlib-dev \
        openssl-dev \
        linux-headers \
        curl \
        ca-certificates \
        git

WORKDIR /build

# NAXSI source — modern wargio/naxsi requires libinjection. We clone with
# --recurse-submodules so naxsi_src/libinjection is populated, and we DO NOT
# install libinjection system-wide. Reason: when NAXSI's configure detects a
# system libinjection it sets ngx_module_libs which is only honoured for
# DYNAMIC modules. We build NAXSI as a STATIC module, so we deliberately let
# its build system fall back to compiling libinjection's *.c into naxsi
# itself (the "Using submodule libinjection" branch in naxsi_src/config).
RUN ( git clone --depth 1 --recurse-submodules --branch ${NAXSI_VERSION} \
        https://github.com/wargio/naxsi.git \
      || git clone --depth 1 --recurse-submodules \
        https://github.com/wargio/naxsi.git )

# nginx source.
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
        -o nginx.tar.gz \
    && tar xzf nginx.tar.gz \
    && rm nginx.tar.gz

WORKDIR /build/nginx-${NGINX_VERSION}

# Configure nginx with NAXSI as a STATIC module (simpler than dynamic for a
# pinned image). Keep the feature set minimal — no http_v2, no mail, etc.
RUN ./configure \
        --prefix=/usr/local/nginx \
        --sbin-path=/usr/local/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --with-http_ssl_module \
        --with-http_realip_module \
        --add-module=/build/naxsi/naxsi_src \
    && make -j"$(nproc)" \
    && make install


FROM alpine:3.19 AS runtime

RUN apk add --no-cache pcre zlib openssl gettext curl ca-certificates bash \
    && mkdir -p /etc/nginx /etc/nginx/templates /etc/nginx/naxsi \
                /var/log/nginx /var/cache/nginx \
                /usr/local/nginx/client_body_temp \
                /usr/local/nginx/proxy_temp \
                /usr/local/nginx/fastcgi_temp \
                /usr/local/nginx/uwsgi_temp \
                /usr/local/nginx/scgi_temp

# Compiled binary and core rules.
COPY --from=builder /usr/local/sbin/nginx /usr/local/sbin/nginx
COPY --from=builder /build/naxsi/naxsi_rules/ /etc/nginx/naxsi/

# Custom config.
COPY nginx.conf /etc/nginx/nginx.conf
COPY naxsi.conf /etc/nginx/naxsi.conf
COPY amhf.conf.template /etc/nginx/templates/amhf.conf.template
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
