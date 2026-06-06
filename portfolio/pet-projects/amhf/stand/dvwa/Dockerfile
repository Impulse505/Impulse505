# Tiny init container that POSTs to a running DVWA to create its DB and set
# security=low. Runs once, exits 0.
FROM alpine:3.19

RUN apk add --no-cache curl bash

COPY dvwa-init.sh /usr/local/bin/dvwa-init.sh
RUN chmod +x /usr/local/bin/dvwa-init.sh

CMD ["/bin/sh", "/usr/local/bin/dvwa-init.sh"]
