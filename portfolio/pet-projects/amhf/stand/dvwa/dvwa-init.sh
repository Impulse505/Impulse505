#!/bin/sh
# AMHF DVWA initialiser. Runs as a one-shot init container after DVWA itself
# is healthy. Posts to setup.php to create the database, then patches the
# default security level to "low" so AMHF sees a textbook-grade vulnerable app.
#
# DVWA upstream creds: admin / password.

set -eu

DVWA_BASE="${DVWA_BASE:-http://dvwa}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-password}"

echo "[dvwa-init] waiting for ${DVWA_BASE}/login.php ..."
for i in $(seq 1 60); do
    if curl -fsS -o /dev/null "${DVWA_BASE}/login.php"; then
        echo "[dvwa-init] DVWA is up after ${i} polls."
        break
    fi
    sleep 2
done

COOKIE_JAR="$(mktemp)"
trap 'rm -f "${COOKIE_JAR}"' EXIT

echo "[dvwa-init] creating database via setup.php ..."
# DVWA's setup.php creates the schema on POST.
curl -fsS -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
    -X POST "${DVWA_BASE}/setup.php" \
    --data "create_db=Create+%2F+Reset+Database" \
    -o /dev/null || echo "[dvwa-init] setup.php POST returned non-2xx; continuing"

echo "[dvwa-init] login as ${ADMIN_USER} ..."
# Fetch the login page first to get a CSRF token (DVWA uses 'user_token').
LOGIN_HTML="$(curl -fsS -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" "${DVWA_BASE}/login.php")"
USER_TOKEN="$(echo "${LOGIN_HTML}" | grep -oE "name='user_token' value='[a-f0-9]+" | head -1 | cut -d"'" -f4)"

curl -fsS -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
    -X POST "${DVWA_BASE}/login.php" \
    --data "username=${ADMIN_USER}&password=${ADMIN_PASS}&Login=Login&user_token=${USER_TOKEN}" \
    -o /dev/null || echo "[dvwa-init] login POST returned non-2xx; continuing"

echo "[dvwa-init] setting security level to low ..."
SEC_HTML="$(curl -fsS -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" "${DVWA_BASE}/security.php")"
USER_TOKEN="$(echo "${SEC_HTML}" | grep -oE "name='user_token' value='[a-f0-9]+" | head -1 | cut -d"'" -f4)"

curl -fsS -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
    -X POST "${DVWA_BASE}/security.php" \
    --data "security=low&seclev_submit=Submit&user_token=${USER_TOKEN}" \
    -o /dev/null || echo "[dvwa-init] security POST returned non-2xx; continuing"

echo "[dvwa-init] done."
