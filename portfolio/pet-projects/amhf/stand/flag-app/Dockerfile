# AMHF Flag-app — deterministic backend for BackendOracle markers.
# python:3.12-slim is debian-bookworm-based; /bin/echo is GNU coreutils, which is
# what subprocess.run(["/bin/echo", ...]) targets. No external network needed at runtime.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=5000

# curl: used by the docker-compose healthcheck and by smoke_stand.py via docker exec.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Materialize the path-traversal canary and the allow-list root.
RUN printf 'amhf_canary_v1\n' > /etc/amhf_canary \
    && mkdir -p /var/amhf \
    && printf 'amhf_var_sample\n' > /var/amhf/sample.txt \
    && chmod 0644 /etc/amhf_canary /var/amhf/sample.txt

EXPOSE 5000

# 2 workers x 4 threads is plenty for the smoke stand. Bind 0.0.0.0 only on amhf-net.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]
