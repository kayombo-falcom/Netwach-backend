FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# The network app shells out to these for live LAN scanning/probing/OS
# fingerprinting (see network/platform.py, network/os_fingerprint.py) —
# nmap's -O needs NET_ADMIN/NET_RAW (granted in docker-compose.yml), not just
# the binary being present.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iw ethtool iputils-ping nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
