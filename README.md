# Netwatch — Backend API

> Django REST API that scans your real LAN: device discovery, OS fingerprinting, Wi-Fi info, packet loss and DNS capture.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-6.1-092E20?logo=django&logoColor=white)
![DRF](https://img.shields.io/badge/DRF-3.18-A30000?logo=django&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![JWT](https://img.shields.io/badge/Auth-JWT-000000?logo=jsonwebtokens&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![nmap](https://img.shields.io/badge/nmap-OS_detection-4682B4)

> 🚧 Active work is on the [`development`](https://github.com/kayombo-falcom/Netwach-backend/tree/development) branch.

Powers the [Netwatch dashboard](https://github.com/kayombo-falcom/Netwatch-frontend). It is a **modular monolith**: one Django app per business area (users, authorization, authentication, network), each with its own models, repositories, services, serializers, views, URLs and tests, plus a `shared/` package. The API is versioned under `/api/v1/`.

## ✨ Features

| Area | What it does |
| --- | --- |
| Auth | JWT login, refresh and logout; custom `User` model (email + role) |
| Device discovery | LAN scan with ARP, ping, mDNS, NetBIOS and SSDP |
| OS detection | nmap fingerprinting plus extra signals |
| Hostnames & vendors | Reverse lookups and ISP/brand matching |
| Wi-Fi & adapters | Interface, signal, channel and band info (`iw`, `ip`, `ethtool`) |
| Packet loss | Ping-based link quality checks |
| DNS capture | Long-running service that logs DNS lookups on the LAN |
| ARP inspection | Optional ARP-based traffic inspection, **off by default**. Use only on a network you own. |

## 🛠 Tech Stack

| Layer | Technology |
| --- | --- |
| Language | Python 3.12 |
| Framework | Django 6.1, Django REST Framework 3.18 |
| Auth | djangorestframework-simplejwt, PyJWT |
| Database | PostgreSQL 16 (psycopg 3) |
| Config & CORS | python-dotenv, django-cors-headers |
| Network tools | nmap, iproute2, iw, ethtool, iputils-ping, raw sockets |
| DevOps | Docker Compose (host networking, `NET_ADMIN` / `NET_RAW`) |

**Docker services:** `db` (Postgres) · `web` (API) · `dns-capture` (DNS logger) · `arp-mitm` (optional, off by default)

## 🚀 Getting Started

```bash
git clone https://github.com/kayombo-falcom/Netwach-backend.git
cd Netwach-backend
git checkout development
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env            # then fill in real values
```

**Database + run locally**

```bash
docker compose up -d db         # start Postgres only
python manage.py migrate
python manage.py runserver      # http://localhost:8000
```

**Or run the full stack in Docker:** `docker compose up -d`

**Seed the admin user** (reads `ADMIN_EMAIL` / `ADMIN_PASSWORD` / `ADMIN_NAME` from `.env`; safe to re-run):

```bash
python manage.py seed_admin
```

> On Windows, enable Docker Desktop **Host Networking** and WSL2 **mirrored networking** so the container sees the real LAN. See the [frontend README](https://github.com/kayombo-falcom/Netwatch-frontend/tree/development#-windows-hosts-one-time).

## 🔐 Auth endpoints

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| POST | `/api/v1/auth/login/` | `{ "email", "password" }` | `{ "access", "refresh" }` |
| POST | `/api/v1/auth/refresh/` | `{ "refresh" }` | `{ "access", "refresh" }` |

Access tokens last 15 minutes, refresh tokens 7 days (rotating). Send `Authorization: Bearer <access>` on authenticated requests.

## 🧰 Useful commands

```bash
python manage.py makemigrations   # after changing models
python manage.py migrate          # apply migrations
python manage.py check            # validate config without a DB
python manage.py shell            # shell with models loaded
```

## 👤 Author

**Hirorims Kayombo** · [Portfolio](https://hirorims.netlify.app/) · [GitHub](https://github.com/kayombo-falcom)
