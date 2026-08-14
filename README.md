# NetWatch Backend

Django + DRF API for the NetWatch dashboard. Auth is JWT-based (`djangorestframework-simplejwt`) against a custom `accounts.User` model (email + role, no Django username/staff/superuser defaults).

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements.txt
cp .env.example .env          # then fill in real values
```

## Database

```bash
docker compose up -d db       # start Postgres only
python manage.py migrate      # apply migrations
```

## Run

```bash
python manage.py runserver    # http://localhost:8000
```

Or run the full stack (API + Postgres) in Docker:

```bash
docker compose up -d
```

## Seed the admin user

Reads `ADMIN_EMAIL` / `ADMIN_PASSWORD` / `ADMIN_NAME` from `.env`. Safe to re-run — skips if the user already exists.

```bash
python manage.py seed_admin
```

## Auth endpoints

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/auth/login/` | `{ "email", "password" }` | `{ "access", "refresh" }` |
| POST | `/api/auth/refresh/` | `{ "refresh" }` | `{ "access", "refresh" }` |

Access tokens last 15 minutes, refresh tokens 7 days (rotating). Send `Authorization: Bearer <access>` on authenticated requests.

## Other commands

```bash
python manage.py makemigrations   # generate migrations after changing models
python manage.py migrate          # apply migrations to the database
python manage.py check            # validate config without a DB connection
python manage.py shell            # interactive shell with models loaded
```
