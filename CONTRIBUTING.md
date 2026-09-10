# Contributing

This backend is a **modular monolith**: one Django/DRF app, one PostgreSQL database,
one deploy — but organized internally as independent business modules instead of
technical layers. Each module owns its own models, business logic, and API surface,
and modules talk to each other through narrow, explicit seams instead of reaching
into each other's tables directly.

## Module layout

Every business module (`users/`, `authorization/`, `authentication/`, and any new
one you add) follows the same skeleton:

```
<module>/
  apps.py            # AppConfig — name = "<module>"
  models.py           # DB tables this module owns
  repositories.py      # all ORM queries for this module's models go through here
  services.py            # business logic / rules — NOT in views or serializers
  serializers.py           # thin — request/response shape only
  views.py                  # thin — call a service, return Response
  permissions.py              # only if the module needs its own DRF permission classes
  urls.py                      # included from netwatch_backend/urls_v1.py
  migrations/
  tests/
```

`shared/` is a plain Python package (not a registered Django app — no models) for
cross-cutting infra used by every module's repositories, e.g. `BaseRepository`.

## Where logic goes

- **Models** hold entity invariants (e.g. `User.is_locked_out()`, `User.set_password()`).
- **Repositories** are the only place raw ORM queries (`Model.objects...`) happen.
- **Services** hold business rules and orchestrate repositories — this is where a
  view's request gets turned into a decision. Services raise plain DRF exceptions
  (`rest_framework.exceptions.ValidationError`, `AuthenticationFailed`, etc.) —
  no bespoke exception hierarchy, DRF's default handler already renders these.
- **Serializers** validate input shape and format only — no DB writes, no business
  rules. `create()`/`update()` delegate to a service.
- **Views** are thin: parse/validate input via a serializer, call a service, return
  a `Response`. No business logic, no direct `Model.objects` calls.

## Cross-module dependencies

Keep these as thin and one-directional as possible:

- `authentication` → `users` (needs `User`/`UserRepository` to authenticate)
- `users` → `authorization` (role validation, `HasPermission`)
- `authorization` → `users` — one narrow, explicit exception: checking whether a
  role is still in use before deleting it. This is the seam to replace with an
  API/event call if `authorization` is ever split into its own service.

A new module should only need `authorization.permissions.HasPermission` /
`authorization.repositories.RoleRepository` for RBAC — never import another
module's `models.py` directly; go through its `repositories.py`.

## Adding a new module

1. Copy the skeleton above under a new top-level directory (e.g. `devices/`).
2. Add it to `INSTALLED_APPS` in `netwatch_backend/settings.py`.
3. Wire its `urls.py` into `netwatch_backend/urls_v1.py`:
   `path('devices/', include('devices.urls'))`.
4. Write the model, then `python manage.py makemigrations devices`.

## Day-to-day loop

```bash
# after changing a model
python manage.py makemigrations <app_name>
python manage.py migrate

# run tests for one module, or everything
python manage.py test <app_name>
python manage.py test

# see it live
docker compose up                 # full stack (API + Postgres)
python manage.py runserver        # API only, if Postgres is reachable directly
```

Before committing:

```bash
python manage.py makemigrations --check
python manage.py test
```


## Code comments

Most code needs no comment at all — well-named functions and variables already say what it does. Only add one when the *why* isn't obvious from the code itself: a non-obvious constraint, a workaround, a gotcha. When a comment is warranted, keep it short, clear, plain language — one line covers most cases; avoid jargon and long sentences.

## API versioning

All routes live under `/api/v1/...`, aggregated in `netwatch_backend/urls_v1.py`.
A future breaking change to a module's API gets a new `netwatch_backend/urls_v2.py`
rather than changing `v1` in place.
