# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WaaS Self-Service Portal — a Flask 3.1 / Python 3.13 web app for managing Barracuda Web Application and API Security (WaaS) resources. Users register WaaS API accounts, then browse and manage applications, certificates, proxy settings, and security logs through a UI that wraps the WaaS REST API.

## Running the Application

```bash
cd /home/admin/waas-ss-portal
source venv/bin/activate
pip install -r requirements.txt
python3 run.py                   # Starts on 0.0.0.0:5000, debug mode
```

On first run, `run.py` auto-creates database tables and seeds admin user (`admin`/`admin`).

**CLI commands:** `flask init-db`, `flask create-admin`, `flask seed`

**Environment variables:** `PORT`, `FLASK_DEBUG`, `SECRET_KEY`, `DATABASE_URL`, `WAAS_API_BASE_URL`, `WAAS_API_V2_BASE_URL`

**No test suite exists yet.** No linting or CI/CD is configured.

## Architecture

**Application factory** in `app/__init__.py` → `create_app()` initializes extensions, registers blueprints, sets up template filters and context processors.

**Config:** `config.py` has `DevelopmentConfig`, `ProductionConfig`, `TestingConfig` classes.

**Database:** SQLite via Flask-SQLAlchemy at `instance/waas-portal.db`. Models in `app/models.py`.

### Blueprint Structure (all in `app/routes/`)

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `main` | `/` | Landing page, dashboard |
| `auth` | `/auth` | Login, logout, profile, change password |
| `admin` | `/admin` | User management, audit log |
| `accounts` | `/accounts` | WaaS API account CRUD |
| `applications` | `/applications` | Browse WaaS applications per account |
| `certificates` | `/certificates` | Browse/upload certificates per account |
| `logs` | `/logs` | WAF logs, access logs, false positive analysis |
| `proxy` | `/proxy` | Proxy/backend settings per application |

### Key Modules

- `app/waas_client.py` — `WaasClient` class wrapping the Barracuda WaaS REST API (v2 + v4)
- `app/models.py` — `User`, `WaasAccount`, `AuditLog`, `ProxySession`, `SystemSettings`
- `app/forms.py` — WTForms classes (must stay in sync with templates that reference them)
- `app/encryption.py` — Fernet encrypt/decrypt for API keys stored at rest

## WaaS API Integration (Dual Versions)

| API | Base URL | Auth Header | Used For |
|-----|----------|-------------|----------|
| **v4** (primary) | `.../v4/waasapi` | `Authorization: Bearer <api_key>` | Applications, certs, logs, proxy, security config |
| **v2** (legacy) | `.../v2/waasapi` | `auth-api: <token>` (no Bearer prefix) | Account verification |

- `WaasClient.from_account(account)` — factory that picks auth method (API key or v2 email/password)
- v2 tokens are cached encrypted on `WaasAccount` and auto-refreshed when expired
- All API calls go through `_make_request()`; pass `api_version='v2'` for v2-only endpoints
- Errors raised as `WaasApiError`

## Critical Patterns & Pitfalls

- **`User.display_name` is a read-only @property** — computed from first_name/last_name/username. Never set it directly or pass to constructor.
- **`AuditLog.timestamp`** — the datetime field is `timestamp`, NOT `created_at`.
- **`WaasAccount` has no `description` field.** At least one credential type required: API key OR email+password.
- **Account ownership** — always filter by `user_id=current_user.id` when querying WaasAccount.
- **Encrypted properties** — use `account.api_key` (auto-encrypts/decrypts), never read `api_key_encrypted` directly. Same for `waas_email`, `waas_password`, `v2_auth_token`.
- **Form-template sync** — every `form.field_name` in a template must exist on the form class in `forms.py`, and vice versa.
- **POST-only actions** — delete/verify/toggle routes must be POST; use form buttons, not `<a>` tags.
- **CSRF for non-WTForms POSTs** — use `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.

## Route Pattern: Account-Scoped Resources

Applications, certificates, logs, and proxy settings are scoped to a WaaS account:
- List views take `?account_id=N` as query parameter
- Detail views use `/<int:account_id>/<resource_id>` in URL path
- Helper `get_client_for_account(account_id)` verifies ownership and returns `(WaasClient, account)` tuple

## Frontend

- Bootstrap 5.3.3 + Bootstrap Icons 1.11.3 (CDN)
- All templates extend `base.html`; override `{% block title %}` and `{% block content %}`
- Cards are the primary content container; tables use `table table-hover`
- Custom CSS in `app/static/css/style.css`, JS in `app/static/js/app.js`
- Template filters: `datetime_format`, `filesizeformat`, `epoch_ms`, `null_dash`

## Deployment

- Nginx reverse proxy in front of Flask dev server
- Gunicorn is installed but not yet configured for production
- Background run: `nohup python3 run.py > portal.log 2>&1 &`
