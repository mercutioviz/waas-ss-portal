# WaaS Self-Service Portal — Implementation Plan

*Last updated: 2026-03-09*

---

## Current Project Status

### ✅ Fully Working (Routes + Templates + Tested)

| Area | Routes | Templates | Notes |
|------|--------|-----------|-------|
| **Auth** | login, logout, profile, change_password, keepalive | login.html, profile.html, change_password.html | Password hashing, Flask-Login sessions, session timeout |
| **Main** | index (redirect), dashboard, counts | dashboard.html | `/` redirects to `/dashboard`; AJAX cert/app counts |
| **Accounts** | list, add, edit, view, verify, delete | list.html, add.html, edit.html, view.html | Full CRUD, API key encryption, account verification |
| **Admin** | index, users, user_create, user_edit, toggle_active, audit_log | index.html, users.html, user_create.html, user_edit.html, audit_log.html, panel.html | Role-based access, audit logging |
| **Applications** | list, view, create, delete, security, dns | list.html, view.html, create.html, security.html, dns.html | v4/v2 toggle, create/delete via v2, security/DNS via v4 |
| **Certificates** | list, view, upload, delete | list.html, view.html, upload.html | Per-application SNI certificates (v4), aggregated list view |
| **Logs** | index, waf, access, fp_analysis | index.html, waf.html, access.html, fp_analysis.html | Account/app selector, WAF/access log viewers |
| **Proxy** | launch, start, stop, session, waf-logs | launch.html, session.html | noVNC browser proxy sessions |

### API Version Mapping

All WaaS API calls now use the correct endpoints. Users see API version badges in the UI.

| Feature | API Version | Endpoint |
|---------|-------------|----------|
| List applications | v4 (default) or v2 (toggle) | `GET /applications/` |
| View application | v4 | `GET /applications/{name}/export/` |
| Create application | v2 | `POST /applications/` |
| Delete application | v2 | `DELETE /applications/{id}/` |
| Security config | v4 | `GET /applications/{name}/basic_security/`, `/request_limits/`, `/clickjacking_protection/`, `/data_theft_protection/` |
| Update security | v4 | `PATCH /applications/{name}/basic_security/` |
| DNS/CNAME info | v4 | Extracted from application export (`endpoints.cname`, `endpoints.domains`) |
| Certificates | v4 | `GET /applications/{name}/sni_certificates/` (per-app) |
| Account verify | v2 | `GET /accounts/` |
| WAF/access logs | v4 | `GET /applications/{name}/logs/` |

### Infrastructure In Place
- **WaasClient** (`app/waas_client.py`): Dual v2/v4 API support with correct endpoint paths, retry on 5xx, configurable timeout
- **Encryption** (`app/encryption.py`): Fernet encrypt/decrypt for API keys at rest
- **AuditLog**: Logging wired into account, application, certificate, security, and proxy operations
- **Forms**: `ApplicationCreateForm`, `CertificateUploadForm`, `WaasAccountForm`, auth forms
- **Base template**: Navbar, flash messages, Bootstrap 5.3, Bootstrap Icons, confirmation modal, session timeout modal, breadcrumb block
- **Rate limiting**: Flask-Limiter on login (5/min) and verify (10/min)
- **Account lockout**: 5 failed attempts → 15-minute lockout

---

## Implementation Phases

### Phase 1: Complete Missing Templates ✅ DONE

**Goal:** Make all existing routes functional by creating the 6 missing templates.

| # | Task | Template | Status |
|---|------|----------|--------|
| 1.1 | Certificate upload form | `certificates/upload.html` | ✅ Complete |
| 1.2 | WAF log viewer | `logs/waf.html` | ✅ Complete |
| 1.3 | Access log viewer | `logs/access.html` | ✅ Complete |
| 1.4 | False positive analysis | `logs/fp_analysis.html` | ✅ Complete |
| 1.5 | Application security config | `applications/security.html` | ✅ Complete |
| 1.6 | Application DNS info | `applications/dns.html` | ✅ Complete |

---

### Phase 2: Application Management CRUD ✅ DONE

**Goal:** Allow users to create and delete WaaS applications (not just view).

**Key findings:**
- The v4 API does not support application CRUD at the root level — create/delete use the **v2 API**
- Rename (PATCH) is documented as "Not yet supported" by the v2 API — edit deferred
- Security config is spread across 4 separate v4 endpoints (basic_security, request_limits, clickjacking, data_theft)
- Certificates are per-application in v4 (`/sni_certificates/`), not global — routes updated accordingly
- DNS/CNAME data comes from the application export, not a dedicated endpoint

| # | Task | Files Affected | Status |
|---|------|---------------|--------|
| 2.1 | Create `ApplicationCreateForm` in forms.py | `app/forms.py` | ✅ Complete |
| 2.2 | Add v2 CRUD methods to WaasClient | `app/waas_client.py` | ✅ Complete |
| 2.3 | Add create_application route (v2 API) | `app/routes/applications.py` | ✅ Complete |
| 2.4 | Add delete_application route (POST, v2 API) | `app/routes/applications.py` | ✅ Complete |
| 2.5 | Create `applications/create.html` template | `app/templates/applications/` | ✅ Complete |
| 2.6 | Update list with v2/v4 toggle, create/delete buttons | `app/templates/applications/list.html` | ✅ Complete |
| 2.7 | Update view with API version badge | `app/templates/applications/view.html` | ✅ Complete |
| 2.8 | Wire audit logging for create/delete | `app/routes/applications.py` | ✅ Complete |
| 2.9 | Fix security config to use correct v4 endpoints | `app/waas_client.py`, `security.html` | ✅ Complete |
| 2.10 | Fix DNS to extract from export data | `app/waas_client.py` | ✅ Complete |
| 2.11 | Fix certificates to use per-app SNI endpoints | `app/waas_client.py`, `app/routes/certificates.py`, templates | ✅ Complete |
| 2.12 | Fix back-navigation in security/DNS templates | `security.html`, `dns.html`, `applications.py` | ✅ Complete |
| — | ~~Edit/rename~~ | — | Deferred (v2 API "Not yet supported") |

---

### Tier 1: Error Pages, Dashboard, and Cert Warnings ✅ DONE

**Goal:** Custom error pages, dashboard enhancements, and certificate expiry warnings.

- Custom 404, 403, 500 error pages
- Dashboard stat cards with real data
- Certificate expiry warnings (30-day threshold)

---

### Tier 2: UI/UX Polish, Security Hardening, API Robustness ✅ DONE

**Goal:** Confirmation modals, breadcrumbs, form validation, search/filter, session timeout, rate limiting, account lockout, and API retry.

| # | Task | Status |
|---|------|--------|
| A | Reusable confirmation modal (replaces inline `confirm()`) | ✅ Complete |
| B | Breadcrumb navigation on 10 account-scoped templates | ✅ Complete |
| C | Client-side Bootstrap form validation on 6 form templates | ✅ Complete |
| D | Client-side search/filter on application and certificate lists | ✅ Complete |
| E | Session timeout (30 min) with 28-min warning modal and keepalive | ✅ Complete |
| F | Rate limiting via Flask-Limiter (login 5/min, verify 10/min, 429 page) | ✅ Complete |
| G | Account lockout (5 failures → 15-min cooldown) | ✅ Complete |
| H | API retry (1 retry on 502/503/504) and configurable timeout | ✅ Complete |

---

### Phase 5: WaaS App Config Templates ⬅️ NEXT

**Goal:** Allow users to save WaaS security configurations as reusable templates and apply them to one or many applications in bulk.

#### Context

Currently only `protection_mode` (Active/Passive) is editable via `PATCH /basic_security/`. The v4 API also supports updating request limits, clickjacking protection, and data theft protection through separate endpoints. Config templates capture a snapshot of these settings so users can standardize security posture across applications.

#### 5.1 — Expand Security Config Editing

Extend `WaasClient` and the security config UI to support editing all four config areas, not just protection mode.

| # | Task | Files |
|---|------|-------|
| 5.1.1 | Add `update_request_limits(app_id, data)` method | `app/waas_client.py` |
| 5.1.2 | Add `update_clickjacking_protection(app_id, data)` method | `app/waas_client.py` |
| 5.1.3 | Add `update_data_theft_protection(app_id, data)` method | `app/waas_client.py` |
| 5.1.4 | Expand security config form/template to edit all 4 areas | `app/templates/applications/security.html`, `app/forms.py` |
| 5.1.5 | Update security config route to dispatch to correct endpoint | `app/routes/applications.py` |

#### 5.2 — Config Template Model & CRUD

| # | Task | Files |
|---|------|-------|
| 5.2.1 | Create `ConfigTemplate` model | `app/models.py` |
|       | Fields: `id`, `user_id` (FK), `name`, `description`, `config_data` (JSON), `created_at`, `updated_at` |
|       | `config_data` stores: `basic_security`, `request_limits`, `clickjacking_protection`, `data_theft_protection` |
| 5.2.2 | Create `ConfigTemplateForm` | `app/forms.py` |
| 5.2.3 | Create `templates` blueprint with CRUD routes | `app/routes/templates.py` |
|       | `GET /templates/` — list user's templates |
|       | `GET /templates/create` — form to create from scratch |
|       | `POST /templates/create` — save new template |
|       | `GET /templates/<id>` — view template details |
|       | `GET /templates/<id>/edit` — edit template |
|       | `POST /templates/<id>/edit` — update template |
|       | `POST /templates/<id>/delete` — delete template |
| 5.2.4 | Create templates: `templates/list.html`, `templates/create.html`, `templates/view.html`, `templates/edit.html` | `app/templates/templates/` |
| 5.2.5 | Register blueprint, add nav link | `app/__init__.py`, `app/templates/base.html` |
| 5.2.6 | Add "Save as Template" button on security config page | `app/templates/applications/security.html` |
|       | `POST /templates/create-from-app/<account_id>/<app_id>` — snapshot current app config into new template |

#### 5.3 — Apply Template to Single Application

| # | Task | Files |
|---|------|-------|
| 5.3.1 | Add "Apply Template" dropdown/button on security config page | `app/templates/applications/security.html` |
| 5.3.2 | Add `apply_template` route | `app/routes/templates.py` |
|       | `POST /templates/<id>/apply/<account_id>/<app_id>` |
|       | Calls each WaasClient update method for the config areas in the template |
| 5.3.3 | Show diff/preview before applying (optional enhancement) | `app/templates/templates/apply_preview.html` |
| 5.3.4 | Audit log template application | `app/routes/templates.py` |

#### 5.4 — Apply Template to Multiple Applications (Bulk)

| # | Task | Files |
|---|------|-------|
| 5.4.1 | Create bulk apply page with app multi-select | `app/templates/templates/bulk_apply.html` |
|       | `GET /templates/<id>/bulk-apply?account_id=N` — shows template summary + checkboxes for all apps on account |
| 5.4.2 | Add bulk apply route | `app/routes/templates.py` |
|       | `POST /templates/<id>/bulk-apply` — accepts list of `(account_id, app_id)` pairs |
|       | Iterates through selected apps, applies template to each, collects results |
|       | Returns summary: N succeeded, M failed (with per-app error details) |
| 5.4.3 | Create results page | `app/templates/templates/bulk_results.html` |
|       | Shows per-app success/failure with expandable error details |
| 5.4.4 | Add "Apply to Multiple Apps" button on template view page | `app/templates/templates/view.html` |
| 5.4.5 | Audit log each bulk application | `app/routes/templates.py` |

#### Implementation Notes

- **Config data format:** JSON blob with top-level keys matching API endpoint names: `basic_security`, `request_limits`, `clickjacking_protection`, `data_theft_protection`. Each key's value is the dict to PATCH to that endpoint. Keys can be omitted to skip that area.
- **Template ownership:** Templates are per-user (`user_id` FK). Admin users can optionally see/use all templates (future enhancement).
- **Bulk apply safety:** Each app is applied independently so one failure doesn't block others. Rate limit API calls with a small delay between apps if needed to avoid WaaS API throttling.
- **No cross-account templates:** Templates are API-version-agnostic (v4 config structure). They can be applied to any app on any account the user owns.

---

### Phase 6: Internationalization (i18n)

**Goal:** Make the UI translatable so the portal can be used in multiple languages.

#### 6.1 — Flask-Babel Setup

| # | Task | Files |
|---|------|-------|
| 6.1.1 | Install Flask-Babel, add to `requirements.txt` | `requirements.txt` |
| 6.1.2 | Initialize Babel in `create_app()` | `app/__init__.py` |
|       | Configure `BABEL_DEFAULT_LOCALE = 'en'`, `BABEL_SUPPORTED_LOCALES = ['en', ...]` |
|       | Add locale selector function (from user preference, Accept-Language header, or session) |
| 6.1.3 | Create `babel.cfg` extraction config | `babel.cfg` |
|       | Map Jinja2 templates and Python source files for string extraction |
| 6.1.4 | Add `LOCALE` field to `User` model (nullable, defaults to `'en'`) | `app/models.py` |
| 6.1.5 | Add language selector to user profile / navbar | `app/templates/base.html`, `app/routes/auth.py` |

#### 6.2 — Mark Strings for Translation

| # | Task | Files |
|---|------|-------|
| 6.2.1 | Wrap Python flash messages and form labels with `_()` / `gettext()` | All route files in `app/routes/`, `app/forms.py` |
| 6.2.2 | Wrap template UI strings with `{{ _('...') }}` | All templates in `app/templates/` |
|       | Targets: nav labels, headings, button text, table headers, empty-state messages, error pages, modal text |
|       | Do NOT translate: user data, API field names, technical identifiers |
| 6.2.3 | Wrap JavaScript strings with a `gettext()` helper | `app/static/js/app.js` |
|       | Expose translations via a `<script>` block in `base.html` or a `/translations.js` endpoint |

#### 6.3 — Extract and Compile Translations

| # | Task | Files |
|---|------|-------|
| 6.3.1 | Run `pybabel extract` to generate `messages.pot` | `translations/messages.pot` |
| 6.3.2 | Initialize first translation catalog (e.g., `es`, `fr`, `de`, `ja`) | `translations/<lang>/LC_MESSAGES/messages.po` |
| 6.3.3 | Translate `.po` file (manual or machine-assisted) | `.po` files |
| 6.3.4 | Compile with `pybabel compile` | `.mo` files |
| 6.3.5 | Add Babel CLI commands to `CLAUDE.md` and document workflow | `CLAUDE.md` |

#### 6.4 — Language Switching

| # | Task | Files |
|---|------|-------|
| 6.4.1 | Add `/auth/set-language` POST endpoint | `app/routes/auth.py` |
|       | Saves preference to `User.locale` (if logged in) or session (if anonymous) |
| 6.4.2 | Add language dropdown in navbar (flag icons or language codes) | `app/templates/base.html` |
| 6.4.3 | Login page language selector (for unauthenticated users) | `app/templates/auth/login.html` |

#### Implementation Notes

- **Flask-Babel** handles locale selection, message extraction, and Jinja2 integration.
- **Translation workflow:** `pybabel extract` → `pybabel init/update` → translate `.po` → `pybabel compile`. This can be scripted as a Makefile target or Flask CLI command.
- **Scope of first pass:** Start with English as the base. Mark all strings in Phase 6.2 but only create one additional language initially to validate the pipeline. More languages can be added later by translating `.po` files.
- **Date/number formatting:** Flask-Babel provides `format_datetime()`, `format_decimal()`, etc. Update template filters to be locale-aware.
- **RTL support:** Not in initial scope. Can be added later with a CSS class toggle on `<html>` for Arabic/Hebrew if needed.

---

### Phase 7: Advanced Features (Future)

**Goal:** Add power-user and operational features.

| # | Task | Description |
|---|------|-------------|
| 7.1 | Log export | Download WAF/access logs as CSV or JSON |
| 7.2 | Scheduled reports | Email summaries of WAF activity |
| 7.3 | Multi-user account sharing | Allow accounts to be shared between portal users |
| 7.4 | API key rotation | Rotate WaaS API keys from the portal |
| 7.5 | Comparison views | Compare security configs between apps side-by-side |
| 7.6 | Loading indicators | Spinners/overlays while API calls are in progress |
| 7.7 | Toast notifications | Replace flash messages with auto-dismissing toasts |
| 7.8 | Responsive improvements | Test and fix mobile layout issues |

---

## Architecture Notes for Future Development

### Adding a New Blueprint
1. Create `app/routes/newfeature.py` with `bp = Blueprint('newfeature', __name__, url_prefix='/newfeature')`
2. Register in `app/__init__.py` inside `create_app()`
3. Create template directory `app/templates/newfeature/`
4. Add any new forms to `app/forms.py`
5. Add nav link in `app/templates/base.html`

### Adding a New WaaS API Endpoint
1. Add method to `WaasClient` in `app/waas_client.py`
2. Follow the `_make_request()` pattern for consistent error handling
3. Specify `api_version='v2'` for v2 endpoints (default is v4)
4. Use in routes with try/except `WaasApiError`

### API Version Guidelines
- **Default to v4** for read operations (richer data, app-name-based)
- **Use v2** for create/delete operations (only API that supports them)
- **Show API version badges** in the UI so users know which API is in use
- v2 uses integer app IDs; v4 uses app names as identifiers

### Translation Workflow (i18n)
1. Mark new strings with `_()` in Python or `{{ _('...') }}` in templates
2. Run `pybabel extract -F babel.cfg -o translations/messages.pot .`
3. Run `pybabel update -i translations/messages.pot -d translations`
4. Edit `.po` files in `translations/<lang>/LC_MESSAGES/`
5. Run `pybabel compile -d translations`

### Template Checklist for New Pages
- [ ] Extends `base.html`
- [ ] Sets `{% block title %}`
- [ ] Sets `{% block breadcrumbs %}` with navigation chain
- [ ] Uses Bootstrap 5.3 card layout
- [ ] Forms include `{{ form.hidden_tag() }}` or manual CSRF token
- [ ] Forms have `class="needs-validation" novalidate`
- [ ] Destructive actions use `data-confirm-message` on form
- [ ] Error handling for empty states
- [ ] Consistent button styling (primary/danger/secondary)
- [ ] POST-only for destructive actions
- [ ] API version badge where applicable
- [ ] All UI strings wrapped with `_()` for i18n
