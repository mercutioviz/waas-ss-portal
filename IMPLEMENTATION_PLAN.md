# WaaS Self-Service Portal — Implementation Plan

*Last updated: 2026-03-11 (Phase 7 medium items)*

---

## Current Project Status

### ✅ Fully Working (Routes + Templates + Tested)

| Area | Routes | Templates | Notes |
|------|--------|-----------|-------|
| **Auth** | login, logout, profile, change_password, keepalive | login.html, profile.html, change_password.html | Password hashing, Flask-Login sessions, session timeout |
| **Main** | index (redirect), dashboard, counts | dashboard.html | `/` redirects to `/dashboard`; AJAX cert/app counts |
| **Accounts** | list, add, edit, view, verify, delete, rotate_key | list.html, add.html, edit.html, view.html, rotate_key.html | Full CRUD, API key encryption, account verification, key rotation |
| **Admin** | index, users, user_create, user_edit, toggle_active, audit_log | index.html, users.html, user_create.html, user_edit.html, audit_log.html, panel.html | Role-based access, audit logging |
| **Applications** | list, view, create, delete, security, dns, compare, api_config | list.html, view.html, create.html, security.html, dns.html, compare.html | v4/v2 toggle, create/delete via v2, security/DNS via v4, side-by-side comparison, JSON config API |
| **Certificates** | list, view, upload, delete | list.html, view.html, upload.html | Per-application SNI certificates (v4), aggregated list view |
| **Logs** | index, waf, access, fp_analysis | index.html, waf.html, access.html, fp_analysis.html | Account/app selector, WAF/access log viewers, CSV/JSON export |
| **Proxy** | launch, start, stop, session, waf-logs | launch.html, session.html | noVNC browser proxy sessions |
| **Templates** | list, add, view, edit, edit_config, delete, save_as_template, apply, bulk_apply, export, import | list.html, view.html, add.html, edit.html, edit_config.html, save_as.html, bulk_apply.html, bulk_results.html, import.html | Config templates with CRUD, save-from-app, quick apply via AJAX, bulk apply across accounts, JSON import/export |

### API Version Mapping

All WaaS API calls now use the correct endpoints. Users see API version badges in the UI.

| Feature | API Version | Endpoint |
|---------|-------------|----------|
| List applications | v4 (default) or v2 (toggle) | `GET /applications/` |
| View application | v4 | `GET /applications/{name}/export/` |
| Create application | v2 | `POST /applications/` |
| Delete application | v2 | `DELETE /applications/{id}/` |
| Security config | v4 | `GET /applications/{name}/basic_security/`, `/request_limits/`, `/clickjacking_protection/`, `/data_theft_protection/` |
| Update security | v4 | `PATCH /applications/{name}/basic_security/`, `/request_limits/`, `/clickjacking_protection/`, `/data_theft_protection/` |
| DNS/CNAME info | v4 | Extracted from application export (`endpoints.cname`, `endpoints.domains`) |
| Certificates | v4 | `GET /applications/{name}/sni_certificates/` (per-app) |
| Account verify | v2 | `GET /accounts/` |
| WAF/access logs | v4 | `GET /applications/{name}/logs/` |
| Import (apply template) | v4 | `PATCH /applications/{name}/import/?include_servers=bool&include_endpoints=bool` |

### Infrastructure In Place
- **WaasClient** (`app/waas_client.py`): Dual v2/v4 API support with correct endpoint paths, retry on 5xx, configurable timeout
- **Encryption** (`app/encryption.py`): Fernet encrypt/decrypt for API keys at rest
- **AuditLog**: Logging wired into account, application, certificate, security, and proxy operations
- **Config Templates** (`app/routes/templates.py`): Save, reuse, and bulk-apply WaaS app security configs; per-user or global templates
- **Forms**: `ApplicationCreateForm`, `CertificateUploadForm`, `WaasAccountForm`, `ConfigTemplateForm`, `TemplateFromAppForm`, `RotateApiKeyForm`, auth forms
- **Base template**: Navbar, toast notifications, loading overlay, Bootstrap 5.3, Bootstrap Icons, confirmation modal, session timeout modal, breadcrumb block
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

### Phase 5: WaaS App Config Templates ✅ DONE

**Goal:** Allow users to save WaaS security configurations as reusable templates and apply them to one or many applications in bulk.

**What was built:**

- **`ConfigTemplate` model** — `id`, `user_id`, `name`, `description`, `config_data` (JSON), `is_global`, `created_at`, `updated_at`. `config_dict` property auto-serializes/deserializes JSON.
- **`import_application()` on WaasClient** — `PATCH /applications/{appName}/import/` with `include_servers` / `include_endpoints` query params. Merges partial config without replacing missing fields.
- **`ConfigTemplateForm` / `TemplateFromAppForm`** — Forms with section checkboxes (basic security, request limits, clickjacking, data theft, servers, endpoints).
- **`templates` blueprint** (10 routes) — Full CRUD, save-from-app with section selection, single quick-apply via AJAX, bulk-apply across accounts with per-app results.
- **`/applications/api/list` JSON endpoint** — Returns app names for AJAX dropdown in quick-apply.
- **9 HTML templates** — list, view, add, edit, edit_config (raw JSON editor with validation), save_as, bulk_apply, bulk_results.
- **Visibility** — Templates are per-user (private) or global (admin-only toggle). Viewers blocked from mutations.
- **Integration** — "Save as Template" buttons on app view and security pages; "Templates" nav link in navbar.
- **Audit logging** — All mutations (create, edit, delete, apply, bulk-apply) logged.

---

### Phase 6: Internationalization (i18n) ✅ DONE

**Goal:** Make the UI translatable so the portal can be used in multiple languages.

**What was built:**

- **Flask-Babel 4.0.0** integrated with locale selector chain: `User.locale` → `session['locale']` → `Accept-Language` header → `'en'` default
- **630 translatable strings** extracted and fully translated to Spanish (es)
- **All 40 HTML templates** wrapped with `{{ _('...') }}`
- **All 83 flash messages** across 9 route files wrapped with `_()`
- **All 61 form fields** (labels, placeholders, validators, choices) wrapped with `_l()`
- **JavaScript strings** translated via `window.i18n` dict rendered in `base.html`
- **Language switcher** dropdown in navbar for both authenticated and anonymous users
- **`/auth/set-locale` POST endpoint** saves preference to session and `User.locale` (if authenticated)
- **`User.locale`** column added for per-user language persistence
- **`babel.cfg`** extraction config for `.py` and `.html` files
- **Translation files** in `app/translations/es/LC_MESSAGES/` (`.po` and `.mo`)

**Translation workflow:**
```bash
pybabel extract -F babel.cfg -k _l -o app/translations/messages.pot .
pybabel update -i app/translations/messages.pot -d app/translations
# Edit .po files...
pybabel compile -d app/translations
```

---

### Phase 7: Advanced Features ✅ DONE (9 of 11)

**Goal:** Add power-user and operational features. Small-complexity items completed first, then medium items.

**What was built (small items):**

- **Toast Notifications (7.9)** — Replaced flash message alerts with Bootstrap 5 toasts: fixed top-right, auto-dismiss (5s default, 8s for danger), stacking, category-specific colors (success/danger/warning/info). Global `window.showToast(message, category)` JS function for programmatic use.
- **Loading Indicators (7.8)** — Full-screen semi-transparent overlay with centered spinner. `window.showLoading(message)` / `window.hideLoading()` JS functions. Auto-wired to forms via `data-loading` attribute on account add/edit, app create, cert upload, bulk apply forms.
- **Log Export (7.2)** — `?format=csv` and `?format=json` query params on WAF and access log routes. CSV uses `DictWriter` with correct field lists per log type. JSON with `json.dumps`. File download with `Content-Disposition: attachment`. Audit log entries on export. Export dropdown buttons in log page headers.
- **API Key Rotation (7.7)** — `RotateApiKeyForm` with new key input and verify checkbox. `/accounts/<id>/rotate-key` route. Optional verification via lightweight API call before saving. Invalidates cached v2 tokens. Audit log with `action='account_key_rotation'`. "Rotate API Key" button on account view page.
- **Template Import/Export (7.4)** — Export route returns JSON with name, description, config_data, is_global, exported_at, version. Import route validates JSON structure (name + config_data required), creates `ConfigTemplate`. `is_global` only honored for admins. "Import Template" button in list header, export icon per row and on view page.

**What was built (medium items):**

- **Expanded Security Config Editing (7.1)** — 3 new `WaasClient` methods (`update_request_limits`, `update_clickjacking_protection`, `update_data_theft_protection`) for individual PATCH endpoints. Route dispatches based on `section` form field with proper type conversion (int for limits, bool for toggles). 3 new collapsible edit forms in security.html with pre-populated values from API. Section name included in audit log details.
- **Template Diff/Preview (7.3)** — JSON API endpoint (`/applications/api/<account_id>/<app_id>/config`) returns current security config. "Preview Changes" button on template quick-apply fetches current config and renders side-by-side diff modal with color-coded differences (green=added, yellow=modified, red=removed) and summary counts.
- **Comparison Views (7.5)** — Checkbox column in v4 app list with "Compare Selected (N)" button (enabled at exactly 2). `compare_applications` route fetches security configs for both apps. `compare.html` template shows side-by-side tables per section (protection mode, request limits, clickjacking, data theft) with `table-success`/`table-warning` row highlighting for matching/differing values.
- **Responsive Improvements (7.10)** — Mobile breakpoints at 575.98px (compact card padding, smaller stat numbers, compact tables, 44px touch targets) and 576–768px (intermediate sizing). Dashboard stat cards `col-6 col-md-4`. App list hides Group/Servers/Health on mobile with `d-none d-md-table-cell`. Security cards use `col-lg-6` for tablet stacking. App view header stacks on mobile (`flex-column flex-sm-row`). WAF/access log filter inputs use responsive CSS classes instead of inline widths; low-priority columns hidden on mobile. Template quick-apply uses `col-12 col-md-4`.
- **i18n** — All new strings translated to Spanish (655 total, 0 untranslated, 0 fuzzy).

| # | Task | Description | Complexity | Status |
|---|------|-------------|------------|--------|
| 7.1 | Expand security config editing | Edit request limits, clickjacking, data theft (not just protection mode) via individual PATCH endpoints | Medium | ✅ Complete |
| 7.2 | Log export | Download WAF/access logs as CSV or JSON | Small | ✅ Complete |
| 7.3 | Template diff/preview | Show before/after diff when applying a template to an app | Medium | ✅ Complete |
| 7.4 | Template import/export | Download templates as JSON files, upload to import | Small | ✅ Complete |
| 7.5 | Comparison views | Compare security configs between apps side-by-side | Medium | ✅ Complete |
| 7.6 | Multi-user account sharing | Allow WaaS accounts to be shared between portal users | Large | Pending |
| 7.7 | API key rotation | Rotate WaaS API keys from the portal | Small | ✅ Complete |
| 7.8 | Loading indicators | Spinners/overlays while API calls are in progress | Small | ✅ Complete |
| 7.9 | Toast notifications | Replace flash messages with auto-dismissing toasts | Small | ✅ Complete |
| 7.10 | Responsive improvements | Test and fix mobile layout issues | Medium | ✅ Complete |
| 7.11 | Scheduled reports | Email summaries of WAF activity | Large | Pending |

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
1. Mark new strings with `_()` in Python or `{{ _('...') }}` in templates; use `_l()` for class-definition-time strings (form labels, validators)
2. Run `pybabel extract -F babel.cfg -k _l -o app/translations/messages.pot .`
3. Run `pybabel update -i app/translations/messages.pot -d app/translations`
4. Edit `.po` files in `app/translations/<lang>/LC_MESSAGES/`
5. Run `pybabel compile -d app/translations`

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
