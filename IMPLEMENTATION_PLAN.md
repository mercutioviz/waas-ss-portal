# WaaS Self-Service Portal — Implementation Plan

*Last updated: 2026-03-30 (Phase 9 added — new features & improvements)*

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

### Phase 7: Advanced Features ✅ DONE (11 of 11)

**Goal:** Add power-user and operational features. Small-complexity items completed first, then medium items, then large items.

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
- **i18n** — All new strings translated to Spanish (655+ total, 0 untranslated, 0 fuzzy).

**What was built (large items):**

- **Multi-User Account Sharing (7.6)** — `AccountShare` model with `(account_id, user_id)` unique constraint and `permission` levels (`read`/`write`/`admin`). Central access helpers: `get_user_accounts()` returns owned + shared accounts with `_permission` annotation; `get_account_for_user()` returns `(account, permission)` tuple checking ownership then shares; `can_write()` / `can_admin()` for permission gating. `ShareAccountForm` with username/email lookup and permission dropdown. Sharing management page (`/accounts/<id>/sharing`) with collaborator table and add/revoke forms. All 7 route files updated to use `get_account_for_user()` instead of `filter_by(user_id=)` — applications, certificates, logs, proxy, main dashboard, templates all support shared accounts. Account list shows "Shared with You" section with permission badges. Account view shows sharing card with collaborator list. Owner-only restriction on delete; admin+ for edit/rotate/share; write+ for mutations; read for viewing.
- **Scheduled Reports (7.11)** — `ScheduledReport` model (name, account, report_type, frequency, day_of_week, hour, recipients JSON, is_active, next_run_at) and `ReportRun` model (status, recipient_count, error_message, summary JSON). Flask-Mail + Flask-APScheduler integrated. `report_service.py` with 3 generators: `generate_waf_summary()` (top attacks, IPs, severity), `generate_access_summary()` (top URLs, status codes, methods), `generate_security_overview()` (protection modes per app). Email rendering via 4 HTML templates with inline CSS. 15-minute interval scheduler job. `reports` blueprint with full CRUD, toggle active, run-now, run history. 5 page templates (list, add, edit, view, run_detail). `flask run-reports` CLI command. "Reports" nav link in navbar.

| # | Task | Description | Complexity | Status |
|---|------|-------------|------------|--------|
| 7.1 | Expand security config editing | Edit request limits, clickjacking, data theft (not just protection mode) via individual PATCH endpoints | Medium | ✅ Complete |
| 7.2 | Log export | Download WAF/access logs as CSV or JSON | Small | ✅ Complete |
| 7.3 | Template diff/preview | Show before/after diff when applying a template to an app | Medium | ✅ Complete |
| 7.4 | Template import/export | Download templates as JSON files, upload to import | Small | ✅ Complete |
| 7.5 | Comparison views | Compare security configs between apps side-by-side | Medium | ✅ Complete |
| 7.6 | Multi-user account sharing | Allow WaaS accounts to be shared between portal users with read/write/admin permissions | Large | ✅ Complete |
| 7.7 | API key rotation | Rotate WaaS API keys from the portal | Small | ✅ Complete |
| 7.8 | Loading indicators | Spinners/overlays while API calls are in progress | Small | ✅ Complete |
| 7.9 | Toast notifications | Replace flash messages with auto-dismissing toasts | Small | ✅ Complete |
| 7.10 | Responsive improvements | Test and fix mobile layout issues | Medium | ✅ Complete |
| 7.11 | Scheduled reports | Email summaries of WAF activity via Flask-Mail + Flask-APScheduler | Large | ✅ Complete |

---

### Phase 8: Dark Mode, Delete App Button, Show API Call ✅ DONE

**Goal:** Three user-facing features — a dark/light theme toggle, a more accessible delete application button, and a "show me the API call" feature that displays curl equivalents.

**What was built:**

- **Dark/Light Mode Toggle (8.1)** — `User.theme` column with `get_theme()` cascade (`User.theme` → `session['theme']` → `'light'`). FOUC prevention via inline `<script>` reading `localStorage` before body renders. Sun/moon toggle button in navbar (auth + anon). JS `toggleTheme()` flips `data-bs-theme`, saves to `localStorage`, fire-and-forget POST to `/auth/set-theme`. CSS overrides for `[data-bs-theme="dark"]` covering body, cards, tables, code blocks, diffs, inline-edit fields, footer, loading overlay. Bootstrap 5.3's built-in dark mode handles most components automatically.
- **Delete Button on View Page (8.2)** — `view_application()` route resolves v2 integer app ID by calling `list_applications_v2()` and matching by name. Delete button in Quick Actions card, guarded by `v2_app_id`, `user_can_write`, and `account.has_v2_credentials`. Uses existing `data-confirm-message` pattern for confirmation modal.
- **API Curl Display (8.3)** — `generate_curl_command()` method on `WaasClient` builds formatted multi-line curl strings with redacted auth tokens (first 10 chars + `...[REDACTED]`). Reusable `api_curl_modal.html` Jinja macro with `api_curl_button(modal_id)` and `api_curl_modal(id, curl_command)`. `copyToClipboard()` JS with clipboard API + fallback. Curl buttons on application list, view, create, and security pages.

---

#### 8.1 Dark Mode / Light Mode Toggle (Medium)

**Current state:** Bootstrap 5.3.3 is in use and `data-bs-theme="light"` is already hardcoded on the `<html>` tag in `base.html`. Bootstrap 5.3's built-in dark mode support means most components (cards, tables, navbars, modals, forms) will adapt automatically when toggling `data-bs-theme` to `"dark"`.

**Persistence chain:** `localStorage` (instant, no flash of wrong theme) → `User.theme` column (persists across devices) → `session['theme']` (unauthenticated users) → `'light'` default.

**Tasks:**

| # | Task | Files | Notes |
|---|------|-------|-------|
| 8.1.1 | Add `theme` column to User model | `app/models.py` | `db.Column(db.String(10), default='light')` after existing `locale` field. `db.create_all()` auto-adds column. |
| 8.1.2 | Add `/auth/set-theme` POST endpoint | `app/routes/auth.py` | Follow `/auth/set-locale` pattern — accept `theme` param (`light`/`dark`), update `session['theme']` and `current_user.theme` if authenticated, redirect to referrer. |
| 8.1.3 | Add `get_theme()` context processor | `app/__init__.py` | Chain: `User.theme` → `session['theme']` → `'light'`. Inject into templates as `current_theme`. |
| 8.1.4 | Make `<html data-bs-theme>` dynamic | `app/templates/base.html` | Change to `data-bs-theme="{{ current_theme }}"`. |
| 8.1.5 | Add theme toggle to navbar | `app/templates/base.html` | Sun/moon icon button between language dropdown and user dropdown. Present for both authenticated and unauthenticated users. On click: toggle `data-bs-theme`, save to `localStorage`, POST to `/auth/set-theme`. |
| 8.1.6 | Add early theme-init script | `app/templates/base.html` | Inline `<script>` in `<head>` (before body renders) that reads `localStorage.getItem('theme')` and sets `data-bs-theme` immediately to prevent flash of wrong theme on page load. |
| 8.1.7 | Add dark mode CSS overrides | `app/static/css/style.css` | Use `[data-bs-theme="dark"]` selector for: body background, card headers, navbar (`navbar-dark bg-primary` → theme-aware), footer (`bg-light` → theme-aware), toast colors, code blocks, custom stat card colors on dashboard. |
| 8.1.8 | Add theme toggle JS function | `app/static/js/app.js` | `window.toggleTheme()`: flip `data-bs-theme`, update icon (sun ↔ moon), save to `localStorage`, POST to `/auth/set-theme` via fetch. |
| 8.1.9 | i18n — translate new strings | `app/translations/es/` | Translate toggle tooltip/label ("Dark mode", "Light mode"). |

---

#### 8.2 Delete Application Button on View Page (Small)

**Current state:** Delete is **fully implemented** in the backend:
- Route: `DELETE /applications/<account_id>/<int:app_id>/delete` (POST, `applications.py` ~line 210)
- API client: `WaasClient.delete_application_v2(app_id)` calls `DELETE /v2/waasapi/applications/{id}/`
- List template: Delete button already appears in `list.html` when viewing v2 API mode (shows v2 integer IDs)

**Gap:** The application **view page** (`view.html`) has no delete button. The view page uses the v4 API (app names), but delete requires a v2 integer app ID. The v2 app ID needs to be resolved and passed to the template.

**Tasks:**

| # | Task | Files | Notes |
|---|------|-------|-------|
| 8.2.1 | Resolve v2 app ID in view route | `app/routes/applications.py` | In `view_application()`, if account has v2 credentials, call v2 `GET /applications/` to find the integer ID matching the app name. Pass `v2_app_id` to template. Cache or do a lightweight lookup. |
| 8.2.2 | Add delete button to view page | `app/templates/applications/view.html` | Add a "Delete Application" button in the Quick Actions card (or page header). Use the existing `data-confirm-message` pattern with the confirmation modal. Only show if: `v2_app_id` is available, user has write permission, user is not a viewer. |
| 8.2.3 | i18n — translate new strings | `app/translations/es/` | Translate confirmation message and button label. |

---

#### 8.3 "Show Me the API Call" — Curl Command Display (Medium)

**Goal:** For any API operation the portal performs, let users see the equivalent `curl` command. Useful for learning, debugging, and scripting outside the portal.

**Current state:**
- `WaasClient._make_request()` already builds URLs, headers, and auth for both v2 and v4 APIs
- Token redaction logic already exists (lines ~270-277 of `waas_client.py`) — shows first 10-17 chars then `...[REDACTED]`
- Clone error display (`clone.html`) already shows request method, URL, request data, and response data in an expandable detail section
- `WaasApiError` class stores `request_method`, `request_url`, `request_data`, `response_data`

**Auth header differences:**
- v4: `Authorization: Bearer <api_key>`
- v2: `auth-api: <token>` (no Bearer prefix)

**Implementation approach:** Server-side curl generation in `WaasClient` + reusable Jinja macro for display + copy-to-clipboard JS.

**Tasks:**

| # | Task | Files | Notes |
|---|------|-------|-------|
| 8.3.1 | Add `generate_curl_command()` to WaasClient | `app/waas_client.py` | Method that accepts `method`, `endpoint`, `data`, `params`, `api_version` and returns a formatted, multi-line curl string. Reuse URL/header/auth building logic from `_make_request()`. Always redact auth tokens. |
| 8.3.2 | Create reusable API call modal macro | `app/templates/macros/api_curl_modal.html` (new) | Jinja macro: `api_curl_button(modal_id)` renders a small `<i class="bi bi-code-slash"></i> API` button; `api_curl_modal(id, curl_command)` renders a modal with syntax-highlighted curl in a `<pre>` block and a "Copy" button. |
| 8.3.3 | Add `copyToClipboard()` JS helper | `app/static/js/app.js` | `window.copyToClipboard(text)` using `navigator.clipboard.writeText()` with toast feedback ("Copied!" / "Copy failed"). |
| 8.3.4 | Add curl to application view page | `app/routes/applications.py`, `view.html` | In `view_application()`, generate curl for the `GET /applications/{name}/export/` call. Pass to template. Show button + modal in the "Raw API Data" card header. |
| 8.3.5 | Add curl to security config page | `app/routes/applications.py`, `security.html` | Generate curl commands for each of the 4 security GET endpoints. Show button + modal per section and/or in the "Raw Security Data" card header. |
| 8.3.6 | Add curl to create/clone forms | `applications/create.html`, `applications/clone.html` | For write operations, generate the curl command from the submitted form data and show it in the success flash or a post-submit modal. Alternatively, add a "Preview API Call" button that builds the curl from current form values via JS before submission. |
| 8.3.7 | Add curl to list applications page | `app/routes/applications.py`, `list.html` | Generate curl for `GET /applications/` and show a small API button in the page header. |
| 8.3.8 | Add JSON endpoint for dynamic curl generation | `app/routes/applications.py` | `GET /applications/api/<account_id>/curl?operation=<op>&app_id=<id>` returns JSON with `{curl_command, method, url, headers_redacted}`. Used by AJAX for operations where curl depends on current form state. |
| 8.3.9 | i18n — translate new strings | `app/translations/es/` | Translate button labels ("Show API Call", "Copy curl Command"), modal title, toast messages. |

**Security considerations:**
- Auth tokens must ALWAYS be redacted in displayed curl commands (reuse existing redaction logic)
- Viewer role users can see curl for read operations but tokens are still redacted
- Rate limit the JSON curl endpoint to prevent abuse

---

#### Phase 8 Summary

| # | Feature | Complexity | Status |
|---|---------|------------|--------|
| 8.1 | Dark mode / light mode toggle | Medium (9 tasks) | ✅ Complete |
| 8.2 | Delete app button on view page | Small (3 tasks) | ✅ Complete |
| 8.3 | "Show me the API call" curl display | Medium (9 tasks) | ✅ Complete |

---

## Phase 9: New Features & Improvements

*Added: 2026-03-30*

### Quick Wins

| # | Task | Description | Status |
|---|------|-------------|--------|
| 9.1 | Dashboard Widgets | Add Chart.js charts to dashboard — attack trends over time, top blocked IPs, request volume, server health overview | Pending |
| 9.2 | Bulk Delete | Allow selecting multiple apps/rules for batch deletion with confirmation | Pending |
| 9.3 | Notification Preferences | Let users choose email vs. in-app notifications for report delivery | Pending |
| 9.4 | API Key Expiry Warnings | Track and alert when v2 tokens or API keys are approaching expiration | Pending |

### Medium Effort

| # | Task | Description | Status |
|---|------|-------------|--------|
| 9.5 | Real-Time Log Streaming | Use WebSocket infrastructure to stream WAF logs live instead of requiring manual refresh | Pending |
| 9.6 | Config Drift Detection | Compare an app's current config against its saved template/feature and highlight differences | Pending |
| 9.7 | Role-Based Dashboard | Different dashboard views for admin vs. user vs. viewer roles | Pending |
| 9.8 | Search/Filter Everywhere | Global search across apps, accounts, templates, and features | Pending |
| 9.9 | Application Groups Management | CRUD for app groups with bulk operations per group | Pending |
| 9.10 | Two-Factor Authentication (2FA) | TOTP support for portal login security | Pending |

### Larger Features

| # | Task | Description | Status |
|---|------|-------------|--------|
| 9.11 | REST API for Portal | Expose portal functionality via a JSON API for automation/CI-CD integration | Pending |
| 9.12 | Webhook/Alert System | Trigger alerts on WAF events (e.g., spike in blocked requests, server health changes) | Pending |
| 9.13 | Configuration Change History | Track config changes per app over time with diffs (beyond audit log) | Pending |
| 9.14 | Multi-Language Expansion | Add French, German, Portuguese translations leveraging existing i18n infrastructure | Pending |
| 9.15 | Terraform/IaC Export | Export app configurations as infrastructure-as-code definitions | Pending |

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
