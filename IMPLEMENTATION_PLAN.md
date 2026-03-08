# WaaS Self-Service Portal — Implementation Plan

*Last updated: 2026-03-08*

---

## Current Project Status

### ✅ Fully Working (Routes + Templates + Tested)

| Area | Routes | Templates | Notes |
|------|--------|-----------|-------|
| **Auth** | login, logout, profile, change_password | login.html, profile.html, change_password.html | Password hashing, Flask-Login sessions |
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
- **WaasClient** (`app/waas_client.py`): Dual v2/v4 API support with correct endpoint paths
- **Encryption** (`app/encryption.py`): Fernet encrypt/decrypt for API keys at rest
- **AuditLog**: Logging wired into account, application, certificate, security, and proxy operations
- **Forms**: `ApplicationCreateForm`, `CertificateUploadForm`, `WaasAccountForm`, auth forms
- **Base template**: Navbar, flash messages, Bootstrap 5.3, Bootstrap Icons

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

**API version visibility:** List view defaults to v4 with a toggle to v2. Create/delete show v2 API badges. View shows v4 badge. Users always know which API is in use.

---

### Phase 3: Dashboard Enhancements ⬅️ NEXT

**Goal:** Make the dashboard useful with real data and quick actions.

| # | Task | Description |
|---|------|-------------|
| 3.1 | Account summary cards | Show each account with app count, cert count, status |
| 3.2 | Quick action buttons | Links to add account, view apps, upload cert |
| 3.3 | Recent activity feed | Show recent AuditLog entries for the user |
| 3.4 | Certificate expiration warnings | Highlight certs expiring within 30 days |
| 3.5 | System status indicators | Show API connectivity status per account |

**Dependencies:** Phase 2 complete (correct API endpoints for counts).

---

### Phase 4: UI/UX Polish

**Goal:** Improve user experience and visual consistency.

| # | Task | Description |
|---|------|-------------|
| 4.1 | Loading indicators | Spinners/overlays while API calls are in progress |
| 4.2 | Confirmation dialogs | JavaScript confirm for delete/destructive actions |
| 4.3 | Breadcrumb navigation | Add breadcrumbs for account → app → sub-page navigation |
| 4.4 | Toast notifications | Replace flash messages with auto-dismissing toasts |
| 4.5 | Responsive improvements | Test and fix mobile layout issues |
| 4.6 | Form validation feedback | Real-time client-side validation where appropriate |
| 4.7 | Search/filter on list pages | Client-side or server-side search for accounts, apps, certs |

---

### Phase 5: Error Handling & Robustness

**Goal:** Handle edge cases gracefully.

| # | Task | Description |
|---|------|-------------|
| 5.1 | Custom error pages | 404, 403, 500 error templates |
| 5.2 | API timeout handling | User-friendly messages when WaaS API is slow/down |
| 5.3 | Session timeout | Graceful redirect to login when session expires |
| 5.4 | Rate limiting | Prevent excessive API calls (per user/account) |
| 5.5 | Input sanitization | Review all form inputs for XSS/injection risks |

---

### Phase 6: Advanced Features (Future)

**Goal:** Add power-user and operational features.

| # | Task | Description |
|---|------|-------------|
| 6.1 | Log export | Download WAF/access logs as CSV or JSON |
| 6.2 | Scheduled reports | Email summaries of WAF activity |
| 6.3 | Multi-user account sharing | Allow accounts to be shared between portal users |
| 6.4 | API key rotation | Rotate WaaS API keys from the portal |
| 6.5 | Bulk operations | Apply security config changes across multiple apps |
| 6.6 | Comparison views | Compare security configs between apps |

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

### Template Checklist for New Pages
- [ ] Extends `base.html`
- [ ] Sets `{% block title %}`
- [ ] Uses Bootstrap 5.3 card layout
- [ ] Forms include `{{ form.hidden_tag() }}` or manual CSRF token
- [ ] Error handling for empty states
- [ ] Consistent button styling (primary/danger/secondary)
- [ ] POST-only for destructive actions
- [ ] API version badge where applicable
