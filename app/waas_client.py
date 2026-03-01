"""
WaaS API Client
Handles communication with the Barracuda WaaS REST API (v2 and v4).

Auth priority:
  1. If a v4 API key is available, use it as Bearer token (default).
  2. If v2 email/password credentials are available, obtain (or refresh)
     a v2 auth token via POST /api_login/ and use it as Bearer token.
"""
import logging
import time
import requests
from flask import current_app
import json

logger = logging.getLogger(__name__)


class WaasApiError(Exception):
    """Custom exception for WaaS API errors"""
    def __init__(self, message, status_code=None, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class WaasClient:
    """Client for interacting with the WaaS API (v2 and v4)."""

    def __init__(self, api_key, base_url=None, base_url_v2=None):
        """Create a client with an explicit auth token.

        For building a client from a WaasAccount (with auto token refresh),
        use the class method ``from_account()`` instead.
        """
        self.api_key = api_key
        self._account = None  # set by from_account()
        self.base_url = base_url or current_app.config.get(
            'WAAS_API_BASE_URL',
            'https://api.waas.barracudanetworks.com/v4/waasapi'
        )
        self.base_url_v2 = base_url_v2 or current_app.config.get(
            'WAAS_API_V2_BASE_URL',
            'https://api.waas.barracudanetworks.com/v2/waasapi'
        )
        # Strip trailing slash from base URLs to avoid double slashes
        self.base_url = self.base_url.rstrip('/')
        self.base_url_v2 = self.base_url_v2.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
        self._set_auth()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------
    @classmethod
    def from_account(cls, account):
        """Build a WaasClient from a WaasAccount model instance.

        Auth priority:
          - If the account has an api_key, use it directly.
          - Otherwise, obtain/refresh a v2 auth token from email+password.

        The returned client stores a reference to the account so it can
        transparently refresh the v2 token when it expires.
        """
        if account.has_api_key:
            logger.info(f'from_account: using v4 API key for account "{account.account_name}" (id={account.id})')
            client = cls(api_key=account.api_key)
        elif account.has_v2_credentials:
            logger.info(f'from_account: using v2 credentials for account "{account.account_name}" (id={account.id})')
            token = cls._resolve_v2_token(account)
            client = cls(api_key=token)
        else:
            raise WaasApiError('Account has no API key and no v2 credentials configured.')

        client._account = account
        return client

    # ------------------------------------------------------------------
    # v2 Login
    # ------------------------------------------------------------------
    @staticmethod
    def v2_login(email, password, base_url_v2=None):
        """Authenticate against the v2 API and return (token, expiry).

        Sends ``POST /v2/waasapi/api_login/`` with form-urlencoded
        ``email`` and ``password``.

        Returns:
            tuple: (key: str, expiry: int) — the auth token and its
            Unix-epoch expiry timestamp.

        Raises:
            WaasApiError on any failure.
        """
        v2_base = base_url_v2 or current_app.config.get(
            'WAAS_API_V2_BASE_URL',
            'https://api.waas.barracudanetworks.com/v2/waasapi'
        )
        v2_base = v2_base.rstrip('/')
        url = f'{v2_base}/api_login/'

        logger.info(f'WaaS v2 Login Request: POST {url} (email={email})')

        try:
            response = requests.post(
                url,
                data={'email': email, 'password': password},
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=30,
            )

            logger.info(f'WaaS v2 Login Response: {response.status_code} {response.reason}')

            try:
                response_data = response.json()
            except (json.JSONDecodeError, ValueError):
                response_data = {'raw': response.text}
                logger.warning(f'  v2 Login response not JSON: {response.text[:500]}')

            if not response.ok:
                error_msg = response_data.get('message', response_data.get('error', f'HTTP {response.status_code}'))
                logger.error(f'WaaS v2 Login Error: {response.status_code} - {error_msg}')
                raise WaasApiError(
                    f'v2 login failed: {error_msg}',
                    status_code=response.status_code,
                    response_data=response_data,
                )

            key = response_data.get('key')
            expiry = response_data.get('expiry')
            if not key:
                raise WaasApiError('v2 login succeeded but no auth token returned.', response_data=response_data)

            logger.info(f'WaaS v2 Login succeeded. Token expires at {expiry}.')
            return key, expiry

        except requests.exceptions.ConnectionError as e:
            logger.error(f'WaaS v2 Login Connection Error: {e}')
            raise WaasApiError(f'Cannot connect to WaaS v2 API for login: {e}')
        except requests.exceptions.Timeout as e:
            logger.error(f'WaaS v2 Login Timeout: {e}')
            raise WaasApiError(f'WaaS v2 login timed out: {e}')
        except requests.exceptions.RequestException as e:
            logger.error(f'WaaS v2 Login Request Error: {e}')
            raise WaasApiError(f'WaaS v2 login request failed: {e}')

    @classmethod
    def _resolve_v2_token(cls, account):
        """Return a valid v2 auth token for the given account.

        Uses cached token if still valid; otherwise performs a fresh login
        and caches the new token on the account model.
        """
        if account.v2_token_valid:
            logger.debug('Using cached v2 auth token.')
            return account.v2_auth_token

        logger.info('v2 auth token missing or expired — refreshing via login.')
        key, expiry = cls.v2_login(account.waas_email, account.waas_password)

        # Cache on the account (caller should commit the session)
        account.v2_auth_token = key
        account.v2_token_expiry = expiry

        from app import db
        db.session.commit()

        return key

    def _ensure_auth(self, force_v2=False):
        """Refresh the Bearer token if it came from a v2 login and has expired.

        Args:
            force_v2: If True, switch to a v2 auth token even when an API key
                      is available.  Used for v2-only endpoints like /accounts/.
        """
        if not self._account:
            return

        need_v2 = force_v2 or (not self._account.has_api_key and self._account.has_v2_credentials)

        if need_v2 and self._account.has_v2_credentials:
            if force_v2 or not self._account.v2_token_valid:
                logger.info('_ensure_auth: obtaining/refreshing v2 auth token')
                new_token = self._resolve_v2_token(self._account)
                self.api_key = new_token
                self._set_auth()
            elif self._account.v2_token_valid and self._account.v2_auth_token:
                # We have a cached valid v2 token — use it
                logger.debug('_ensure_auth: switching to cached v2 auth token for v2 request')
                self.api_key = self._account.v2_auth_token
                self._set_auth()
        elif not force_v2 and self._account.has_api_key:
            # Restore API key for v4 calls (may have been swapped to v2 token earlier)
            if self.api_key != self._account.api_key:
                logger.debug('_ensure_auth: restoring v4 API key for v4 request')
                self.api_key = self._account.api_key
                self._set_auth()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _set_auth(self, api_version='v4'):
        """Set authentication header.

        v4 uses ``Authorization: Bearer <token>``.
        v2 uses ``auth-api: <token>`` (no Bearer prefix).
        """
        if api_version == 'v2':
            self.session.headers.pop('Authorization', None)
            self.session.headers['auth-api'] = self.api_key
        else:
            self.session.headers.pop('auth-api', None)
            self.session.headers['Authorization'] = f'Bearer {self.api_key}'

    def _make_request(self, method, endpoint, data=None, params=None, files=None, timeout=30, api_version='v4'):
        """Make an API request and handle response.

        Args:
            api_version: 'v4' (default) or 'v2' to select the base URL.
        """
        # Refresh token if necessary — force v2 token for v2 API calls
        self._ensure_auth(force_v2=(api_version == 'v2'))

        # Set correct auth header format for the API version
        self._set_auth(api_version=api_version)

        # Ensure endpoint starts with / and ends with /
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
        if not endpoint.endswith('/'):
            endpoint = f'{endpoint}/'

        base = self.base_url_v2 if api_version == 'v2' else self.base_url
        url = f'{base}{endpoint}'

        # Debug logging - redact auth tokens
        redacted_headers = dict(self.session.headers)
        if 'Authorization' in redacted_headers:
            token = redacted_headers['Authorization']
            if len(token) > 17:  # "Bearer " + at least 10 chars
                redacted_headers['Authorization'] = token[:17] + '...[REDACTED]'
        if 'auth-api' in redacted_headers:
            token = redacted_headers['auth-api']
            if len(token) > 10:
                redacted_headers['auth-api'] = token[:10] + '...[REDACTED]'

        logger.info(f'WaaS API Request: {method} {url}')
        logger.debug(f'  Headers: {redacted_headers}')
        if params:
            logger.debug(f'  Params: {params}')
        if data:
            logger.debug(f'  Data: {json.dumps(data, default=str)[:500]}')

        try:
            kwargs = {
                'params': params,
                'timeout': timeout,
            }
            if files:
                # Remove Content-Type for multipart uploads
                headers = dict(self.session.headers)
                headers.pop('Content-Type', None)
                kwargs['headers'] = headers
                kwargs['files'] = files
                logger.debug(f'  Files: {list(files.keys()) if isinstance(files, dict) else "provided"}')
            elif data:
                kwargs['json'] = data

            response = self.session.request(method, url, **kwargs)

            logger.info(f'WaaS API Response: {response.status_code} {response.reason} for {method} {url}')

            # Parse response
            try:
                response_data = response.json()
                logger.debug(f'  Response body (first 500 chars): {json.dumps(response_data, default=str)[:500]}')
            except (json.JSONDecodeError, ValueError):
                response_data = {'raw': response.text}
                logger.warning(f'  Response not JSON. Raw (first 500 chars): {response.text[:500]}')

            if not response.ok:
                error_msg = response_data.get('message', response_data.get('error', f'HTTP {response.status_code}'))
                logger.error(f'WaaS API Error: {response.status_code} - {error_msg}')
                logger.error(f'  Full response: {json.dumps(response_data, default=str)[:1000]}')
                raise WaasApiError(
                    f'WaaS API error: {error_msg}',
                    status_code=response.status_code,
                    response_data=response_data
                )

            return response_data

        except requests.exceptions.ConnectionError as e:
            logger.error(f'WaaS API Connection Error: {e}')
            raise WaasApiError(f'Cannot connect to WaaS API: {e}')
        except requests.exceptions.Timeout as e:
            logger.error(f'WaaS API Timeout: {e}')
            raise WaasApiError(f'WaaS API request timed out: {e}')
        except requests.exceptions.RequestException as e:
            logger.error(f'WaaS API Request Error: {e}')
            raise WaasApiError(f'WaaS API request failed: {e}')

    # === Account / Verify (v2 API) ===
    def verify_account(self):
        """Verify auth and get account info (uses v2 API).

        Returns the full v2 response including the ``accounts`` list.
        """
        return self._make_request('GET', '/accounts/', api_version='v2')

    # === Applications ===
    def list_applications(self, params=None):
        """List all applications"""
        return self._make_request('GET', '/applications/', params=params)

    def get_application(self, app_id):
        """Get a single application export (full config) by name"""
        return self._make_request('GET', f'/applications/{app_id}/export/', params={
            'include_servers': 'true',
            'include_endpoints': 'true'
        })

    def create_application(self, data):
        """Create a new application"""
        return self._make_request('POST', '/applications/', data=data)

    def update_application(self, app_id, data):
        """Update an application"""
        return self._make_request('PUT', f'/applications/{app_id}/', data=data)

    def delete_application(self, app_id):
        """Delete an application"""
        return self._make_request('DELETE', f'/applications/{app_id}/')

    # === Application Security Config ===
    def get_security_config(self, app_id):
        """Get security configuration for an application"""
        return self._make_request('GET', f'/applications/{app_id}/security/')

    def update_security_config(self, app_id, data):
        """Update security configuration"""
        return self._make_request('PUT', f'/applications/{app_id}/security/', data=data)

    # === Certificates ===
    def list_certificates(self, params=None):
        """List all certificates"""
        return self._make_request('GET', '/certificates/', params=params)

    def get_certificate(self, cert_id):
        """Get a single certificate"""
        return self._make_request('GET', f'/certificates/{cert_id}/')

    def upload_certificate(self, files, data=None):
        """Upload a certificate"""
        return self._make_request('POST', '/certificates/', files=files, data=data)

    def delete_certificate(self, cert_id):
        """Delete a certificate"""
        return self._make_request('DELETE', f'/certificates/{cert_id}/')

    # === Logs ===
    def get_access_logs(self, app_id, params=None):
        """Get access logs for an application"""
        return self._make_request('GET', f'/applications/{app_id}/logs/access/', params=params)

    def get_waf_logs(self, app_id, params=None):
        """Get WAF logs for an application"""
        return self._make_request('GET', f'/applications/{app_id}/logs/waf/', params=params)

    def get_audit_logs(self, params=None):
        """Get audit/system logs"""
        return self._make_request('GET', '/logs/audit/', params=params)

    # === DNS / CNAME ===
    def get_dns_info(self, app_id):
        """Get DNS/CNAME information for an application"""
        return self._make_request('GET', f'/applications/{app_id}/dns/')

    # === Proxy ===
    def get_proxy_settings(self, app_id):
        """Get reverse proxy settings for an application"""
        return self._make_request('GET', f'/applications/{app_id}/proxy/')

    def update_proxy_settings(self, app_id, data):
        """Update reverse proxy settings"""
        return self._make_request('PUT', f'/applications/{app_id}/proxy/', data=data)