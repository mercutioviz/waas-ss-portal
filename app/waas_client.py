"""
WaaS API Client
Handles communication with the Barracuda WaaS REST API (v4)
"""
import logging
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
    """Client for interacting with the WaaS API (v4)"""

    def __init__(self, api_key, base_url=None):
        self.api_key = api_key
        self.base_url = base_url or current_app.config.get(
            'WAAS_API_BASE_URL',
            'https://api.waas.barracudanetworks.com/v4/waasapi'
        )
        # Strip trailing slash from base URL to avoid double slashes
        self.base_url = self.base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
        self._set_auth()

    def _set_auth(self):
        """Set authentication header"""
        self.session.headers['Authorization'] = f'Bearer {self.api_key}'

    def _make_request(self, method, endpoint, data=None, params=None, files=None, timeout=30):
        """Make an API request and handle response"""
        # Ensure endpoint starts with / and ends with /
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
        if not endpoint.endswith('/'):
            endpoint = f'{endpoint}/'

        url = f'{self.base_url}{endpoint}'

        # Debug logging - redact auth token
        redacted_headers = dict(self.session.headers)
        if 'Authorization' in redacted_headers:
            token = redacted_headers['Authorization']
            # Show first 10 chars of token for identification, redact the rest
            if len(token) > 17:  # "Bearer " + at least 10 chars
                redacted_headers['Authorization'] = token[:17] + '...[REDACTED]'

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

    # === Account / Verify ===
    def verify_account(self):
        """Verify API key and get account info"""
        return self._make_request('GET', '/account/')

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