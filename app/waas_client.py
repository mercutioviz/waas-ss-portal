"""
WaaS API Client
Handles communication with the Barracuda WaaS REST API
"""
import requests
from flask import current_app
import json


class WaasApiError(Exception):
    """Custom exception for WaaS API errors"""
    def __init__(self, message, status_code=None, response_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class WaasClient:
    """Client for interacting with the WaaS API"""

    def __init__(self, api_key, base_url=None):
        self.api_key = api_key
        self.base_url = base_url or current_app.config.get('WAAS_API_BASE_URL', 'https://api.waas.barracudanetworks.com')
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
        url = f'{self.base_url}{endpoint}'

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
            elif data:
                kwargs['json'] = data

            response = self.session.request(method, url, **kwargs)

            # Parse response
            try:
                response_data = response.json()
            except (json.JSONDecodeError, ValueError):
                response_data = {'raw': response.text}

            if not response.ok:
                error_msg = response_data.get('message', response_data.get('error', f'HTTP {response.status_code}'))
                raise WaasApiError(
                    f'WaaS API error: {error_msg}',
                    status_code=response.status_code,
                    response_data=response_data
                )

            return response_data

        except requests.exceptions.ConnectionError as e:
            raise WaasApiError(f'Cannot connect to WaaS API: {e}')
        except requests.exceptions.Timeout as e:
            raise WaasApiError(f'WaaS API request timed out: {e}')
        except requests.exceptions.RequestException as e:
            raise WaasApiError(f'WaaS API request failed: {e}')

    # === Account / Verify ===
    def verify_account(self):
        """Verify API key and get account info"""
        return self._make_request('GET', '/v2/waas/account')

    # === Applications ===
    def list_applications(self, params=None):
        """List all applications"""
        return self._make_request('GET', '/v2/waas/applications', params=params)

    def get_application(self, app_id):
        """Get a single application by ID"""
        return self._make_request('GET', f'/v2/waas/applications/{app_id}')

    def create_application(self, data):
        """Create a new application"""
        return self._make_request('POST', '/v2/waas/applications', data=data)

    def update_application(self, app_id, data):
        """Update an application"""
        return self._make_request('PUT', f'/v2/waas/applications/{app_id}', data=data)

    def delete_application(self, app_id):
        """Delete an application"""
        return self._make_request('DELETE', f'/v2/waas/applications/{app_id}')

    # === Application Security Config ===
    def get_security_config(self, app_id):
        """Get security configuration for an application"""
        return self._make_request('GET', f'/v2/waas/applications/{app_id}/security')

    def update_security_config(self, app_id, data):
        """Update security configuration"""
        return self._make_request('PUT', f'/v2/waas/applications/{app_id}/security', data=data)

    # === Certificates ===
    def list_certificates(self, params=None):
        """List all certificates"""
        return self._make_request('GET', '/v2/waas/certificates', params=params)

    def get_certificate(self, cert_id):
        """Get a single certificate"""
        return self._make_request('GET', f'/v2/waas/certificates/{cert_id}')

    def upload_certificate(self, files, data=None):
        """Upload a certificate"""
        return self._make_request('POST', '/v2/waas/certificates', files=files, data=data)

    def delete_certificate(self, cert_id):
        """Delete a certificate"""
        return self._make_request('DELETE', f'/v2/waas/certificates/{cert_id}')

    # === Logs ===
    def get_access_logs(self, app_id, params=None):
        """Get access logs for an application"""
        return self._make_request('GET', f'/v2/waas/applications/{app_id}/logs/access', params=params)

    def get_waf_logs(self, app_id, params=None):
        """Get WAF logs for an application"""
        return self._make_request('GET', f'/v2/waas/applications/{app_id}/logs/waf', params=params)

    def get_audit_logs(self, params=None):
        """Get audit/system logs"""
        return self._make_request('GET', '/v2/waas/logs/audit', params=params)

    # === DNS / CNAME ===
    def get_dns_info(self, app_id):
        """Get DNS/CNAME information for an application"""
        return self._make_request('GET', f'/v2/waas/applications/{app_id}/dns')

    # === Proxy ===
    def get_proxy_settings(self, app_id):
        """Get reverse proxy settings for an application"""
        return self._make_request('GET', f'/v2/waas/applications/{app_id}/proxy')

    def update_proxy_settings(self, app_id, data):
        """Update reverse proxy settings"""
        return self._make_request('PUT', f'/v2/waas/applications/{app_id}/proxy', data=data)