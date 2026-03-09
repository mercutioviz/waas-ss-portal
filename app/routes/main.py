from datetime import datetime, date
from flask import Blueprint, render_template, redirect, url_for, jsonify
from flask_login import login_required, current_user
import logging

logger = logging.getLogger(__name__)


def _parse_cert_expiry(value):
    """Try to parse a certificate expiry string into a date object."""
    if not value or value in ('-', '"-"', ''):
        return None
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%fZ',
                '%b %d %H:%M:%S %Y GMT', '%d/%m/%Y', '%m/%d/%Y'):
        try:
            return datetime.strptime(str(value).strip(), fmt).date()
        except ValueError:
            continue
    # Try ISO format as fallback
    try:
        return datetime.fromisoformat(str(value).strip()).date()
    except (ValueError, TypeError):
        return None

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Landing page - redirect to dashboard if logged in"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard view"""
    from app.models import WaasAccount, AuditLog
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    recent_activity = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', accounts=accounts, recent_activity=recent_activity)


@bp.route('/dashboard/counts')
@login_required
def dashboard_counts():
    """AJAX endpoint returning per-account application/certificate counts and cert expiry warnings."""
    from app.models import WaasAccount
    from app.waas_client import WaasClient, WaasApiError

    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()

    total_apps = 0
    total_certs = 0
    account_data = []
    expiring_certs = []
    errors = []
    today = date.today()

    for account in accounts:
        acct_info = {
            'id': account.id,
            'name': account.account_name,
            'app_count': 0,
            'cert_count': 0,
            'status': 'ok',
            'has_api_key': account.has_api_key,
            'has_v2_credentials': account.has_v2_credentials,
        }

        try:
            client = WaasClient.from_account(account)
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: cannot create client for account {account.id}: {e}')
            acct_info['status'] = 'error'
            errors.append(str(e))
            account_data.append(acct_info)
            continue

        # Applications
        try:
            apps_resp = client.list_applications()
            if isinstance(apps_resp, list):
                acct_info['app_count'] = len(apps_resp)
            elif isinstance(apps_resp, dict):
                if 'results' in apps_resp:
                    acct_info['app_count'] = len(apps_resp['results'])
                elif 'count' in apps_resp:
                    acct_info['app_count'] = apps_resp['count']
                elif 'applications' in apps_resp:
                    acct_info['app_count'] = len(apps_resp['applications'])
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: failed to list apps for account {account.id}: {e}')
            errors.append(str(e))

        # Certificates
        try:
            certs_resp = client.list_certificates()
            certs_list = []
            if isinstance(certs_resp, list):
                certs_list = certs_resp
            elif isinstance(certs_resp, dict):
                certs_list = certs_resp.get('results',
                             certs_resp.get('certificates',
                             certs_resp.get('data', [])))
            acct_info['cert_count'] = len(certs_list)

            # Check for expiring certs
            for cert in certs_list:
                expiry_str = cert.get('expiry', cert.get('expiryDate'))
                expiry_date = _parse_cert_expiry(expiry_str)
                if expiry_date:
                    days_remaining = (expiry_date - today).days
                    if days_remaining <= 30:
                        expiring_certs.append({
                            'name': cert.get('name', 'Unknown'),
                            'app_name': cert.get('_app_name', ''),
                            'account_id': account.id,
                            'account_name': account.account_name,
                            'expiry': str(expiry_date),
                            'days_remaining': days_remaining,
                        })
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: failed to list certs for account {account.id}: {e}')
            errors.append(str(e))

        total_apps += acct_info['app_count']
        total_certs += acct_info['cert_count']
        account_data.append(acct_info)

    return jsonify({
        'app_count': total_apps,
        'cert_count': total_certs,
        'accounts': account_data,
        'expiring_certs': sorted(expiring_certs, key=lambda c: c['days_remaining']),
        'errors': errors,
    })


@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')
