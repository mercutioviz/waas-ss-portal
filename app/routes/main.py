from flask import Blueprint, render_template, redirect, url_for, jsonify
from flask_login import login_required, current_user
import logging

logger = logging.getLogger(__name__)

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
    from app.models import WaasAccount
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    return render_template('dashboard.html', accounts=accounts)


@bp.route('/dashboard/counts')
@login_required
def dashboard_counts():
    """AJAX endpoint returning application and certificate counts across all active accounts."""
    from app.models import WaasAccount
    from app.waas_client import WaasClient, WaasApiError

    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()

    app_count = 0
    cert_count = 0
    errors = []

    for account in accounts:
        try:
            client = WaasClient.from_account(account)
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: cannot create client for account {account.id}: {e}')
            errors.append(str(e))
            continue

        # Applications
        try:
            apps_resp = client.list_applications()
            if isinstance(apps_resp, list):
                app_count += len(apps_resp)
            elif isinstance(apps_resp, dict):
                if 'results' in apps_resp:
                    app_count += len(apps_resp['results'])
                elif 'count' in apps_resp:
                    app_count += apps_resp['count']
                elif 'applications' in apps_resp:
                    app_count += len(apps_resp['applications'])
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: failed to list apps for account {account.id}: {e}')
            errors.append(str(e))

        # Certificates
        try:
            certs_resp = client.list_certificates()
            if isinstance(certs_resp, list):
                cert_count += len(certs_resp)
            elif isinstance(certs_resp, dict):
                if 'results' in certs_resp:
                    cert_count += len(certs_resp['results'])
                elif 'count' in certs_resp:
                    cert_count += certs_resp['count']
                elif 'certificates' in certs_resp:
                    cert_count += len(certs_resp['certificates'])
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: failed to list certs for account {account.id}: {e}')
            errors.append(str(e))

    return jsonify({
        'app_count': app_count,
        'cert_count': cert_count,
        'errors': errors,
    })


@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')
