from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app.models import WaasAccount, AuditLog
from app.waas_client import WaasClient, WaasApiError

bp = Blueprint('applications', __name__, url_prefix='/applications')


def get_client_for_account(account_id):
    """Helper to get WaasClient for a user's account"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first()
    if not account:
        return None, None
    return WaasClient(account.api_key), account


@bp.route('/')
@login_required
def list_applications():
    """List applications - user selects which WaaS account to view"""
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    selected_account_id = request.args.get('account_id', type=int)

    applications = []
    selected_account = None
    error = None

    if selected_account_id:
        client, selected_account = get_client_for_account(selected_account_id)
        if client:
            try:
                result = client.list_applications()
                applications = result if isinstance(result, list) else result.get('results', result.get('data', []))
            except WaasApiError as e:
                error = str(e)
        else:
            error = 'Account not found or inactive.'

    return render_template(
        'applications/list.html',
        accounts=accounts,
        applications=applications,
        selected_account=selected_account,
        selected_account_id=selected_account_id,
        error=error
    )


@bp.route('/<int:account_id>/<app_id>')
@login_required
def view_application(account_id, app_id):
    """View application details"""
    client, account = get_client_for_account(account_id)
    if not client:
        flash('Account not found or inactive.', 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
    except WaasApiError as e:
        flash(f'Failed to load application: {e}', 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    return render_template(
        'applications/view.html',
        account=account,
        application=application
    )


@bp.route('/<int:account_id>/<app_id>/security')
@login_required
def security_config(account_id, app_id):
    """View/edit security configuration for an application"""
    client, account = get_client_for_account(account_id)
    if not client:
        flash('Account not found or inactive.', 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
        security = client.get_security_config(app_id)
    except WaasApiError as e:
        flash(f'Failed to load security config: {e}', 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    return render_template(
        'applications/security.html',
        account=account,
        application=application,
        security=security
    )


@bp.route('/<int:account_id>/<app_id>/security', methods=['POST'])
@login_required
def update_security_config(account_id, app_id):
    """Update security configuration"""
    if current_user.role == 'viewer':
        flash('You do not have permission to modify configurations.', 'danger')
        return redirect(url_for('applications.security_config', account_id=account_id, app_id=app_id))

    client, account = get_client_for_account(account_id)
    if not client:
        flash('Account not found or inactive.', 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        client.update_security_config(app_id, data)

        AuditLog.log(
            user_id=current_user.id,
            action='security_config_update',
            resource_type='application',
            resource_id=None,
            details=f'Updated security config for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        flash('Security configuration updated.', 'success')
    except WaasApiError as e:
        flash(f'Failed to update security config: {e}', 'danger')

    return redirect(url_for('applications.security_config', account_id=account_id, app_id=app_id))


@bp.route('/<int:account_id>/<app_id>/dns')
@login_required
def dns_info(account_id, app_id):
    """View DNS/CNAME information for an application"""
    client, account = get_client_for_account(account_id)
    if not client:
        flash('Account not found or inactive.', 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
        dns = client.get_dns_info(app_id)
    except WaasApiError as e:
        flash(f'Failed to load DNS info: {e}', 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    return render_template(
        'applications/dns.html',
        account=account,
        application=application,
        dns=dns
    )