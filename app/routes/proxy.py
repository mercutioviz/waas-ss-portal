from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import WaasAccount, AuditLog
from app.waas_client import WaasClient, WaasApiError

bp = Blueprint('proxy', __name__, url_prefix='/proxy')


@bp.route('/<int:account_id>/<app_id>')
@login_required
def view_proxy(account_id, app_id):
    """View reverse proxy settings for an application"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    proxy_settings = None
    application = None
    error = None

    try:
        client = WaasClient(account.api_key)
        application = client.get_application(app_id)
        proxy_settings = client.get_proxy_settings(app_id)
    except WaasApiError as e:
        error = str(e)

    return render_template(
        'proxy/view.html',
        account=account,
        app_id=app_id,
        application=application,
        proxy_settings=proxy_settings,
        error=error
    )


@bp.route('/<int:account_id>/<app_id>', methods=['POST'])
@login_required
def update_proxy(account_id, app_id):
    """Update reverse proxy settings"""
    if current_user.role == 'viewer':
        flash('You do not have permission to modify proxy settings.', 'danger')
        return redirect(url_for('proxy.view_proxy', account_id=account_id, app_id=app_id))

    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    try:
        client = WaasClient(account.api_key)
        data = request.get_json() if request.is_json else request.form.to_dict()
        client.update_proxy_settings(app_id, data)

        AuditLog.log(
            user_id=current_user.id,
            action='proxy_settings_update',
            resource_type='application',
            details=f'Updated proxy settings for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        flash('Proxy settings updated successfully.', 'success')
    except WaasApiError as e:
        flash(f'Failed to update proxy settings: {e}', 'danger')

    return redirect(url_for('proxy.view_proxy', account_id=account_id, app_id=app_id))