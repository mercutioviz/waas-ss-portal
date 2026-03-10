import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app.models import WaasAccount, AuditLog
from app.waas_client import WaasClient, WaasApiError
from app.forms import ApplicationCreateForm

logger = logging.getLogger(__name__)

bp = Blueprint('applications', __name__, url_prefix='/applications')


def get_client_for_account(account_id):
    """Helper to get WaasClient for a user's account"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first()
    if not account:
        return None, None
    return WaasClient.from_account(account), account


def _parse_app_list(result):
    """Normalise the raw API list response into a plain Python list."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        apps = result.get('results', result.get('data', result.get('applications', [])))
        return apps if isinstance(apps, list) else [result]
    return []


@bp.route('/')
@login_required
def list_applications():
    """List applications — user selects which WaaS account to view.

    Supports ``?api_version=v2`` query param to switch between v4 (default)
    and v2 API for the listing.  The template shows which API is in use.
    """
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    selected_account_id = request.args.get('account_id', type=int)
    api_version = request.args.get('api_version', 'v4')  # default to v4

    applications = []
    selected_account = None
    error = None

    if selected_account_id:
        client, selected_account = get_client_for_account(selected_account_id)
        if client:
            try:
                if api_version == 'v2' and selected_account.has_v2_credentials:
                    result = client.list_applications_v2()
                    applications = _parse_app_list(result)
                    logger.info(f'Listed {len(applications)} apps via v2 API')
                else:
                    # Fall back to v4 if v2 requested but no v2 creds
                    if api_version == 'v2' and not selected_account.has_v2_credentials:
                        api_version = 'v4'
                        flash(_('v2 credentials not available — using v4 API.'), 'warning')
                    result = client.list_applications()
                    applications = _parse_app_list(result)
                    logger.info(f'Listed {len(applications)} apps via v4 API')

                if applications:
                    first_app = applications[0]
                    logger.info(f'First application keys: {list(first_app.keys()) if isinstance(first_app, dict) else type(first_app).__name__}')
                else:
                    logger.info('No applications returned from API')
            except WaasApiError as e:
                error = str(e)
        else:
            error = _('Account not found or inactive.')

    return render_template(
        'applications/list.html',
        accounts=accounts,
        applications=applications,
        selected_account=selected_account,
        selected_account_id=selected_account_id,
        api_version=api_version,
        error=error
    )


@bp.route('/api/list')
@login_required
def api_list_applications():
    """JSON endpoint returning app names for a given account_id."""
    account_id = request.args.get('account_id', type=int)
    if not account_id:
        return jsonify({'applications': [], 'error': 'account_id required'}), 400

    client, account = get_client_for_account(account_id)
    if not client:
        return jsonify({'applications': [], 'error': 'Account not found or inactive'}), 404

    try:
        result = client.list_applications()
        apps = _parse_app_list(result)
        app_list = []
        for app in apps:
            if isinstance(app, dict):
                app_list.append({
                    'name': app.get('name', ''),
                    'app_group': app.get('app_group', ''),
                })
        return jsonify({'applications': app_list})
    except WaasApiError as e:
        return jsonify({'applications': [], 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>')
@login_required
def view_application(account_id, app_id):
    """View application details (v4 export API)."""
    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
    except WaasApiError as e:
        flash(_('Failed to load application: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    return render_template(
        'applications/view.html',
        account=account,
        application=application,
        app_id=app_id
    )


@bp.route('/<int:account_id>/create', methods=['GET', 'POST'])
@login_required
def create_application(account_id):
    """Create a new WaaS application via v2 API."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to create applications.'), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    if not account.has_v2_credentials:
        flash(_('Application creation requires v2 API credentials (email + password) on this account.'), 'warning')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    form = ApplicationCreateForm()

    if form.validate_on_submit():
        data = {
            'applicationName': form.application_name.data.strip(),
            'hostnames': [{'hostname': form.hostname.data.strip()}],
            'backendIp': form.backend_ip.data.strip(),
            'backendPort': form.backend_port.data,
            'backendType': form.backend_type.data,
            'useExistingIp': False,
            'maliciousTraffic': form.malicious_traffic.data,
            'useHttps': form.use_https.data,
            'useHttp': form.use_http.data,
            'redirectHTTP': form.redirect_http.data,
        }

        if form.use_https.data:
            data['httpsServicePort'] = 443
        if form.use_http.data:
            data['httpServicePort'] = 80

        try:
            result = client.create_application_v2(data)
            app_name = form.application_name.data.strip()

            AuditLog.log(
                user_id=current_user.id,
                action='application_create',
                resource_type='application',
                resource_id=app_name,
                details=f'Created application "{app_name}" on account {account.account_name} (v2 API)',
                ip_address=request.remote_addr
            )

            flash(_('Application "%(name)s" created successfully.', name=app_name), 'success')
            return redirect(url_for('applications.list_applications', account_id=account_id))
        except WaasApiError as e:
            flash(_('Failed to create application: %(error)s', error=str(e)), 'danger')

    return render_template(
        'applications/create.html',
        form=form,
        account=account
    )


@bp.route('/<int:account_id>/<int:app_id>/delete', methods=['POST'])
@login_required
def delete_application(account_id, app_id):
    """Delete a WaaS application via v2 API.

    ``app_id`` is the v2 integer application ID.
    """
    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete applications.'), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    if not account.has_v2_credentials:
        flash(_('Application deletion requires v2 API credentials on this account.'), 'warning')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    app_name = request.form.get('app_name', f'ID {app_id}')

    try:
        client.delete_application_v2(app_id)

        AuditLog.log(
            user_id=current_user.id,
            action='application_delete',
            resource_type='application',
            resource_id=str(app_id),
            details=f'Deleted application "{app_name}" (ID {app_id}) from account {account.account_name} (v2 API)',
            ip_address=request.remote_addr
        )

        flash(_('Application "%(name)s" deleted.', name=app_name), 'success')
    except WaasApiError as e:
        flash(_('Failed to delete application: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('applications.list_applications', account_id=account_id))


@bp.route('/<int:account_id>/<app_id>/security')
@login_required
def security_config(account_id, app_id):
    """View/edit security configuration for an application (v4 API)."""
    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
        security = client.get_security_config(app_id)
    except WaasApiError as e:
        flash(_('Failed to load security config: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    return render_template(
        'applications/security.html',
        account=account,
        application=application,
        security=security,
        app_id=app_id
    )


@bp.route('/<int:account_id>/<app_id>/security', methods=['POST'])
@login_required
def update_security_config(account_id, app_id):
    """Update security configuration (v4 API)."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to modify configurations.'), 'danger')
        return redirect(url_for('applications.security_config', account_id=account_id, app_id=app_id))

    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
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

        flash(_('Security configuration updated.'), 'success')
    except WaasApiError as e:
        flash(_('Failed to update security config: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('applications.security_config', account_id=account_id, app_id=app_id))


@bp.route('/<int:account_id>/<app_id>/dns')
@login_required
def dns_info(account_id, app_id):
    """View DNS/CNAME information for an application (v4 API)."""
    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
        dns = client.get_dns_info(app_id)
    except WaasApiError as e:
        flash(_('Failed to load DNS info: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    return render_template(
        'applications/dns.html',
        account=account,
        application=application,
        dns=dns,
        app_id=app_id
    )
