"""
Proxy routes — noVNC browser proxy sessions.

Allows users to browse their WaaS-protected application through a server-side
Chromium browser with DNS overrides, exposed via noVNC in an iframe.
"""
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_required, current_user

from app.models import WaasAccount, AuditLog, ProxySession
from app.waas_client import WaasClient, WaasApiError
from app.proxy_manager import (
    start_session,
    stop_session,
    get_active_session,
    cleanup_stale_sessions,
    ProxyManagerError,
)

bp = Blueprint('proxy', __name__, url_prefix='/proxy')


def _get_account_and_app(account_id, app_id):
    """Helper: load account (owned by current user) and application export data.

    Returns (account, app_data, client) or aborts with 404.
    """
    account = WaasAccount.query.filter_by(
        id=account_id,
        user_id=current_user.id,
        is_active=True,
    ).first_or_404()

    client = WaasClient(account.api_key)
    try:
        app_data = client.get_application(app_id)
    except WaasApiError as e:
        flash(f'Failed to load application data: {e}', 'danger')
        app_data = None

    return account, app_data, client


@bp.route('/<int:account_id>/<app_id>')
@login_required
def launch(account_id, app_id):
    """Launch page — shows app info, domain selector, CNAME, active session status."""
    # Clean up any stale sessions first
    cleanup_stale_sessions()

    account, app_data, client = _get_account_and_app(account_id, app_id)

    # Extract endpoints data
    endpoints = {}
    domains = []
    cname = ''
    if app_data:
        endpoints = app_data.get('endpoints', {}) or {}
        if isinstance(endpoints, dict):
            domains = endpoints.get('domains', []) or []
            cname = endpoints.get('cname', '') or ''

    # Check for an active session
    active_session = get_active_session(current_user.id, account_id, app_id)

    return render_template(
        'proxy/launch.html',
        account=account,
        app_id=app_id,
        app_data=app_data,
        domains=domains,
        cname=cname,
        active_session=active_session,
    )


@bp.route('/<int:account_id>/<app_id>/start', methods=['POST'])
@login_required
def start(account_id, app_id):
    """Start a new noVNC proxy session for the selected domain."""
    if current_user.role == 'viewer':
        flash('You do not have permission to start proxy sessions.', 'danger')
        return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))

    account = WaasAccount.query.filter_by(
        id=account_id,
        user_id=current_user.id,
        is_active=True,
    ).first_or_404()

    domain = request.form.get('domain', '').strip()
    cname = request.form.get('cname', '').strip()

    if not domain:
        flash('Please select a domain to browse.', 'warning')
        return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))

    if not cname:
        flash('CNAME is required to start a proxy session.', 'warning')
        return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))

    try:
        session = start_session(
            user_id=current_user.id,
            account_id=account_id,
            app_id=app_id,
            domain=domain,
            cname=cname,
        )

        AuditLog.log(
            user_id=current_user.id,
            action='proxy_session_start',
            resource_type='proxy_session',
            resource_id=session.id,
            details=f'Started proxy session for {domain} (app: {app_id}, account: {account.account_name})',
            ip_address=request.remote_addr,
        )

        flash(f'Proxy session started for {domain}.', 'success')
        return redirect(url_for('proxy.session_view', account_id=account_id, app_id=app_id))

    except ProxyManagerError as e:
        flash(f'Failed to start proxy session: {e}', 'danger')
        return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))


@bp.route('/<int:account_id>/<app_id>/stop', methods=['POST'])
@login_required
def stop(account_id, app_id):
    """Stop the active proxy session."""
    account = WaasAccount.query.filter_by(
        id=account_id,
        user_id=current_user.id,
        is_active=True,
    ).first_or_404()

    active_session = get_active_session(current_user.id, account_id, app_id)
    if not active_session:
        flash('No active session to stop.', 'warning')
        return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))

    try:
        stop_session(active_session.id)

        AuditLog.log(
            user_id=current_user.id,
            action='proxy_session_stop',
            resource_type='proxy_session',
            resource_id=active_session.id,
            details=f'Stopped proxy session for {active_session.domain} (app: {app_id}, account: {account.account_name})',
            ip_address=request.remote_addr,
        )

        flash('Proxy session stopped.', 'success')
    except ProxyManagerError as e:
        flash(f'Error stopping session: {e}', 'danger')

    return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))


@bp.route('/<int:account_id>/<app_id>/session')
@login_required
def session_view(account_id, app_id):
    """Session view — embedded noVNC iframe + WAF log panel."""
    account = WaasAccount.query.filter_by(
        id=account_id,
        user_id=current_user.id,
        is_active=True,
    ).first_or_404()

    active_session = get_active_session(current_user.id, account_id, app_id)
    if not active_session:
        flash('No active proxy session. Please start one first.', 'warning')
        return redirect(url_for('proxy.launch', account_id=account_id, app_id=app_id))

    # Build the noVNC URL — goes through nginx /vnc/<port>/ proxy to the correct websockify
    ws_port = active_session.websocket_port
    novnc_url = f'/vnc/{ws_port}/vnc.html?autoconnect=true&resize=scale&reconnect=true&port=443&path=vnc/{ws_port}/websockify&encrypt=1'

    return render_template(
        'proxy/session.html',
        account=account,
        app_id=app_id,
        session=active_session,
        novnc_url=novnc_url,
    )


@bp.route('/<int:account_id>/<app_id>/waf-logs')
@login_required
def waf_logs(account_id, app_id):
    """AJAX endpoint — returns WAF logs as JSON for the active session period."""
    account = WaasAccount.query.filter_by(
        id=account_id,
        user_id=current_user.id,
        is_active=True,
    ).first_or_404()

    active_session = get_active_session(current_user.id, account_id, app_id)
    if not active_session:
        return jsonify({'logs': [], 'error': 'No active session'})

    try:
        client = WaasClient(account.api_key)

        # Build time filter params — logs since session started
        params = {}
        if active_session.started_at:
            params['from_time'] = active_session.started_at.strftime('%Y-%m-%dT%H:%M:%SZ')
            params['to_time'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        result = client.get_waf_logs(app_id, params=params)

        # The API may return a list directly or a dict with a data/logs key
        logs = []
        if isinstance(result, list):
            logs = result
        elif isinstance(result, dict):
            logs = result.get('data', result.get('logs', result.get('items', [])))

        return jsonify({'logs': logs, 'session_id': active_session.id})

    except WaasApiError as e:
        return jsonify({'logs': [], 'error': str(e)})