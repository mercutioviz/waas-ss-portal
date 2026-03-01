from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import WaasAccount
from app.waas_client import WaasClient, WaasApiError

bp = Blueprint('logs', __name__, url_prefix='/logs')


@bp.route('/')
@login_required
def index():
    """Log viewer index - choose account and application"""
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    return render_template('logs/index.html', accounts=accounts)


@bp.route('/<int:account_id>/<app_id>/waf')
@login_required
def waf_logs(account_id, app_id):
    """View WAF logs for an application"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    # Pagination and filter params
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    params = {
        'page': page,
        'per_page': per_page,
    }

    # Optional filters
    for key in ['attack_type', 'severity', 'action', 'start_date', 'end_date', 'client_ip']:
        val = request.args.get(key)
        if val:
            params[key] = val

    logs = []
    error = None
    total = 0

    try:
        client = WaasClient.from_account(account)
        result = client.get_waf_logs(app_id, params=params)
        if isinstance(result, list):
            logs = result
            total = len(result)
        else:
            logs = result.get('results', result.get('data', []))
            total = result.get('total', result.get('count', len(logs)))
    except WaasApiError as e:
        error = str(e)

    return render_template(
        'logs/waf.html',
        account=account,
        app_id=app_id,
        logs=logs,
        total=total,
        page=page,
        per_page=per_page,
        error=error,
        filters=params
    )


@bp.route('/<int:account_id>/<app_id>/access')
@login_required
def access_logs(account_id, app_id):
    """View access logs for an application"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    params = {
        'page': page,
        'per_page': per_page,
    }

    for key in ['status_code', 'method', 'start_date', 'end_date', 'client_ip', 'url_path']:
        val = request.args.get(key)
        if val:
            params[key] = val

    logs = []
    error = None
    total = 0

    try:
        client = WaasClient.from_account(account)
        result = client.get_access_logs(app_id, params=params)
        if isinstance(result, list):
            logs = result
            total = len(result)
        else:
            logs = result.get('results', result.get('data', []))
            total = result.get('total', result.get('count', len(logs)))
    except WaasApiError as e:
        error = str(e)

    return render_template(
        'logs/access.html',
        account=account,
        app_id=app_id,
        logs=logs,
        total=total,
        page=page,
        per_page=per_page,
        error=error,
        filters=params
    )


@bp.route('/<int:account_id>/<app_id>/fp-analysis')
@login_required
def fp_analysis(account_id, app_id):
    """False positive analysis view for WAF logs"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    logs = []
    error = None

    try:
        client = WaasClient.from_account(account)
        # Fetch recent WAF logs with action=block for FP analysis
        params = {
            'per_page': 100,
            'action': 'block',
        }
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date

        result = client.get_waf_logs(app_id, params=params)
        if isinstance(result, list):
            logs = result
        else:
            logs = result.get('results', result.get('data', []))
    except WaasApiError as e:
        error = str(e)

    # Group logs by attack type/rule for analysis
    attack_groups = {}
    for log_entry in logs:
        attack_type = log_entry.get('attack_type', log_entry.get('rule_name', 'Unknown'))
        if attack_type not in attack_groups:
            attack_groups[attack_type] = {
                'count': 0,
                'samples': [],
                'unique_ips': set(),
                'unique_urls': set(),
            }
        group = attack_groups[attack_type]
        group['count'] += 1
        if len(group['samples']) < 5:
            group['samples'].append(log_entry)
        group['unique_ips'].add(log_entry.get('client_ip', 'unknown'))
        group['unique_urls'].add(log_entry.get('url', log_entry.get('request_url', 'unknown')))

    # Convert sets to counts for template
    for group in attack_groups.values():
        group['unique_ip_count'] = len(group['unique_ips'])
        group['unique_url_count'] = len(group['unique_urls'])
        del group['unique_ips']
        del group['unique_urls']

    return render_template(
        'logs/fp_analysis.html',
        account=account,
        app_id=app_id,
        attack_groups=attack_groups,
        total_blocked=len(logs),
        error=error
    )