"""
Log viewer routes — WAF logs, access logs, and false-positive analysis.

Uses the v4 unified logs API which returns both WAF (LogType=WF) and
access/traffic (LogType=TR) entries in a single response.  Applications
are listed via the v2 API.
"""
import csv
import io
import json
from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app.models import WaasAccount, AuditLog, get_user_accounts, get_account_for_user
from app.waas_client import WaasClient, WaasApiError

bp = Blueprint('logs', __name__, url_prefix='/logs')

# Valid quick-range values accepted by the v4 API
QUICK_RANGES = [
    ('r_1h', 'Last 1 Hour'),
    ('r_24h', 'Last 24 Hours'),
    ('r_7d', 'Last 7 Days'),
    ('r_14d', 'Last 14 Days'),
    ('r_30d', 'Last 30 Days'),
    ('r_45d', 'Last 45 Days'),
    ('r_60d', 'Last 60 Days'),
]


def _get_account(account_id):
    """Load an active account accessible by the current user, or 404."""
    from flask import abort
    account, perm = get_account_for_user(account_id, current_user)
    if not account:
        abort(404)
    return account


def _get_applications(account):
    """Fetch application list via v2 API.  Returns list of dicts or []."""
    try:
        client = WaasClient.from_account(account)
        result = client.list_applications_v2()
        return result.get('results', [])
    except WaasApiError as e:
        flash(_('Failed to load applications: %(error)s', error=str(e)), 'danger')
        return []


WAF_CSV_FIELDS = [
    'EpochTime', 'Severity', 'Action', 'AttackGroup', 'Attack', 'URL',
    'Method', 'ClientIP', 'ClientIP_country_code', 'countryName',
    'owasp', 'owasp_risk_score',
]

ACCESS_CSV_FIELDS = [
    'EpochTime', 'ClientIP', 'ClientIP_country_code', 'countryName',
    'Method', 'URL', 'HTTPStatus', 'BytesSent', 'TimeTaken',
    'Protocol', 'Protected', 'ResponseType',
]


def _export_logs_as_csv(logs, log_type):
    """Export log entries as a CSV string."""
    fields = WAF_CSV_FIELDS if log_type == 'waf' else ACCESS_CSV_FIELDS
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for entry in logs:
        writer.writerow({f: entry.get(f, '') for f in fields})
    return output.getvalue()


def _export_logs_as_json(logs):
    """Export log entries as a JSON string."""
    return json.dumps(logs, indent=2, default=str)


def _make_export_response(logs, log_type, fmt, app_name, account_id):
    """Build a file download response for log export and create audit entry."""
    if fmt == 'csv':
        data = _export_logs_as_csv(logs, log_type)
        mimetype = 'text/csv'
        ext = 'csv'
    else:
        data = _export_logs_as_json(logs)
        mimetype = 'application/json'
        ext = 'json'

    filename = f'{log_type}_logs_{app_name}.{ext}'
    response = make_response(data)
    response.headers['Content-Type'] = mimetype
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

    AuditLog.log(
        user_id=current_user.id,
        action='log_export',
        resource_type=f'{log_type}_logs',
        resource_id=account_id,
        details=f'Exported {len(logs)} {log_type} log entries as {fmt.upper()} for {app_name}',
        ip_address=request.remote_addr,
    )

    return response


# ------------------------------------------------------------------
# Index / Launcher
# ------------------------------------------------------------------
@bp.route('/')
@login_required
def index():
    """Launcher page: account → application → log-type selector."""
    accounts = get_user_accounts(current_user)

    account_id = request.args.get('account_id', type=int)
    selected_account = None
    applications = []

    if account_id:
        selected_account, perm = get_account_for_user(account_id, current_user)
        if selected_account:
            applications = _get_applications(selected_account)

    return render_template(
        'logs/index.html',
        accounts=accounts,
        selected_account=selected_account,
        applications=applications,
    )


# ------------------------------------------------------------------
# WAF Logs
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/waf')
@login_required
def waf_logs(account_id, app_name):
    """WAF (firewall) log viewer with filtering."""
    account = _get_account(account_id)

    # Filter params from query string
    quick_range = request.args.get('quick_range', 'r_24h')
    client_ip = request.args.get('client_ip', '').strip()
    page = request.args.get('page', 1, type=int)
    items_per_page = request.args.get('per_page', 50, type=int)

    filter_fields = {}
    if client_ip:
        filter_fields['ClientIP'] = [{'condition': 'is', 'value': client_ip}]

    export_fmt = request.args.get('format', '').lower()

    logs = []
    total = 0
    error = None

    try:
        client = WaasClient.from_account(account)
        result = client.get_logs(
            app_name,
            quick_range=quick_range,
            page=page,
            items_per_page=items_per_page,
            filter_fields=filter_fields or None,
        )
        all_entries = result.get('results', [])
        # Filter to WAF entries only
        logs = [e for e in all_entries if e.get('LogType') == 'WF']
        total = result.get('count', len(all_entries))
    except WaasApiError as e:
        error = str(e)

    if export_fmt in ('csv', 'json') and logs:
        return _make_export_response(logs, 'waf', export_fmt, app_name, account.id)

    return render_template(
        'logs/waf.html',
        account=account,
        app_name=app_name,
        logs=logs,
        total=total,
        page=page,
        per_page=items_per_page,
        quick_range=quick_range,
        client_ip=client_ip,
        quick_ranges=QUICK_RANGES,
        error=error,
    )


# ------------------------------------------------------------------
# Access Logs
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/access')
@login_required
def access_logs(account_id, app_name):
    """Access / traffic log viewer with filtering."""
    account = _get_account(account_id)

    quick_range = request.args.get('quick_range', 'r_24h')
    client_ip = request.args.get('client_ip', '').strip()
    page = request.args.get('page', 1, type=int)
    items_per_page = request.args.get('per_page', 50, type=int)
    export_fmt = request.args.get('format', '').lower()

    filter_fields = {}
    if client_ip:
        filter_fields['ClientIP'] = [{'condition': 'is', 'value': client_ip}]

    logs = []
    total = 0
    error = None

    try:
        client = WaasClient.from_account(account)
        result = client.get_logs(
            app_name,
            quick_range=quick_range,
            page=page,
            items_per_page=items_per_page,
            filter_fields=filter_fields or None,
        )
        all_entries = result.get('results', [])
        # Filter to traffic/access entries only
        logs = [e for e in all_entries if e.get('LogType') == 'TR']
        total = result.get('count', len(all_entries))
    except WaasApiError as e:
        error = str(e)

    if export_fmt in ('csv', 'json') and logs:
        return _make_export_response(logs, 'access', export_fmt, app_name, account.id)

    return render_template(
        'logs/access.html',
        account=account,
        app_name=app_name,
        logs=logs,
        total=total,
        page=page,
        per_page=items_per_page,
        quick_range=quick_range,
        client_ip=client_ip,
        quick_ranges=QUICK_RANGES,
        error=error,
    )


# ------------------------------------------------------------------
# False-Positive Analysis
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/fp-analysis')
@login_required
def fp_analysis(account_id, app_name):
    """False-positive analysis — groups blocked WAF entries by attack type."""
    account = _get_account(account_id)

    quick_range = request.args.get('quick_range', 'r_7d')

    logs = []
    error = None

    try:
        client = WaasClient.from_account(account)
        result = client.get_logs(
            app_name,
            quick_range=quick_range,
            page=1,
            items_per_page=1000,  # fetch a large batch for analysis
        )
        all_entries = result.get('results', [])
        # Only WAF entries with DENY action
        logs = [
            e for e in all_entries
            if e.get('LogType') == 'WF' and e.get('Action') == 'DENY'
        ]
    except WaasApiError as e:
        error = str(e)

    # Group by AttackType + RuleID
    attack_groups = {}
    for entry in logs:
        attack_type = entry.get('AttackType', entry.get('Attack', 'Unknown'))
        rule_id = entry.get('RuleID', 'unknown')
        group_key = f'{attack_type}|{rule_id}'

        if group_key not in attack_groups:
            attack_groups[group_key] = {
                'attack_type': attack_type,
                'attack_name': entry.get('Attack', attack_type),
                'attack_group': entry.get('AttackGroup', '—'),
                'rule_id': rule_id,
                'rule_type': entry.get('RuleType', '—'),
                'owasp': entry.get('owasp', '—'),
                'cwe': entry.get('cwe', '—'),
                'owasp_api': entry.get('owasp_api_top_ten', '—'),
                'owasp_risk_score': entry.get('owasp_risk_score', '—'),
                'count': 0,
                'samples': [],
                'unique_ips': set(),
                'unique_urls': set(),
            }

        group = attack_groups[group_key]
        group['count'] += 1
        if len(group['samples']) < 5:
            group['samples'].append(entry)
        group['unique_ips'].add(entry.get('ClientIP', 'unknown'))
        group['unique_urls'].add(entry.get('URL', 'unknown'))

    # Convert sets to counts for template serialisation
    for group in attack_groups.values():
        group['unique_ip_count'] = len(group['unique_ips'])
        group['unique_url_count'] = len(group['unique_urls'])
        del group['unique_ips']
        del group['unique_urls']

    # Sort by count descending
    sorted_groups = sorted(attack_groups.values(), key=lambda g: g['count'], reverse=True)

    return render_template(
        'logs/fp_analysis.html',
        account=account,
        app_name=app_name,
        attack_groups=sorted_groups,
        total_blocked=len(logs),
        quick_range=quick_range,
        quick_ranges=QUICK_RANGES,
        error=error,
    )