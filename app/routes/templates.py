import json
import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import WaasAccount, AuditLog, ConfigTemplate
from app.forms import ConfigTemplateForm, TemplateFromAppForm
from app.waas_client import WaasClient, WaasApiError

logger = logging.getLogger(__name__)

bp = Blueprint('templates', __name__, url_prefix='/templates')


def get_client_for_account(account_id):
    """Helper to get WaasClient for a user's account"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first()
    if not account:
        return None, None
    return WaasClient.from_account(account), account


def get_template_or_404(template_id, owner_only=False):
    """Get a template by ID, checking visibility rules.

    If owner_only=True, only the owner can access it.
    Otherwise, owner or global templates are accessible.
    """
    template = ConfigTemplate.query.get_or_404(template_id)
    if owner_only:
        if template.user_id != current_user.id:
            return None
    else:
        if template.user_id != current_user.id and not template.is_global:
            return None
    return template


@bp.route('/')
@login_required
def list_templates():
    """List user's templates and global templates"""
    my_templates = ConfigTemplate.query.filter_by(user_id=current_user.id).order_by(ConfigTemplate.updated_at.desc()).all()
    global_templates = ConfigTemplate.query.filter(
        ConfigTemplate.is_global == True,
        ConfigTemplate.user_id != current_user.id
    ).order_by(ConfigTemplate.updated_at.desc()).all()
    return render_template('templates/list.html', my_templates=my_templates, global_templates=global_templates)


@bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_template():
    """Create a new template"""
    if current_user.role == 'viewer':
        flash('You do not have permission to create templates.', 'danger')
        return redirect(url_for('templates.list_templates'))

    form = ConfigTemplateForm()

    if form.validate_on_submit():
        # Restrict global toggle to admins
        is_global = form.is_global.data and current_user.is_admin

        template = ConfigTemplate(
            user_id=current_user.id,
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            is_global=is_global,
            config_data='{}'
        )
        db.session.add(template)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_create',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Created config template: {template.name}',
            ip_address=request.remote_addr
        )

        flash(f'Template "{template.name}" created. Now edit its configuration.', 'success')
        return redirect(url_for('templates.edit_config', template_id=template.id))

    return render_template('templates/add.html', form=form)


@bp.route('/<int:template_id>')
@login_required
def view_template(template_id):
    """View template details"""
    template = get_template_or_404(template_id)
    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('templates.list_templates'))

    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    return render_template('templates/view.html', template=template, accounts=accounts)


@bp.route('/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    """Edit template metadata"""
    template = get_template_or_404(template_id, owner_only=True)
    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('templates.list_templates'))

    if current_user.role == 'viewer':
        flash('You do not have permission to edit templates.', 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    form = ConfigTemplateForm(obj=template)

    if form.validate_on_submit():
        template.name = form.name.data.strip()
        template.description = form.description.data.strip() if form.description.data else None
        template.is_global = form.is_global.data and current_user.is_admin
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_edit',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Edited config template: {template.name}',
            ip_address=request.remote_addr
        )

        flash(f'Template "{template.name}" updated.', 'success')
        return redirect(url_for('templates.view_template', template_id=template.id))

    return render_template('templates/edit.html', form=form, template=template)


@bp.route('/<int:template_id>/edit-config', methods=['GET', 'POST'])
@login_required
def edit_config(template_id):
    """Edit raw JSON config data"""
    template = get_template_or_404(template_id, owner_only=True)
    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('templates.list_templates'))

    if current_user.role == 'viewer':
        flash('You do not have permission to edit templates.', 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    if request.method == 'POST':
        config_text = request.form.get('config_data', '{}')
        try:
            parsed = json.loads(config_text)
            template.config_dict = parsed
            db.session.commit()

            AuditLog.log(
                user_id=current_user.id,
                action='template_config_edit',
                resource_type='config_template',
                resource_id=template.id,
                details=f'Edited config data for template: {template.name}',
                ip_address=request.remote_addr
            )

            flash('Template configuration updated.', 'success')
            return redirect(url_for('templates.view_template', template_id=template.id))
        except json.JSONDecodeError as e:
            flash(f'Invalid JSON: {e}', 'danger')

    return render_template('templates/edit_config.html', template=template)


@bp.route('/<int:template_id>/delete', methods=['POST'])
@login_required
def delete_template(template_id):
    """Delete a template"""
    template = get_template_or_404(template_id, owner_only=True)
    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('templates.list_templates'))

    if current_user.role == 'viewer':
        flash('You do not have permission to delete templates.', 'danger')
        return redirect(url_for('templates.list_templates'))

    template_name = template.name
    AuditLog.log(
        user_id=current_user.id,
        action='template_delete',
        resource_type='config_template',
        resource_id=template.id,
        details=f'Deleted config template: {template_name}',
        ip_address=request.remote_addr
    )

    db.session.delete(template)
    db.session.commit()

    flash(f'Template "{template_name}" deleted.', 'success')
    return redirect(url_for('templates.list_templates'))


@bp.route('/from-app/<int:account_id>/<app_id>', methods=['GET', 'POST'])
@login_required
def save_as_template(account_id, app_id):
    """Create a template from a live application's exported config"""
    if current_user.role == 'viewer':
        flash('You do not have permission to create templates.', 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    client, account = get_client_for_account(account_id)
    if not client:
        flash('Account not found or inactive.', 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        app_config = client.get_application(app_id)
    except WaasApiError as e:
        flash(f'Failed to export application config: {e}', 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    # Also fetch security config for section-level extraction
    try:
        security_config = client.get_security_config(app_id)
    except WaasApiError:
        security_config = {}

    form = TemplateFromAppForm()

    if form.validate_on_submit():
        # Build partial config from selected sections
        config = {}

        if form.include_basic_security.data:
            if 'protection_mode' in security_config:
                config['protection_mode'] = security_config['protection_mode']
            elif 'protection_mode' in app_config:
                config['protection_mode'] = app_config['protection_mode']

        if form.include_request_limits.data and security_config.get('request_limits'):
            config['request_limits'] = security_config['request_limits']

        if form.include_clickjacking.data and security_config.get('clickjacking_protection'):
            config['clickjacking_protection'] = security_config['clickjacking_protection']

        if form.include_data_theft.data and security_config.get('data_theft_protection'):
            config['data_theft_protection'] = security_config['data_theft_protection']

        if form.include_servers.data and app_config.get('servers'):
            config['servers'] = app_config['servers']

        if form.include_endpoints.data and app_config.get('endpoints'):
            config['endpoints'] = app_config['endpoints']

        is_global = form.is_global.data and current_user.is_admin

        template = ConfigTemplate(
            user_id=current_user.id,
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            is_global=is_global,
        )
        template.config_dict = config
        db.session.add(template)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_create_from_app',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Created template "{template.name}" from app {app_id} (account: {account.account_name})',
            ip_address=request.remote_addr
        )

        flash(f'Template "{template.name}" created from application "{app_id}".', 'success')
        return redirect(url_for('templates.view_template', template_id=template.id))

    # Pre-fill name suggestion
    if request.method == 'GET':
        form.name.data = f'{app_id} - Security Template'

    return render_template(
        'templates/save_as.html',
        form=form,
        account=account,
        app_id=app_id,
        app_config=app_config,
        security_config=security_config
    )


@bp.route('/<int:template_id>/apply/<int:account_id>/<app_id>', methods=['POST'])
@login_required
def apply_template(template_id, account_id, app_id):
    """Apply a template to a single application"""
    if current_user.role == 'viewer':
        flash('You do not have permission to apply templates.', 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    template = get_template_or_404(template_id)
    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('templates.list_templates'))

    client, account = get_client_for_account(account_id)
    if not client:
        flash('Account not found or inactive.', 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    include_servers = request.form.get('include_servers') == 'on'
    include_endpoints = request.form.get('include_endpoints') == 'on'

    try:
        client.import_application(
            app_id,
            template.config_dict,
            include_servers=include_servers,
            include_endpoints=include_endpoints
        )

        AuditLog.log(
            user_id=current_user.id,
            action='template_apply',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Applied template "{template.name}" to app {app_id} (account: {account.account_name})',
            ip_address=request.remote_addr
        )

        flash(f'Template "{template.name}" applied to "{app_id}" successfully.', 'success')
    except WaasApiError as e:
        flash(f'Failed to apply template to "{app_id}": {e}', 'danger')

    return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))


@bp.route('/<int:template_id>/bulk-apply', methods=['GET', 'POST'])
@login_required
def bulk_apply(template_id):
    """Apply a template to multiple applications"""
    if current_user.role == 'viewer':
        flash('You do not have permission to apply templates.', 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    template = get_template_or_404(template_id)
    if not template:
        flash('Template not found or access denied.', 'danger')
        return redirect(url_for('templates.list_templates'))

    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()

    if request.method == 'POST':
        selected_apps = request.form.getlist('selected_apps')
        include_servers = request.form.get('include_servers') == 'on'
        include_endpoints = request.form.get('include_endpoints') == 'on'

        if not selected_apps:
            flash('No applications selected.', 'warning')
            return redirect(url_for('templates.bulk_apply', template_id=template_id))

        results = []
        for app_entry in selected_apps:
            # Format: "account_id:app_name"
            try:
                acct_id_str, app_name = app_entry.split(':', 1)
                acct_id = int(acct_id_str)
            except (ValueError, IndexError):
                results.append({'app': app_entry, 'account': 'Unknown', 'success': False, 'error': 'Invalid format'})
                continue

            client, account = get_client_for_account(acct_id)
            if not client:
                results.append({'app': app_name, 'account': f'ID {acct_id}', 'success': False, 'error': 'Account not found'})
                continue

            try:
                client.import_application(
                    app_name,
                    template.config_dict,
                    include_servers=include_servers,
                    include_endpoints=include_endpoints
                )
                results.append({'app': app_name, 'account': account.account_name, 'success': True, 'error': None})
            except WaasApiError as e:
                results.append({'app': app_name, 'account': account.account_name, 'success': False, 'error': str(e)})

        success_count = sum(1 for r in results if r['success'])
        fail_count = len(results) - success_count

        AuditLog.log(
            user_id=current_user.id,
            action='template_bulk_apply',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Bulk applied template "{template.name}" to {len(results)} apps ({success_count} ok, {fail_count} failed)',
            ip_address=request.remote_addr
        )

        return render_template(
            'templates/bulk_results.html',
            template=template,
            results=results,
            success_count=success_count,
            fail_count=fail_count
        )

    # GET: fetch apps from all accounts
    accounts_with_apps = []
    for account in accounts:
        try:
            client = WaasClient.from_account(account)
            result = client.list_applications()
            apps = _parse_app_list(result)
            if apps:
                accounts_with_apps.append({'account': account, 'apps': apps})
        except WaasApiError:
            pass

    return render_template(
        'templates/bulk_apply.html',
        template=template,
        accounts_with_apps=accounts_with_apps
    )


def _parse_app_list(result):
    """Normalise the raw API list response into a plain Python list."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        apps = result.get('results', result.get('data', result.get('applications', [])))
        return apps if isinstance(apps, list) else [result]
    return []
