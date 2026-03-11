from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_babel import gettext as _
from datetime import datetime
from app import db
from app.models import WaasAccount, AuditLog
from app.forms import WaasAccountForm, RotateApiKeyForm
from app.waas_client import WaasClient, WaasApiError
from app import limiter

bp = Blueprint('accounts', __name__, url_prefix='/accounts')


@bp.route('/')
@login_required
def list_accounts():
    """List user's WaaS accounts"""
    accounts = WaasAccount.query.filter_by(user_id=current_user.id).all()
    return render_template('accounts/list.html', accounts=accounts)


@bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_account():
    """Add a new WaaS API account"""
    form = WaasAccountForm()
    if form.validate_on_submit():
        account = WaasAccount(
            user_id=current_user.id,
            account_name=form.account_name.data,
        )

        # Store credentials (at least one set is guaranteed by form validation)
        if form.api_key.data and form.api_key.data.strip():
            account.api_key = form.api_key.data.strip()
        if form.waas_email.data and form.waas_email.data.strip():
            account.waas_email = form.waas_email.data.strip()
        if form.waas_password.data and form.waas_password.data.strip():
            account.waas_password = form.waas_password.data.strip()

        # Save first so we have an ID for audit log
        db.session.add(account)
        db.session.commit()

        # Attempt verification if v2 credentials are available
        flash_msg = _('Account "%(name)s" added successfully.', name=account.account_name)
        if account.has_v2_credentials:
            try:
                # Login via v2 to get auth token, then verify
                client = WaasClient.from_account(account)
                account_info = client.verify_account()
                accounts_list = account_info.get('accounts', [])
                if accounts_list:
                    account.waas_account_id = str(accounts_list[0].get('id', ''))
                account.last_verified = datetime.utcnow()
                account.is_active = True
                db.session.commit()
                flash_msg = _('Account "%(name)s" added and verified successfully.', name=account.account_name)
            except WaasApiError as e:
                flash_msg = _('Account "%(name)s" added, but verification failed: %(error)s. You can retry later.', name=account.account_name, error=str(e))
        elif account.has_api_key:
            flash_msg = _('Account "%(name)s" added successfully.', name=account.account_name) + ' ' + _('Add WaaS email/password credentials to enable account verification.')

        AuditLog.log(
            user_id=current_user.id,
            action='account_add',
            resource_type='waas_account',
            resource_id=account.id,
            details=f'Added WaaS account: {account.account_name}',
            ip_address=request.remote_addr
        )

        flash(flash_msg, 'success')
        return redirect(url_for('accounts.list_accounts'))

    return render_template('accounts/add.html', form=form)


@bp.route('/<int:account_id>')
@login_required
def view_account(account_id):
    """View WaaS account details"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
    return render_template('accounts/view.html', account=account)


@bp.route('/<int:account_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_account(account_id):
    """Edit a WaaS account"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()

    # Pre-populate form; don't expose secrets in the form value
    form = WaasAccountForm(obj=account)

    if request.method == 'GET':
        # Show placeholder hints but don't fill in secret fields
        form.api_key.data = ''
        form.waas_email.data = account.waas_email or ''
        form.waas_password.data = ''

    if form.is_submitted() and form.validate(is_edit=True, account=account):
        account.account_name = form.account_name.data

        # Update credentials only if new values provided
        if form.api_key.data and form.api_key.data.strip():
            account.api_key = form.api_key.data.strip()
        if form.waas_email.data and form.waas_email.data.strip():
            account.waas_email = form.waas_email.data.strip()
        if form.waas_password.data and form.waas_password.data.strip():
            account.waas_password = form.waas_password.data.strip()

        # Invalidate cached v2 token when credentials change
        if form.waas_email.data or form.waas_password.data:
            account.v2_auth_token = None
            account.v2_token_expiry = None

        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='account_edit',
            resource_type='waas_account',
            resource_id=account.id,
            details=f'Edited WaaS account: {account.account_name}',
            ip_address=request.remote_addr
        )

        flash(_('Account "%(name)s" updated.', name=account.account_name), 'success')
        return redirect(url_for('accounts.view_account', account_id=account.id))

    return render_template('accounts/edit.html', form=form, account=account)


@bp.route('/<int:account_id>/verify', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def verify_account(account_id):
    """Re-verify a WaaS account using v2 credentials"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()

    if not account.has_v2_credentials:
        flash(
            _('Cannot verify "%(name)s": WaaS email/password credentials are required for verification. Edit the account to add v2 credentials.', name=account.account_name),
            'warning'
        )
        return redirect(url_for('accounts.view_account', account_id=account_id))

    try:
        client = WaasClient.from_account(account)
        account_info = client.verify_account()
        # v2 response: {"accounts": [{"id": ..., "name": ...}, ...], ...}
        accounts_list = account_info.get('accounts', [])
        if accounts_list:
            account.waas_account_id = str(accounts_list[0].get('id', ''))
        account.last_verified = datetime.utcnow()
        account.is_active = True
        db.session.commit()

        flash(_('Account "%(name)s" verified successfully.', name=account.account_name), 'success')
    except WaasApiError as e:
        flash(_('Verification failed for "%(name)s": %(error)s', name=account.account_name, error=str(e)), 'danger')

    return redirect(url_for('accounts.view_account', account_id=account_id))


@bp.route('/<int:account_id>/delete', methods=['POST'])
@login_required
def delete_account(account_id):
    """Delete a WaaS account"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
    account_name = account.account_name

    AuditLog.log(
        user_id=current_user.id,
        action='account_delete',
        resource_type='waas_account',
        resource_id=account.id,
        details=f'Deleted WaaS account: {account_name}',
        ip_address=request.remote_addr
    )

    db.session.delete(account)
    db.session.commit()

    flash(_('Account "%(name)s" has been deleted.', name=account_name), 'success')
    return redirect(url_for('accounts.list_accounts'))


@bp.route('/<int:account_id>/rotate-key', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def rotate_key(account_id):
    """Rotate the API key for a WaaS account."""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
    form = RotateApiKeyForm()

    if form.validate_on_submit():
        new_key = form.new_api_key.data.strip()

        # Optionally verify the new key with a lightweight API call
        if form.verify_key.data:
            try:
                test_client = WaasClient(api_key=new_key)
                test_client.list_applications()
            except WaasApiError as e:
                flash(_('New API key verification failed: %(error)s. Key was NOT saved.', error=str(e)), 'danger')
                return render_template('accounts/rotate_key.html', form=form, account=account)

        # Save the new key
        account.api_key = new_key
        # Invalidate cached v2 tokens
        account.v2_auth_token = None
        account.v2_token_expiry = None
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='account_key_rotation',
            resource_type='waas_account',
            resource_id=account.id,
            details=f'Rotated API key for account: {account.account_name}',
            ip_address=request.remote_addr,
        )

        flash(_('API key rotated successfully for "%(name)s".', name=account.account_name), 'success')
        return redirect(url_for('accounts.view_account', account_id=account.id))

    return render_template('accounts/rotate_key.html', form=form, account=account)
