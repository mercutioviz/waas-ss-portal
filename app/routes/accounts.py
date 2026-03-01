from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from datetime import datetime
from app import db
from app.models import WaasAccount, AuditLog
from app.forms import WaasAccountForm
from app.waas_client import WaasClient, WaasApiError

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
        flash_msg = f'Account "{account.account_name}" added successfully.'
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
                flash_msg = f'Account "{account.account_name}" added and verified successfully.'
            except WaasApiError as e:
                flash_msg = f'Account "{account.account_name}" added, but verification failed: {e}. You can retry later.'
        elif account.has_api_key:
            flash_msg += ' Add WaaS email/password credentials to enable account verification.'

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

        flash(f'Account "{account.account_name}" updated.', 'success')
        return redirect(url_for('accounts.view_account', account_id=account.id))

    return render_template('accounts/edit.html', form=form, account=account)


@bp.route('/<int:account_id>/verify', methods=['POST'])
@login_required
def verify_account(account_id):
    """Re-verify a WaaS account using v2 credentials"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()

    if not account.has_v2_credentials:
        flash(
            f'Cannot verify "{account.account_name}": WaaS email/password credentials are required for verification. '
            'Edit the account to add v2 credentials.',
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

        flash(f'Account "{account.account_name}" verified successfully.', 'success')
    except WaasApiError as e:
        flash(f'Verification failed for "{account.account_name}": {e}', 'danger')

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

    flash(f'Account "{account_name}" has been deleted.', 'success')
    return redirect(url_for('accounts.list_accounts'))