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
        account.api_key = form.api_key.data

        # Verify the API key by testing connection
        try:
            client = WaasClient(form.api_key.data)
            account_info = client.verify_account()
            account.waas_account_id = account_info.get('id', account_info.get('account_id'))
            account.last_verified = datetime.utcnow()
            flash_msg = f'Account "{account.account_name}" added and verified successfully.'
        except WaasApiError as e:
            # Still save, but warn about verification failure
            flash_msg = f'Account "{account.account_name}" added, but API verification failed: {e}. You can retry verification later.'

        db.session.add(account)
        db.session.commit()

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


@bp.route('/<int:account_id>/verify', methods=['POST'])
@login_required
def verify_account(account_id):
    """Re-verify a WaaS account API key"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()

    try:
        client = WaasClient(account.api_key)
        account_info = client.verify_account()
        account.waas_account_id = account_info.get('id', account_info.get('account_id'))
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