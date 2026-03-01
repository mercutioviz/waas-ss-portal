from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import WaasAccount, AuditLog
from app.waas_client import WaasClient, WaasApiError
from app.forms import CertificateUploadForm

bp = Blueprint('certificates', __name__, url_prefix='/certificates')


@bp.route('/')
@login_required
def list_certificates():
    """List certificates - user selects which WaaS account to view"""
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    selected_account_id = request.args.get('account_id', type=int)

    certificates = []
    selected_account = None
    error = None

    if selected_account_id:
        account = WaasAccount.query.filter_by(id=selected_account_id, user_id=current_user.id, is_active=True).first()
        if account:
            selected_account = account
            try:
                client = WaasClient.from_account(account)
                result = client.list_certificates()
                certificates = result if isinstance(result, list) else result.get('results', result.get('data', []))
            except WaasApiError as e:
                error = str(e)
        else:
            error = 'Account not found or inactive.'

    return render_template(
        'certificates/list.html',
        accounts=accounts,
        certificates=certificates,
        selected_account=selected_account,
        selected_account_id=selected_account_id,
        error=error
    )


@bp.route('/<int:account_id>/upload', methods=['GET', 'POST'])
@login_required
def upload_certificate(account_id):
    """Upload a certificate to a WaaS account"""
    if current_user.role == 'viewer':
        flash('You do not have permission to upload certificates.', 'danger')
        return redirect(url_for('certificates.list_certificates'))

    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()
    form = CertificateUploadForm()

    if form.validate_on_submit():
        try:
            client = WaasClient.from_account(account)

            files = {}
            cert_file = form.certificate_file.data
            if cert_file:
                files['certificate'] = (cert_file.filename, cert_file.stream, cert_file.content_type or 'application/octet-stream')

            key_file = form.certificate_key_file.data
            if key_file:
                files['key'] = (key_file.filename, key_file.stream, key_file.content_type or 'application/octet-stream')

            data = {}
            if form.pfx_password.data:
                data['password'] = form.pfx_password.data
            if form.friendly_name.data:
                data['friendly_name'] = form.friendly_name.data

            result = client.upload_certificate(files=files, data=data)

            AuditLog.log(
                user_id=current_user.id,
                action='certificate_upload',
                resource_type='certificate',
                details=f'Uploaded certificate to account {account.account_name}: {form.friendly_name.data or cert_file.filename}',
                ip_address=request.remote_addr
            )

            flash('Certificate uploaded successfully.', 'success')
            return redirect(url_for('certificates.list_certificates', account_id=account_id))

        except WaasApiError as e:
            flash(f'Failed to upload certificate: {e}', 'danger')

    return render_template(
        'certificates/upload.html',
        account=account,
        form=form
    )


@bp.route('/<int:account_id>/<cert_id>')
@login_required
def view_certificate(account_id, cert_id):
    """View certificate details"""
    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    try:
        client = WaasClient.from_account(account)
        certificate = client.get_certificate(cert_id)
    except WaasApiError as e:
        flash(f'Failed to load certificate: {e}', 'danger')
        return redirect(url_for('certificates.list_certificates', account_id=account_id))

    return render_template(
        'certificates/view.html',
        account=account,
        certificate=certificate
    )


@bp.route('/<int:account_id>/<cert_id>/delete', methods=['POST'])
@login_required
def delete_certificate(account_id, cert_id):
    """Delete a certificate"""
    if current_user.role == 'viewer':
        flash('You do not have permission to delete certificates.', 'danger')
        return redirect(url_for('certificates.list_certificates'))

    account = WaasAccount.query.filter_by(id=account_id, user_id=current_user.id, is_active=True).first_or_404()

    try:
        client = WaasClient.from_account(account)
        client.delete_certificate(cert_id)

        AuditLog.log(
            user_id=current_user.id,
            action='certificate_delete',
            resource_type='certificate',
            details=f'Deleted certificate {cert_id} from account {account.account_name}',
            ip_address=request.remote_addr
        )

        flash('Certificate deleted.', 'success')
    except WaasApiError as e:
        flash(f'Failed to delete certificate: {e}', 'danger')

    return redirect(url_for('certificates.list_certificates', account_id=account_id))