from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.models import User, WaasAccount, AuditLog
from app.forms import UserCreateForm, UserEditForm

bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/')
@login_required
@admin_required
def index():
    """Admin dashboard"""
    user_count = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    account_count = WaasAccount.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()

    return render_template(
        'admin/index.html',
        user_count=user_count,
        active_users=active_users,
        account_count=account_count,
        recent_logs=recent_logs
    )


@bp.route('/users')
@login_required
@admin_required
def list_users():
    """List all users"""
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)


@bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Create a new user"""
    form = UserCreateForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.display_name.data or form.username.data,
            role=form.role.data,
            is_active=True
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='user_create',
            resource_type='user',
            resource_id=user.id,
            details=f'Created user: {user.username} (role: {user.role})',
            ip_address=request.remote_addr
        )

        flash(f'User "{user.username}" created successfully.', 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/user_create.html', form=form)


@bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit a user"""
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)

    if form.validate_on_submit():
        user.email = form.email.data
        user.first_name = form.display_name.data
        user.role = form.role.data
        user.is_active = form.is_active.data

        if form.new_password.data:
            user.set_password(form.new_password.data)

        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='user_edit',
            resource_type='user',
            resource_id=user.id,
            details=f'Edited user: {user.username}',
            ip_address=request.remote_addr
        )

        flash(f'User "{user.username}" updated.', 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/user_edit.html', form=form, edit_user=user)


@bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    """Enable/disable a user"""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot disable your own account.', 'danger')
        return redirect(url_for('admin.list_users'))

    user.is_active = not user.is_active
    db.session.commit()

    action = 'enabled' if user.is_active else 'disabled'
    AuditLog.log(
        user_id=current_user.id,
        action=f'user_{action}',
        resource_type='user',
        resource_id=user.id,
        details=f'User {user.username} {action}',
        ip_address=request.remote_addr
    )

    flash(f'User "{user.username}" has been {action}.', 'success')
    return redirect(url_for('admin.list_users'))


@bp.route('/audit-log')
@login_required
@admin_required
def audit_log():
    """View audit log"""
    page = request.args.get('page', 1, type=int)
    per_page = 50

    # Optional filters
    user_filter = request.args.get('user_id', type=int)
    action_filter = request.args.get('action')

    query = AuditLog.query

    if user_filter:
        query = query.filter_by(user_id=user_filter)
    if action_filter:
        query = query.filter_by(action=action_filter)

    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    users = User.query.order_by(User.username).all()
    actions = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    actions = [a[0] for a in actions]

    return render_template(
        'admin/audit_log.html',
        logs=logs,
        users=users,
        actions=actions,
        user_filter=user_filter,
        action_filter=action_filter
    )