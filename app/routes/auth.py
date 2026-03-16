from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_babel import gettext as _
from datetime import datetime
from app import db
from app.models import User, AuditLog
from app.forms import LoginForm, ChangePasswordForm
from app import limiter

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # Account lockout check
        if user and (user.failed_login_attempts or 0) >= 5 and user.last_failed_login:
            lockout_duration = 15  # minutes
            elapsed = (datetime.utcnow() - user.last_failed_login).total_seconds() / 60
            if elapsed < lockout_duration:
                remaining = int(lockout_duration - elapsed) + 1
                flash(_('Account locked due to too many failed attempts. Try again in %(remaining)s minutes.', remaining=remaining), 'danger')
                return render_template('auth/login.html', form=form)
            else:
                # Lockout expired — reset counter
                user.failed_login_attempts = 0
                db.session.commit()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash(_('Your account has been disabled. Contact an administrator.'), 'danger')
                return render_template('auth/login.html', form=form)

            login_user(user, remember=form.remember_me.data)
            session.permanent = True

            # Update login tracking
            user.last_login = datetime.utcnow()
            user.login_count = (user.login_count or 0) + 1
            user.failed_login_attempts = 0
            db.session.commit()

            # Audit log
            AuditLog.log(
                user_id=user.id,
                action='login',
                details='Successful login',
                ip_address=request.remote_addr,
                user_agent=str(request.user_agent)[:255]
            )

            flash(_('Welcome back, %(name)s!', name=user.display_name), 'success')

            # Redirect to requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            # Track failed login
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()

            flash(_('Invalid username or password.'), 'danger')

    return render_template('auth/login.html', form=form)


@bp.route('/logout')
@login_required
def logout():
    """User logout"""
    AuditLog.log(
        user_id=current_user.id,
        action='logout',
        details='User logged out',
        ip_address=request.remote_addr
    )
    logout_user()
    flash(_('You have been logged out.'), 'info')
    return redirect(url_for('auth.login'))


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def change_password():
    """Change current user's password"""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash(_('Current password is incorrect.'), 'danger')
            return render_template('auth/change_password.html', form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='password_change',
            details='Password changed by user',
            ip_address=request.remote_addr
        )

        flash(_('Your password has been updated.'), 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/change_password.html', form=form)


@bp.route('/keepalive', methods=['POST'])
@login_required
@limiter.limit("100 per minute")
def keepalive():
    """Touch session to keep it alive"""
    session.modified = True
    return jsonify({'status': 'ok'})


@bp.route('/profile')
@login_required
def profile():
    """View current user profile"""
    return render_template('auth/profile.html')


@bp.route('/set-locale', methods=['POST'])
def set_locale():
    """Set the user's preferred locale."""
    locale = request.form.get('locale', 'en')
    supported = current_app.config.get('BABEL_SUPPORTED_LOCALES', ['en', 'es'])
    if locale not in supported:
        locale = 'en'

    session['locale'] = locale

    if current_user.is_authenticated:
        current_user.locale = locale
        db.session.commit()

    next_url = request.form.get('next') or request.referrer or url_for('main.dashboard')
    return redirect(next_url)
