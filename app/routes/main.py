from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Landing page - redirect to dashboard if logged in"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard view"""
    from app.models import WaasAccount
    accounts = WaasAccount.query.filter_by(user_id=current_user.id, is_active=True).all()
    return render_template('dashboard.html', accounts=accounts)


@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')