import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config
from datetime import datetime

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()


def create_app(config_name='default'):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Trust the nginx reverse proxy headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Configure logging - ensure WaaS API client logs are visible
    logging.basicConfig(level=logging.DEBUG if app.debug else logging.INFO)
    # Set WaaS client logger to DEBUG so we see request/response details
    waas_logger = logging.getLogger('app.waas_client')
    waas_logger.setLevel(logging.DEBUG)

    # Initialize config-specific setup
    config[config_name].init_app(app)

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)

    # Configure Flask-Login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login"""
        from app.models import User
        return db.session.get(User, int(user_id))

    # Register custom template filters
    @app.template_filter('datetime_format')
    def datetime_format(value, fmt='%Y-%m-%d %H:%M:%S'):
        """Format a datetime object"""
        if value is None:
            return 'N/A'
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value
        return value.strftime(fmt)

    @app.template_filter('filesizeformat')
    def filesizeformat(bytes_val):
        """Format file size in human-readable format"""
        try:
            bytes_val = float(bytes_val)
            if bytes_val < 1024:
                return f"{bytes_val:.0f} B"
            elif bytes_val < 1024 * 1024:
                return f"{bytes_val / 1024:.1f} KB"
            elif bytes_val < 1024 * 1024 * 1024:
                return f"{bytes_val / (1024 * 1024):.1f} MB"
            else:
                return f"{bytes_val / (1024 * 1024 * 1024):.1f} GB"
        except (ValueError, TypeError):
            return '0 B'

    # Context processor to inject version into all templates
    @app.context_processor
    def inject_version():
        """Make version available to all templates"""
        from config import VERSION
        return {'app_version': VERSION}

    # Context processor to inject CSRF token function
    @app.context_processor
    def inject_csrf_token():
        """Make CSRF token generation available to all templates"""
        from flask_wtf.csrf import generate_csrf
        return {'csrf_token': generate_csrf}

    # Register blueprints
    from app.routes import main, auth, admin, accounts, applications, certificates, logs, proxy
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(accounts.bp)
    app.register_blueprint(applications.bp)
    app.register_blueprint(certificates.bp)
    app.register_blueprint(logs.bp)
    app.register_blueprint(proxy.bp)

    # Create database tables
    with app.app_context():
        db.create_all()

        # Initialize default system settings if not present
        from app.models import SystemSettings
        if not SystemSettings.get_setting('app_name'):
            SystemSettings.set_setting(
                'app_name',
                'WaaS Self-Service Portal',
                value_type='string',
                user_id=None
            )

    return app