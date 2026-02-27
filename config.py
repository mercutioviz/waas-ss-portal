import os
from pathlib import Path

basedir = os.path.abspath(os.path.dirname(__file__))

# Application version
VERSION = '0.1.0'


class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{os.path.join(basedir, "instance", "waas-portal.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # WaaS API base URL
    WAAS_API_BASE_URL = os.environ.get('WAAS_API_BASE_URL') or 'https://api.waas.barracudanetworks.com'

    # Pagination
    ITEMS_PER_PAGE = 20

    # File upload (for certificate files)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')

    @classmethod
    def init_app(cls, app):
        """Initialize application-specific configuration"""
        # Ensure upload directory exists
        upload_dir = Path(cls.UPLOAD_FOLDER)
        try:
            upload_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            app.logger.warning(f"Could not create upload directory {upload_dir}: {e}")

        # Ensure instance directory exists for SQLite
        instance_dir = Path(os.path.join(basedir, 'instance'))
        try:
            instance_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            app.logger.warning(f"Could not create instance directory {instance_dir}: {e}")


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}