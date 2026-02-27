from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    """Model for user accounts"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, user, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)

    # Relationships
    waas_accounts = db.relationship('WaasAccount', backref='owner', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'

    @property
    def display_name(self):
        """Return display name"""
        if self.first_name and self.last_name:
            return f'{self.first_name} {self.last_name}'
        elif self.first_name:
            return self.first_name
        return self.username

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'login_count': self.login_count,
            'waas_account_count': self.waas_accounts.count()
        }


class WaasAccount(db.Model):
    """Model for WaaS API accounts linked to a portal user"""
    __tablename__ = 'waas_accounts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    account_name = db.Column(db.String(100), nullable=False)
    api_key_encrypted = db.Column(db.Text, nullable=False)
    waas_account_id = db.Column(db.String(100))  # Account ID from WaaS API
    is_active = db.Column(db.Boolean, default=True)
    last_verified = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<WaasAccount {self.id}: {self.account_name}>'

    @property
    def api_key(self):
        """Decrypt and return API key"""
        if self.api_key_encrypted:
            from app.encryption import decrypt_value
            return decrypt_value(self.api_key_encrypted)
        return None

    @api_key.setter
    def api_key(self, value):
        """Encrypt and store API key"""
        from app.encryption import encrypt_value
        self.api_key_encrypted = encrypt_value(value)

    def to_dict(self):
        """Convert to dictionary (no sensitive data)"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_name': self.account_name,
            'waas_account_id': self.waas_account_id,
            'is_active': self.is_active,
            'last_verified': self.last_verified.isoformat() if self.last_verified else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class AuditLog(db.Model):
    """Model for audit logging system actions"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), index=True)
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationship
    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action} by User {self.user_id}>'

    @staticmethod
    def log(user_id, action, resource_type=None, resource_id=None, details=None, ip_address=None, user_agent=None):
        """Convenience method to create audit log entry"""
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry

    def to_dict(self):
        """Convert audit log to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class SystemSettings(db.Model):
    """Model for storing system-wide settings"""
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<SystemSettings {self.key}={self.value}>'

    @staticmethod
    def get_setting(key, default=None):
        """Get a single setting value"""
        setting = SystemSettings.query.filter_by(key=key).first()
        if not setting:
            return default

        if setting.value_type == 'bool':
            return setting.value.lower() == 'true'
        elif setting.value_type == 'int':
            return int(setting.value)
        elif setting.value_type == 'json':
            import json
            return json.loads(setting.value)
        return setting.value

    @staticmethod
    def set_setting(key, value, value_type='string', description=None, user_id=None):
        """Set a single setting value"""
        setting = SystemSettings.query.filter_by(key=key).first()

        # Convert value to string for storage
        if value_type == 'bool':
            str_value = 'true' if value else 'false'
        elif value_type == 'json':
            import json
            str_value = json.dumps(value)
        else:
            str_value = str(value)

        if setting:
            setting.value = str_value
            setting.value_type = value_type
            setting.updated_at = datetime.utcnow()
            if user_id:
                setting.updated_by = user_id
        else:
            setting = SystemSettings(
                key=key,
                value=str_value,
                value_type=value_type,
                description=description,
                updated_by=user_id
            )
            db.session.add(setting)

        db.session.commit()
        return setting

    @staticmethod
    def get_all_settings():
        """Get all settings as a dictionary"""
        settings = {}
        for setting in SystemSettings.query.all():
            if setting.value_type == 'bool':
                settings[setting.key] = setting.value.lower() == 'true'
            elif setting.value_type == 'int':
                settings[setting.key] = int(setting.value)
            elif setting.value_type == 'json':
                import json
                settings[setting.key] = json.loads(setting.value)
            else:
                settings[setting.key] = setting.value
        return settings