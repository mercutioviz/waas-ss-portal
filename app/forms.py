from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, Regexp
from flask_wtf.file import FileField, FileAllowed


class LoginForm(FlaskForm):
    """Form for user login"""
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=80)],
        render_kw={'placeholder': 'Enter your username', 'class': 'form-control', 'autocomplete': 'username'}
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()],
        render_kw={'placeholder': 'Enter your password', 'class': 'form-control', 'autocomplete': 'current-password'}
    )
    remember_me = BooleanField('Remember Me', default=False, render_kw={'class': 'form-check-input'})
    submit = SubmitField('Login', render_kw={'class': 'btn btn-primary w-100'})


class RegistrationForm(FlaskForm):
    """Form for user registration (admin only)"""
    username = StringField(
        'Username',
        validators=[
            DataRequired(), Length(min=3, max=80),
            Regexp(r'^[a-zA-Z0-9_-]+$', message='Username can only contain letters, numbers, underscores, and hyphens')
        ],
        render_kw={'placeholder': 'Enter username', 'class': 'form-control'}
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={'placeholder': 'user@example.com', 'class': 'form-control'}
    )
    first_name = StringField(
        'First Name',
        validators=[Length(max=100)],
        render_kw={'placeholder': 'First name (optional)', 'class': 'form-control'}
    )
    last_name = StringField(
        'Last Name',
        validators=[Length(max=100)],
        render_kw={'placeholder': 'Last name (optional)', 'class': 'form-control'}
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters')],
        render_kw={'placeholder': 'Enter password', 'class': 'form-control'}
    )
    password_confirm = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match')],
        render_kw={'placeholder': 'Confirm password', 'class': 'form-control'}
    )
    role = SelectField(
        'Role',
        choices=[
            ('user', 'User - Can manage own WaaS accounts and applications'),
            ('admin', 'Admin - Full system access'),
            ('viewer', 'Viewer - Read-only access')
        ],
        default='user',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    is_active = BooleanField('Account Active', default=True, render_kw={'class': 'form-check-input'})
    submit = SubmitField('Create User', render_kw={'class': 'btn btn-primary'})

    def validate_username(self, username):
        from app.models import User
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')


class ChangePasswordForm(FlaskForm):
    """Form for changing password"""
    current_password = PasswordField(
        'Current Password',
        validators=[DataRequired()],
        render_kw={'placeholder': 'Enter current password', 'class': 'form-control'}
    )
    new_password = PasswordField(
        'New Password',
        validators=[DataRequired(), Length(min=8)],
        render_kw={'placeholder': 'Enter new password', 'class': 'form-control'}
    )
    new_password_confirm = PasswordField(
        'Confirm New Password',
        validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')],
        render_kw={'placeholder': 'Confirm new password', 'class': 'form-control'}
    )
    submit = SubmitField('Change Password', render_kw={'class': 'btn btn-primary'})


class WaasAccountForm(FlaskForm):
    """Form for adding/editing a WaaS API account.

    At least one credential type is required: API key (v4) or email+password (v2).
    """
    account_name = StringField(
        'Account Name',
        validators=[DataRequired(), Length(min=2, max=100)],
        render_kw={'placeholder': 'e.g., Production Account', 'class': 'form-control'}
    )
    api_key = StringField(
        'API Key / Token (v4)',
        validators=[Optional(), Length(min=10, max=500)],
        render_kw={'placeholder': 'Paste WaaS API key here', 'class': 'form-control', 'type': 'password'}
    )
    waas_email = StringField(
        'WaaS Email (v2)',
        validators=[Optional(), Email(), Length(max=120)],
        render_kw={'placeholder': 'user@example.com', 'class': 'form-control'}
    )
    waas_password = PasswordField(
        'WaaS Password (v2)',
        validators=[Optional(), Length(max=255)],
        render_kw={'placeholder': 'Enter WaaS password', 'class': 'form-control'}
    )
    submit = SubmitField('Save Account', render_kw={'class': 'btn btn-primary'})

    def validate(self, extra_validators=None, is_edit=False, account=None):
        """Custom validation: require at least one credential type.

        Args:
            is_edit: If True, blank credential fields are allowed (means "keep existing").
            account: The existing WaasAccount being edited (used to check existing credentials).
        """
        if not super().validate(extra_validators=extra_validators):
            return False

        has_api_key = bool(self.api_key.data and self.api_key.data.strip())
        has_v2_creds = bool(
            self.waas_email.data and self.waas_email.data.strip()
            and self.waas_password.data and self.waas_password.data.strip()
        )

        # On edit, existing credentials count as "having" them
        if is_edit and account:
            existing_api_key = account.has_api_key
            existing_v2_creds = account.has_v2_credentials
        else:
            existing_api_key = False
            existing_v2_creds = False

        if not has_api_key and not has_v2_creds and not existing_api_key and not existing_v2_creds:
            self.api_key.errors.append(
                'At least one credential type is required: API key or WaaS email + password.'
            )
            return False

        # If email provided without password (or vice versa), flag it — but only for new values
        has_email_only = bool(self.waas_email.data and self.waas_email.data.strip()) and not bool(self.waas_password.data and self.waas_password.data.strip())
        has_pass_only = bool(self.waas_password.data and self.waas_password.data.strip()) and not bool(self.waas_email.data and self.waas_email.data.strip())

        # On edit, having only email without new password is OK if v2 creds already exist
        if has_email_only and not (is_edit and existing_v2_creds):
            self.waas_password.errors.append('Password is required when email is provided.')
            return False
        if has_pass_only and not (is_edit and existing_v2_creds):
            self.waas_email.errors.append('Email is required when password is provided.')
            return False

        return True


class UserCreateForm(FlaskForm):
    """Form for admin to create a new user"""
    username = StringField(
        'Username',
        validators=[
            DataRequired(), Length(min=3, max=80),
            Regexp(r'^[a-zA-Z0-9_-]+$', message='Username can only contain letters, numbers, underscores, and hyphens')
        ],
        render_kw={'placeholder': 'Enter username', 'class': 'form-control'}
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={'placeholder': 'user@example.com', 'class': 'form-control'}
    )
    display_name = StringField(
        'Display Name',
        validators=[Optional(), Length(max=200)],
        render_kw={'placeholder': 'Display name (optional)', 'class': 'form-control'}
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters')],
        render_kw={'placeholder': 'Enter password', 'class': 'form-control'}
    )
    password_confirm = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match')],
        render_kw={'placeholder': 'Confirm password', 'class': 'form-control'}
    )
    role = SelectField(
        'Role',
        choices=[('user', 'User'), ('admin', 'Admin'), ('viewer', 'Viewer')],
        default='user',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    submit = SubmitField('Create User', render_kw={'class': 'btn btn-primary'})

    def validate_username(self, username):
        from app.models import User
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')


class UserEditForm(FlaskForm):
    """Form for admin to edit an existing user"""
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={'class': 'form-control'}
    )
    display_name = StringField(
        'Display Name',
        validators=[Optional(), Length(max=200)],
        render_kw={'class': 'form-control'}
    )
    role = SelectField(
        'Role',
        choices=[('user', 'User'), ('admin', 'Admin'), ('viewer', 'Viewer')],
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    is_active = BooleanField('Account Active', render_kw={'class': 'form-check-input'})
    new_password = PasswordField(
        'New Password (leave blank to keep current)',
        validators=[Optional(), Length(min=8)],
        render_kw={'placeholder': 'Leave blank to keep current password', 'class': 'form-control'}
    )
    submit = SubmitField('Update User', render_kw={'class': 'btn btn-primary'})


class CertificateUploadForm(FlaskForm):
    """Form for uploading SSL/TLS certificates"""
    certificate_file = FileField(
        'Certificate File (PEM or PFX)',
        validators=[
            DataRequired(message='Certificate file is required'),
            FileAllowed(['pem', 'pfx', 'p12', 'crt', 'cer', 'key'], 'Only certificate files are allowed')
        ],
        render_kw={'class': 'form-control', 'accept': '.pem,.pfx,.p12,.crt,.cer,.key'}
    )
    certificate_key_file = FileField(
        'Private Key File (PEM, optional for PFX)',
        validators=[
            Optional(),
            FileAllowed(['pem', 'key'], 'Only PEM/KEY files are allowed')
        ],
        render_kw={'class': 'form-control', 'accept': '.pem,.key'}
    )
    pfx_password = PasswordField(
        'PFX Password (if applicable)',
        validators=[Optional(), Length(max=255)],
        render_kw={'placeholder': 'Enter PFX password if uploading PFX file', 'class': 'form-control'}
    )
    friendly_name = StringField(
        'Friendly Name',
        validators=[Optional(), Length(max=255)],
        render_kw={'placeholder': 'Optional label for this certificate', 'class': 'form-control'}
    )
    submit = SubmitField('Upload Certificate', render_kw={'class': 'btn btn-primary'})