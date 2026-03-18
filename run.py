#!/usr/bin/env python3
"""WaaS Self-Service Portal - Entry Point"""

import json
import os
from app import create_app, db, socketio
from app.models import User, Feature

app = create_app()


@app.cli.command('init-db')
def init_db():
    """Initialize the database and create tables."""
    db.create_all()
    print('Database tables created.')


@app.cli.command('create-admin')
def create_admin():
    """Create the default admin user if it doesn't exist."""
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print('Admin user already exists.')
    else:
        admin = User(
            username='admin',
            email='admin@localhost',
            first_name='Administrator',
            role='admin',
            is_active=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created. Username: admin, Password: admin')
        print('*** Change the default password immediately! ***')


@app.cli.command('run-reports')
def run_reports():
    """Run all due scheduled reports immediately."""
    from app.report_service import run_scheduled_reports
    run_scheduled_reports(app)
    print('Scheduled reports processed.')


def seed_features():
    """Seed predefined features (idempotent)."""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        return 0

    predefined = [
        {
            'name': 'Harden TLS 1.2+',
            'description': 'Disable TLS 1.0 and 1.1, enable only TLS 1.2 and 1.3 for stronger encryption.',
            'category': 'Security Hardening',
            'config_data': {
                'tls_settings': {
                    'tls_1_0': 'Off',
                    'tls_1_1': 'Off',
                    'tls_1_2': 'On',
                    'tls_1_3': 'On',
                }
            },
        },
        {
            'name': 'Enable Active Protection',
            'description': 'Switch WAF protection mode from Passive (monitor) to Active (block malicious traffic).',
            'category': 'Security Hardening',
            'config_data': {
                'protection_mode': 'Active',
            },
        },
        {
            'name': 'Strict Request Limits',
            'description': 'Apply restrictive request size limits to defend against oversized payloads and buffer overflow attacks.',
            'category': 'Security Hardening',
            'config_data': {
                'request_limits': {
                    'max_request_length': 32768,
                    'max_request_line_length': 4096,
                    'max_number_of_headers': 50,
                    'max_header_value_length': 4096,
                    'max_number_of_cookies': 20,
                    'max_cookie_value_length': 2048,
                }
            },
        },
        {
            'name': 'Enable Clickjacking Protection',
            'description': 'Enable clickjacking prevention by adding X-Frame-Options and Content-Security-Policy frame-ancestors headers.',
            'category': 'Compliance',
            'config_data': {
                'clickjacking_protection': {
                    'status': 'On',
                    'options': 'Same Origin',
                }
            },
        },
        {
            'name': 'Enable Data Theft Protection',
            'description': 'Enable masking of credit card numbers and Social Security Numbers in HTTP responses.',
            'category': 'Compliance',
            'config_data': {
                'data_theft_protection': {
                    'status': 'On',
                    'credit_card_numbers': 'On',
                    'social_security_numbers': 'On',
                }
            },
        },
    ]

    created = 0
    for feat_data in predefined:
        existing = Feature.query.filter_by(name=feat_data['name'], is_predefined=True).first()
        if not existing:
            feature = Feature(
                user_id=admin.id,
                name=feat_data['name'],
                description=feat_data['description'],
                category=feat_data['category'],
                is_global=True,
                is_predefined=True,
            )
            feature.config_dict = feat_data['config_data']
            db.session.add(feature)
            created += 1

    if created:
        db.session.commit()
    return created


@app.cli.command('seed')
def seed():
    """Initialize DB and create admin user (convenience command)."""
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@localhost',
            first_name='Administrator',
            role='admin',
            is_active=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print('Database initialized with admin user.')
        print('Username: admin / Password: admin')
    else:
        print('Database already initialized. Admin user exists.')

    created = seed_features()
    if created:
        print(f'Seeded {created} predefined features.')
    else:
        print('Predefined features already exist.')


if __name__ == '__main__':
    # Auto-create tables on first run
    with app.app_context():
        db.create_all()
        # Create admin if no users exist
        if User.query.count() == 0:
            admin = User(
                username='admin',
                email='admin@localhost',
                first_name='Administrator',
                role='admin',
                is_active=True
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print('Created default admin user (admin/admin)')

        # Seed predefined features
        created = seed_features()
        if created:
            print(f'Seeded {created} predefined features.')

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)