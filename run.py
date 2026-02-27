#!/usr/bin/env python3
"""WaaS Self-Service Portal - Entry Point"""

import os
from app import create_app, db
from app.models import User

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

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)