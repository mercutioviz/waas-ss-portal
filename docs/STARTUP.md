# WaaS Self-Service Portal — Startup Guide

Steps to start the portal after a server reboot.

## Prerequisites

- Python 3.13 with a virtual environment already set up at `venv/`
- Dependencies installed via `pip install -r requirements.txt`

## Startup Steps

### 1. Navigate to the project directory

```bash
cd /home/admin/waas-ss-portal
```

### 2. Activate the Python virtual environment

```bash
source venv/bin/activate
```

### 3. Start the Flask application

```bash
python3 run.py
```

The dev server starts on `0.0.0.0:5000` with debug mode enabled by default (`FLASK_DEBUG=1`).

On startup, `run.py` automatically:
- Creates the database tables if they don't exist (SQLite file at `instance/waas-portal.db`)
- Seeds a default admin user (`admin` / `admin`) if no users exist in the database

## Quick One-Liner

```bash
cd /home/admin/waas-ss-portal && source venv/bin/activate && python3 run.py
```

## Running in the Background

To keep the server running after closing your terminal:

```bash
cd /home/admin/waas-ss-portal && source venv/bin/activate && nohup python3 run.py > portal.log 2>&1 &
```

View logs with:

```bash
tail -f /home/admin/waas-ss-portal/portal.log
```

## Verification

Once started, the portal should be accessible at `http://<server-ip>:5000`. Log in with the admin credentials.

## Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Port the server listens on |
| `FLASK_DEBUG` | `1` | Set to `0` to disable debug mode |
| `SECRET_KEY` | (dev default) | Override for production |
| `DATABASE_URL` | `sqlite:///instance/waas-portal.db` | Database connection string |
| `WAAS_API_BASE_URL` | `https://api.waas.barracudanetworks.com/v4/waasapi` | WaaS API endpoint |

## Stopping the Server

- **Foreground process:** Press `Ctrl+C` in the terminal.
- **Background process:** Find the PID and kill it:

```bash
ps aux | grep run.py
kill <PID>