"""Gunicorn production configuration."""

import multiprocessing

# Server socket
bind = 'unix:/home/admin/waas-ss-portal/waas-portal.sock'

# Worker processes
worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'
workers = (2 * multiprocessing.cpu_count()) + 1

# Pre-load app so APScheduler runs once, not per-worker
preload_app = True

# Timeouts
timeout = 120
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = 'logs/gunicorn-access.log'
errorlog = 'logs/gunicorn-error.log'
loglevel = 'info'

# Process naming
proc_name = 'waas-portal'

# Security
limit_request_line = 8190
limit_request_fields = 100
