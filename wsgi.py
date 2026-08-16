"""
WSGI entry — gunicorn / uWSGI
  gunicorn wsgi:app --workers 4 --bind 0.0.0.0:5000
"""
from app import create_app
app = create_app()
