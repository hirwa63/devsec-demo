"""Application entry point.

Usage (development)::

    SECRET_KEY=dev-only-key FLASK_ENV=development python run.py

For production, use a proper WSGI server such as gunicorn::

    SECRET_KEY=$(openssl rand -hex 32) gunicorn -w 4 "run:app"
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug=False by default; controlled via FLASK_ENV / config
    app.run(host="127.0.0.1", port=5000)
