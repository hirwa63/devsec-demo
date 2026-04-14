"""Application factory.

Separating the app creation into a factory function (create_app) is a
Flask best-practice that also makes testing much simpler – each test can
spin up its own isolated application instance.
"""

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config

# ---------------------------------------------------------------------------
# Extension singletons – initialised later inside create_app()
# ---------------------------------------------------------------------------
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_override=None):
    """Create and return a configured Flask application.

    Parameters
    ----------
    config_override:
        An optional config class that overrides the environment-derived one.
        Useful in tests.
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    cfg = config_override or get_config()
    app.config.from_object(cfg)

    # ------------------------------------------------------------------
    # Security headers (Content-Security-Policy, HSTS, X-Frame-Options …)
    # Flask-Talisman sets secure HTTP headers automatically.
    # In development we relax CSP so that the debug toolbar works.
    # ------------------------------------------------------------------
    csp = {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self' 'unsafe-inline'",  # allow inline styles for demos
        "img-src": "'self' data:",
    }
    Talisman(
        app,
        content_security_policy=csp,
        force_https=app.config.get("SESSION_COOKIE_SECURE", False),
        strict_transport_security=app.config.get("SESSION_COOKIE_SECURE", False),
    )

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    from app.auth import auth_bp
    from app.routes import main_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(main_bp)

    # ------------------------------------------------------------------
    # Database initialisation
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()

    return app
