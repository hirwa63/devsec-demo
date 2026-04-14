"""Application configuration.

Secrets are loaded exclusively from environment variables; they must NEVER
be hard-coded in source files.  See .env.example for the list of required
variables.
"""

import os
from datetime import timedelta


class BaseConfig:
    # ---------------------------------------------------------------------------
    # Core Flask settings
    # ---------------------------------------------------------------------------
    # SECRET_KEY is used for signing cookies and CSRF tokens.
    # Always set this via an environment variable in production.
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
    if not SECRET_KEY:
        raise ValueError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # ---------------------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "sqlite:///app.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # ---------------------------------------------------------------------------
    # Session / cookie security
    # ---------------------------------------------------------------------------
    SESSION_COOKIE_HTTPONLY: bool = True   # JS cannot access the cookie
    SESSION_COOKIE_SAMESITE: str = "Lax"  # CSRF mitigation
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

    # ---------------------------------------------------------------------------
    # WTForms CSRF protection
    # ---------------------------------------------------------------------------
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # tokens expire after 1 hour

    # ---------------------------------------------------------------------------
    # Rate limiting (flask-limiter)
    # ---------------------------------------------------------------------------
    RATELIMIT_DEFAULT: str = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URI: str = os.environ.get(
        "RATELIMIT_STORAGE_URL", "memory://"
    )


class DevelopmentConfig(BaseConfig):
    DEBUG: bool = True
    # Allow HTTP-only cookies in development (HTTPS not available locally)
    SESSION_COOKIE_SECURE: bool = False


class TestingConfig(BaseConfig):
    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    # Disable CSRF for automated tests
    WTF_CSRF_ENABLED: bool = False
    SESSION_COOKIE_SECURE: bool = False


class ProductionConfig(BaseConfig):
    DEBUG: bool = False
    # Cookies are only transmitted over HTTPS in production
    SESSION_COOKIE_SECURE: bool = True


config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
