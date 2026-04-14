"""Shared pytest fixtures."""

import os

import pytest

# Ensure SECRET_KEY is set before importing anything that triggers create_app
os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-production")
os.environ.setdefault("FLASK_ENV", "testing")

from app import create_app, db as _db
from app.models import User, Note
from config import TestingConfig


@pytest.fixture(scope="session")
def app():
    """Create a test application instance."""
    application = create_app(config_override=TestingConfig)
    return application


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


@pytest.fixture()
def db(app):
    """Provide a clean database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def sample_user(db, app):
    """Create and return a persisted test user."""
    with app.app_context():
        user = User(username="testuser", email="test@example.com")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()
        # Re-query to get an object attached to the current session
        return db.session.get(User, user.id)


@pytest.fixture()
def auth_client(client, sample_user, app):
    """Return a test client that is already logged in as sample_user."""
    with app.app_context():
        with client.session_transaction() as sess:
            sess["_user_id"] = str(sample_user.id)
            sess["_fresh"] = True
    return client
