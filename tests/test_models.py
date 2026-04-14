"""Tests for the User model's security-critical methods."""

import pytest
from app.models import User


def test_password_not_stored_in_plaintext(db, app):
    """set_password must never store the raw password."""
    with app.app_context():
        user = User(username="alice", email="alice@example.com")
        user.set_password("MySecret!")
        assert user.password_hash != "MySecret!"


def test_correct_password_accepted(db, app):
    with app.app_context():
        user = User(username="bob", email="bob@example.com")
        user.set_password("CorrectHorse!")
        assert user.check_password("CorrectHorse!") is True


def test_wrong_password_rejected(db, app):
    with app.app_context():
        user = User(username="carol", email="carol@example.com")
        user.set_password("RightPassword!")
        assert user.check_password("WrongPassword!") is False


def test_bcrypt_prefix(db, app):
    """Hashes should use the bcrypt $2b$ prefix."""
    with app.app_context():
        user = User(username="dave", email="dave@example.com")
        user.set_password("SomePassword1!")
        assert user.password_hash.startswith("$2b$")


def test_unique_hashes_for_same_password(db, app):
    """bcrypt uses a random salt; two users with the same password get different hashes."""
    with app.app_context():
        u1 = User(username="user1", email="u1@example.com")
        u2 = User(username="user2", email="u2@example.com")
        password = "SharedPassword1!"
        u1.set_password(password)
        u2.set_password(password)
        assert u1.password_hash != u2.password_hash
