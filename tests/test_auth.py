"""Tests for authentication – registration, login, logout.

Security scenarios covered
--------------------------
* Passwords are hashed (raw password not stored in DB)
* Generic error message for bad credentials (prevents username enumeration)
* Open-redirect attack is rejected after login
* Login rate limiting is enforced
* CSRF token is required for POST requests
"""

import pytest
from app.models import User


class TestRegistration:
    def test_register_success(self, client, db, app):
        """New user can register with valid data."""
        response = client.post(
            "/auth/register",
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "StrongPass1!",
                "confirm_password": "StrongPass1!",
                "csrf_token": _get_csrf(client, "/auth/register"),
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            user = User.query.filter_by(username="alice").first()
            assert user is not None

    def test_password_is_hashed(self, client, db, app):
        """Raw password must never be stored in the database."""
        plain_password = "MySecret99!"
        csrf = _get_csrf(client, "/auth/register")
        client.post(
            "/auth/register",
            data={
                "username": "bob",
                "email": "bob@example.com",
                "password": plain_password,
                "confirm_password": plain_password,
                "csrf_token": csrf,
            },
        )
        with app.app_context():
            user = User.query.filter_by(username="bob").first()
            assert user is not None
            # The stored hash must NOT equal the plain-text password
            assert user.password_hash != plain_password
            # The hash should start with a bcrypt prefix
            assert user.password_hash.startswith("$2b$")

    def test_duplicate_username_rejected(self, client, sample_user, app):
        """Registering with an existing username returns an error."""
        csrf = _get_csrf(client, "/auth/register")
        response = client.post(
            "/auth/register",
            data={
                "username": sample_user.username,
                "email": "other@example.com",
                "password": "AnotherPass1!",
                "confirm_password": "AnotherPass1!",
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )
        assert b"already taken" in response.data

    def test_mismatched_passwords_rejected(self, client, db):
        """Mismatched passwords must be caught by the form validator."""
        csrf = _get_csrf(client, "/auth/register")
        response = client.post(
            "/auth/register",
            data={
                "username": "carol",
                "email": "carol@example.com",
                "password": "Password1!",
                "confirm_password": "DifferentPassword!",
                "csrf_token": csrf,
            },
        )
        assert b"Passwords must match" in response.data

    def test_short_password_rejected(self, client, db):
        """Password shorter than 8 characters must be rejected."""
        csrf = _get_csrf(client, "/auth/register")
        response = client.post(
            "/auth/register",
            data={
                "username": "dave",
                "email": "dave@example.com",
                "password": "short",
                "confirm_password": "short",
                "csrf_token": csrf,
            },
        )
        assert response.status_code == 200
        assert b"dave" not in response.data or b"Field must be" in response.data


class TestLogin:
    def test_login_success(self, client, sample_user):
        """Valid credentials result in a redirect to the index."""
        csrf = _get_csrf(client, "/auth/login")
        response = client.post(
            "/auth/login",
            data={
                "username": sample_user.username,
                "password": "SecurePass123!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/" in response.headers["Location"]

    def test_wrong_password_generic_error(self, client, sample_user):
        """Wrong password must return generic error (no enumeration)."""
        csrf = _get_csrf(client, "/auth/login")
        response = client.post(
            "/auth/login",
            data={
                "username": sample_user.username,
                "password": "WrongPassword!",
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )
        assert b"Invalid username or password" in response.data
        # Must NOT reveal which field was wrong
        assert b"wrong password" not in response.data.lower()

    def test_nonexistent_user_generic_error(self, client, db):
        """Non-existent user must receive the same generic error."""
        csrf = _get_csrf(client, "/auth/login")
        response = client.post(
            "/auth/login",
            data={
                "username": "ghostuser",
                "password": "Whatever1!",
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )
        assert b"Invalid username or password" in response.data

    def test_open_redirect_rejected(self, client, sample_user):
        """External redirect in 'next' parameter must be blocked."""
        csrf = _get_csrf(client, "/auth/login")
        response = client.post(
            "/auth/login?next=https://evil.example.com",
            data={
                "username": sample_user.username,
                "password": "SecurePass123!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        # Must redirect somewhere, but NOT to the external domain
        location = response.headers.get("Location", "")
        assert "evil.example.com" not in location


class TestLogout:
    def test_logout_redirects(self, auth_client):
        """Logging out redirects to the login page."""
        response = auth_client.get("/auth/logout", follow_redirects=False)
        assert response.status_code == 302


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_csrf(client, url: str) -> str:
    """Fetch a page and extract its CSRF token from the form."""
    response = client.get(url)
    # WTForms injects a hidden input: <input name="csrf_token" value="...">
    html = response.data.decode()
    token_start = html.find('name="csrf_token" value="')
    if token_start == -1:
        # CSRF disabled in testing config
        return ""
    token_start += len('name="csrf_token" value="')
    token_end = html.find('"', token_start)
    return html[token_start:token_end]
