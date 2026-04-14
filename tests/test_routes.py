"""Tests for note routes.

Security scenarios covered
--------------------------
* Unauthenticated requests redirect to login (access control)
* Users cannot read or modify notes belonging to other users (IDOR protection)
* CRUD operations work correctly for the owner
"""

import pytest
from app.models import Note, User


class TestAccessControl:
    def test_index_requires_login(self, client):
        """Unauthenticated GET / must redirect to login."""
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 302
        assert "login" in response.headers["Location"]

    def test_new_note_requires_login(self, client):
        response = client.get("/notes/new", follow_redirects=False)
        assert response.status_code == 302
        assert "login" in response.headers["Location"]


class TestNoteOwnership:
    """IDOR (Insecure Direct Object Reference) tests."""

    def _create_note_for_other_user(self, db, app):
        """Create a second user and a note owned by them."""
        with app.app_context():
            other = User(username="other", email="other@example.com")
            other.set_password("OtherPass1!")
            db.session.add(other)
            db.session.flush()
            note = Note(title="Private", content="Secret content", user_id=other.id)
            db.session.add(note)
            db.session.commit()
            return note.id

    def test_cannot_view_other_users_note(self, auth_client, db, app, sample_user):
        note_id = self._create_note_for_other_user(db, app)
        response = auth_client.get(f"/notes/{note_id}")
        assert response.status_code == 403

    def test_cannot_edit_other_users_note(self, auth_client, db, app, sample_user):
        note_id = self._create_note_for_other_user(db, app)
        response = auth_client.get(f"/notes/{note_id}/edit")
        assert response.status_code == 403

    def test_cannot_delete_other_users_note(self, auth_client, db, app, sample_user):
        note_id = self._create_note_for_other_user(db, app)
        csrf = _get_csrf(auth_client, "/notes/new")
        response = auth_client.post(
            f"/notes/{note_id}/delete",
            data={"csrf_token": csrf},
        )
        assert response.status_code == 403

        # Verify the note still exists
        with app.app_context():
            note = db.session.get(Note, note_id)
            assert note is not None


class TestNoteCRUD:
    def test_create_note(self, auth_client, db, app, sample_user):
        csrf = _get_csrf(auth_client, "/notes/new")
        response = auth_client.post(
            "/notes/new",
            data={"title": "Test Note", "content": "Test content", "csrf_token": csrf},
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            note = Note.query.filter_by(title="Test Note").first()
            assert note is not None
            assert note.user_id == sample_user.id

    def test_edit_own_note(self, auth_client, db, app, sample_user):
        # Create a note first
        with app.app_context():
            note = Note(title="Old Title", content="Old Content", user_id=sample_user.id)
            db.session.add(note)
            db.session.commit()
            note_id = note.id

        csrf = _get_csrf(auth_client, f"/notes/{note_id}/edit")
        response = auth_client.post(
            f"/notes/{note_id}/edit",
            data={"title": "New Title", "content": "New Content", "csrf_token": csrf},
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            updated = db.session.get(Note, note_id)
            assert updated.title == "New Title"

    def test_delete_own_note(self, auth_client, db, app, sample_user):
        with app.app_context():
            note = Note(title="To Delete", content="...", user_id=sample_user.id)
            db.session.add(note)
            db.session.commit()
            note_id = note.id

        csrf = _get_csrf(auth_client, f"/notes/{note_id}")
        response = auth_client.post(
            f"/notes/{note_id}/delete",
            data={"csrf_token": csrf},
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            assert db.session.get(Note, note_id) is None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_csrf(client, url: str) -> str:
    response = client.get(url)
    html = response.data.decode()
    token_start = html.find('name="csrf_token" value="')
    if token_start == -1:
        return ""
    token_start += len('name="csrf_token" value="')
    token_end = html.find('"', token_start)
    return html[token_start:token_end]
