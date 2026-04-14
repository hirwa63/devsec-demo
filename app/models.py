"""Database models.

Security highlights
-------------------
* Passwords are stored as bcrypt hashes – never in plain text.
* The User model exposes no raw password; only set_password / check_password.
* Timestamps are stored in UTC to avoid timezone-related logic bugs.
"""

from datetime import datetime, timezone

from flask_login import UserMixin

from app import db, bcrypt


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    # Stores a bcrypt hash – length 60 chars, but 128 gives room for algorithm upgrades
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    notes = db.relationship("Note", backref="author", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash *password* and store the result.  Never stores the raw value."""
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Return True if *password* matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    # Foreign key enforces ownership; users cannot read each other's notes
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    def __repr__(self) -> str:
        return f"<Note {self.title!r}>"
