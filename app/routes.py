"""Main application blueprint – CRUD operations for notes.

Security highlights
-------------------
* All database queries use SQLAlchemy ORM (parameterised) – no raw SQL.
* Ownership checks on every note operation prevent Insecure Direct Object
  Reference (IDOR) – a user can only access their own notes.
* flask-login's @login_required prevents unauthenticated access.
* WTForms validates and sanitises input; Jinja2 auto-escapes output to
  prevent XSS.
"""

from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length

from app import db, login_manager
from app.models import Note, User

main_bp = Blueprint("main", __name__)


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------

class NoteForm(FlaskForm):
    title = StringField(
        "Title",
        validators=[DataRequired(), Length(max=200)],
    )
    content = TextAreaField(
        "Content",
        validators=[DataRequired(), Length(max=10_000)],
    )


# ---------------------------------------------------------------------------
# User loader (required by flask-login)
# ---------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@main_bp.route("/")
@login_required
def index():
    notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).all()
    return render_template("index.html", notes=notes)


@main_bp.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(
            title=form.title.data,
            content=form.content.data,
            user_id=current_user.id,
        )
        db.session.add(note)
        db.session.commit()
        flash("Note created.", "success")
        return redirect(url_for("main.index"))
    return render_template("note_form.html", form=form, action="Create")


@main_bp.route("/notes/<int:note_id>")
@login_required
def view_note(note_id: int):
    note = Note.query.get_or_404(note_id)
    # IDOR check – abort with 403 if the note belongs to another user
    if note.user_id != current_user.id:
        abort(403)
    return render_template("note_detail.html", note=note)


@main_bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id: int):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)

    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash("Note updated.", "success")
        return redirect(url_for("main.view_note", note_id=note.id))
    return render_template("note_form.html", form=form, action="Edit")


@main_bp.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id: int):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash("Note deleted.", "success")
    return redirect(url_for("main.index"))
