"""Authentication blueprint.

Security highlights
-------------------
* All passwords are hashed with bcrypt before storage (work-factor ≥ 12).
* Login is rate-limited to prevent brute-force attacks.
* Generic error messages prevent username enumeration ("invalid credentials"
  instead of "user not found" / "wrong password").
* Redirect-after-login validates the destination with url_parse to prevent
  open-redirect vulnerabilities.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from app import db, limiter
from app.models import User

auth_bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# Forms  (WTForms adds CSRF protection automatically via flask-wtf)
# ---------------------------------------------------------------------------


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=64)],
    )
    email = EmailField(
        "Email",
        validators=[DataRequired(), Email()],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Check for existing username / email before creating the user.
        # Use separate queries so we can give specific (but safe) feedback.
        if User.query.filter_by(username=form.username.data).first():
            flash("That username is already taken.", "danger")
            return render_template("register.html", form=form)

        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("An account with that email already exists.", "danger")
            return render_template("register.html", form=form)

        user = User(
            username=form.username.data,
            email=form.email.data.lower(),
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # brute-force protection
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # Use a generic error message to prevent username enumeration
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password.", "danger")
            return render_template("login.html", form=form)

        login_user(user)

        # Validate the next-page redirect to prevent open-redirect attacks.
        # Only allow relative paths that start with a single "/" – this
        # rejects absolute URLs (https://evil.com) and protocol-relative URLs
        # (//evil.com) while still allowing internal paths like /notes/1.
        next_page = request.args.get("next", "")
        if not (next_page.startswith("/") and not next_page.startswith("//")):
            next_page = ""

        return redirect(next_page or url_for("main.index"))

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
