import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///booksnook.db")


@app.route("/")
@login_required
def index():
    """Daycare Homepage"""
    return render_template("index.html")


@app.route("/bio", methods=["GET"])
@login_required
def bio():
    """Biography Page"""
    bio = db.execute("SELECT * FROM bio")
    return render_template("bio.html", bio=bio)


@app.route("/calendar", methods=["GET"])
@login_required
def calendar():
    """Calendar Page"""
    return render_template("calendar.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must haz username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash('Successfully Logged In')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change Password"""

    # If user submitted form
    if request.method == "POST":

        # Checks if Old Password was provided
        if not request.form.get("oldPassword"):
            return apology("Old Password is Needed", 403)

        # Checks if New Password was provided
        if not request.form.get("newPassword"):
            return apology("Need a New Password", 403)

        # Checks if New Password was typed in correctly the second time
        if not request.form.get("newPassword") == request.form.get("confirmation"):
            return apology("New Passwords Don't Match", 403)

        details = db.execute("SELECT * FROM users WHERE id = :sid", sid=session["user_id"])

        # Checks if old password matches and if it does, updates to new password
        if check_password_hash(details[0]["hash"], request.form.get("oldPassword")):
            hsp = generate_password_hash(request.form.get("newPassword"), method='pbkdf2:sha256', salt_length=8)
            db.execute("UPDATE users SET hash = :hash WHERE id = :sid", hash=hsp, sid=session["user_id"])
            flash("Password Updated")
            return redirect("/")
    else:
        return render_template("password.html")


@app.route("/payment", methods=["GET"])
@login_required
def payment():
    """Childcare Payments"""
    return render_template("payment.html")


@app.route("/pictures", methods=["GET"])
@login_required
def pictures():
    """Page for Daycare Pictures"""
    return render_template("pictures.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Verify user reached by POST or GET
    if request.method == "POST":

        # Check if Username was submitted empty
        if not request.form.get("username"):
            return apology("Username haz EMPTY", 400)

        # Check if Password or Confirmation was submitted empty
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Pazzword haz EMPTY", 400)

        # Check that Password and Confirmation match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Pazzword No Match", 400)

        # Check if Username is taken
        result = db.execute("SELECT * FROM users WHERE EXISTS (SELECT * FROM users WHERE username = :username)",
                            username=request.form.get("username"))

        if not result and len(request.form.get("username")) > 0:

            # If user name is long enough and exists, Hash Password and register user database
            hsp = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            usn = request.form.get("username")
            db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=usn, hash=hsp)

            # Check database for existence
            rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

            # Setup session ID for user
            session["user_id"] = rows[0]["id"]

            # Return to homepage
            flash("Registration Successful")
            return redirect("/")

        # If Username is taken, return apology
        else:
            return apology("Username Taken", 400)

    # If user requested via GET, send them form to register
    else:
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
