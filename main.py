from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import requests
import urllib.parse
import math
import random

# configure application
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


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def generate():
    """Generate color by requesting api from colormind"""

    random_color = format((math.floor(random.random() *16777216)), 'x')

    # Contact API
    try:
        response = requests.get("http://palett.es/API/v1/palette/from/" + random_color)
        # response.raise_for_status()
    except requests.RequestException:
        return None

    # Parse response
    try:
        color = response.json()
        return color
    except (KeyError, TypeError, ValueError):
        return None

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///colorise.db")


@app.route("/")
def starting():
    """The start of the website"""

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Forget any user_id
        session.clear()

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

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
        session.pop('_flashes', None)
        # Redirect user to home page
        flash("Successfully logged in. Welcome back " + rows[0]["username"] + "!")
        
        return redirect("/home")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # clear any session
    session.clear()

    # if form is submitted via post request to this route
    if request.method == "POST":
        
        # if username is not type
        if not request.form.get("username"):

            # show aplogy page with message
            return apology("must provide username", 403)

        # if password is not entered
        elif not request.form.get("password"):

            # show apology page with message
            return apology("must provide password", 403)
        
        # if confirmation password does not match
        elif request.form.get("confirmation") != request.form.get("password"):

            # show apology page with message
            return apology("confirmation password did not match, 403")

        # get the username from the form
        username = request.form.get("username")

        # get the password from the form and hash the password
        password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # store the user's info in databases
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=password)

        # get the row from the database
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/login")

    # if the request is to get the page
    else:

        # render the register page
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/home", methods=["GET", "POST"])
def start():
    """The user's homepage"""

    if request.method == "POST":

        saved_color = request.form.get("save")
        name = request.form.get("scheme_name")
        # Converting string to list 
        saved_color = saved_color.strip('][').replace("'", "").split(', ') 
        db.execute("INSERT INTO saved (name, '1', '2', '3', '4', '5', users_id) VALUES (:name, :first, :second, :third, :fourth, :fifth, :users_id);", 
                    name=name, first=saved_color[0], second=saved_color[1], third=saved_color[2], fourth=saved_color[3], 
                    fifth=saved_color[4], users_id=session["user_id"])
        session.pop('_flashes', None)
        flash("Color scheme saved as " + name)
        return render_template("home.html", color=saved_color)
    else:
        
        color = generate()
        return render_template("home.html", color=color)


@app.route("/saved", methods=["GET", "POST"])
def saved():
    """The user's saved page"""
    session.pop('_flashes', None)

    if request.method == "POST" :
        if "delete" in request.form:
            name = request.form.get("name")
            name = name.strip('""')
            db.execute("DELETE FROM saved WHERE users_id=:users_id AND name=:name;", users_id=session["user_id"], name=name)
            session.pop('_flashes', None)
            flash("Deleted " + name + " color scheme")
            colors = db.execute("SELECT * FROM saved WHERE users_id=:users_id", users_id=session["user_id"])
            return render_template("saved.html", colors=colors)
        
        elif "preview" in request.form:
            name = request.form.get("name")
            name = name.strip('""')
            color = db.execute("SELECT * FROM saved WHERE users_id=:users_id AND name=:name;", users_id=session["user_id"], name=name)
            color_list = [color[0]["1"], color[0]["2"], color[0]["3"], color[0]["4"], color[0]["5"]]
            session.pop('_flashes', None)
            flash("Previewing " + name + " color scheme")
            return render_template("home.html", color=color_list)
        
    else:
        
        colors = db.execute("SELECT * FROM saved WHERE users_id=:users_id", users_id=session["user_id"])
        return render_template("saved.html", colors=colors)



        
    