import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import re

from helpers import apology, login_required, lookup, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    # get user's stocks and cash
    user_stocks3 = db.execute("SELECT symbol, shares FROM users_stocks WHERE user_id = ?", session["user_id"])
    cash3 = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash3 = cash3[0]["cash"]

    # show the user their info
    return render_template("index.html", user_stocks3=user_stocks3, cash3=cash3, usd=usd, lookup=lookup)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # if user submitted data to the route
    if request.method == "POST":
        # get stock info and the number of shares the user wants to buy
        stock = lookup(request.form.get("symbol"))
        shares1 = int(request.form.get("shares"))
        value = stock["price"] * shares1

        # check if the stock exists
        if stock == None:
            return apology("No Such Stock", 403)

        # check if the user has enough money to buy the stocks
        user_money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        user_money = user_money[0]["cash"]
        if user_money < value:
            return apology("Not Enough Money To buy These Stocks", 403)

        # register the trade
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute("INSERT INTO trades (symbol, shares, user_id, price, transacted) VALUES (?, ?, ?, ?, ?)",
                                        stock["symbol"], shares1, session["user_id"], stock["price"], timestamp)

        # subtract the value from user's money
        db.execute("UPDATE users SET cash = cash-(?) WHERE id = ?", value, session["user_id"])

        '''update this user's stocks'''

        # check if the user has any shares of that stock
        symbol1 = db.execute("SELECT * FROM users_stocks WHERE symbol = ? AND user_id = ?", stock["symbol"], session["user_id"])

        # the user doesn't own any shares of that stock add it
        if symbol1 == []:
            db.execute("INSERT INTO users_stocks (user_id, symbol, shares) VALUES (?, ?, ?)", session["user_id"], stock["symbol"], shares1)

        # if the user already own shares of that stock update them
        else:
            db.execute("UPDATE users_stocks SET shares = shares+(?) WHERE user_id = ? AND symbol = ?", shares1, session["user_id"], stock["symbol"])

        return redirect("/")

    # if the user reached the route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    # get all the trades this user made from the database
    trades4 = db.execute("SELECT * FROM trades WHERE user_id = ? ORDER BY transacted DESC", session["user_id"])

    # display the trades to the user
    return render_template("history.html", trades4=trades4, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # if user submitted username to the route to change password
        if request.form.get("usrname"):
            # check if username exists in users
            usrname = db.execute("SELECT * FROM users WHERE username=?", request.form.get("usrname"))
            if not usrname:
                return apology("username doesn't exist", 403)

            session["temp"] = usrname[0]["username"]

            # send user to type new password page
            return render_template("pass-change.html")

        # if user submitted new password to the route
        if request.form.get("pass"):
            # check if password confirmation matches password
            if request.form.get("pass") != request.form.get("conpass"):
                return apology("password confirmation doesn't match password")

            # change password
            db.execute("UPDATE users SET hash=? WHERE username=?", generate_password_hash(request.form.get("pass")), session["temp"])

            # redirect user to login page
            session.clear()
            return redirect("/login")

        # if user reached route for logging in
        else:
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

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # if user requested change password page, confirm username first
        if re.search("c=$", request.url):
            return render_template("confirm-username.html")

        # else user requested login page
        else:
            return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    # if user submitted data to the route
    if request.method == "POST":
        # get stock info
        stock = lookup(request.form.get("symbol"))

        # if the stock isn't found
        if stock == None:
            return apology("No Such Stock", 43)

        # if stock found display stock info
        return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=stock["price"], usd=usd)

    # user reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conpassword = request.form.get("conpassword")

        # if username or password field empty
        if not username or not password:
            return apology("must provide a username and a password", 403)

        # check password complexity requirements
        if not re.search("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d~!@#$%^&*_\-+=`|\(){}\[\]:;\"'<>,.?/]{8,128}$", password):
            return apology("password must be:\nbetween 8 and 128 characters long inclusive.\nconsist of lowercase, upeercase letters, digits and/or special characters.\n", 403)

        # if username already taken
        existing_user = db.execute("SELECT username FROM users WHERE username = ?", username)
        if existing_user:
            return apology("username already taken", 403)

        # if password confirmation doesn't match password
        if password != conpassword:
            return apology("password confirmation doesn't match password", 403)

        # if everything went fine register the user
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        return redirect("/")

    # send register page if requested
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # if the user reached the route with a request method of POST
    if request.method == "POST":
        # get form info
        symbol2 = request.form.get("symbol")
        shares2 = int(request.form.get("shares"))

        # get user stock info
        user_stock2 = db.execute("SELECT symbol, shares FROM users_stocks WHERE user_id = ? AND symbol = ?", session["user_id"], symbol2)

        # check if user owns any shares of that stock
        if user_stock2 == []:
            return apology("you don't own any shares of that stock")

        # check if the user has the number of shares that he wants to buy
        user_stock2 = user_stock2[0]
        if user_stock2["shares"] < shares2:
            return apology("you don't own this number of shares of that stock")

        # register the trade
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        price2 = lookup(symbol2)
        price2 = price2["price"]
        db.execute("INSERT INTO trades (symbol, shares, user_id, price, transacted) VALUES (?, ?, ?, ?, ?)",
                                        symbol2, -shares2, session["user_id"], price2, timestamp)

        # add the value to user's cash
        value2 = price2 * shares2
        db.execute("UPDATE users SET cash = cash+(?) WHERE id = ?", value2, session["user_id"])

        '''update user's stocks'''

        # if the user sold all his shares delete the stock
        if user_stock2["shares"] == shares2:
            db.execute("DELETE FROM users_stocks WHERE user_id = ? AND symbol = ?", session["user_id"], symbol2)

        # else if the user still have some shares of that stock update them
        else:
            db.execute("UPDATE users_stocks SET shares = shares-(?) WHERE user_id = ? AND symbol = ?", shares2, session["user_id"], symbol2)

        return redirect("/")

    # if the user reached the route with a request method of GET
    else:
        # get user's stocks to show them in a dropdown for the user to choose what stock to sell
        user_stocks2 = db.execute("SELECT symbol FROM users_stocks WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", user_stocks2=user_stocks2)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
