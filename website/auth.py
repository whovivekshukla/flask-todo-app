from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_remembered, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('passsword')

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                flash("Logged in Successfully", category="success")
            else:
                flash("Incorrect Password", category="error")
        else:
            flash("Email is not registered.", category="error")

    return render_template("login.html")

@auth.route('/logout')
def logout():
    return '<p>Logout</p>'

@auth.route('/sign-up', methods=['GET','POST'])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        firstname = request.form.get("firstname")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()

        if user:
            flash("User Already Exists", category="error")
        else:
            if len(firstname) < 2:
              flash("First Name must be greater than 1 character.", category='error')
            elif len(email) < 4:
              flash("Email must be greater than 3 Characters.", category='error')
            elif password1 != password2:
              flash("Your Passwords don't match.", category='error')
            elif len(password1) < 7:
              flash("Your Passwords must have atleast 7 characters.", category='error')
            else:
              new_user = User(email=email, firstname=firstname, password=generate_password_hash(password1, method='sha256'))
              db.session.add(new_user)
              flash('Account created!', category='success')
              return redirect(url_for('views.home'))

    return render_template("sign-up.html")