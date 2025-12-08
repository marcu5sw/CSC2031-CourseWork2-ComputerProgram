import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, current_app, abort
from flask_wtf.csrf import CSRFError
from sqlalchemy import text
from app import db, limiter, principal
from app.forms import RegisterForm, LoginForm, changePasswordForm
from app.models import User
from datetime import datetime
from flask_login import login_required, login_user, current_user, logout_user
from flask_principal import Permission, RoleNeed, identity_loaded
from .permissions import *
from config import fernet
import re

from . import bcrypt
import bleach

main = Blueprint('main', __name__)


#Data sanitisiation function
def safeHTML(user_input):
    return bleach.clean(
        user_input,
        tags = ['b', 'i', 'u',
                'em', 'strong',
                'a', 'p', 'ul',
                'ol', 'li', 'br'],
        attributes = {'a': ['href', 'title']},
        strip = True
    )



#Logging sanitized input
def sanitize_for_log(value):
    return re.sub(r'[\n\r\t]', '_', str(value))


#Error handling for CSRF
@main.errorhandler(CSRFError)
def handle_csrf_error(e):
    #Logging the error
    current_app.logger.warning(
        f"CSRF ERROR DETECTED FROM IP {request.remote_addr} AT {datetime.now()}"
    )
    return render_template('error.html', reason = e.description), 403

@main.before_request
def make_session_permanent():
    session.permanent = True

@main.route('/')
def home():
    #print(response.headers)
    return render_template('home.html')



@main.route('/login', methods=['GET', 'POST'])
#@limiter.limit("100 per minute", methods=["POST"]) #ONLY APPLIES TO POST REQUESTS
def login():
    print("Before initializing login")

    form = LoginForm()
    print("Before validating login")
    if request.method == 'POST' and form.validate_on_submit():

        #sanitizing input
        username = safeHTML(request.form['username'])
        password = request.form['password']

        #Mitigating SQL injection (ORM based)
        user = User.query.filter_by(username=username).first()  # Checking User exists

        #CASE 1: Right username and password
        #Checking password against what stored in DB
        if user and bcrypt.check_password_hash(user.password, password): #Comparing the 2 hash values

            print("Works")
            #row = db.session.execute(text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")).mappings().first()
            #if row:
                #user = db.session.get(User, row['id'])  # creates a User object
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio

            #Logging successful login
            current_app.logger.info(
                f"LOGIN SUCCESSFUL: USERNAME={sanitize_for_log(user.username)}, ROLE={user.role}, "
                f"ENDPOINT=/login, IP={request.remote_addr}, DATETIME={datetime.now()}"
            )



            login_user(user)
            user.loginattempts = 0  # Resetting to 0 after a correct login attempt
            return redirect(url_for('main.dashboard'))


        #CASE 2: Right username but wrong password
        elif user:
            user.loginattempts += 1 #Tracking loging failure
            db.session.commit()
            #Logging the failure
            current_app.logger.warning(
                f"LOGIN FAILURE:  USERNAME={user.username}, ROLE={user.role}, ENDPOINT={request.path}, "
                f"IP={request.remote_addr}, DATETIME={datetime.now()},"
                f"ATTEMPT NUMBER: {user.loginattempts}"
            )
            flash('Password is invalid, please try again')


            #Locking user out after 5 failed attempts
            if user.loginattempts >= 6:
                current_app.logger.warning(
                    f"USER EXCEEDED 5 LOGIN FAILURES, LOCKING OUT"
                )
                flash('Too many login attempts, try again later')
                return 'Too many login attempts, try again later', 403




            #Redirecting back to login page
            return redirect(url_for('main.login'))



        #CASE 3: Username doesn't exist
        else:
            flash("This user does not exist")
            current_app.logger.warning(
                f'USER LOGIN ATTEMPT FAILED FOR {username} from IP {request.remote_addr}'
            )
            return redirect(url_for('main.login'))



    return render_template('login.html', form=form)

@main.route('/dashboard')
@login_required
def dashboard():

   #Checking user is first logged in
    if not current_user:
        flash('User not found')
        return redirect(url_for('main.login'))


    #Decrypting the users bio
    decrypted_bio = fernet.decrypt(session['bio'])
    #Decoding to remove "b"
    return render_template('dashboard.html', username=current_user.username, bio=decrypted_bio.decode())



@main.route('/register', methods=['GET', 'POST'])
#@limiter.limit('7 per minute', method=['POST']) #Only applies to post requests
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
            #Sanitizing input
            username = safeHTML(request.form['username'])
            password = safeHTML(request.form['password'])
            bio = safeHTML(request.form['bio'])
            role = safeHTML(request.form.get('role', 'user'))
            #loginattempts = request.form.get('loginattempts', 0) #Default is 0

            #Encrypting users bio
            encrypted_bio = fernet.encrypt(bio.encode())



            #Hashing users password
            password = bcrypt.generate_password_hash(password).decode('utf-8')
            #db.session.execute(text(f"INSERT INTO user (username, password, role, bio) VALUES ('{username}', '{password}', '{role}', '{bio}')"))
            #Changing to parameterized queries to protect against SQL injection
            db.session.execute(text(f"INSERT INTO user (username, password, role, bio, loginattempts)"
                                    f" VALUES (:username, :password, :role, :bio, :loginattempts)"),#: so read as parameters, not columns
                                    #Needs to be a dictionary, not tuples
                               {
                                   "username": username,
                                   "password": password,
                                   "role": role,
                                   "bio": encrypted_bio,
                                   "loginattempts": 0
                               })

            db.session.commit()

            # Logging successful registration
            current_app.logger.info(
                f"Registration Successful for {username} from IP {request.remote_addr} at {datetime.now()}")

            return redirect(url_for('main.dashboard'))






    if not form.validate_on_submit():

        # Logging errors
        current_app.logger.warning(f"Registration Failed: {form.errors} from IP {request.remote_addr} at {datetime.now()}")


        # Flashing the error
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field} - {error}")


        #Redirecting back to register form
        return render_template('register.html', form=form)



    return render_template('register.html', form=form)



@main.route('/admin-panel')
@login_required
@admin_permission.require(http_exception=403) #Checking stored user role (done in __init__ ) with defined variable
def admin():
    return render_template('admin.html')



@main.route('/moderator')
@login_required
@moderator_permission.require(http_exception=403)
def moderator():
    return render_template('moderator.html')



@main.route('/user-dashboard')
@login_required
@user_permission.require(http_exception=403)
def user_dashboard():
    return render_template('user_dashboard.html', username=session.get('user'))




@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():


    form = changePasswordForm()

    if 'user' not in session:
        flash("Please login to change your password")
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")





    if request.method == 'POST' and form.validate_on_submit():

        # Sanitizing inputs
        current_password = safeHTML(form.current_password.data)
        new_password = safeHTML(form.new_password.data)

        #Checking current password matches stored password (Comparing hash values)
        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash("Current password is incorrect, try again.")
            return render_template('change_password.html', form=form)

        #Checking new password doesn't match current password (don't need hashing)
        if new_password == current_password:
            flash("New Password cannot be the same as the current password, try again.")
            return render_template('change_password.html', form=form)


        #Hashing new password and storing in DB
        hashed_new = bcrypt.generate_password_hash(new_password).decode('utf-8')
        #db.session.execute(text(f"INSERT INTO user (username, password, role, bio)"))

        #Different to insert which uses VALUE. VALUE not valid syntax for update command
        db.session.execute(
            text(f"UPDATE user SET password = :newpass WHERE username = :storedusername"),
                #Needs to be dictionary, not tuple
                {
                "newpass": hashed_new,
                "storedusername": current_user.username,
                }
        )



        db.session.commit()

        flash("Password has been changed successfully.")
        return redirect(url_for('main.dashboard'))



    return render_template('change_password.html', form=form)



@main.route('/logout')
@login_required
def logout():
    #Checking user is first logged in
    if current_user.is_authenticated:
        logout_user()
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for('main.dashboard'))

    #Can't log out a user that is not logged in
    flash("You are not signed in, can't log out")
    return redirect(url_for('main.dashboard'))




