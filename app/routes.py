import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, current_app, abort
from sqlalchemy import text
from app import db, limiter
from app.forms import RegisterForm, LoginForm, changePasswordForm
from app.models import User
from datetime import datetime
from flask_login import login_required, login_user, current_user
from sqlalchemy.engine import cursor



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


@main.before_request
def make_session_permanent():
    session.permanent = True

@main.route('/')
def home():
    return render_template('home.html')



@main.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per minute", methods=["POST"]) #ONLY APPLIES TO POST REQUESTS
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
        #Hashing password and checking against DB
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
                f"REGISTRATION SUCCESSFUL FOR {username} from IP {request.remote_addr} at {datetime.now()}"
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
                f"REGISTRATION NOT SUCCESSFUL FOR {username} from IP {request.remote_addr} at {datetime.now()}"
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
            return redirect(url_for('main.login'))



    return render_template('login.html', form=form)

@main.route('/dashboard')
@login_required
def dashboard():
    '''if 'user' in session:
        username = session['user']
        bio = session['bio']
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))'''
    return render_template('dashboard.html', username=current_user.username, bio=current_user.bio)



@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
            #Sanitizing input
            username = safeHTML(request.form['username'])
            password = safeHTML(request.form['password'])
            bio = safeHTML(request.form['bio'])
            role = request.form.get('role', 'user')

            #Hashing users password
            password = bcrypt.generate_password_hash(password).decode('utf-8')
            #db.session.execute(text(f"INSERT INTO user (username, password, role, bio) VALUES ('{username}', '{password}', '{role}', '{bio}')"))
            #Changing to parameterized queries to protect against SQL injection
            db.session.execute(text(f"INSERT INTO user (username, password, role, bio)"
                                    f" VALUES (:username, :password, :role, :bio)"),#: so read as parameters, not columns
                                    #Needs to be a dictionary, not tuples
                               {
                                   "username": username,
                                   "password": password,
                                   "role": role,
                                   "bio": bio
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
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        current_app.logger.warning(
            f'{current_user.username} TRYING TO ACCESS THE ADMIN-PANEL'
        )
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
@login_required
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        current_app.logger.warning(
            f'{current_user.username} TRYING TO ACCESS THE MODERATOR DASHBOARD'
        )
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        current_app.logger.warning(
            f'{current_user.username} TRYING TO ACCESS THE USER DASHBOARD'
        )
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))




#1) Users current password needs to match hash value of stored value
#2) Users new password can't match current password


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():


    form = changePasswordForm()

    if 'user' not in session:
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
            text(f"UPDATE user SET password = (:newpass) WHERE username = (:storedusername)"),
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








'''def change_password():

    form = changePasswordForm()
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = form.username.data

    if request.method == 'POST':
        #Sanitizing users input
        current_password = safeHTML(request.form.get('current_password', ''))
        new_password = safeHTML(request.form.get('new_password', ''))

        user = db.session.execute(
            text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{current_password}' LIMIT 1")
        ).mappings().first()
        #Changing to parameterized queries to protect from SQL injection
        user = cursor.execute(text(f"SELECT * FROM user WHERE username = (username) AND password = (current_password) LIMIT 1)"
                                   f"VALUES (:username,:current_password)", #: so read as parameters, not columns
                                   #Needs to be dictionary, not tuple
                                   {
                                       "username": username,
                                       "current_password": current_password
                                   }
                                   )
                              )
        #Checking user exists after input validation and data sanitization
        user = User.query.filter_by(username=username).first()

        # Enforce: current password must be valid for user
        if not user:
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        # Enforce: new password must be different from current password
        #Hashing new password and comparing to current password (already hashed at login/register stage)
        if bcrypt.check_password_hash(user.password, current_password):
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        #Changin to parameterized queries to protect against SQL injection
        db.session.execute(
            text(f"UPDATE user SET password = '{new_password}' WHERE username = '{username}'")
        )
        db.session.execute(text(f"UPDATE user SET password = (new_password) WHERE username = (username)"
                                f"VALUES (:username,:new_password)", #: So read as parameters, not columns
                                {
                                    "username": username,
                                 "new_password": new_password
                                }))
        db.session.commit()
        #Changing to parameterized queries to protect from SQL injection
        #db.session.execute("UPDATE user SET password = ? WHERE username = ?",
                           #(username, new_password))

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html', form=form)'''








