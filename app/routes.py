import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, current_app
from sqlalchemy import text
from app import db
from app.forms import RegisterForm, LoginForm
from app.models import User
from datetime import datetime
from flask_login import login_required, login_user, current_user
from . import bcrypt

main = Blueprint('main', __name__)





@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()

    if request.method == 'POST' and form.validate_on_submit():

        username = request.form['username']
        password = request.form['password']

        #Hashing password and checking against DB
        user = User.query.filter_by(username=username).first() #Getting default user with same password
        if user and bcrypt.check_password_hash(user.password, password): #Comparing the 2 hash values

            print("Works")



            row = db.session.execute(text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")).mappings().first()
            if row:
                user = db.session.get(User, row['id'])  # creates a User object
                session['user'] = user.username
                session['role'] = user.role
                session['bio'] = user.bio

                #Logging successful login
                current_app.logger.info(
                    f"Registration Successful for {username} from IP {request.remote_addr} at {datetime.now()}"
                )


                return redirect(url_for('main.dashboard'))
            else:
                flash('Login credentials are invalid, please try again')

            print("Works2")
            login_user(user)

            return redirect(url_for('main.dashboard'))


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
            username = request.form['username']
            password = request.form['password']
            bio = request.form['bio']
            role = request.form.get('role', 'user')

            #Hashing users password
            password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.execute(text(f"INSERT INTO user (username, password, role, bio) VALUES ('{username}', '{password}', '{role}', '{bio}')"))

            db.session.commit()

            # Logging successful registration
            current_app.logger.info(
                f"Registration Successful for {username} from IP {request.remote_addr} at {datetime.now()}")

            return redirect(url_for('main.login'))






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
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
@login_required
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        user = db.session.execute(
            text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{current_password}' LIMIT 1")
        ).mappings().first()

        # Enforce: current password must be valid for user
        if not user:
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        # Enforce: new password must be different from current password
        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        db.session.execute(
            text(f"UPDATE user SET password = '{new_password}' WHERE username = '{username}'")
        )
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')


