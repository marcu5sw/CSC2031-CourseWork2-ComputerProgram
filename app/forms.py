from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, Length, Regexp
import re




#Custom Validators for Password
def passwordPolicy(form, field):

    password = field.data
    username = form.username.data


    #At least one upper case
    upper = Regexp( r'(?=.*[A-Z]).*$', message = "Passwords must contain at least 1 uppercase letter")
    upper(form, field)

    #At least one digit
    digit = Regexp (r'(?=.*[0-9]).*$', message = "Passwords must contain at least 1 digit")
    digit(form, field)

    #At least one special Character
    specialCharacter = Regexp(r'(?=.*[!@#$%^&*]).*$', message = "Passwords must contain at least 1 special character")
    specialCharacter(form, field)

    #Can't contain any part of the username (email)
    if password.lower() in username.lower():
        raise ValidationError('Password cannot contain any part of the username (email)')


    #Black listed names
    blackListedNames = ['Password123$', 'Qwerty123!', 'Adminadmin1@', 'weLcome123!']
    if password in blackListedNames:
        raise ValidationError('Password is blocked because it is common')


    #No repeated Character:
    pattern = r"(.)\1\1"
    if re.search(pattern, password):
        raise ValidationError('Password cannot contain character sequences (e.g, AAA, 111, !!!)')







class RegisterForm(FlaskForm):


    username = EmailField('Username',validators=[DataRequired(message="Username required."),
                                                 Email(),
                                                 Length(min=12, max=32,
                                                        message='Username must be between 12 and 32 characters long.')])



    password = PasswordField('Password',validators=[DataRequired(message="Password required."),
                                                    Length(min=10,
                                                           message="Password must be at least 10 characters long."),
                                                    passwordPolicy])


    bio = StringField('Bio',validators=[DataRequired(message="Bio required."),
                                        Length(max=30, message="Bio must be less than 30 characters long.")])



    register = SubmitField('Register')



class LoginForm(FlaskForm):

    #Don't need input validation if users are already registered
    username = EmailField('Username',validators=[DataRequired(message="Username required."),])
    password = PasswordField('Password',validators=[DataRequired(message="Password required."),])
    login = SubmitField('Login')



