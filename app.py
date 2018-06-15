import os
import base64
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
import pyqrcode
from flask import Flask, request, render_template
from werkzeug.security import generate_password_hash, check_password_hash
#from app import db, lm


#create app instances
app= Flask(__name__)
app.config.from_object('config')

#init extensions
bootstap = Bootstrap(app)
db= SQLAlchemy(app)
lm= LoginManager(app)


class user(UserMixin, db.Model):
    __tablename__='users'
    id= db.Column(db.Integer, primary_key= True)
    username=db.Column(db.String(80), index= True)
    password_hash= db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if slf.otp_secret is None:
            #generate a random secret
            self.otp_secret=base64.b32encode(os.random(10).decode('utf-8'))

@property
def password(self):
    raise AttributeError('Password is not a readable attribute')

@password.setter
def password(self, password):
    self.password_hash=generate_password_hash(password)

def verify_password(self, password):
    return check_password_hash(self.hash,password)


"""
enter your path from the app 'free OTP' #below get_top_uri
"""
def get_totp_uri(self):
    return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo'.format(self.username, self.otp_secret)

def verify_totp(self, token):
    return onetimepass.valid_totp(token,self.otp_secret)

@lm.user_loader
def load_user(user_id):
    #User loader callback for FLASK-LOGIN.
    return User.query.get(int(user_id))

class registration_form(FlaskForm):
    username = StringField('Username', validators=[Required(),Length(1, 80)])
    password = PasswordField('Password', validators=[Required()])
    password_again=PasswordField('Password again', validators= [Required()])
    submit= SubmitField('Register')

class LoginForm(FlaskForm):
    #registration_form
    username = StringField('Username', validators=[Required(),Length(1,80)])
    password=  PasswordField('Password', validators=[Required()])
    token= StringField('Token', validators=[Required(), Length(6, 6)])
    submit= SubmitField('Login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods= ['GET', 'POST'])
def register():
    ''' USER Registration route. '''
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = registration_form()
    if form.validate_on_submit():
        user= User.query.filter_by(username= form.username.data).first()
        if user is not None:
            flash('Username already exists.' )
            return redirect(url_for('register'))
        #add new user to the db
        user= User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        #redirect to the Two FACT auth
        session['username']=user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)

@app.route('/twofactor')
def two_factor():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
        #make sur the browser doesnt cache the QR code
    return render_template('two_factor.html'), 200, {
        'Cache-Control':'no-cache, no-store, must-revalidate',
        'Pragma': 'no_cache',
        'Expires': '0'}

@app.route ('/qrcode')
def qrcode():
    if 'username' not in session:
        abort (404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)
        #for added security, remove username from session
    del session['username']
    #render qr code for free totp

    url= pyqecode.create(user.get_top_uri())
    stream= BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(),200,{


            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0' }

#route for user who has successfully logged in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        #if user is logged in we get here
        return redirect(url_for('index'))
    form= LoginForm()
    if form.validate_on_submit():
        user= User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        flash('You are now logged in')
        return redirect(url_for('index'))
    return render_template('login.html',form=form)

@app.route('/logout')
def logout():
    """logout route"""
    logout_user()
    return redirect(url_for('index'))

#create db table if they ont exist
db.create_all()


if __name__=='__main__':
    run.app(host='0.0.0.0', debug=True)
