
from flask import Flask, request, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import UserMixin
from app import db, lm

app= Flask(__name__)

class user(UserMixin, db.Model):
    __tablename__='users'
    id= db.Column(db.Integer, primary_key= True)
    username=db.Column(db.String(80), index= True)
    password_hash= db.Column(db.String(128))

@property
def password(self):
    raise AttributeError('Password is not a readable attribute')

@password.setter
def password(self, password):
    self.password_hash=generate_password_hash(password)

def verift_password(self, password):
    return check_password_hash(self.hash,password)

class registration_form(Flask_form):
    username = StringField('Username', validators=[Required(),length(1, 80)])
    password = PasswordField('Password', validators=[Required()])
    password_again=PasswrodField('Password again', validators= [Required()])
    submit= SubmitField('Register')

class login_form(Flask_form):
    username= StringField('Username',validators=[Required(), length(1, 80)])
    password= PasswordField('Password', validators=[Required()])
    submit= SubmitField('Login')

"""
add route which leads to registration form
where user data is stored in the database as a new user
"""

#route for user who has successfully logged in
@app.route('/login')
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


class login_form(Flask_form):
    username = StringField('Username', validators=[Required(),length(1,80)])
    password=  PasswordField('Password', validators=[Required()])
    token= StringField('Token', validators=[Required(), length(6, 6)])
    submit= SubmitField('Login')

@app.route('/login', methods= ['GET','POST'])
def login():
    form=login_form()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or not user.verify_totp(form.token.data):
            flash('Invalid Uname 0r password or token')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

if __name__=='__main__':
    run.app(debug=True)
