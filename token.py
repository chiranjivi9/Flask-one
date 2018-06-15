from flask imprt Flask, UserMixin, flask_login
from flask import Flask, render_template, json, request
from flask.ext.mysql import MySQL
from werkzeug import generate_password_hash, check_password_hash
import os
import base64
import onetimepass

class User(UserMixin, db.Model)

    otp_secret=db.Column(db.String(16))
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if slf.otp_secret is None:
            #generate a random secret
            self.otp_secret=base64.b32encode(os.random(10).decode('utf-8))

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' /.format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token,self.otp_secret)

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
        'Pragma': 'no_cache'
        'Expires': '0'}
