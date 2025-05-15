from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import time
import re
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

app = Flask(__name__)
app.secret_key = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
users = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200))
    timestamp = db.Column(db.Integer)

@app.route('/')
def index():
    return render_template('index.html', logged_in='user' in session)

@app.route('/news')
def news():
    return render_template('news.html', logged_in='user' in session)

@app.route('/match', methods=['GET', 'POST'])
def match():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')[:80]
        email_input = request.form.get('email', '')[:200]
        user = User.query.filter_by(username=username).first()
        if not user:
            result = "✘ User not found"
        elif not user.email:
            result = "✘ User doesn't have a recovery email set"
        elif check_password_hash(user.email, email_input):
            result = "✔ Match"
        else:
            result = "✘ No match"
    return render_template('match.html', logged_in='user' in session, result=result)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['user']).first()
    return render_template('dashboard.html', logged_in=True, user=user.username, user_timestamp=user.timestamp, user_has_email=bool(user.email))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mode = request.form.get('mode')
        username = request.form.get('username', '')[:80]
        password = request.form.get('password', '')[:100]
        if not re.fullmatch(r'[a-z0-9]+', username):
            flash('✘ Username must only contain lowercase letters and numbers')
            return render_template('login.html', logged_in='user' in session)
        if mode == 'register':
            if not username or not password:
                flash('✘ Username and password required')
            elif not re.fullmatch(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}', password):
                flash('✘ Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and symbol')
            else:
                email = request.form.get('email', '')[:200]
                if email and not EMAIL_REGEX.fullmatch(email):
                    flash('✘ Invalid email format')
                    return render_template('login.html', logged_in='user' in session)
                hashed_email = generate_password_hash(email) if email else None
                new_user = User(
                    username=username,
                    password=generate_password_hash(password),
                    email=hashed_email,
                    timestamp=int(time.time())
                )
                db.session.add(new_user)
                try:
                    db.session.commit()
                    session['user'] = username
                    return redirect(url_for('dashboard'))
                except IntegrityError:
                    db.session.rollback()
                    flash('✘ Username already exists')
        elif mode == 'login':
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session['user'] = username
                return redirect(url_for('dashboard'))
            flash('✘ Invalid username or password')
    return render_template('login.html', logged_in='user' in session)

@app.route('/help')
def help():
    return render_template('help.html', logged_in='user' in session)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user' in session:
        user = User.query.filter_by(username=session['user']).first()
        if user:
            db.session.delete(user)
            db.session.commit()
        session.pop('user', None)
    return redirect(url_for('index'))

def handle_error(error):
    code = 500
    description = "Internal Server Error"
    if isinstance(error, HTTPException):
        code = error.code
        description = error.description
    return render_template('error.html', code=code, description=description)

for cls in HTTPException.__subclasses__():
    app.register_error_handler(cls, handle_error)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", debug=True)
