from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

db.init_app(app)
jwt = JWTManager(app)

@app.before_request
def create_tables():
    db.create_all()

# ------------------ Routes ------------------

@app.route('/')
def home():
    return redirect(url_for('login_web'))

@app.route('/register', methods=['GET', 'POST'])
def register_web():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('User already exists')
            return redirect(url_for('register_web'))

        # hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login_web'))

    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login_web():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        # ✅ Use plain comparison since you are NOT hashing passwords
        if user and user.password == password:
            token = create_access_token(identity=user.username)
            session['username'] = user.username
            session['token'] = token
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login_web'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Please log in to view the dashboard.")
        return redirect(url_for('login_web'))

    users = User.query.all()
    return render_template('dashboard.html', users=users, current_user_id=session.get('user_id'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' not in session:
        flash("Login required.")
        return redirect(url_for('login_web'))

    # Prevent user from deleting themselves
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account from here.")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' deleted.")
    else:
        flash("User not found.")

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login_web'))

if __name__ == '__main__':
    app.run(debug=True)
