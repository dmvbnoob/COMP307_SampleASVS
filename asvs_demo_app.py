from flask import Flask, render_template, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from wtforms import Form, StringField, PasswordField, validators

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

#### ASVS Link: https://github.com/OWASP/ASVS/tree/master

### ASVS V2: Authentication
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

### Database Model for User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    # ASVS V2.4: Passwords securely stored with hashing
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # ASVS V2.4: Passwords securely verified with hash comparison
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

## Index
@app.route('/')
def home():
    return '''
    <h1>Welcome to the ASVS Demo App!</h1>
    <p>Please <a href="/register">register</a> if you're new, or <a href="/login">log in</a> if you already have an account.</p>
    '''

### ASVS V5: Input Validation
# Form for Registration with Basic Input Validation
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=3, max=150), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=6), validators.DataRequired()])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        existing_user = User.query.filter_by(username=username).first()

        # ASVS V2.2: Prevents duplicate usernames (unique constraint)
        if existing_user:
            flash('Username already taken, choose a different one.', 'danger')
            return redirect('/register')

        user = User(username=username)
        user.set_password(password)  # Hash password before saving

        # Save user securely to database
        db.session.add(user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect('/login')
    return render_template('register.html', form=form)

### ASVS V7: Error Handling
# Securely handles errors without exposing sensitive information
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # ASVS V2.1: Securely verifies password hash
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid username or password.', 'danger')  # Avoids revealing specifics

    return render_template('login.html')

### ASVS V4: Access Control
# Restrict access to authenticated users only
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

### ASVS V3: Session Management
# Logout user securely
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect('/login')

# Run the Flask app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
