from flask import Flask, render_template, request, redirect, url_for, flash, current_app, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import logging
from flask import request, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app = Flask(__name__, static_folder='static')

class Config:
    SECRET_KEY = 'cT9UvAdyX8TUtEo9FTXJ6yLg59gD4q8g'
    SQLALCHEMY_DATABASE_URI = 'mysql://username:password@localhost/room_buddy_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'email@gmail.com'
    MAIL_PASSWORD = 'passkey or password'
    MAIL_DEFAULT_SENDER = 'email@gmail.com'
    UPLOAD_FOLDER = 'D:/Room buddy/static/Uploads'

    # Token expiration time in seconds (1 hour)
    TOKEN_EXPIRATION = 3600  

app.config.from_object(Config)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.Enum('male', 'female', 'other'), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        try:
            return str(self.user_id)
        except AttributeError:
            raise NotImplementedError("No `user_id` attribute - override `get_id`")

class RoomPost(db.Model):
    __tablename__ = 'room_posts'
    post_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    rent = db.Column(db.Float, nullable=False)
    utilities = db.Column(db.String(100), nullable=False)
    availability = db.Column(db.DateTime, nullable=False)
    furnished = db.Column(db.Boolean, nullable=False)
    type = db.Column(db.String(100), nullable=False)
    photos = db.Column(db.Text)  # Store paths or URLs to photos
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.Enum('male', 'female', 'other'))
    age_group = db.Column(db.String(50))
    smoking = db.Column(db.Enum('yes','no','no preference'))
    students_only = db.Column(db.Enum('yes','no','no preference'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('room_posts', lazy=True))
    bedrooms = db.Column(db.Integer, nullable=False)
    bathrooms = db.Column(db.Integer, nullable=False)
    pets = db.Column(db.Boolean, nullable=False)
    laundry = db.Column(db.Enum('in_unit', 'on_site', 'none'), nullable=False)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['login_username']
        password = request.form['login_password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.confirmed:
                login_user(user)
                flash('Login successful!', 'success')
                session.pop('_flashes', None)  # Clear flash messages
                return redirect(url_for('postad'))
            else:
                flash('Please confirm your email address first.', 'warning')
        else:
            flash('Incorrect username or password.', 'error')
    return render_template('login.html')

def generate_confirmation_token(email):
    return ts.dumps(email, salt='email-confirm-key')

def confirm_token(token):
    try:
        email = ts.loads(token, salt='email-confirm-key', max_age=Config.TOKEN_EXPIRATION)
    except BadSignature:
        # Signature is invalid
        return None
    except SignatureExpired:
        # Signature has expired
        return None
    return email

def send_verification_email(user_email):
    try:
        token = generate_confirmation_token(user_email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email_verification.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        msg = Message(subject, recipients=[user_email], html=html)
        mail.send(msg)
        current_app.logger.info(f"Verification email sent to {user_email}")
    except Exception as e:
        current_app.logger.error(f"Error sending email: {e}")
        raise

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['register_username']
        email = request.form['register_email']
        password = request.form['register_password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        gender = request.form['gender']
        phone_number = request.form['phone_number']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already in use. Please choose a different one.', 'error')
        else:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already in use. Please choose a different one.', 'error')
            else:
                if len(password) < 8 or not any(char.isdigit() for char in password) or not any(not char.isalnum() for char in password):
                    flash('Password must be 8+ characters and contain at least 1 number and 1 special character.', 'error')
                else:
                    new_user = User(
                        username=username,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        gender=gender,
                        phone_number=phone_number
                    )
                    new_user.set_password(password)
                    db.session.add(new_user)
                    db.session.commit()
                    send_verification_email(email)
                    flash('Registration successful! A confirmation email has been sent. Please confirm your email to log in.', 'success')
                    return redirect(url_for('login'))  # Redirect to login page after registration
    
    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('index'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please log in.', 'success')
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

import uuid

def save_photos(photos):
    saved_paths = []
    for photo in photos:
        if photo.filename != '':
            filename = secure_filename(photo.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"  # Generate unique filename
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            photo.save(filepath)
            saved_paths.append(unique_filename)  # Save only the unique filename
    return saved_paths



@app.route('/postad', methods=['GET', 'POST'])
@login_required
def postad():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        rent = float(request.form['rent'])
        utilities = request.form['utilities']
        availability_str = request.form['availability']  # Get date string from form
        availability = datetime.strptime(availability_str, '%Y-%m-%d')
        furnished = request.form['furnished'] == 'yes'
        room_type = request.form.get('type', '')  # Use request.form.get to handle optional field
        city = request.form['city']
        state = request.form['state']
        photos = request.files.getlist('photos')
        gender = request.form['gender'] if request.form['gender'] else None
        age_group = request.form['age_group'] if request.form['age_group'] else None
        smoking = request.form['smoking'] if request.form['smoking'] else 'no preference'
        students_only = request.form['students_only'] if request.form['students_only'] else 'no preference'
        bedrooms = int(request.form['bedrooms'])
        bathrooms = int(request.form['bathrooms'])
        pets = request.form['pets'] == 'yes'
        laundry = request.form['laundry'] if request.form['laundry'] else 'none'

        # Save uploaded photos and get paths or URLs
        photo_paths = save_photos(photos)

        app.logger.info(f"Form data: smoking={smoking}, students_only={students_only}, laundry={laundry}")

        new_room_post = RoomPost(
            title=title,
            description=description,
            rent=rent,
            utilities=utilities,
            availability=availability,
            furnished=furnished,
            type=room_type,
            city=city,
            state=state,
            photos=','.join(photo_paths),  # Store multiple photos as comma-separated values
            gender=gender,
            age_group=age_group,
            smoking=smoking,
            students_only=students_only,
            bedrooms=bedrooms,
            bathrooms=bathrooms,
            pets=pets,
            laundry=laundry,
            user_id=current_user.user_id
        )
        
        db.session.add(new_room_post)
        db.session.commit()
        flash('Ad posted successfully!', 'success')
        return redirect(url_for('postad'))  # Redirect to postad after posting
    
    return render_template('postad.html')


from datetime import datetime

@app.route('/search', methods=['GET', 'POST'])
def search():
    search_query = ''
    bedrooms = ''
    bathrooms = ''
    city = ''
    rent = ''
    availability = ''
    gender = ''

    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        bedrooms = request.form.get('bedrooms', '')
        bathrooms = request.form.get('bathrooms', '')
        city = request.form.get('city', '')
        rent = request.form.get('rent', '')
        availability = request.form.get('availability', '')
        gender = request.form.get('gender', '')

        filters = [
            RoomPost.title.ilike(f'%{search_query}%') |
            RoomPost.city.ilike(f'%{search_query}%') |
            RoomPost.state.ilike(f'%{search_query}%') |
            RoomPost.description.ilike(f'%{search_query}%')
        ]

        if bedrooms:
            filters.append(RoomPost.bedrooms == int(bedrooms))
        if bathrooms:
            filters.append(RoomPost.bathrooms == int(bathrooms))
        if city:
            filters.append(RoomPost.city.ilike(f'%{city}%'))
        if rent:
            filters.append(RoomPost.rent <= float(rent))
        if availability:
            availability_date = datetime.strptime(availability, '%Y-%m-%d')
            filters.append(RoomPost.availability <= availability_date)
        if gender:
            filters.append(RoomPost.gender == gender)

        search_results = RoomPost.query.filter(*filters).all()
    else:
        search_results = RoomPost.query.all()
    for post in search_results:
        post.description = truncate_description(post.description)

    return render_template(
        'search.html',
        room_posts=search_results,
        search_query=search_query,
        bedrooms=bedrooms,
        bathrooms=bathrooms,
        city=city,
        rent=rent,
        availability=availability,
        gender=gender
    )
def truncate_description(description):
    # Truncate the description to 3 lines
    max_lines = 8
    words = description.split()
    truncated_description = ""
    line_length = 0
    lines = 0
    for word in words:
        if lines >= max_lines:
            break
        truncated_description += word + " "
        line_length += len(word) + 1
        if line_length > 40:  # Adjust based on desired line length
            truncated_description += "\n"
            line_length = 0
            lines += 1
    return truncated_description.strip()


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    session.pop('_flashes', None)  # Clear flash messages
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(email)
            recover_url = url_for('reset_password', token=token, _external=True)
            html = render_template('recover_email.html', user=user, recover_url=recover_url)
            subject = "Password reset requested"
            msg = Message(subject, recipients=[email], html=html)
            mail.send(msg)
            current_app.logger.info(f"Password reset email sent to {email}")
            flash('Password reset instructions have been sent to your email.', 'success')
        else:
            flash('No account found with that email address.', 'error')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif len(password) < 8 or not any(char.isdigit() for char in password) or not any(not char.isalnum() for char in password):
            flash('Password must be 8+ characters and contain at least 1 number and 1 special character.', 'error')
        else:
            user = User.query.filter_by(email=email).first_or_404()
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Password reset successful! You can now log in with your new password.', 'success')
            session.pop('_flashes', None)  # Clear flash messages
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    app.run(debug=True)
