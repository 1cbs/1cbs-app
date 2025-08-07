# --- Eventlet Patching (MUST be at the very top) ---
import eventlet
eventlet.monkey_patch()

import os
import secrets
import string
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, leave_room, emit
from sqlalchemy import func

# --- Initialization ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, async_mode='eventlet')

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Create Application Directories ---
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Admin Credentials ---
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# --- Association Tables for Many-to-Many Relationships ---
anime_genres = db.Table('anime_genres',
    db.Column('anime_series_id', db.Integer, db.ForeignKey('anime_series.id'), primary_key=True),
    db.Column('genre_id', db.Integer, db.ForeignKey('genre.id'), primary_key=True)
)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_master = db.Column(db.Boolean, default=False, nullable=False)
    watch_history = db.relationship('WatchHistory', backref='user', lazy=True, cascade="all, delete-orphan")
    ratings = db.relationship('Rating', backref='user', lazy=True, cascade="all, delete-orphan")

class Genre(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class AnimeSeries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    image_url = db.Column(db.String(500))
    episodes = db.relationship('AnimeEpisodes', backref='series', lazy=True, cascade="all, delete-orphan")
    genres = db.relationship('Genre', secondary=anime_genres, lazy='subquery', backref=db.backref('series', lazy=True))
    ratings = db.relationship('Rating', backref='series', lazy=True, cascade="all, delete-orphan")

class AnimeEpisodes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    series_id = db.Column(db.Integer, db.ForeignKey('anime_series.id'), nullable=False)
    watch_history = db.relationship('WatchHistory', backref='episode', lazy=True, cascade="all, delete-orphan")

class WatchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    episode_id = db.Column(db.Integer, db.ForeignKey('anime_episodes.id'), nullable=False)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    series_id = db.Column(db.Integer, db.ForeignKey('anime_series.id'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)

class WatchParty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_code = db.Column(db.String(8), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    leader_sid = db.Column(db.String(100), nullable=False)
    video_title = db.Column(db.String(200), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)

# --- (Other models like Videos and Passwords remain the same) ---
class Videos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)

class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)

# --- Encryption ---
key_str = os.getenv('FERNET_KEY')
if not key_str: key_str = Fernet.generate_key().decode()
fernet = Fernet(key_str.encode())

def encrypt_data(data): return fernet.encrypt(data.encode()).decode()
def decrypt_data(encrypted_data): return fernet.decrypt(encrypted_data.encode()).decode()

# --- User Access & Helper Functions ---
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def master_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_master'):
            flash("You must be an administrator to access this page.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route("/")
def index():
    return redirect(url_for('anime'))

# --- User Authentication Routes ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if 'user_id' in session: return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if username.lower() == ADMIN_USERNAME.lower():
            flash("This username is reserved for the administrator.", "danger")
            return render_template("register.html")
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.", "danger")
        else:
            new_user = User(username=username, password_hash=generate_password_hash(password), is_master=False)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! You can now log in.", "success")
            return redirect(url_for('login'))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session: return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter(func.lower(User.username) == func.lower(username)).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_master'] = user.is_master
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

# --- Main Page Routes ---
@app.route("/anime")
def anime():
    query = request.args.get('query', '')
    genre_filter = request.args.get('genre', '')
    
    series_query = AnimeSeries.query
    
    if query:
        series_query = series_query.filter(AnimeSeries.title.ilike(f'%{query}%'))
    
    if genre_filter:
        series_query = series_query.join(anime_genres).join(Genre).filter(Genre.name == genre_filter)

    series_list = series_query.order_by(AnimeSeries.title).all()
    genres = Genre.query.order_by(Genre.name).all()
    
    # Calculate average ratings
    series_with_ratings = []
    for series in series_list:
        avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.series_id == series.id).scalar() or 0
        series_with_ratings.append({'series': series, 'avg_rating': round(avg_rating, 1)})

    return render_template("anime.html", series_list_with_ratings=series_with_ratings, genres=genres, query=query, genre_filter=genre_filter)

@app.route("/anime/series/<int:series_id>")
def anime_series_details(series_id):
    series = AnimeSeries.query.get_or_404(series_id)
    avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.series_id == series.id).scalar() or 0
    
    user_rating = None
    if 'user_id' in session:
        rating = Rating.query.filter_by(user_id=session['user_id'], series_id=series.id).first()
        if rating:
            user_rating = rating.stars
            
    return render_template("anime_details.html", series=series, episodes=series.episodes, avg_rating=round(avg_rating, 1), user_rating=user_rating)

# --- (Other page routes like /videos and /files remain the same) ---
@app.route("/files")
def files():
    file_list = []
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        file_list = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template("files.html", files=file_list)

@app.route("/videos")
def videos():
    video_list = Videos.query.order_by(Videos.title).all()
    return render_template("videos.html", videos=video_list)

# --- API-like routes for new features ---
@app.route("/api/rate_series/<int:series_id>", methods=["POST"])
@login_required
def rate_series(series_id):
    stars = int(request.form.get('stars'))
    if not 1 <= stars <= 5:
        return jsonify({'error': 'Invalid rating'}), 400
        
    rating = Rating.query.filter_by(user_id=session['user_id'], series_id=series_id).first()
    if rating:
        rating.stars = stars
    else:
        new_rating = Rating(user_id=session['user_id'], series_id=series_id, stars=stars)
        db.session.add(new_rating)
    db.session.commit()
    
    avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.series_id == series_id).scalar() or 0
    return jsonify({'success': True, 'new_avg_rating': round(avg_rating, 1)})

@app.route("/api/watch_history/add", methods=["POST"])
@login_required
def add_to_watch_history():
    episode_id = request.json.get('episode_id')
    if not episode_id:
        return jsonify({'error': 'Missing episode ID'}), 400
    
    existing = WatchHistory.query.filter_by(user_id=session['user_id'], episode_id=episode_id).first()
    if not existing:
        new_history = WatchHistory(user_id=session['user_id'], episode_id=episode_id)
        db.session.add(new_history)
        db.session.commit()
    
    return jsonify({'success': True})

# --- (All other routes for watch together, vault, and admin actions remain largely the same) ---
# ...

# --- Create database and admin user if they don't exist ---
with app.app_context():
    db.create_all()
    if ADMIN_PASSWORD and not User.query.filter_by(username=ADMIN_USERNAME).first():
        admin_user = User(username=ADMIN_USERNAME, password_hash=generate_password_hash(ADMIN_PASSWORD), is_master=True)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{ADMIN_USERNAME}' created.")

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)
