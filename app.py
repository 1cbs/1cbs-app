import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy

# --- Initialization ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Create Application Directories ---
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Password Management ---
MASTER_PASSWORD_HASH = os.getenv('MASTER_PASSWORD_HASH')

# --- Database Models ---
class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)

class Videos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)

class AnimeSeries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    image_url = db.Column(db.String(500))
    episodes = db.relationship('AnimeEpisodes', backref='series', lazy=True, cascade="all, delete-orphan")

class AnimeEpisodes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    series_id = db.Column(db.Integer, db.ForeignKey('anime_series.id'), nullable=False)

# --- Encryption ---
key_str = os.getenv('FERNET_KEY')
if not key_str:
    key_str = Fernet.generate_key().decode()
fernet = Fernet(key_str.encode())

def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return fernet.decrypt(encrypted_data.encode()).decode()

# --- User Access Control ---
from functools import wraps

@app.before_request
def set_default_access_level():
    # If the user isn't logged in as master, treat them as a viewer.
    if 'level' not in session:
        session['level'] = 'viewer'

def master_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('level') != 'master':
            flash("You must be an administrator to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route("/")
def index():
    # The homepage now redirects to the anime library
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if session['level'] == 'master':
        return redirect(url_for('anime'))

    if request.method == "POST":
        password = request.form["password"]
        if MASTER_PASSWORD_HASH and check_password_hash(MASTER_PASSWORD_HASH, password):
            session['level'] = 'master'
            flash("Login successful. You now have admin privileges.", "success")
            return redirect(url_for('anime'))
        else:
            flash("Invalid password.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    # Logging out resets the session to viewer
    session.pop('level', None)
    flash("You have been logged out.", "success")
    return redirect(url_for("anime"))

# --- Public Page Routes ---
@app.route("/files")
def files():
    file_list = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template("files.html", files=file_list)

@app.route("/videos")
def videos():
    video_list = Videos.query.order_by(Videos.title).all()
    return render_template("videos.html", videos=video_list)

@app.route("/anime")
def anime():
    series_list = AnimeSeries.query.order_by(AnimeSeries.title).all()
    return render_template("anime.html", series_list=series_list)

@app.route("/anime/series/<int:series_id>")
def anime_series_details(series_id):
    series = AnimeSeries.query.get_or_404(series_id)
    return render_template("anime_details.html", series=series, episodes=series.episodes)

# --- Master-Only Routes ---
@app.route("/vault")
@master_required
def vault():
    passwords_raw = Passwords.query.order_by(Passwords.name).all()
    passwords = []
    for p in passwords_raw:
        try:
            decrypted = decrypt_data(p.encrypted_password)
            passwords.append({'id': p.id, 'name': p.name, 'password': decrypted})
        except Exception:
            passwords.append({'id': p.id, 'name': p.name, 'password': '*** DECRYPTION ERROR ***'})
    return render_template("vault.html", passwords=passwords)

# --- All 'add' and 'delete' actions (all require master access) ---
@app.route("/vault/add", methods=["POST"])
@master_required
def add_password():
    new_password = Passwords(name=request.form['name'], encrypted_password=encrypt_data(request.form['password']))
    db.session.add(new_password)
    db.session.commit()
    flash(f"Password for '{request.form['name']}' added.", "success")
    return redirect(url_for("vault"))

@app.route("/vault/delete/<int:id>", methods=["POST"])
@master_required
def delete_password(id):
    password_to_delete = Passwords.query.get_or_404(id)
    db.session.delete(password_to_delete)
    db.session.commit()
    flash("Password deleted.", "success")
    return redirect(url_for("vault"))

@app.route("/upload/file", methods=["POST"])
@master_required
def upload_file():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({"success": f"File '{filename}' uploaded"}), 200

@app.route("/download/file/<filename>")
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route("/delete/file/<filename>", methods=["POST"])
@master_required
def delete_file(filename):
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    flash(f"File '{filename}' deleted.", "success")
    return redirect(url_for("files"))

@app.route("/videos/add", methods=["POST"])
@master_required
def add_video():
    new_video = Videos(title=request.form['title'], url=request.form['url'])
    db.session.add(new_video)
    db.session.commit()
    flash(f"Video '{request.form['title']}' added.", "success")
    return redirect(url_for("videos"))

@app.route("/videos/delete/<int:id>", methods=["POST"])
@master_required
def delete_video(id):
    video_to_delete = Videos.query.get_or_404(id)
    db.session.delete(video_to_delete)
    db.session.commit()
    flash("Video deleted.", "success")
    return redirect(url_for("videos"))

@app.route("/anime/series/add", methods=["POST"])
@master_required
def add_anime_series():
    new_series = AnimeSeries(title=request.form['title'], image_url=request.form['image_url'])
    db.session.add(new_series)
    db.session.commit()
    flash(f"Series '{request.form['title']}' added.", "success")
    return redirect(url_for("anime"))

@app.route("/anime/series/delete/<int:id>", methods=["POST"])
@master_required
def delete_anime_series(id):
    series_to_delete = AnimeSeries.query.get_or_404(id)
    db.session.delete(series_to_delete)
    db.session.commit()
    flash("Series and all its episodes deleted.", "success")
    return redirect(url_for("anime"))

@app.route("/anime/episode/add/<int:series_id>", methods=["POST"])
@master_required
def add_anime_episode(series_id):
    new_episode = AnimeEpisodes(title=request.form['title'], url=request.form['url'], series_id=series_id)
    db.session.add(new_episode)
    db.session.commit()
    flash(f"Episode '{request.form['title']}' added.", "success")
    return redirect(url_for("anime_series_details", series_id=series_id))

@app.route("/anime/episode/delete/<int:id>", methods=["POST"])
@master_required
def delete_anime_episode(id):
    episode_to_delete = AnimeEpisodes.query.get_or_404(id)
    series_id = episode_to_delete.series_id
    db.session.delete(episode_to_delete)
    db.session.commit()
    flash("Episode deleted.", "success")
    return redirect(url_for("anime_series_details", series_id=series_id))

# --- Create database tables if they don't exist ---
with app.app_context():
    db.create_all()
