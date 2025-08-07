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
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD') # Plain text password from Render

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_master = db.Column(db.Boolean, default=False, nullable=False)
    parties = db.relationship('WatchParty', backref='leader', lazy=True, cascade="all, delete-orphan")

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

class WatchParty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_code = db.Column(db.String(8), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    leader_sid = db.Column(db.String(100), nullable=False)
    video_title = db.Column(db.String(200), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)

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
            flash("Username already exists. Please choose a different one.", "danger")
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
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_master'] = user.is_master
            if user.is_master:
                flash("Administrator login successful.", "success")
            else:
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

# --- (All other page routes remain the same) ---
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

@app.route("/anime")
def anime():
    series_list = AnimeSeries.query.order_by(AnimeSeries.title).all()
    return render_template("anime.html", series_list=series_list)

@app.route("/anime/series/<int:series_id>")
def anime_series_details(series_id):
    series = AnimeSeries.query.get_or_404(series_id)
    return render_template("anime_details.html", series=series, episodes=series.episodes)

@app.route("/watch-together")
@login_required
def watch_together_lobby():
    parties = WatchParty.query.join(User).add_columns(WatchParty.room_code, WatchParty.video_title, User.username.label("leader_username")).all()
    videos = Videos.query.order_by(Videos.title).all()
    anime_episodes = AnimeEpisodes.query.join(AnimeSeries).order_by(AnimeSeries.title, AnimeEpisodes.title).all()
    return render_template("watch_together_lobby.html", parties=parties, videos=videos, anime_episodes=anime_episodes)

def generate_room_code(length=6):
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))

@app.route("/watch-together/create", methods=["POST"])
@login_required
def create_watch_party():
    video_selection = request.form.get('video_selection')
    if not video_selection:
        flash("You must select a video to watch.", "danger")
        return redirect(url_for('watch_together_lobby'))
    video_type, video_id = video_selection.split('-')
    video_id = int(video_id)
    video = None
    if video_type == 'anime': video = AnimeEpisodes.query.get(video_id)
    elif video_type == 'video': video = Videos.query.get(video_id)
    if not video:
        flash("Could not find the selected video.", "danger")
        return redirect(url_for('anime'))
    room_code = generate_room_code()
    session['party_info'] = {'room_code': room_code, 'video_title': video.title, 'video_url': video.url}
    return redirect(url_for('watch_together_room', room_code=room_code))

@app.route("/watch-together/join", methods=["POST"])
@login_required
def join_watch_party():
    room_code = request.form.get('room_code').upper()
    party = WatchParty.query.filter_by(room_code=room_code).first()
    if party:
        session['party_info'] = {'room_code': room_code, 'video_title': party.video_title, 'video_url': party.video_url}
        return redirect(url_for('watch_together_room', room_code=room_code))
    else:
        flash("Invalid party code.", "danger")
        return redirect(url_for('watch_together_lobby'))

@app.route("/watch-together/room/<room_code>")
@login_required
def watch_together_room(room_code):
    party_info = session.get('party_info')
    if not party_info or party_info['room_code'] != room_code:
        return redirect(url_for('watch_together_lobby'))
    return render_template("watch_together_room.html", party=party_info)

# --- Socket.IO Event Handlers ---
@socketio.on('join')
def on_join(data):
    room_code = data['room_code']
    username = session.get('username', 'A guest')
    join_room(room_code)
    party = WatchParty.query.filter_by(room_code=room_code).first()
    leader_sid = None
    if not party: # First person to join becomes the leader
        party_info = session.get('party_info')
        new_party = WatchParty(room_code=room_code, leader_id=session['user_id'], leader_sid=request.sid, video_title=party_info['video_title'], video_url=party_info['video_url'])
        db.session.add(new_party)
        db.session.commit()
        leader_sid = request.sid
    else:
        leader_sid = party.leader_sid
    emit('status', {'msg': f'{username} has joined the room.', 'leader_sid': leader_sid}, room=room_code)

@socketio.on('player_event')
def handle_player_event(data):
    room_code = data['room_code']
    party = WatchParty.query.filter_by(room_code=room_code).first()
    if party and party.leader_sid == request.sid: # Only leader can control
        emit('player_control', data, room=room_code, include_self=False)

@socketio.on('chat_message')
def handle_chat_message(data):
    room_code = data['room_code']
    emit('new_chat_message', {'username': session.get('username'), 'message': data['message']}, room=room_code)

@socketio.on('disconnect')
def on_disconnect():
    party = WatchParty.query.filter_by(leader_sid=request.sid).first()
    if party:
        emit('status', {'msg': f'The party leader ({party.leader.username}) has disconnected. The party has ended.'}, room=party.room_code)
        db.session.delete(party)
        db.session.commit()

# --- Admin & Master-Only Routes/Actions ---
@app.route("/vault")
@master_required
def vault():
    passwords_raw = Passwords.query.order_by(Passwords.name).all()
    passwords = []
    for p in passwords_raw:
        try: decrypted = decrypt_data(p.encrypted_password)
        except: decrypted = '*** DECRYPTION ERROR ***'
        passwords.append({'id': p.id, 'name': p.name, 'password': decrypted})
    return render_template("vault.html", passwords=passwords)

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
    db.session.delete(Passwords.query.get_or_404(id))
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
    db.session.add(Videos(title=request.form['title'], url=request.form['url']))
    db.session.commit()
    flash(f"Video '{request.form['title']}' added.", "success")
    return redirect(url_for("videos"))

@app.route("/videos/delete/<int:id>", methods=["POST"])
@master_required
def delete_video(id):
    db.session.delete(Videos.query.get_or_404(id))
    db.session.commit()
    flash("Video deleted.", "success")
    return redirect(url_for("videos"))

@app.route("/anime/series/add", methods=["POST"])
@master_required
def add_anime_series():
    new_series = AnimeSeries(title=request.form.get('title'), image_url=request.form.get('image_url'))
    db.session.add(new_series)
    db.session.commit()
    flash(f"Series '{request.form.get('title')}' added.", "success")
    return redirect(url_for("anime"))

@app.route("/anime/series/delete/<int:id>", methods=["POST"])
@master_required
def delete_anime_series(id):
    db.session.delete(AnimeSeries.query.get_or_404(id))
    db.session.commit()
    flash("Series and all its episodes deleted.", "success")
    return redirect(url_for("anime"))

@app.route("/anime/episode/add/<int:series_id>", methods=["POST"])
@master_required
def add_anime_episode(series_id):
    db.session.add(AnimeEpisodes(title=request.form['title'], url=request.form['url'], series_id=series_id))
    db.session.commit()
    flash(f"Episode '{request.form['title']}' added.", "success")
    return redirect(url_for("anime_series_details", series_id=series_id))

@app.route("/anime/episode/delete/<int:id>", methods=["POST"])
@master_required
def delete_anime_episode(id):
    episode = AnimeEpisodes.query.get_or_404(id)
    series_id = episode.series_id
    db.session.delete(episode)
    db.session.commit()
    flash("Episode deleted.", "success")
    return redirect(url_for("anime_series_details", series_id=series_id))

# --- Create database and admin user if they don't exist ---
with app.app_context():
    db.create_all()
    if ADMIN_PASSWORD and not User.query.filter_by(username=ADMIN_USERNAME).first():
        admin_user = User(
            username=ADMIN_USERNAME,
            password_hash=generate_password_hash(ADMIN_PASSWORD),
            is_master=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{ADMIN_USERNAME}' created.")

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)
