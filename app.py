import os
import sqlite3
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# --- Initialization ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
DB_FOLDER = 'vault'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DB_FOLDER'] = DB_FOLDER

# --- Create Application Directories ---
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DB_FOLDER'], exist_ok=True)

# --- Password Management ---
MASTER_PASSWORD_HASH = os.getenv('MASTER_PASSWORD_HASH')
VIEWER_PASSWORD_HASH = os.getenv('VIEWER_PASSWORD_HASH')

def generate_hashes_if_needed():
    if not MASTER_PASSWORD_HASH:
        master_pass = secrets.token_urlsafe(16)
        print("--- SETUP REQUIRED ---")
        print(f"No MASTER_PASSWORD_HASH found in .env file.")
        print(f"To get started, add the following lines to your .env file:")
        print(f"MASTER_PASSWORD_HASH='{generate_password_hash(master_pass)}'")
        print(f"# The password for the hash above is: {master_pass}")
        print("-" * 20)
    if not VIEWER_PASSWORD_HASH:
        viewer_pass = secrets.token_urlsafe(16)
        print("--- SETUP REQUIRED ---")
        print(f"No VIEWER_PASSWORD_HASH found in .env file.")
        print(f"To get started, add the following lines to your .env file:")
        print(f"VIEWER_PASSWORD_HASH='{generate_password_hash(viewer_pass)}'")
        print(f"# The password for the hash above is: {viewer_pass}")
        print("-" * 20)

# --- Database and Encryption ---
def get_db_connection():
    conn = sqlite3.connect(os.path.join(app.config['DB_FOLDER'], 'data.db'))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                encrypted_password TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                url TEXT NOT NULL
            );
        """)
        # New table for Anime Series
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anime_series (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL UNIQUE,
                image_url TEXT
            );
        """)
        # New table for Anime Episodes, linked to a series
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anime_episodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                series_id INTEGER NOT NULL,
                FOREIGN KEY (series_id) REFERENCES anime_series (id)
            );
        """)
        conn.commit()

def load_or_generate_key():
    key_path = os.path.join(app.config['DB_FOLDER'], 'secret.key')
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, 'wb') as f:
            f.write(key)
    else:
        with open(key_path, 'rb') as f:
            key = f.read()
    return key

key = load_or_generate_key()
fernet = Fernet(key)

def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return fernet.decrypt(encrypted_data.encode()).decode()

# --- User Access Control Decorators ---
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'level' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def master_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('level') != 'master':
            flash("You do not have permission to perform this action.", "danger")
            return redirect(url_for('files'))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---
@app.route("/", methods=["GET", "POST"])
def login():
    if 'level' in session:
        return redirect(url_for('files'))

    if request.method == "POST":
        password = request.form["password"]
        if MASTER_PASSWORD_HASH and check_password_hash(MASTER_PASSWORD_HASH, password):
            session['level'] = 'master'
            return redirect(url_for('files'))
        if VIEWER_PASSWORD_HASH and check_password_hash(VIEWER_PASSWORD_HASH, password):
            session['level'] = 'viewer'
            return redirect(url_for('files'))
        
        flash("Invalid password.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# --- Main Page Routes ---
@app.route("/files")
@login_required
def files():
    file_list = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template("files.html", files=file_list)

@app.route("/videos")
@login_required
def videos():
    with get_db_connection() as conn:
        video_list = conn.execute("SELECT id, title, url FROM videos ORDER BY title").fetchall()
    return render_template("videos.html", videos=video_list)

@app.route("/vault")
@master_required
def vault():
    passwords = []
    with get_db_connection() as conn:
        passwords_raw = conn.execute("SELECT id, name, encrypted_password FROM passwords ORDER BY name").fetchall()
    for p in passwords_raw:
        try:
            decrypted = decrypt_data(p['encrypted_password'])
            passwords.append({'id': p['id'], 'name': p['name'], 'password': decrypted})
        except Exception:
            passwords.append({'id': p['id'], 'name': p['name'], 'password': '*** DECRYPTION ERROR ***'})
    return render_template("vault.html", passwords=passwords)

# --- Anime Library Routes ---
@app.route("/anime")
@login_required
def anime():
    with get_db_connection() as conn:
        series_list = conn.execute("SELECT id, title, image_url FROM anime_series ORDER BY title").fetchall()
    return render_template("anime.html", series_list=series_list)

@app.route("/anime/series/<int:series_id>")
@login_required
def anime_series_details(series_id):
    with get_db_connection() as conn:
        series = conn.execute("SELECT id, title FROM anime_series WHERE id = ?", (series_id,)).fetchone()
        episodes = conn.execute("SELECT id, title, url FROM anime_episodes WHERE series_id = ? ORDER BY title", (series_id,)).fetchall()
    if series is None:
        return "Series not found", 404
    return render_template("anime_details.html", series=series, episodes=episodes)

@app.route("/anime/series/add", methods=["POST"])
@master_required
def add_anime_series():
    title = request.form['title']
    image_url = request.form['image_url']
    with get_db_connection() as conn:
        conn.execute("INSERT INTO anime_series (title, image_url) VALUES (?, ?)", (title, image_url))
        conn.commit()
    flash(f"Series '{title}' added successfully.", "success")
    return redirect(url_for("anime"))

@app.route("/anime/episode/add/<int:series_id>", methods=["POST"])
@master_required
def add_anime_episode(series_id):
    title = request.form['title']
    url = request.form['url']
    with get_db_connection() as conn:
        conn.execute("INSERT INTO anime_episodes (title, url, series_id) VALUES (?, ?, ?)", (title, url, series_id))
        conn.commit()
    flash(f"Episode '{title}' added successfully.", "success")
    return redirect(url_for("anime_series_details", series_id=series_id))

@app.route("/anime/series/delete/<int:id>", methods=["POST"])
@master_required
def delete_anime_series(id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM anime_episodes WHERE series_id = ?", (id,))
        conn.execute("DELETE FROM anime_series WHERE id = ?", (id,))
        conn.commit()
    flash("Series and all its episodes have been deleted.", "success")
    return redirect(url_for("anime"))

@app.route("/anime/episode/delete/<int:id>", methods=["POST"])
@master_required
def delete_anime_episode(id):
    # Get series_id before deleting to redirect correctly
    with get_db_connection() as conn:
        episode = conn.execute("SELECT series_id FROM anime_episodes WHERE id = ?", (id,)).fetchone()
        if episode:
            series_id = episode['series_id']
            conn.execute("DELETE FROM anime_episodes WHERE id = ?", (id,))
            conn.commit()
            flash("Episode deleted successfully.", "success")
            return redirect(url_for("anime_series_details", series_id=series_id))
    return redirect(url_for("anime"))

# --- (Other routes for files, videos, vault remain the same) ---

# --- Password Vault Actions ---
@app.route("/vault/add", methods=["POST"])
@master_required
def add_password():
    name = request.form['name']
    password = request.form['password']
    encrypted_password = encrypt_data(password)
    with get_db_connection() as conn:
        conn.execute("INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", (name, encrypted_password))
        conn.commit()
    flash(f"Password for '{name}' added successfully.", "success")
    return redirect(url_for("vault"))

@app.route("/vault/delete/<int:id>", methods=["POST"])
@master_required
def delete_password(id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM passwords WHERE id = ?", (id,))
        conn.commit()
    flash("Password deleted successfully.", "success")
    return redirect(url_for("vault"))

# --- File Manager Actions ---
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
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route("/delete/file/<filename>", methods=["POST"])
@master_required
def delete_file(filename):
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    flash(f"File '{filename}' deleted.", "success")
    return redirect(url_for("files"))

# --- Video URL Actions ---
@app.route("/videos/add", methods=["POST"])
@master_required
def add_video():
    title = request.form['title']
    url = request.form['url']
    with get_db_connection() as conn:
        conn.execute("INSERT INTO videos (title, url) VALUES (?, ?)", (title, url))
        conn.commit()
    flash(f"Video '{title}' added successfully.", "success")
    return redirect(url_for("videos"))

@app.route("/videos/delete/<int:id>", methods=["POST"])
@master_required
def delete_video(id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM videos WHERE id = ?", (id,))
        conn.commit()
    flash("Video deleted successfully.", "success")
    return redirect(url_for("videos"))

# --- Main Execution ---
if __name__ == "__main__":
    init_db()
    generate_hashes_if_needed()
    app.run(debug=True, port=5000)
