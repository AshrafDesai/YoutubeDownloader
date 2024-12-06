import os, sys, uuid, time, json, logging, threading, webbrowser, subprocess
from pathlib import Path
import yt_dlp
from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session
import re
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY='123123',
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='',
    MAIL_PASSWORD='',
    TEMPLATES_AUTO_RELOAD=False
)

db = SQLAlchemy(app)
mail = Mail(app)
download_sessions = {}
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_DOWNLOAD_DIR = os.path.join(os.path.expanduser('~'), 'Downloads', 'YouTubeDownloader')
active_downloads = {}
progress_data = {}
download_status = {}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

SUPPORTED_FORMATS = {
    'video': [
        {'height': 2160, 'label': '4K', 'format': 'mp4'},
        {'height': 1440, 'label': '1440p', 'format': 'mp4'},
        {'height': 1080, 'label': '1080p', 'format': 'mp4'},
        {'height': 720, 'label': '720p', 'format': 'mp4'},
        {'height': 480, 'label': '480p', 'format': 'mp4'},
        {'height': 360, 'label': '360p', 'format': 'mp4'}
    ],
    'audio': [
        {'quality': '320', 'label': 'High Quality (320kbps)', 'format': 'mp3'},
        {'quality': '256', 'label': 'Good Quality (256kbps)', 'format': 'mp3'},
        {'quality': '192', 'label': 'Medium Quality (192kbps)', 'format': 'mp3'},
        {'quality': '128', 'label': 'Normal Quality (128kbps)', 'format': 'mp3'},
        {'quality': '96', 'label': 'Low Quality (96kbps)', 'format': 'mp3'},
        {'quality': '64', 'label': 'Very Low Quality (64kbps)', 'format': 'mp3'}
    ],
    'playlist': [
        {'height': 2160, 'label': '4K', 'format': 'mp4'},
        {'height': 1440, 'label': '1440p', 'format': 'mp4'},
        {'height': 1080, 'label': '1080p', 'format': 'mp4'},
        {'height': 720, 'label': '720p', 'format': 'mp4'},
        {'height': 480, 'label': '480p', 'format': 'mp4'},
        {'height': 360, 'label': '360p', 'format': 'mp4'}
    ]
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class DownloadProgress:
    def __init__(self, session_id):
        self.session_id = session_id
        self.status = 'initializing'
        self.progress = 0
        self.speed = '0 KB/s'
        self.eta = 'Unknown'
        self.filename = ''
        self.total_bytes = 0
        self.downloaded_bytes = 0
        self.current_item = 1
        self.total_items = 1
        self.error = None
        self.completed = False
        self.playlist_status = ''
        self.playlist_name = ''
        self.paused = False

    def to_dict(self):
        return {
            'status': self.status, 'progress': self.progress,
            'speed': self.speed, 'eta': self.eta,
            'filename': self.filename, 'total_bytes': self.total_bytes,
            'downloaded_bytes': self.downloaded_bytes,
            'current_item': self.current_item, 'total_items': self.total_items,
            'error': self.error, 'completed': self.completed,
            'playlist_status': self.playlist_status,
            'playlist_name': self.playlist_name, 'paused': self.paused
        }

FFMPEG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                          'ffmpeg-2024-11-18-git-970d57988d-full_build', 
                          'bin', 'ffmpeg.exe')

def setup_yt_dlp():
    """Setup yt-dlp and verify FFmpeg"""
    try:
        # Update yt-dlp
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "yt-dlp"],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Check FFmpeg
        if not os.path.exists(FFMPEG_PATH):
            logger.error(f"FFmpeg not found at {FFMPEG_PATH}")
            return False
            
        # Test FFmpeg with full path
        try:
            result = subprocess.run([FFMPEG_PATH, '-version'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  shell=True)  # Add shell=True for Windows
            if result.returncode == 0:
                logger.info("FFmpeg found successfully!")
                return FFMPEG_PATH
            else:
                logger.error(f"FFmpeg test failed with return code: {result.returncode}")
                return False
        except Exception as e:
            logger.error(f"FFmpeg test failed: {str(e)}")
            return False

    except Exception as e:
        logger.error(f"Setup error: {str(e)}")
        return False

def sanitize_filename(filename):
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    filename = filename.strip('. ')
    filename = filename.replace(' ', '_')
    return filename[:255] if len(filename) > 255 else filename

def format_bytes_speed(bytes_per_second):
    if not bytes_per_second:
        return '0 B/s'
    
    # Convert to float if it's a string
    try:
        bytes_per_second = float(bytes_per_second)
    except (TypeError, ValueError):
        return '0 B/s'
    
    # Define units and their thresholds
    units = [
        (1024 ** 3, 'GB/s'),
        (1024 ** 2, 'MB/s'),
        (1024, 'KB/s'),
        (1, 'B/s')
    ]
    
    # Find appropriate unit
    for factor, unit in units:
        if bytes_per_second >= factor:
            speed = bytes_per_second / factor
            # Format with 2 decimal places if >= 1, 1 decimal place if < 1
            if speed >= 1:
                return f"{speed:.2f} {unit}"
            else:
                return f"{speed:.1f} {unit}"
    
    return '0 B/s'

def update_progress(d, session_id):
    if session_id not in progress_data:
        return
    progress = progress_data[session_id]
    
    while download_status.get(session_id, {}).get('paused', False):
        progress.status = 'paused'
        time.sleep(0.5)
    
    if d['status'] == 'downloading':
        progress.status = 'downloading'
        progress.filename = os.path.basename(d.get('filename', ''))
        progress.downloaded_bytes = d.get('downloaded_bytes', 0)
        progress.total_bytes = d.get('total_bytes', 0)
        if progress.total_bytes:
            progress.progress = (progress.downloaded_bytes / progress.total_bytes) * 100
        progress.speed = format_bytes_speed(d.get('speed', 0))
        progress.eta = str(d.get('eta', 'Unknown'))

        # Add playlist status
        if 'info_dict' in d and d['info_dict'].get('playlist_count'):
            current_index = d['info_dict'].get('playlist_index', 1)
            total_count = d['info_dict']['playlist_count']
            progress.playlist_status = f"[download] Downloading item {current_index} of {total_count}"
            progress.current_item = current_index
            progress.total_items = total_count

    elif d['status'] == 'finished':
        if progress.current_item >= progress.total_items:
            progress.status = 'completed'
            progress.progress = 100
            progress.completed = True
        else:
            progress.current_item += 1

def get_formats(download_type):
    """Return available formats based on download type"""
    if download_type == 'video':
        return [
            {'label': '4K', 'height': 2160, 'format': 'mp4'},
            {'label': '1080p', 'height': 1080, 'format': 'mp4'},
            {'label': '720p', 'height': 720, 'format': 'mp4'},
            {'label': '480p', 'height': 480, 'format': 'mp4'},
            {'label': '360p', 'height': 360, 'format': 'mp4'}
        ]
    elif download_type == 'audio':
        return [
            {'label': 'High Quality', 'quality': 0, 'format': 'mp3'},
            {'label': 'Medium Quality', 'quality': 5, 'format': 'mp3'},
            {'label': 'Low Quality', 'quality': 9, 'format': 'mp3'}
        ]
    else:  # playlist
        return [
            {'label': 'Best Quality', 'quality': 'best', 'format': 'mp4'},
            {'label': 'Medium Quality', 'quality': 'medium', 'format': 'mp4'},
            {'label': 'Audio Only', 'quality': 'audio', 'format': 'mp3'}
        ]

def process_download(session_id, session_data):
    """Process the download in background"""
    try:
        def progress_hook(d):
            if d['status'] == 'downloading':
                total = d.get('total_bytes', 0)
                downloaded = d.get('downloaded_bytes', 0)
                if total > 0:
                    progress = (downloaded / total) * 100
                else:
                    progress = 0
                
                session_data.update({
                    'status': 'downloading',
                    'progress': progress,
                    'speed': d.get('speed', 0),
                    'eta': d.get('eta', 'Unknown'),
                    'filename': d.get('filename', ''),
                    'total_bytes': total
                })

            elif d['status'] == 'finished':
                session_data['status'] = 'processing'
                
            elif d['status'] == 'error':
                session_data['status'] = 'error'
                session_data['error'] = d.get('error', 'Unknown error occurred')

        ydl_opts = {
            'format': 'bestvideo[height<=?{}]+bestaudio/best'.format(
                session_data['format_data'].get('height', 720)
            ) if session_data['type'] == 'video' else 'bestaudio/best',
            'progress_hooks': [progress_hook],
            'outtmpl': os.path.join(session_data['download_path'], '%(title)s.%(ext)s'),
            'ffmpeg_location': FFMPEG_PATH
        }

        if session_data['type'] == 'audio':
            ydl_opts.update({
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': str(session_data['format_data'].get('quality', '0'))
                }]
            })

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([session_data['url']])
            
        session_data['status'] = 'completed'
        session_data['progress'] = 100

    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        session_data['status'] = 'error'
        session_data['error'] = str(e)
    finally:
        # Clean up session after 5 seconds
        threading.Timer(5.0, lambda: download_sessions.pop(session_id, None)).start()

def start_download(url, ydl_opts, session_id):
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
        if session_id in progress_data:
            progress_data[session_id].status = 'completed'
            progress_data[session_id].progress = 100
            progress_data[session_id].completed = True
    except Exception as e:
        logger.error(f"Error during download: {str(e)}")
        if session_id in progress_data:
            progress_data[session_id].status = 'error'
            progress_data[session_id].error = str(e)


def initialize_download(url, download_type, quality, custom_path=None, playlist_info=None):
    session_id = str(uuid.uuid4())
    progress_data[session_id] = DownloadProgress(session_id)
    download_status[session_id] = {'paused': False}

    # Set base directory
    base_dir = custom_path if custom_path else DEFAULT_DOWNLOAD_DIR
    os.makedirs(base_dir, exist_ok=True)

    # Determine download directory and format
    if playlist_info and download_type == 'playlist':
        playlist_name = sanitize_filename(playlist_info.get('title', 'playlist'))
        download_dir = os.path.join(base_dir, playlist_name)
        os.makedirs(download_dir, exist_ok=True)
        progress_data[session_id].playlist_name = playlist_name
        progress_data[session_id].total_items = playlist_info.get('count', 1)
    else:
        download_dir = base_dir

    # Configure format based on download type
    if download_type == 'audio':
        format_spec = 'bestaudio/best'
        postprocessors = [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': 'mp3',
            'preferredquality': '192'  # Default to 192kbps for audio
        }]
    else:  # video or playlist
        if quality == 'best':
            format_spec = 'bestvideo+bestaudio/best'
        else:
            try:
                # Convert quality string to integer height
                height = int(quality) if quality.isdigit() else 720  # default to 720p
                format_spec = f'bestvideo[height<={height}]+bestaudio/best[height<={height}]'
            except (ValueError, AttributeError):
                format_spec = 'bestvideo[height<=720]+bestaudio/best'  # fallback to 720p

        postprocessors = []

    # Configure yt-dlp options
    ydl_opts = {
        'format': format_spec,
        'outtmpl': os.path.join(download_dir, '%(title)s.%(ext)s'),
        'progress_hooks': [lambda d: update_progress(d, session_id)],
        'postprocessors': postprocessors,
        'quiet': True,
        'no_warnings': True,
        'ignoreerrors': True,
        'extract_flat': False,
        'force_generic_extractor': False,
        'nocheckcertificate': True,
        'ffmpeg_location': FFMPEG_PATH
    }

    # Store download information
    active_downloads[session_id] = {
        'url': url,
        'ydl_opts': ydl_opts,
        'download_dir': download_dir
    }

    # Start download in background thread
    threading.Thread(target=start_download, args=(url, ydl_opts, session_id)).start()
    return session_id

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/thank-you')
@login_required
def thank_you():
    return render_template('thank_you.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        data = request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        otp_code = ''.join(random.choices('0123456789', k=6))
        new_otp = OTP(email=email, otp=otp_code)
        
        db.session.add(new_user)
        db.session.add(new_otp)
        db.session.commit()

        msg = Message('Email Verification',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[email])
        msg.body = f'Your verification code is: {otp_code}'
        mail.send(msg)

        return jsonify({
            'message': 'Registration successful! Please check your email for verification code.',
            'email': email
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/verify-email')
def verify_email():
    """Handle email verification page"""
    email = request.args.get('email')
    if not email:
        return redirect(url_for('register'))
    
    return render_template('verify.html', email=email)

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        otp_code = data.get('otp')

        otp_record = OTP.query.filter_by(email=email)\
            .order_by(OTP.created_at.desc())\
            .first()

        if not otp_record:
            return jsonify({'error': 'No OTP found for this email'}), 400

        current_time = datetime.now(timezone.utc)
        otp_time = otp_record.created_at
        
        if otp_time.tzinfo is None:
            otp_time = otp_time.replace(tzinfo=timezone.utc)
            
        if current_time - otp_time > timedelta(minutes=15):
            return jsonify({'error': 'OTP has expired'}), 400

        if otp_record.otp != otp_code:
            return jsonify({'error': 'Invalid OTP'}), 400

        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({
                'message': 'Email verified successfully! Please login to continue.',
                'redirect': '/login'
            })
        
        return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    try:
        data = request.form
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 400
            
        if not user.is_verified:
            return jsonify({'error': 'Please verify your email first'}), 400
            
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return jsonify({
                'message': 'Login successful!',
                'redirect': '/downloader'
            })
        
        return jsonify({'error': 'Invalid email or password'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/downloader')
@login_required
def downloader():
    return render_template('downloader.html')

@app.route('/get-info', methods=['POST'])
@login_required
def get_info():
    try:
        data = request.get_json()
        url = data.get('url')
        download_type = data.get('type', 'video')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': True if download_type == 'playlist' else False
        }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            
            if not info:
                return jsonify({'error': 'Could not extract video information'}), 400

            # Handle playlist
            if 'entries' in info:
                entries = list(info.get('entries', []))
                if not entries:
                    return jsonify({'error': 'No videos found in playlist'}), 400
                
                response_data = {
                    'title': info.get('title', 'Unknown Playlist'),
                    'thumbnail': entries[0].get('thumbnail', '') if entries else '',
                    'is_playlist': True,
                    'playlist_count': len(entries),
                    'duration': sum(entry.get('duration', 0) for entry in entries if entry.get('duration')),
                    'available_formats': get_formats(download_type)
                }
            else:
                # Handle single video
                response_data = {
                    'title': info.get('title', 'Unknown Title'),
                    'thumbnail': info.get('thumbnail', ''),
                    'duration': info.get('duration', 0),
                    'is_playlist': False,
                    'available_formats': get_formats(download_type)
                }

            return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error in get_info: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/initialize-download', methods=['POST'])
@login_required
def handle_download_init():
    try:
        data = request.get_json()
        url = data.get('url')
        download_type = data.get('type')
        format_data = data.get('format_data', {})
        
        # Extract quality from format_data
        if download_type == 'audio':
            quality = format_data.get('quality', '192')
        else:
            quality = str(format_data.get('height', '720'))
        
        custom_path = data.get('custom_path')
        
        # Get playlist info if it's a playlist
        playlist_info = None
        if download_type == 'playlist':
            playlist_info = {
                'title': data.get('title', 'playlist'),
                'count': data.get('playlist_count', 0)
            }

        session_id = initialize_download(
            url=url,
            download_type=download_type,
            quality=quality,
            custom_path=custom_path,
            playlist_info=playlist_info
        )

        return jsonify({'session_id': session_id})

    except Exception as e:
        logger.error(f"Error initializing download: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/download-progress/<session_id>')
@login_required
def download_progress(session_id):
    def generate():
        try:
            while True:
                if session_id not in progress_data:
                    break
                    
                progress = progress_data[session_id]
                data = progress.to_dict()
                
                yield f"data: {json.dumps(data)}\n\n"
                
                if progress.completed or progress.error:
                    break
                    
                time.sleep(0.5)
                
        except GeneratorExit:
            logger.info(f"Client disconnected from progress updates for session {session_id}")
        except Exception as e:
            logger.error(f"Error in progress updates: {str(e)}")
        finally:
            # Cleanup if the connection is closed
            if session_id in progress_data and (
                progress_data[session_id].completed or 
                progress_data[session_id].error
            ):
                progress_data.pop(session_id, None)
                active_downloads.pop(session_id, None)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )

@app.route('/pause-download/<session_id>', methods=['POST'])
@login_required
def pause_download(session_id):
    if session_id in download_sessions:
        download_sessions[session_id]['paused'] = True
        return jsonify({'success': True})
    return jsonify({'error': 'Download session not found'}), 404

@app.route('/resume-download/<session_id>', methods=['POST'])
@login_required
def resume_download(session_id):
    if session_id in download_sessions:
        download_sessions[session_id]['paused'] = False
        return jsonify({'success': True})
    return jsonify({'error': 'Download session not found'}), 404



@app.route('/cleanup', methods=['POST'])
@login_required
def cleanup():
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        if session_id in download_sessions:
            del download_sessions[session_id]
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error in cleanup: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/exit', methods=['POST'])
@login_required
def exit_app():
    try:
        # Clean up any active downloads
        user_sessions = [sid for sid, data in download_sessions.items() 
                        if data.get('user_id') == current_user.id]
        
        for session_id in user_sessions:
            if session_id in download_sessions:
                del download_sessions[session_id]
        
        # Log the user out
        logout_user()
        
        return jsonify({
            'success': True,
            'redirect': url_for('thank_you')
        })
    except Exception as e:
        logger.error(f"Error during exit: {str(e)}")
        return jsonify({'error': str(e)}), 500
def open_browser():
    time.sleep(1.5)
    webbrowser.open('http://127.0.0.1:5000')

def main():
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database initialized successfully")

        os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)
        logger.info(f"Default download folder: {DEFAULT_DOWNLOAD_DIR}")

        ffmpeg_path = setup_yt_dlp()
        if not ffmpeg_path:
            logger.error("Failed to setup FFmpeg. Please check the installation.")
            sys.exit(1)

        logger.info("Starting server...")
        threading.Thread(target=open_browser, daemon=True).start()
        app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

    except Exception as e:
        logger.error(f"Startup error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
