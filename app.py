import os
import json
import hashlib
import random
import smtplib
import subprocess
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
import yt_dlp
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
from threading import Thread

app = Flask(__name__)
app.secret_key = '123123'

USER_DB = 'users.json'
FFMPEG_PATH = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"

# Initialize users.json if not exists
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w') as f:
        json.dump({}, f)
DOWNLOAD_HISTORY_DB = 'download_history.json'
if not os.path.exists(DOWNLOAD_HISTORY_DB):
    with open(DOWNLOAD_HISTORY_DB, 'w') as f:
        json.dump({}, f)

download_progress = {
    'percent': 0,
    'status': 'Not started',
    'title': '',
    'speed': '',
    'eta': '',
    'filename': ''
}

# --- Helper Functions ---
def send_otp(email):
    """Send OTP to user's email for verification."""
    otp = str(random.randint(100000, 999999))
    sender_email = "ashrafdesai6598@gmail.com"
    sender_password = "wtuf hyek gvmp opcs"  # Use App Password for Gmail
    subject = "OTP for Account Verification"
    body = f"Your OTP is {otp}. Use it to verify your account."

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
        return otp
    except Exception as e:
        print(f"Failed to send email: {e}")
        return None


def verify_user_credentials(username, password):
    """Verify login credentials."""
    with open(USER_DB, 'r') as f:
        users = json.load(f)
    user = users.get(username)
    if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
        return True
    return False


def save_user(username, email, password):
    """Save new user data to the database."""
    with open(USER_DB, 'r') as f:
        users = json.load(f)
    users[username] = {
        'email': email,
        'password': hashlib.sha256(password.encode()).hexdigest()
    }
    with open(USER_DB, 'w') as f:
        json.dump(users, f)

def get_video_info(url):
    """Get video information using yt-dlp."""
    try:
        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': True
        }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            return {
                'title': info.get('title', 'Unknown Title'),
                'duration': info.get('duration', 0),
                'thumbnail': info.get('thumbnail', ''),
                'uploader': info.get('uploader', 'Unknown'),
                'is_playlist': info.get('_type', 'video') == 'playlist',
                'playlist_count': len(info.get('entries', [])) if info.get('_type') == 'playlist' else 1
            }
    except Exception as e:
        print(f"Error fetching video info: {e}")
        return None

def save_download_history(username, video_info, download_type):
    """Save download history to database."""
    try:
        with open(DOWNLOAD_HISTORY_DB, 'r') as f:
            history = json.load(f)
        
        if username not in history:
            history[username] = []
        
        history[username].append({
            'title': video_info.get('title', 'Unknown'),
            'type': download_type,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'thumbnail': video_info.get('thumbnail', '')
        })
        
        with open(DOWNLOAD_HISTORY_DB, 'w') as f:
            json.dump(history, f)
    except Exception as e:
        print(f"Error saving history: {e}")

def get_download_history(username):
    """Get user's download history."""
    try:
        with open(DOWNLOAD_HISTORY_DB, 'r') as f:
            history = json.load(f)
        return history.get(username, [])
    except Exception:
        return []

def update_progress(percent, status, title='', speed='', eta=''):
    """Update download progress."""
    download_progress['percent'] = percent
    download_progress['status'] = status
    download_progress['title'] = title
    download_progress['speed'] = speed
    download_progress['eta'] = eta

def progress_hook(d):
    """Callback function for yt-dlp to update download progress"""
    if d['status'] == 'downloading':
        download_progress.update({
            'status': 'downloading',
            'filename': d.get('filename', ''),
            'percent': float(d.get('downloaded_bytes', 0) / d.get('total_bytes', 1) * 100),
            'speed': d.get('speed', 0),  # Speed in bytes/second
            'eta': d.get('eta', 0),      # ETA in seconds
            'downloaded_bytes': d.get('downloaded_bytes', 0),
            'total_bytes': d.get('total_bytes', 0)
        })
    elif d['status'] == 'finished':
        download_progress.update({
            'status': 'finished',
            'percent': 100
        })

def download_video(url, choice, download_path):
    """Download video or audio using yt-dlp."""
    ffmpeg_location = "--ffmpeg-location C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"
    
    commands = {
        1: f'yt-dlp {ffmpeg_location} --format "best[ext=mp4]" -o "{download_path}/%(title)s.%(ext)s" "{url}"',
        2: f'yt-dlp {ffmpeg_location} --yes-playlist --format "best[ext=mp4]" -o "{download_path}/%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" "{url}"',
        3: f'yt-dlp {ffmpeg_location} --extract-audio --audio-format mp3 -o "{download_path}/%(title)s.%(ext)s" "{url}"',
        4: f'yt-dlp {ffmpeg_location} --yes-playlist --extract-audio --audio-format mp3 -o "{download_path}/%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" "{url}"'
    }
    
    command = commands.get(choice)
    if not command:
        update_progress(0, "Invalid download option", '', '', '')
        return

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output and 'download' in output and '%' in output:
            try:
                percent = int(output.split()[1].replace('%', ''))
                update_progress(percent, 'Downloading...')
            except (ValueError, IndexError):
                continue
    
    stderr = process.stderr.read()
    if stderr:
        update_progress(0, 'Download Failed')
        print(f"Download Error: {stderr}")
    else:
        update_progress(100, 'Download Complete')

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        otp = send_otp(email)
        if otp:
            session['otp'] = otp
            session['email'] = email
            session['username'] = username
            return redirect(url_for('verify_otp'))
        flash("Error sending OTP. Try again.", "danger")
    return render_template('register.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        if request.form['otp'] == session.get('otp'):
            return redirect(url_for('set_password'))
        flash("Invalid OTP. Please try again.", "danger")
    return render_template('verify_otp.html')


@app.route('/set_password', methods=['GET', 'POST'])
def set_password():
    if request.method == 'POST':
        password = request.form['password']
        save_user(session['username'], session['email'], password)
        session.clear()
        flash("Account created successfully!", "success")
        return redirect(url_for('login'))
    return render_template('set_password.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_user_credentials(username, password):
            session['username'] = username
            return redirect(url_for('download'))
        flash("Invalid credentials. Try again.", "danger")
    return render_template('login.html')

@app.route('/download', methods=['GET', 'POST'])
def download():
    try:
        url = request.form.get('url')
        download_type = request.form.get('choice')
        quality = request.form.get('quality')
        path = request.form.get('path', 'downloads')

        # Reset progress
        global download_progress
        download_progress = {
            'status': 'Not started',
            'percent': 0,
            'speed': 0,
            'eta': 0,
            'filename': '',
            'downloaded_bytes': 0,
            'total_bytes': 0
        }

        # Create downloads directory if it doesn't exist
        if not os.path.exists(path):
            os.makedirs(path)

        ydl_opts = {
            'format': quality if quality != 'best' else 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best',
            'progress_hooks': [progress_hook],
            'outtmpl': f'{path}/%(title)s.%(ext)s'
        }

        # Start download in a separate thread
        thread = Thread(target=start_download, args=(url, ydl_opts))
        thread.daemon = True
        thread.start()

        return jsonify({'status': 'Download started'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get-video-info', methods=['POST'])
def get_video_info_route():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': 'in_playlist'
        }
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            
            video_info = {
                'title': info.get('title', 'Unknown Title'),
                'thumbnail': info.get('thumbnail', ''),
                'channel': info.get('uploader', 'Unknown Channel'),
                'duration': str(info.get('duration', 0)),
                'views': str(info.get('view_count', 0)),
                'description': info.get('description', ''),
                'is_playlist': info.get('_type') == 'playlist',
                'playlist_count': len(info.get('entries', [])) if info.get('_type') == 'playlist' else 0
            }
            
            return jsonify(video_info)

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/download-progress')
def download_progress_route():
    def generate():
        while True:
            data = {
                'status': download_progress['status'],
                'percent': round(download_progress['percent'], 1),
                'speed': format_speed(download_progress['speed']),
                'eta': format_eta(download_progress['eta']),
                'filename': download_progress['filename'],
                'downloaded': download_progress['downloaded_bytes'],
                'total': download_progress['total_bytes']
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)
            if download_progress['status'] == 'finished':
                break
    return Response(generate(), mimetype='text/event-stream')

def progress_hook(d):
    if d['status'] == 'downloading':
        download_progress.update({
            'status': 'downloading',
            'filename': d.get('filename', ''),
            'percent': float(d.get('downloaded_bytes', 0) / d.get('total_bytes', 1) * 100),
            'speed': d.get('speed', 0),
            'eta': d.get('eta', 0),
            'downloaded_bytes': d.get('downloaded_bytes', 0),
            'total_bytes': d.get('total_bytes', 0)
        })
    elif d['status'] == 'finished':
        download_progress.update({
            'status': 'finished',
            'percent': 100
        })

def start_download(url, ydl_opts):
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
    except Exception as e:
        download_progress['status'] = f'Error: {str(e)}'


def format_speed(speed):
    """Format speed in bytes/second to human readable format"""
    if not speed:
        return "0 B/s"
    units = ['B/s', 'KB/s', 'MB/s', 'GB/s']
    unit_index = 0
    while speed >= 1024 and unit_index < len(units) - 1:
        speed /= 1024
        unit_index += 1
    return f"{speed:.1f} {units[unit_index]}"

def format_eta(eta):
    """Format ETA seconds to human readable format"""
    if not eta:
        return "Calculating..."
    if eta == float('inf'):
        return "Unknown"
    
    hours = eta // 3600
    minutes = (eta % 3600) // 60
    seconds = eta % 60
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
