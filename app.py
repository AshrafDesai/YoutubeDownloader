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
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
import yt_dlp
from datetime import datetime
from threading import Thread

app = Flask(__name__)
app.secret_key = '123123'

# Configuration
USER_DB = 'users.json'
DOWNLOAD_HISTORY_DB = 'download_history.db'
FFMPEG_PATH = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"  # Update this path
DOWNLOAD_PATH = "downloads"  # Default download path

# Initialize databases
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w') as f:
        json.dump({}, f)

if not os.path.exists(DOWNLOAD_HISTORY_DB):
    with open(DOWNLOAD_HISTORY_DB, 'w') as f:
        json.dump({}, f)

# Global download progress tracker
download_progress = {
    'status': 'Not started',
    'percent': 0,
    'speed': 0,
    'eta': 0,
    'filename': '',
    'downloaded_bytes': 0,
    'total_bytes': 0,
    'start_time': None
}

def progress_hook(d):
    """Callback function for yt-dlp to update download progress"""
    global download_progress
    
    if d['status'] == 'downloading':
        # Get the current filename being downloaded
        filename = d.get('info_dict', {}).get('title', 'Unknown')
        
        # Calculate progress
        total = d.get('total_bytes') or d.get('total_bytes_estimate', 0)
        downloaded = d.get('downloaded_bytes', 0)
        
        if total > 0:
            percent = (downloaded / total) * 100
        else:
            percent = 0

        # Calculate speed and ETA
        speed = d.get('speed', 0)
        eta = d.get('eta', 0)

        # Update progress information
        download_progress.update({
            'status': f'Downloading: {filename}',
            'title': filename,
            'percent': round(percent, 1),
            'speed': speed,
            'eta': eta,
            'downloaded_bytes': downloaded,
            'total_bytes': total,
            'start_time': download_progress['start_time'] or datetime.now()
        })
    
    elif d['status'] == 'finished':
        download_progress.update({
            'status': 'Processing completed file...',
            'percent': 100,
            'speed': 0,
            'eta': 0
        })
def send_otp(email):
    """Send OTP to user's email for verification."""
    otp = str(random.randint(100000, 999999))
    sender_email = "your-email@gmail.com"  # Update with your email
    sender_password = "your-app-password"   # Update with your app password
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "YouTube Downloader - Verify Your Account"
    
    body = f"""
    Hello!
    
    Your verification code is: {otp}
    
    Please use this code to complete your registration.
    
    Best regards,
    YouTube Downloader Team
    """
    
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
            'thumbnail': video_info.get('thumbnail', ''),
            'url': video_info.get('webpage_url', '')
        })
        
        with open(DOWNLOAD_HISTORY_DB, 'w') as f:
            json.dump(history, f)
    except Exception as e:
        print(f"Error saving history: {e}")

def start_download(url, ydl_opts):
    """Start the download process using yt-dlp."""
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
    except Exception as e:
        download_progress['status'] = f'Error: {str(e)}'

# Routes
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with open(USER_DB, 'r') as f:
            users = json.load(f)
        
        if username in users and users[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['username'] = username
            return redirect(url_for('downloader'))
        
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        
        with open(USER_DB, 'r') as f:
            users = json.load(f)
        
        if username in users:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        otp = send_otp(email)
        if otp:
            session['registration'] = {
                'username': username,
                'email': email,
                'otp': otp
            }
            return redirect(url_for('verify_otp'))
        
        flash('Failed to send OTP', 'error')
    return render_template('register.html')

@app.route('/downloader')
def downloader():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('download.html', username=session['username'])


@app.route('/download', methods=['POST'])
def download():
    try:
        url = request.form.get('url')
        choice = int(request.form.get('choice'))
        quality = request.form.get('quality', 'best')
        download_path = request.form.get('path', 'downloads')

        # Reset progress
        global download_progress
        download_progress = {
            'status': 'Starting download...',
            'percent': 0,
            'speed': 0,
            'eta': 0,
            'title': '',
            'downloaded_bytes': 0,
            'total_bytes': 0,
            'start_time': datetime.now()
        }

        if not os.path.exists(download_path):
            os.makedirs(download_path)

        # Configure format based on quality selection
        if quality == 'best':
            format_str = 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
        else:
            format_str = f'bestvideo[height<={quality}][ext=mp4]+bestaudio[ext=m4a]/best[height<={quality}][ext=mp4]/best'

        ydl_opts = {
            'format': format_str if choice in [1, 2] else 'bestaudio/best',
            'extract_audio': choice in [3, 4],
            'audio_format': 'mp3' if choice in [3, 4] else None,
            'progress_hooks': [progress_hook],
            'outtmpl': os.path.join(download_path, '%(title)s.%(ext)s'),
            'ffmpeg_location': FFMPEG_PATH,
            'verbose': True,
            'postprocessor_hooks': [progress_hook],
            'writethumbnail': True,
            'keepvideo': True,
        }

        if choice in [2, 4]:
            ydl_opts.update({
                'yes_playlist': True,
                'outtmpl': os.path.join(download_path, '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s')
            })
        else:
            ydl_opts['noplaylist'] = True

        thread = Thread(target=start_download, args=(url, ydl_opts))
        thread.daemon = True
        thread.start()

        return jsonify({'status': 'Download started'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-progress')
def download_progress_route():
    def generate():
        while True:
            # Format the data for the frontend
            data = {
                'status': download_progress['status'],
                'percent': download_progress['percent'],
                'speed': format_speed(download_progress['speed']),
                'eta': format_eta(download_progress['eta']),
                'title': download_progress['title'],
            }
            
            yield f"data: {json.dumps(data)}\n\n"
            
            if download_progress['status'] == 'finished':
                break
            
            time.sleep(0.5)
    
    return Response(generate(), mimetype='text/event-stream')


@app.route('/get_playlist_info', methods=['POST'])
def get_playlist_info():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': True,
        }
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            playlist_info = ydl.extract_info(url, download=False)
            
            if playlist_info.get('_type') != 'playlist':
                return jsonify({'error': 'Not a playlist URL'}), 400
            
            videos = []
            for entry in playlist_info.get('entries', []):
                videos.append({
                    'title': entry.get('title', 'Unknown Title'),
                    'duration': str(int(entry.get('duration', 0) // 60)) + ':' + 
                               str(int(entry.get('duration', 0) % 60)).zfill(2),
                    'thumbnail': entry.get('thumbnail', ''),
                    'url': entry.get('url', ''),
                    'video_id': entry.get('id', ''),
                    'status': 'pending'
                })
            
            return jsonify({
                'playlist_title': playlist_info.get('title', 'Unknown Playlist'),
                'video_count': len(videos),
                'videos': videos
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/get-video-info', methods=['POST'])
def get_video_info_route():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': True
        }
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            
            video_info = {
                'title': info.get('title', 'Unknown Title'),
                'duration': str(int(info.get('duration', 0) // 60)) + ':' + 
                           str(int(info.get('duration', 0) % 60)).zfill(2),
                'thumbnail': info.get('thumbnail', ''),
                'channel': info.get('uploader', 'Unknown Channel'),
                'views': format(info.get('view_count', 0), ','),
                'description': info.get('description', 'No description available'),
                'is_playlist': info.get('_type') == 'playlist',
                'playlist_count': len(info.get('entries', [])) if info.get('_type') == 'playlist' else 1
            }
            
            return jsonify(video_info)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400

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