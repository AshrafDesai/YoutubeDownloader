import os
import json
import hashlib
import random
import smtplib
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
FFMPEG_PATH = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"
DOWNLOAD_PATH = "downloads"

# Initialize databases
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w') as f:
        json.dump({}, f)

if not os.path.exists(DOWNLOAD_HISTORY_DB):
    with open(DOWNLOAD_HISTORY_DB, 'w') as f:
        json.dump({}, f)

# Global progress trackers
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

playlist_progress = {
    'videos': [],
    'current_video': 0,
    'total_videos': 0,
    'status': 'Not started',
    'playlist_title': '',
    'current_video_title': ''
}

def send_otp(email):
    """Send OTP to user's email for verification."""
    otp = str(random.randint(100000, 999999))
    sender_email = "your-email@gmail.com"
    sender_password = "your-app-password"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "YouTube Downloader - Verify Your Account"
    
    body = f"Your verification code is: {otp}"
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

def update_playlist_video_progress(video_info, status='pending'):
    """Update individual video progress in playlist"""
    video_entry = {
        'title': video_info.get('title', 'Unknown'),
        'status': status,
        'progress': 0,
        'speed': '0 B/s',
        'eta': 'Unknown',
        'thumbnail': video_info.get('thumbnail', ''),
        'duration': str(int(video_info.get('duration', 0) // 60)) + ':' + 
                   str(int(video_info.get('duration', 0) % 60)).zfill(2),
        'index': video_info.get('playlist_index', 0),
        'size': '0 MB'
    }
    
    existing_video = next(
        (video for video in playlist_progress['videos'] 
         if video['title'] == video_entry['title']), 
        None
    )
    
    if existing_video:
        existing_video.update(video_entry)
    else:
        playlist_progress['videos'].append(video_entry)

def progress_hook(d):
    """Enhanced callback function for yt-dlp to update download progress"""
    global download_progress, playlist_progress
    
    if d['status'] == 'downloading':
        total = d.get('total_bytes') or d.get('total_bytes_estimate', 0)
        downloaded = d.get('downloaded_bytes', 0)
        
        if total > 0:
            percent = (downloaded / total) * 100
        else:
            percent = 0

        current_filename = os.path.basename(d.get('filename', ''))
        
        # Update general download progress
        download_progress.update({
            'status': 'downloading',
            'filename': current_filename,
            'percent': round(percent, 1),
            'speed': d.get('speed', 0),
            'eta': d.get('eta', 0),
            'downloaded_bytes': downloaded,
            'total_bytes': total,
            'start_time': download_progress['start_time'] or datetime.now()
        })
        
        # Update playlist video progress
        if playlist_progress['status'] == 'downloading':
            playlist_progress['current_video_title'] = current_filename
            for video in playlist_progress['videos']:
                if video['title'] in current_filename:
                    video.update({
                        'status': 'downloading',
                        'progress': round(percent, 1),
                        'speed': format_speed(d.get('speed', 0)),
                        'eta': format_eta(d.get('eta', 0)),
                        'size': format_size(total)
                    })
                    break
    
    elif d['status'] == 'finished':
        current_filename = os.path.basename(d.get('filename', ''))
        
        # Update general download progress
        download_progress.update({
            'status': 'finished',
            'percent': 100,
            'speed': 0,
            'eta': 0
        })
        
        # Update playlist video progress
        if playlist_progress['status'] == 'downloading':
            for video in playlist_progress['videos']:
                if video['title'] in current_filename:
                    video.update({
                        'status': 'completed',
                        'progress': 100,
                        'speed': '0 B/s',
                        'eta': '0s'
                    })
                    playlist_progress['current_video'] += 1
                    break

def start_playlist_download(url, ydl_opts):
    """Handle playlist download process"""
    try:
        playlist_progress['status'] = 'downloading'
        
        # First pass: Get playlist information
        with yt_dlp.YoutubeDL({'extract_flat': True}) as ydl:
            playlist_info = ydl.extract_info(url, download=False)
            playlist_progress.update({
                'total_videos': len(playlist_info['entries']),
                'playlist_title': playlist_info.get('title', 'Unknown Playlist')
            })
            
            # Initialize progress for each video
            for entry in playlist_info['entries']:
                update_playlist_video_progress(entry)
        
        # Second pass: Download videos
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
            
        playlist_progress['status'] = 'completed'
        
    except Exception as e:
        playlist_progress['status'] = f'Error: {str(e)}'
        print(f"Download error: {e}")

def start_single_video_download(url, ydl_opts):
    """Handle single video download"""
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
    except Exception as e:
        download_progress['status'] = f'Error: {str(e)}'
        print(f"Download error: {e}")
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
        password = request.form['password']
        
        with open(USER_DB, 'r') as f:
            users = json.load(f)
        
        if username in users:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        users[username] = {
            'email': email,
            'password': hashlib.sha256(password.encode()).hexdigest()
        }
        
        with open(USER_DB, 'w') as f:
            json.dump(users, f)
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/downloader')
def downloader():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('download.html', username=session['username'])

@app.route('/download', methods=['POST'])
def download():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        url = request.form.get('url')
        choice = int(request.form.get('choice'))
        download_path = request.form.get('path', DOWNLOAD_PATH)
        
        # Reset progress trackers
        global download_progress, playlist_progress
        download_progress = {
            'status': 'Not started',
            'percent': 0,
            'speed': 0,
            'eta': 0,
            'filename': '',
            'downloaded_bytes': 0,
            'total_bytes': 0,
            'start_time': datetime.now()
        }
        
        playlist_progress = {
            'videos': [],
            'current_video': 0,
            'total_videos': 0,
            'status': 'Not started',
            'playlist_title': '',
            'current_video_title': ''
        }
        
        if not os.path.exists(download_path):
            os.makedirs(download_path)
        
        ydl_opts = {
            'format': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' if choice in [1, 2] else None,
            'extract_audio': choice in [3, 4],
            'audio_format': 'mp3' if choice in [3, 4] else None,
            'progress_hooks': [progress_hook],
            'outtmpl': os.path.join(download_path, '%(title)s.%(ext)s'),
            'ffmpeg_location': FFMPEG_PATH,
            'verbose': True
        }
        
        if choice in [2, 4]:  # Playlist options
            ydl_opts['yes_playlist'] = True
            ydl_opts['outtmpl'] = os.path.join(download_path, '%(playlist)s/%(playlist_index)s - %(title)s.%(ext)s')
            thread = Thread(target=start_playlist_download, args=(url, ydl_opts))
        else:
            ydl_opts['noplaylist'] = True
            thread = Thread(target=start_single_video_download, args=(url, ydl_opts))
        
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'status': 'Download started',
            'is_playlist': choice in [2, 4]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-progress')
def download_progress_route():
    def generate():
        while True:
            data = {
                'status': download_progress['status'],
                'percent': download_progress['percent'],
                'speed': format_speed(download_progress['speed']),
                'eta': format_eta(download_progress['eta']),
                'filename': download_progress['filename'],
                'downloaded': format_size(download_progress['downloaded_bytes']),
                'total': format_size(download_progress['total_bytes'])
            }
            
            yield f"data: {json.dumps(data)}\n\n"
            
            if download_progress['status'] in ['finished', 'error']:
                break
            
            time.sleep(0.5)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/playlist-progress')
def playlist_progress_route():
    def generate():
        while True:
            data = {
                'videos': playlist_progress['videos'],
                'current_video': playlist_progress['current_video'],
                'total_videos': playlist_progress['total_videos'],
                'status': playlist_progress['status'],
                'playlist_title': playlist_progress['playlist_title'],
                'current_video_title': playlist_progress['current_video_title']
            }
            
            yield f"data: {json.dumps(data)}\n\n"
            
            if playlist_progress['status'] in ['completed', 'error']:
                break
            
            time.sleep(1)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/get-video-info', methods=['POST'])
def get_video_info():
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
            
            is_playlist = info.get('_type') == 'playlist'
            
            if is_playlist:
                playlist_info = {
                    'type': 'playlist',
                    'title': info.get('title', 'Unknown Playlist'),
                    'video_count': len(info.get('entries', [])),
                    'videos': [{
                        'title': entry.get('title', 'Unknown Title'),
                        'duration': str(int(entry.get('duration', 0) // 60)) + ':' + 
                                  str(int(entry.get('duration', 0) % 60)).zfill(2),
                        'thumbnail': entry.get('thumbnail', ''),
                    } for entry in info.get('entries', [])]
                }
                return jsonify(playlist_info)
            else:
                video_info = {
                    'type': 'video',
                    'title': info.get('title', 'Unknown Title'),
                    'duration': str(int(info.get('duration', 0) // 60)) + ':' + 
                               str(int(info.get('duration', 0) % 60)).zfill(2),
                    'thumbnail': info.get('thumbnail', ''),
                    'channel': info.get('uploader', 'Unknown Channel'),
                    'views': format(info.get('view_count', 0), ','),
                    'description': info.get('description', 'No description available')
                }
                return jsonify(video_info)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def format_size(bytes):
    """Format size in bytes to human readable format"""
    if not bytes:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB']
    unit_index = 0
    size = float(bytes)
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    return f"{size:.1f} {units[unit_index]}"

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

if __name__ == '__main__':
    app.run(debug=True)