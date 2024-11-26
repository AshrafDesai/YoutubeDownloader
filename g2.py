import os
import json
import hashlib
import random
import smtplib
import subprocess
import threading
import time
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
import yt_dlp

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

USER_DB = 'users.json'
FFMPEG_PATH = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"
DOWNLOAD_HISTORY_DB = 'download_history.json'

# Initialize database files
for db_file in [USER_DB, DOWNLOAD_HISTORY_DB]:
    if not os.path.exists(db_file):
        with open(db_file, 'w') as f:
            json.dump({}, f)

download_progress = {'percent': 0, 'status': 'Not started', 'title': '', 'speed': '', 'eta': ''}

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
                'views': info.get('view_count', 0),
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
            'title': video_info['title'],
            'url': video_info['url'],
            'type': download_type,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'thumbnail': video_info.get('thumbnail', '')
        })
        
        with open(DOWNLOAD_HISTORY_DB, 'w') as f:
            json.dump(history, f)
    except Exception as e:
        print(f"Error saving download history: {e}")

def get_download_history(username):
    """Get user's download history."""
    try:
        with open(DOWNLOAD_HISTORY_DB, 'r') as f:
            history = json.load(f)
        return history.get(username, [])
    except Exception:
        return []

def download_video(url, choice, download_path, quality='best'):
    """Enhanced download function with quality selection and progress tracking."""
    try:
        # Get video info first
        video_info = get_video_info(url)
        if not video_info:
            update_progress(0, 'Failed to fetch video info')
            return

        update_progress(0, f'Starting download: {video_info["title"]}', video_info['title'])

        # Configure yt-dlp options based on choice
        ydl_opts = {
            'ffmpeg_location': FFMPEG_PATH,
            'progress_hooks': [progress_hook],
            'outtmpl': os.path.join(download_path, '%(title)s.%(ext)s'),
            'quiet': False,
            'no_warnings': True
        }

        if choice in [1, 2]:  # Video download
            if quality == 'best':
                format_str = 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
            else:
                format_str = f'bestvideo[height<={quality}][ext=mp4]+bestaudio[ext=m4a]/best[height<={quality}][ext=mp4]/best'
            
            ydl_opts.update({
                'format': format_str,
                'merge_output_format': 'mp4'
            })
        else:  # Audio download
            ydl_opts.update({
                'format': 'bestaudio/best',
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }]
            })

        if choice in [2, 4]:  # Playlist
            ydl_opts['outtmpl'] = os.path.join(download_path, '%(playlist)s/%(playlist_index)s. %(title)s.%(ext)s')
            ydl_opts['yes_playlist'] = True
        else:
            ydl_opts['noplaylist'] = True

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
            
        update_progress(100, 'Download Complete', video_info['title'])
        
        # Save to download history
        save_download_history(session['username'], {
            'title': video_info['title'],
            'url': url,
            'thumbnail': video_info['thumbnail']
        }, 'Video' if choice in [1, 2] else 'Audio')

    except Exception as e:
        update_progress(0, f'Download Failed: {str(e)}')

def progress_hook(d):
    """Enhanced progress hook for detailed download information."""
    if d['status'] == 'downloading':
        try:
            total = d.get('total_bytes', 0) or d.get('total_bytes_estimate', 0)
            downloaded = d.get('downloaded_bytes', 0)
            
            if total > 0:
                percent = (downloaded / total) * 100
                speed = d.get('speed', 0)
                eta = d.get('eta', 0)
                
                speed_str = f'{speed/1024/1024:.1f} MB/s' if speed else 'Unknown'
                eta_str = f'{eta//60}:{eta%60:02d}' if eta else 'Unknown'
                
                update_progress(
                    percent,
                    'Downloading...',
                    d.get('filename', '').split('/')[-1],
                    speed_str,
                    eta_str
                )
        except Exception as e:
            print(f"Progress calculation error: {e}")
    elif d['status'] == 'finished':
        update_progress(100, 'Processing...', d.get('filename', '').split('/')[-1])

def update_progress(percent, status, title='', speed='', eta=''):
    """Update global download progress with more details."""
    download_progress.update({
        'percent': round(percent, 1),
        'status': status,
        'title': title,
        'speed': speed,
        'eta': eta
    })

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download', methods=['GET', 'POST'])
def download():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            url = request.form['url']
            choice = int(request.form['choice'])
            download_path = request.form['path']
            quality = request.form.get('quality', 'best')
            
            # Validate URL
            if not re.match(r'^https?://(www\.)?(youtube\.com|youtu\.be)/.+$', url):
                flash("Please enter a valid YouTube URL.", "danger")
                return redirect(url_for('download'))
            
            # Get video info before starting download
            video_info = get_video_info(url)
            if not video_info:
                flash("Could not fetch video information. Please check the URL.", "danger")
                return redirect(url_for('download'))
            
            # Create download directory if it doesn't exist
            os.makedirs(download_path, exist_ok=True)
            
            # Start download in background thread
            threading.Thread(
                target=download_video,
                args=(url, choice, download_path, quality),
                daemon=True
            ).start()
            
            flash(f"Download started for: {video_info['title']}", "success")
            
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
    
    # Get download history for display
    history = get_download_history(session['username'])
    
    return render_template(
        'download.html',
        username=session['username'],
        history=history
    )

@app.route('/api/video-info')
def video_info():
    """API endpoint to get video information."""
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    info = get_video_info(url)
    if info:
        return jsonify(info)
    return jsonify({'error': 'Could not fetch video information'}), 400

@app.route('/download-progress')
def download_progress_route():
    def generate():
        while True:
            yield f"data: {json.dumps(download_progress)}\n\n"
            time.sleep(1)
    return Response(generate(), content_type='text/event-stream')

# Add template for download.html
"""
{% extends "base.html" %}
{% block content %}
<div class="container mt-4">
    <h2>YouTube Downloader</h2>
    
    <div class="card mb-4">
        <div class="card-body">
            <form method="POST">
                <div class="form-group">
                    <label>YouTube URL:</label>
                    <input type="url" name="url" class="form-control" required>
                </div>
                
                <div class="form-group mt-3">
                    <label>Download Type:</label>
                    <select name="choice" class="form-control">
                        <option value="1">Single Video</option>
                        <option value="2">Video Playlist</option>
                        <option value="3">Single Audio</option>
                        <option value="4">Audio Playlist</option>
                    </select>
                </div>
                
                <div class="form-group mt-3">
                    <label>Quality:</label>
                    <select name="quality" class="form-control">
                        <option value="best">Best</option>
                        <option value="1080">1080p</option>
                        <option value="720">720p</option>
                        <option value="480">480p</option>
                        <option value="360">360p</option>
                    </select>
                </div>
                
                <div class="form-group mt-3">
                    <label>Download Path:</label>
                    <input type="text" name="path" class="form-control" 
                           value="{{ request.form.get('path', 'downloads') }}" required>
                </div>
                
                <button type="submit" class="btn btn-primary mt-3">Download</button>
            </form>
        </div>
    </div>
    
    <div class="card mb-4">
        <div class="card-body">
            <h5>Download Progress</h5>
            <div class="progress">
                <div id="progress-bar" class="progress-bar" role="progressbar"></div>
            </div>
            <p id="progress-status" class="mt-2">Ready to download</p>
            <p id="download-details" class="small"></p>
        </div>
    </div>
    
    <div class="card">
        <div class="card-body">
            <h5>Download History</h5>
            <div class="row">
                {% for item in history %}
                <div class="col-md-4 mb-3">
                    <div class="card">
                        {% if item.thumbnail %}
                        <img src="{{ item.thumbnail }}" class="card-img-top" alt="{{ item.title }}">
                        {% endif %}
                        <div class="card-body">
                            <h6 class="card-title">{{ item.title }}</h6>
                            <p class="card-text small">
                                Type: {{ item.type }}<br>
                                Date: {{ item.date }}
                            </p>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
</div>

<script>
const evtSource = new EventSource("{{ url_for('download_progress_route') }}");
evtSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    document.getElementById('progress-bar').style.width = data.percent + '%';
    document.getElementById('progress-bar').setAttribute('aria-valuenow', data.percent);
    document.getElementById('progress-status').textContent = data.status;
    
    let details = '';
    if (data.title) details += `File: ${data.title}<br>`;
    if (data.speed) details += `Speed: ${data.speed}<br>`;
    if (data.eta) details += `ETA: ${data.eta}`;
    document.getElementById('download-details').innerHTML = details;
};
</script>
{% endblock %}
"""

if __name__ == '__main__':
    app.run(debug=True)