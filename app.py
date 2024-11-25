import os
from flask import Flask, render_template, request, send_from_directory, flash, jsonify, Response
import yt_dlp as youtube_dl
import tempfile
import time

app = Flask(__name__)
app.secret_key = '123123'  # Secret key for session management

DOWNLOAD_PATH = os.path.join(os.path.expanduser("~"), "Downloads")
progress_data = {}

# Progress hook for download progress
def progress_hook(d):
    if d['status'] == 'downloading':
        percent = d.get('downloaded_bytes', 0) / d.get('total_bytes', 1) * 100
        video_id = d['info_dict']['id']
        progress_data[video_id] = percent
    elif d['status'] == 'finished':
        video_id = d['info_dict']['id']
        progress_data[video_id] = 100  # Mark download as finished

# Function to download video
def download_video(url, format_code, download_path, video_id):
    ydl_opts = {
        'outtmpl': os.path.join(download_path, '%(title)s.%(ext)s'),
        'progress_hooks': [progress_hook],
        'postprocessors': [{
            'key': 'FFmpegVideoConvertor',
            'preferedformat': 'mp4',  # Ensure the format is mp4
        }],
        'format': format_code
    }

    try:
        with youtube_dl.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
    except Exception as e:
        flash(f"Error: {e}", "danger")
        print(f"Error during download: {e}")

# Route to handle the form submission and video download
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        quality_choice = int(request.form.get('quality_choice'))
        
        # Fetch available formats dynamically
        available_formats = get_available_formats(url)

        if available_formats:
            # Get the best format or user's selected format
            format_code = select_format(available_formats, quality_choice)
            video_id = str(int(time.time()))  # Unique video id based on timestamp
            download_video(url, format_code, DOWNLOAD_PATH, video_id)
            flash('Download started successfully!', 'success')
        else:
            flash('No available formats found for the requested video.', 'danger')

    return render_template('index.html')

# Function to fetch available formats for a given YouTube URL
def get_available_formats(url):
    try:
        ydl_opts = {'quiet': True, 'extract_flat': True}
        with youtube_dl.YoutubeDL(ydl_opts) as ydl:
            info_dict = ydl.extract_info(url, download=False)
            formats = info_dict.get('formats', [])
            return formats
    except Exception as e:
        flash(f"Error fetching formats: {e}", 'danger')
        return []

# Function to select the format based on user choice
def select_format(formats, quality_choice):
    best_quality = None

    if quality_choice == 5:
        best_quality = 'best'
    else:
        for format in formats:
            if format.get('height', 0) <= quality_choice:
                best_quality = format['format_id']
                break

    if best_quality:
        return best_quality
    else:
        return 'best'  # Fallback to best available format

# SSE Stream to send progress updates to the frontend
@app.route('/progress/<video_id>')
def progress(video_id):
    def generate():
        while video_id in progress_data:
            percent = progress_data[video_id]
            yield f"data: {percent}\n\n"
            time.sleep(1)
    return Response(generate(), content_type='text/event-stream')

# Route to get available formats for a given URL
@app.route('/get_formats', methods=['POST'])
def get_formats():
    url = request.json['url']
    formats = get_available_formats(url)
    return jsonify(formats)

if __name__ == '__main__':
    app.run(debug=True)
