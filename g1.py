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

app = Flask(__name__)
app.secret_key = '123123'

USER_DB = 'users.json'

# Initialize users.json file if it doesn't exist
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w') as f:
        json.dump({}, f)

# Send OTP to user's email
def send_otp(email):
    otp = str(random.randint(100000, 999999))
    
    sender_email = "ashrafdesai6598@gmail.com"
    sender_password = "wtuf hyek gvmp opcs"  # For Gmail, use App Password
    subject = "OTP for Account Creation"
    body = f"Welcome! Your OTP is {otp}. Use it to verify your account."

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        return otp
    except Exception as e:
        print(f"Failed to send email: {e}")
        return None

# Verify the user login credentials
def verify_user_credentials(username, password):
    with open(USER_DB, 'r') as f:
        users = json.load(f)
    user = users.get(username)
    if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
        return True
    return False

# Save user details after registration
def save_user(username, email, password):
    with open(USER_DB, 'r') as f:
        users = json.load(f)
    
    users[username] = {'email': email, 'password': hashlib.sha256(password.encode()).hexdigest()}
    
    with open(USER_DB, 'w') as f:
        json.dump(users, f)

download_progress = {
    'percent': 0,
    'status': 'Not started'
}

def update_progress(percent, status):
    """
    Updates the global download progress and status.
    """
    download_progress['percent'] = percent
    download_progress['status'] = status
    print(f"Progress Updated: {percent}%, Status: {status}")  # Debugging

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
        else:
            flash("Error sending OTP. Try again.", "danger")
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            return redirect(url_for('set_password'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
    return render_template('verify_otp.html')

@app.route('/set_password', methods=['GET', 'POST'])
def set_password():
    if request.method == 'POST':
        password = request.form['password']
        username = session.get('username')
        email = session.get('email')
        save_user(username, email, password)
        flash("Account created successfully!", "success")
        session.clear()  
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
        else:
            flash("Invalid username or password. Please try again.", "danger")
    return render_template('login.html')

@app.route('/download', methods=['GET', 'POST'])
def download():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            url = request.form['url']
            choice = int(request.form['choice'])
            download_path = request.form['path']
            
            if choice not in [1, 2, 3, 4]:
                flash("Invalid choice, please select a valid option", "danger")
                return redirect(url_for('download'))

            # Start the download in a separate thread
            thread = threading.Thread(target=download_video, args=(url, choice, download_path))
            thread.start()
            flash("Download started! Please wait...", "success")
            return redirect(url_for('download'))
        
        except KeyError as e:
            print(f"Error: Missing form field: {e}")  # Debugging
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('download'))
    
    return render_template('download.html')

def download_video(url, choice, download_path):
    ffmpeg_path = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"
    ffmpeg_location = f'--ffmpeg-location "{ffmpeg_path}"'
    format_option = '--format "best[ext=mp4]"'  # For MP4 format

    if choice == 1:
        command = f'yt-dlp {ffmpeg_location} {format_option} -o "{download_path}/%(title)s.%(ext)s" -q --no-playlist --no-warnings "{url}"'
    elif choice == 2:
        command = f'yt-dlp {ffmpeg_location} {format_option} -i -o "{download_path}/%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" --yes-playlist --newline --no-warnings "{url}"'
    elif choice == 3:
        command = f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(title)s.%(ext)s" --extract-audio --audio-format mp3 --no-warnings "{url}"'
    elif choice == 4:
        command = f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(title)s.%(ext)s" --yes-playlist --extract-audio --audio-format mp3 --no-warnings "{url}"'

    print(f"Running command: {command}")  # Debugging
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            if 'download' in output and '%' in output:
                try:
                    percent = int(output.split()[1].replace('%', ''))
                    update_progress(percent, 'Downloading...')
                    print(f"Downloaded {percent}%")  # Debugging
                except (ValueError, IndexError):
                    continue

    stderr = process.stderr.read()
    if stderr:
        print(f"Error: {stderr.strip()}")
        update_progress(0, 'Download Failed')
    else:
        update_progress(100, 'Download Complete')

# SSE Endpoint for sending progress updates
def send_progress_update(percent, status):
    progress_data = {
        'percent': percent,
        'status': status
    }
    return f"data: {json.dumps(progress_data)}\n\n"

@app.route('/download-progress')
def download_progress_route():
    """
    SSE endpoint to send download progress to the client.
    """
    def generate():
        while True:
            # Send the current progress and status
            yield send_progress_update(download_progress['percent'], download_progress['status'])

            # Stop sending updates if the download is complete or failed
            if download_progress['percent'] == 100 or download_progress['status'] in ['Download Complete', 'Download Failed']:
                print("Terminating SSE stream.")  # Debugging
                break

            time.sleep(1)  # Delay between updates

    return Response(generate(), content_type='text/event-stream')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
