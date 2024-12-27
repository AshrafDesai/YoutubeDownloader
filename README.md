
https://app.eraser.io/workspace/CcIRJOJR6ZKDqLiCIKwU?origin=share

# YouTube Downloader

A simple and user-friendly web application for downloading videos, playlists, or audio from YouTube. Built with Flask, this application allows users to easily input a YouTube URL and download the desired content in various formats and qualities.

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [License](#license)

## Features

- Download videos, audio, or playlists from YouTube.
- Select download quality (e.g., 720p, 1080p, etc.).
- Progress tracking with a visual progress bar.
- Pause, resume, and cancel downloads.
- Email verification for user registration.
- User authentication with Flask-Login.
- Responsive design using Bootstrap.

## Technologies Used

- **Backend**: Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript (jQuery, Bootstrap)
- **Video Downloading**: [yt-dlp](https://github.com/yt-dlp/yt-dlp)
- **Email Sending**: Flask-Mail
- **User Authentication**: Flask-Login

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/youtube-downloader.git
   cd youtube-downloader
   ```

2. **Create a virtual environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required packages**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Download FFmpeg**:
   - Download FFmpeg from [FFmpeg's official website](https://ffmpeg.org/download.html) and place the executable in the project directory or specify the path in the `app.py` file.

5. **Set up your email configuration**:
   - Update the email configuration in `app.py` with your email credentials.

## Usage

1. **Run the application**:
   ```bash
   python app.py
   ```

2. **Open your web browser** and navigate to `http://127.0.0.1:5000`.

3. **Register a new account** or log in if you already have an account.

4. **Enter the YouTube URL** you want to download, select the download type (video/audio/playlist), and choose the quality.

5. **Click "Get Info"** to fetch video details, then click "Start Download" to begin downloading.

6. **Monitor the download progress** and use the pause/resume/cancel buttons as needed.

## Configuration

- **Database**: The application uses SQLite for user data storage. The database file is created automatically on the first run.
- **Email Verification**: Users must verify their email addresses to activate their accounts. An OTP is sent to the registered email during registration.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Feel free to customize this `README.md` file according to your project's specific details and requirements. If you have any additional sections or information you'd like to include, let me know!
