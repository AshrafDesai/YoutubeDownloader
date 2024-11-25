import subprocess
import os
import urllib.request
import sys
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk


# Check if the internet is connected
def internet_on():
    try:
        urllib.request.urlopen('http://google.com', timeout=1)
        return True
    except urllib.request.URLError:
        return False


# Verify the YouTube URL
def verify(url):
    if internet_on():
        try:
            separation = url.split('/')
            if separation[2] == 'www.youtube.com' or separation[2] == 'youtu.be':
                return True
            else:
                messagebox.showerror("Invalid URL", "Not a valid YouTube URL")
                return False
        except Exception:
            messagebox.showerror("Invalid URL", "Oops, Not a valid URL")
            return False


# Quality Input Formatter
def quality_input(quality_choice):
    quality = ['240', '360', '480', '720']
    if quality_choice == 5:
        return ""
    else:
        return '-f "bestvideo[height<={q}]+bestaudio/best[height<={q}]"'.format(q=quality[quality_choice - 1])


# Start Download Process
def start_download(download_type, url, quality_choice, download_path):
    try:
        if not url:
            messagebox.showerror("Input Error", "Please provide a valid YouTube URL")
            return

        ffmpeg_path = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"
        ffmpeg_location = f'--ffmpeg-location "{ffmpeg_path}"'

        quality = quality_input(quality_choice)

        if download_type == 1:  # Video download
            command = f'yt-dlp {ffmpeg_location} -o "{download_path}/%(title)s.%(ext)s" -q --no-playlist --no-warnings {quality} --merge-output-format mp4 "{url}"'
        elif download_type == 2:  # Playlist of Video files
            command = f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" --yes-playlist --newline --no-warnings {quality} --merge-output-format mp4 "{url}"'
        elif download_type == 3:  # Audio download
            command = f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(title)s.%(ext)s" --extract-audio --audio-format mp3 --no-warnings "{url}"'
        elif download_type == 4:  # Playlist of Audio files
            command = f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(title)s.%(ext)s" --yes-playlist --extract-audio --audio-format mp3 --no-warnings "{url}"'

        # Running the download command
        subprocess.call(command, shell=True)

        messagebox.showinfo("Download Complete", f"Download complete! Files saved in: {download_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


# Browse for folder to save files
def browse_folder():
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        download_path_entry.delete(0, tk.END)
        download_path_entry.insert(0, folder_selected)


# Handle Start Button click
def on_start_button_click():
    url = url_entry.get()
    download_path = download_path_entry.get()

    if not url:
        messagebox.showwarning("Input Error", "Please enter a valid YouTube URL")
        return

    if not download_path:
        messagebox.showwarning("Input Error", "Please select a download folder")
        return

    if verify(url):
        download_type = download_type_var.get()
        quality_choice = quality_var.get()
        start_download(download_type, url, quality_choice, download_path)


# Setting up the GUI window
window = tk.Tk()
window.title("YouTube Downloader")
window.geometry("600x500")
window.resizable(False, False)

# Add some padding
pad_x = 20
pad_y = 10

# URL entry
url_label = tk.Label(window, text="Enter YouTube URL:", font=("Arial", 12))
url_label.pack(pady=pad_y)
url_entry = tk.Entry(window, width=50, font=("Arial", 12))
url_entry.pack(pady=pad_y)

# Download Type selection
download_type_var = tk.IntVar()

download_type_label = tk.Label(window, text="Select Download Type:", font=("Arial", 12))
download_type_label.pack(pady=pad_y)

download_type_radio1 = tk.Radiobutton(window, text="Video", variable=download_type_var, value=1, font=("Arial", 12))
download_type_radio1.pack(pady=pad_y)

download_type_radio2 = tk.Radiobutton(window, text="Playlist of Video Files", variable=download_type_var, value=2, font=("Arial", 12))
download_type_radio2.pack(pady=pad_y)

download_type_radio3 = tk.Radiobutton(window, text="Audio", variable=download_type_var, value=3, font=("Arial", 12))
download_type_radio3.pack(pady=pad_y)

download_type_radio4 = tk.Radiobutton(window, text="Playlist of Audio Files", variable=download_type_var, value=4, font=("Arial", 12))
download_type_radio4.pack(pady=pad_y)

# Quality selection
quality_label = tk.Label(window, text="Select Video Quality:", font=("Arial", 12))
quality_label.pack(pady=pad_y)

quality_var = tk.IntVar(value=5)
quality_radio1 = tk.Radiobutton(window, text="240p", variable=quality_var, value=1, font=("Arial", 12))
quality_radio1.pack(pady=pad_y)

quality_radio2 = tk.Radiobutton(window, text="360p", variable=quality_var, value=2, font=("Arial", 12))
quality_radio2.pack(pady=pad_y)

quality_radio3 = tk.Radiobutton(window, text="480p", variable=quality_var, value=3, font=("Arial", 12))
quality_radio3.pack(pady=pad_y)

quality_radio4 = tk.Radiobutton(window, text="720p", variable=quality_var, value=4, font=("Arial", 12))
quality_radio4.pack(pady=pad_y)

quality_radio5 = tk.Radiobutton(window, text="Best Available", variable=quality_var, value=5, font=("Arial", 12))
quality_radio5.pack(pady=pad_y)

# Download path
download_path_label = tk.Label(window, text="Select Download Path:", font=("Arial", 12))
download_path_label.pack(pady=pad_y)

download_path_entry = tk.Entry(window, width=50, font=("Arial", 12))
download_path_entry.pack(pady=pad_y)

browse_button = tk.Button(window, text="Browse", command=browse_folder, font=("Arial", 12))
browse_button.pack(pady=pad_y)

# Start Download Button
start_button = tk.Button(window, text="Start Download", command=on_start_button_click, font=("Arial", 14), bg="#4CAF50", fg="white")
start_button.pack(pady=20)

# Run the GUI
window.mainloop()
