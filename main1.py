import subprocess
import os
import urllib.request
import urllib.error
import sys
import bs4

def internet_on():
    """
    Checking whether connected to the internet 
    if not connected to internet but connected to wifi, not yet logged in, 
    returns a '200' code for trying to fetch results (wifi default login page)
    URLError if there is no internet or default wifi redirecting, AttributeError for handling 'Nonetype' object (response) in the above
    """
    try:
        response = urllib.request.urlopen('http://google.com', timeout=1)
        soup = bs4.BeautifulSoup(response, 'lxml')
        if soup.title.text == 'Google':
            return True
    except (urllib.request.URLError, AttributeError):
        print("Hmmm... you're not connected to the Internet")
        sys.exit(1)

def verify(url):
    """
    Verifying URL, whether it's a URL, whether that URL belongs to YouTube or not
    """
    if internet_on() == True:
        try:
            separation = url.split('/')
            if separation[2] == 'www.youtube.com' or separation[2] == 'youtu.be':
                print('URL belongs to YouTube')
                return True
            else:
                print("Not a YouTube URL")
        except Exception:
            print('Oops, Not a valid URL')
            sys.exit(1)

def quality_input():
    quality = ['240', '360', '480', '720']
    print("\nPlease select quality")
    userInput = int(input(
        '\n\t[1] 240p \n\t[2] 360p \n\t[3] 480p \n\t[4] 720p \n\t[5] Default (best available quality)\n'))
    if userInput == 5:
        return ""
    else:
        return '-f "bestvideo[height<={q}]+bestaudio/best[height<={q}]"'.format(q=quality[userInput-1])

def main():
    try:
        choice = int(input(
            'Enter \n\t[1] Video \n\t[2] Playlist of video files \n\t[3] Audio \n\t[4] Playlist of audio files\n'))
        if choice not in [1, 2, 3, 4]:
            print("Enter a proper number from the choice, next time")
            sys.exit(1)

        url = str(input('Enter a valid URL from YouTube '))

        if verify(url) == True:

            # Ask user for download directory
            download_path = input(f'Default download path is: {os.getcwd()}/Downloads\nEnter the directory where you want to save the files (press Enter to use default): ')
            if not download_path:
                download_path = os.path.join(os.getcwd(), 'Downloads')

            # Set the ffmpeg path directly here
            ffmpeg_path = "C:/Ashraf/Youtube/ffmpeg-2024-11-18-git-970d57988d-full_build/bin"  # <-- Set this to your ffmpeg installation directory
            ffmpeg_location = f'--ffmpeg-location "{ffmpeg_path}"'

            # Select quality input
            quality = quality_input()

            if choice == 1:
                # Video download - Force MP4 format and avoid WEBM
                subprocess.call(f'yt-dlp {ffmpeg_location} -o "{download_path}/%(title)s.%(ext)s" -q --no-playlist --no-warnings {quality} --merge-output-format mp4 "{url}"', shell=True)
                print(f'\n\nThe process is over and your file is in: {download_path}')

            elif choice == 2:
                # Playlist of video files - Force MP4 format and avoid WEBM
                subprocess.call(f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" --yes-playlist --newline --no-warnings {quality} --merge-output-format mp4 "{url}"', shell=True)
                print(f'\n\nThe process is over and your files are in: {download_path}')

            elif choice == 3:
                # Audio download - Ensure MP3 format
                subprocess.call(f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(title)s.%(ext)s" --extract-audio --audio-format mp3 --no-warnings "{url}"', shell=True)
                print(f'\n\nThe process is over. Your audio files are in: {download_path}')

            elif choice == 4:
                # Playlist of audio files - Ensure MP3 format
                subprocess.call(f'yt-dlp {ffmpeg_location} -i -o "{download_path}/%(title)s.%(ext)s" --yes-playlist --extract-audio --audio-format mp3 --no-warnings "{url}"', shell=True)
                print(f'\n\nThe process is over. Your audio files are in: {download_path}')

    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
