import subprocess
import os
import urllib.request
import urllib.error
import sys
import bs4

def internet_on():
    try:
        response = urllib.request.urlopen('http://google.com', timeout=1)
        soup = bs4.BeautifulSoup(response, 'html.parser')  # Use html.parser to avoid lxml dependency
        if soup.title and soup.title.text == 'Google':
            return True
    except (urllib.request.URLError, AttributeError):
        print("Hmmm... you're not connected to the Internet")
        sys.exit(1)

def verify(url):
    if internet_on():
        try:
            separation = url.split('/')
            if separation[2] in ['www.youtube.com', 'youtu.be']:
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
        return "best"
    else:
        return f"bestvideo[height<={quality[userInput-1]}]+bestaudio/best"

def main():
    try:
        choice = int(input(
            'Enter \n\t[1] Video \n\t[2] Playlist of video files \n\t[3] Audio \n\t[4] Playlist of audio files\n'))
        if choice not in [1, 2, 3, 4]:
            print("Enter a proper number from the choice, next time")
            sys.exit(1)

        url = str(input('Enter a valid URL from YouTube '))
        if verify(url):
            if choice == 1:
                subprocess.call(f'yt-dlp -o "Video downloads/%(title)s.%(ext)s" --no-playlist --no-warnings -f "{quality_input()}" "{url}"', shell=True)
                print('\nThe process is over, and your file is probably residing in "Video downloads"')

            elif choice == 2:
                subprocess.call(f'yt-dlp -i -o "%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" --yes-playlist --newline --no-warnings -f "{quality_input()}" "{url}"', shell=True)
                print('\nThe process is over, and files are in a folder named after the playlist!')

            elif choice == 3:
                subprocess.call(f'yt-dlp -i -o "%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" --yes-playlist --extract-audio --audio-format mp3 --no-warnings "{url}"', shell=True)
                print('\nThe process is over, and files are in a folder named after the playlist!')

            elif choice == 4:
                subprocess.call(f'yt-dlp -i -o "%(playlist)s/%(playlist_index)s.%(title)s.%(ext)s" --yes-playlist --newline --no-warnings "{url}"', shell=True)
                print('\nThe process is over, and files are in a folder named after the playlist!')

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()
