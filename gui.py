from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.progressbar import ProgressBar
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.graphics import Color, Rectangle

class YouTubeDownloaderApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        # Heading
        self.label = Label(text="YouTube Downloader", font_size=28, bold=True, color=(0.3, 0.3, 0.3, 1))
        layout.add_widget(self.label)

        # URL input
        self.url_input = TextInput(hint_text="Enter YouTube URL", size_hint=(1, 0.1), height=40, font_size=16)
        self.url_input.background_normal = ''
        self.url_input.background_color = (0.95, 0.95, 0.95, 1)
        self.url_input.foreground_color = (0.3, 0.3, 0.3, 1)
        layout.add_widget(self.url_input)

        # Download path input
        self.path_input = TextInput(hint_text="Enter Download Path", size_hint=(1, 0.1), height=40, font_size=16)
        self.path_input.background_normal = ''
        self.path_input.background_color = (0.95, 0.95, 0.95, 1)
        self.path_input.foreground_color = (0.3, 0.3, 0.3, 1)
        layout.add_widget(self.path_input)

        # Browse button
        self.browse_button = Button(text="Browse", size_hint=(1, 0.1), background_color=(0.6, 0.8, 0.4, 1), font_size=16)
        self.browse_button.bind(on_press=self.browse_path)
        layout.add_widget(self.browse_button)

        # Quality spinner
        self.quality_label = Label(text="Select Video Quality", size_hint=(1, 0.1), font_size=16, color=(0.3, 0.3, 0.3, 1))
        layout.add_widget(self.quality_label)
        self.quality_spinner = Spinner(
            text='Best',
            values=('Best', '720p', '480p', '360p', '240p'),
            size_hint=(1, 0.1),
            background_normal='',
            background_color=(0.9, 0.9, 0.9, 1),
            color=(0.3, 0.3, 0.3, 1)
        )
        layout.add_widget(self.quality_spinner)

        # Download button
        self.download_button = Button(text="Download Video", size_hint=(1, 0.1), background_color=(0.4, 0.7, 0.4, 1), font_size=16)
        self.download_button.bind(on_press=self.download_video)
        layout.add_widget(self.download_button)

        # Progress bar (color customization via canvas)
        self.progress_bar = ProgressBar(max=100, value=0, size_hint=(1, 0.1))
        self.progress_bar.canvas.before.clear()  # Clear the canvas to reset custom drawing
        with self.progress_bar.canvas.before:
            Color(0.3, 0.6, 0.3, 1)  # Set the color to green
            self.rect = Rectangle(size=self.progress_bar.size, pos=self.progress_bar.pos)

        self.progress_bar.bind(size=self.update_rect, pos=self.update_rect)
        layout.add_widget(self.progress_bar)

        return layout

    def browse_path(self, instance):
        filechooser = FileChooserIconView()
        filechooser.bind(on_submit=self.select_path)
        filechooser.size_hint = (1, 1)
        popup = Popup(title="Select Folder", content=filechooser, size_hint=(0.9, 0.9))
        popup.open()

    def select_path(self, instance, value):
        if value:
            self.path_input.text = value[0]

    def download_video(self, instance):
        url = self.url_input.text
        path = self.path_input.text
        quality = self.quality_spinner.text

        # Simulate downloading with a progress bar
        self.progress_bar.value = 0
        self.update_progress_bar()

        # In a real app, this would be where you download the video
        print(f"Downloading video from {url} at {quality} to {path}")

    def update_progress_bar(self):
        if self.progress_bar.value < 100:
            self.progress_bar.value += 10
            # Update every 0.5 seconds to simulate progress
            from kivy.clock import Clock
            Clock.schedule_once(lambda dt: self.update_progress_bar(), 0.5)

    def update_rect(self, instance, value):
        self.rect.size = instance.size
        self.rect.pos = instance.pos

if __name__ == "__main__":
    YouTubeDownloaderApp().run()
