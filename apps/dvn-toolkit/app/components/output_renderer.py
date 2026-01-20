"""
Output Renderer - Visual output formatting
Terminal output, progress indicators
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.progressbar import ProgressBar
from kivy.graphics import Color, Rectangle
from kivy.utils import get_color_from_hex
from kivy.clock import Clock
from kivy.metrics import dp, sp
from datetime import datetime

from ..utils.text_utils import clean_output


class TerminalOutput(TextInput):
    """Terminal-style output with timestamps and scrolling"""

    def __init__(self, theme, **kwargs):
        super().__init__(**kwargs)
        self.theme = theme
        self.readonly = True
        self.multiline = True
        self.font_name = 'Roboto'
        self.font_size = sp(11)
        self.padding = [dp(10), dp(10), dp(10), dp(10)]

        self.do_scroll_x = False
        self.do_scroll_y = True
        self.scroll_y = 0

        self.allow_copy = False
        self.use_bubble = False
        self.use_handles = False

        self.background_color = get_color_from_hex(theme['terminal_bg'])
        self.foreground_color = get_color_from_hex(theme['terminal_text'])

    def append(self, text, timestamp=True):
        # Clean ANSI codes and box chars for Android display
        text = clean_output(text)
        if timestamp:
            ts = datetime.now().strftime('%H:%M:%S')
            self.text += f"[{ts}] {text}\n"
        else:
            self.text += f"{text}\n"
        self.cursor = (len(self.text), 0)
        self.scroll_y = 0

    def append_raw(self, text):
        self.append(text, timestamp=False)

    def append_success(self, text):
        self.append(f"[OK] {text}")

    def append_error(self, text):
        self.append(f"[ERROR] {text}")

    def append_warning(self, text):
        self.append(f"[WARN] {text}")

    def append_separator(self):
        self.append_raw("-" * 40)

    def clear_output(self):
        self.text = ""

    def update_theme(self, theme):
        self.theme = theme
        self.background_color = get_color_from_hex(theme['terminal_bg'])
        self.foreground_color = get_color_from_hex(theme['terminal_text'])


class ProgressIndicator(BoxLayout):
    """Progress indicator with status text"""

    def __init__(self, theme, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(44)
        self.spacing = dp(4)
        self.padding = [dp(10), dp(4), dp(10), dp(4)]
        self.theme = theme

        self.status_label = Label(
            text='Ready',
            font_size=sp(11),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(18),
            halign='left',
            valign='middle'
        )
        self.status_label.bind(size=self.status_label.setter('text_size'))

        self.progress_bar = ProgressBar(
            max=100,
            value=0,
            size_hint_y=None,
            height=dp(16)
        )

        self.add_widget(self.status_label)
        self.add_widget(self.progress_bar)

    def set_status(self, text):
        self.status_label.text = text

    def set_progress(self, value):
        self.progress_bar.value = min(100, max(0, value))

    def _animate_indeterminate(self, dt=None):
        self.progress_bar.value = (self.progress_bar.value + 5) % 100

    def start_animation(self):
        Clock.schedule_interval(self._animate_indeterminate, 0.05)

    def stop_animation(self):
        Clock.unschedule(self._animate_indeterminate)
        self.progress_bar.value = 0

    def complete(self):
        self.stop_animation()
        self.progress_bar.value = 100
        self.status_label.text = 'Complete'


class TableRenderer(BoxLayout):
    """Render data as a table"""

    def __init__(self, theme, headers=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.theme = theme
        self.headers = headers or []
        self.rows = []

        self._build_header()

    def _build_header(self):
        if not self.headers:
            return

        theme = self.theme
        header_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(28)
        )

        with header_row.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            Rectangle(pos=header_row.pos, size=header_row.size)

        for header in self.headers:
            label = Label(
                text=str(header),
                font_size=sp(11),
                bold=True,
                color=get_color_from_hex(theme['accent']),
                halign='left',
                valign='middle'
            )
            label.bind(size=label.setter('text_size'))
            header_row.add_widget(label)

        self.add_widget(header_row)

    def add_row(self, values):
        theme = self.theme
        row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(24)
        )

        for value in values:
            label = Label(
                text=str(value),
                font_size=sp(10),
                color=get_color_from_hex(theme['text']),
                halign='left',
                valign='middle'
            )
            label.bind(size=label.setter('text_size'))
            row.add_widget(label)

        self.rows.append(row)
        self.add_widget(row)

    def clear_rows(self):
        for row in self.rows:
            self.remove_widget(row)
        self.rows = []


class SummaryCard(BoxLayout):
    """Summary card for output results"""

    def __init__(self, theme, title='', **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(70)
        self.padding = [dp(10), dp(6), dp(10), dp(6)]
        self.spacing = dp(4)
        self.theme = theme

        with self.canvas.before:
            Color(*get_color_from_hex(theme['bg_card']))
            self._bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        title_label = Label(
            text=title,
            font_size=sp(12),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(20),
            halign='left',
            valign='middle'
        )
        title_label.bind(size=title_label.setter('text_size'))

        self.value_label = Label(
            text='--',
            font_size=sp(18),
            bold=True,
            color=get_color_from_hex(theme['text']),
            size_hint_y=1,
            halign='center',
            valign='middle'
        )

        self.add_widget(title_label)
        self.add_widget(self.value_label)

    def set_value(self, value):
        self.value_label.text = str(value)
