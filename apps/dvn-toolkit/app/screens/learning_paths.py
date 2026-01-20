"""
Learning Paths Screen - Browse and select learning journeys
Shows all available paths with progress indicators
"""

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.progressbar import ProgressBar
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.uix.behaviors import ButtonBehavior

from ..data.paths_registry import get_all_paths, SKILL_BEGINNER, SKILL_INTERMEDIATE
from ..data.progress_tracker import get_progress_tracker


class PathCard(ButtonBehavior, BoxLayout):
    """Card displaying a learning path"""

    def __init__(self, path_data, theme, progress_info, on_select=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(120)
        self.padding = [dp(14), dp(12), dp(14), dp(12)]
        self.spacing = dp(6)

        self.path_data = path_data
        self.theme = theme
        self.progress_info = progress_info
        self.on_select_callback = on_select

        self._build_ui()
        self.bind(on_press=self._on_press)

    def _build_ui(self):
        """Build the card UI"""
        # Background
        with self.canvas.before:
            Color(*get_color_from_hex(self.theme['bg_card']))
            self._bg = RoundedRectangle(
                pos=self.pos, size=self.size, radius=[dp(12)]
            )
        self.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Header row: icon, title, skill badge
        header = BoxLayout(size_hint_y=None, height=dp(28))

        icon = Label(
            text=self.path_data['icon'],
            size_hint=(None, 1),
            width=dp(32),
            font_size=sp(16),
            color=get_color_from_hex(self.theme['accent'])
        )

        title = Label(
            text=self.path_data['name'],
            font_size=sp(14),
            bold=True,
            color=get_color_from_hex(self.theme['text']),
            halign='left',
            valign='middle'
        )
        title.bind(size=title.setter('text_size'))

        skill = self.path_data['skill_level']
        stars = '*' if skill == SKILL_BEGINNER else ('**' if skill == SKILL_INTERMEDIATE else '***')
        skill_badge = Label(
            text=stars,
            size_hint=(None, 1),
            width=dp(40),
            font_size=sp(12),
            color=get_color_from_hex(self.theme['accent'])
        )

        header.add_widget(icon)
        header.add_widget(title)
        header.add_widget(skill_badge)

        # Description
        desc = Label(
            text=self.path_data['description'],
            font_size=sp(11),
            color=get_color_from_hex(self.theme['text_dim']),
            size_hint_y=None,
            height=dp(32),
            halign='left',
            valign='top'
        )
        desc.bind(size=desc.setter('text_size'))

        # Progress row
        progress_row = BoxLayout(size_hint_y=None, height=dp(24), spacing=dp(8))

        lessons_count = len(self.path_data['lessons'])
        current = self.progress_info.get('current_lesson', 0)
        percentage = self.progress_info.get('percentage', 0)

        progress_text = Label(
            text=f"{current}/{lessons_count} lessons",
            size_hint=(None, 1),
            width=dp(80),
            font_size=sp(10),
            color=get_color_from_hex(self.theme['text_dim']),
            halign='left'
        )
        progress_text.bind(size=progress_text.setter('text_size'))

        progress_bar = ProgressBar(
            max=100,
            value=percentage,
            size_hint_y=None,
            height=dp(8)
        )

        status_text = Label(
            text='CONTINUE' if current > 0 else 'START',
            size_hint=(None, 1),
            width=dp(70),
            font_size=sp(10),
            bold=True,
            color=get_color_from_hex(self.theme['accent']),
            halign='right'
        )
        status_text.bind(size=status_text.setter('text_size'))

        progress_row.add_widget(progress_text)
        progress_row.add_widget(progress_bar)
        progress_row.add_widget(status_text)

        self.add_widget(header)
        self.add_widget(desc)
        self.add_widget(progress_row)

    def _on_press(self, instance):
        if self.on_select_callback:
            self.on_select_callback(self.path_data)


class LearningPathsScreen(Screen):
    """Browse all learning paths"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        """Build the learning paths screen UI"""
        self.clear_widgets()
        theme = self.app.theme_manager.current

        main_layout = BoxLayout(orientation='vertical')

        # Background
        with main_layout.canvas.before:
            Color(*get_color_from_hex(theme['bg']))
            main_layout._bg = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Header
        main_layout.add_widget(self._build_header(theme))

        # Stats bar
        main_layout.add_widget(self._build_stats(theme))

        # Scrollable path list
        scroll = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self.paths_list = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(12),
            padding=[dp(12), dp(12), dp(12), dp(20)]
        )
        self.paths_list.bind(minimum_height=self.paths_list.setter('height'))

        self._populate_paths(theme)

        scroll.add_widget(self.paths_list)
        main_layout.add_widget(scroll)

        self.add_widget(main_layout)

    def _build_header(self, theme) -> BoxLayout:
        """Build header with back button"""
        header = BoxLayout(
            size_hint_y=None, height=dp(52),
            padding=[dp(8), dp(8), dp(8), dp(8)]
        )

        with header.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            header._bg = Rectangle(pos=header.pos, size=header.size)
        header.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        back_btn = Button(
            text='<',
            size_hint=(None, 1), width=dp(44),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(18)
        )
        back_btn.bind(on_press=self._on_back)

        title = Label(
            text='LEARNING PATHS',
            font_size=sp(16), bold=True,
            color=get_color_from_hex(theme['accent'])
        )

        spacer = BoxLayout(size_hint=(None, 1), width=dp(44))

        header.add_widget(back_btn)
        header.add_widget(title)
        header.add_widget(spacer)

        return header

    def _build_stats(self, theme) -> BoxLayout:
        """Build stats bar showing overall progress"""
        tracker = get_progress_tracker()
        stats = tracker.get_stats()

        bar = BoxLayout(
            size_hint_y=None, height=dp(50),
            padding=[dp(16), dp(8), dp(16), dp(8)],
            spacing=dp(20)
        )

        with bar.canvas.before:
            Color(*get_color_from_hex(theme['accent'] + '20'))
            bar._bg = Rectangle(pos=bar.pos, size=bar.size)
        bar.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Lessons completed
        lessons_stat = self._create_stat(
            theme, str(stats['total_lessons_completed']), 'Lessons'
        )

        # Paths completed
        paths_complete = tracker.get_completed_paths_count()
        paths_stat = self._create_stat(theme, str(paths_complete), 'Paths Done')

        bar.add_widget(lessons_stat)
        bar.add_widget(paths_stat)
        bar.add_widget(BoxLayout())  # Spacer

        return bar

    def _create_stat(self, theme, value, label) -> BoxLayout:
        """Create a stat display"""
        stat = BoxLayout(orientation='vertical', size_hint=(None, 1), width=dp(70))

        value_lbl = Label(
            text=value,
            font_size=sp(18),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=0.6
        )
        label_lbl = Label(
            text=label,
            font_size=sp(10),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=0.4
        )

        stat.add_widget(value_lbl)
        stat.add_widget(label_lbl)
        return stat

    def _populate_paths(self, theme):
        """Populate the paths list"""
        self.paths_list.clear_widgets()
        tracker = get_progress_tracker()

        paths = get_all_paths()
        for path in paths:
            lessons_count = len(path['lessons'])
            progress_info = tracker.get_path_progress(path['id'], lessons_count)

            card = PathCard(
                path, theme, progress_info,
                on_select=self._on_path_select
            )
            self.paths_list.add_widget(card)

    def _on_path_select(self, path_data):
        """Handle path selection"""
        self.app.show_lesson(path_data)

    def _on_back(self, instance):
        """Go back to dashboard"""
        self.app.show_dashboard()

    def refresh(self):
        """Rebuild UI"""
        self._build_ui()
