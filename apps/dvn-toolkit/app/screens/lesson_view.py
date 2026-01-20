"""
Lesson View Screen - Display individual lessons with exercises
Guides users through learning objectives with associated tools
"""

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp

from ..data.paths_registry import get_path, get_lesson
from ..data.progress_tracker import get_progress_tracker
from ..data.tool_registry import TOOLS


class LessonViewScreen(Screen):
    """View for a single lesson"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.current_path = None
        self.current_lesson = None
        self.lesson_index = 0
        self._build_ui()

    def setup_lesson(self, path_data, lesson_index=None):
        """Set up the screen for a specific path/lesson"""
        self.current_path = path_data
        tracker = get_progress_tracker()

        # Use provided index or get current from tracker
        if lesson_index is not None:
            self.lesson_index = lesson_index
        else:
            self.lesson_index = tracker.get_current_lesson_index(path_data['id'])

        # Clamp to valid range
        max_index = len(path_data['lessons']) - 1
        self.lesson_index = max(0, min(self.lesson_index, max_index))

        self.current_lesson = path_data['lessons'][self.lesson_index]

        # Mark path as started
        tracker.start_path(path_data['id'])

        self._build_ui()

    def _build_ui(self):
        """Build the lesson view UI"""
        self.clear_widgets()
        theme = self.app.theme_manager.current

        if not self.current_lesson:
            return

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

        # Progress bar
        main_layout.add_widget(self._build_progress_bar(theme))

        # Scrollable content
        scroll = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        content = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(16),
            padding=[dp(16), dp(12), dp(16), dp(20)]
        )
        content.bind(minimum_height=content.setter('height'))

        # Lesson title
        title = Label(
            text=self.current_lesson['title'],
            font_size=sp(20),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(36),
            halign='left'
        )
        title.bind(size=title.setter('text_size'))
        content.add_widget(title)

        # Objective
        objective_card = self._build_card(
            theme, 'OBJECTIVE', self.current_lesson['objective']
        )
        content.add_widget(objective_card)

        # Content
        content_card = self._build_content_card(theme)
        content.add_widget(content_card)

        # Exercise
        if self.current_lesson.get('exercise'):
            exercise_card = self._build_exercise_card(theme)
            content.add_widget(exercise_card)

        # Tool info
        tool_card = self._build_tool_card(theme)
        content.add_widget(tool_card)

        scroll.add_widget(content)
        main_layout.add_widget(scroll)

        # Bottom actions
        main_layout.add_widget(self._build_actions(theme))

        self.add_widget(main_layout)

    def _build_header(self, theme) -> BoxLayout:
        """Build header with navigation"""
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

        path_name = self.current_path['name'] if self.current_path else ''
        title = Label(
            text=path_name,
            font_size=sp(14),
            color=get_color_from_hex(theme['text']),
            halign='center'
        )

        lesson_num = f"{self.lesson_index + 1}/{len(self.current_path['lessons'])}"
        counter = Label(
            text=lesson_num,
            size_hint=(None, 1), width=dp(44),
            font_size=sp(12),
            color=get_color_from_hex(theme['text_dim'])
        )

        header.add_widget(back_btn)
        header.add_widget(title)
        header.add_widget(counter)

        return header

    def _build_progress_bar(self, theme) -> BoxLayout:
        """Build lesson progress bar"""
        from kivy.uix.progressbar import ProgressBar

        container = BoxLayout(size_hint_y=None, height=dp(8))

        total = len(self.current_path['lessons']) if self.current_path else 1
        progress = ((self.lesson_index + 1) / total) * 100

        bar = ProgressBar(max=100, value=progress)
        container.add_widget(bar)

        return container

    def _build_card(self, theme, title, content) -> BoxLayout:
        """Build a simple card with title and content"""
        card = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=[dp(14), dp(12), dp(14), dp(12)],
            spacing=dp(8)
        )

        with card.canvas.before:
            Color(*get_color_from_hex(theme['bg_card']))
            card._bg = RoundedRectangle(
                pos=card.pos, size=card.size, radius=[dp(10)]
            )
        card.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        title_lbl = Label(
            text=title,
            font_size=sp(11),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(20),
            halign='left'
        )
        title_lbl.bind(size=title_lbl.setter('text_size'))

        content_lbl = Label(
            text=content,
            font_size=sp(13),
            color=get_color_from_hex(theme['text']),
            size_hint_y=None,
            halign='left',
            valign='top'
        )
        content_lbl.bind(
            width=lambda i, w: setattr(i, 'text_size', (w, None)),
            texture_size=lambda i, s: setattr(i, 'height', s[1])
        )

        card.add_widget(title_lbl)
        card.add_widget(content_lbl)
        card.bind(minimum_height=card.setter('height'))

        return card

    def _build_content_card(self, theme) -> BoxLayout:
        """Build the main lesson content card"""
        return self._build_card(theme, 'LEARN', self.current_lesson['content'])

    def _build_exercise_card(self, theme) -> BoxLayout:
        """Build the exercise card"""
        exercise = self.current_lesson['exercise']
        content = f"{exercise['instruction']}\n\nHint: {exercise.get('hint', '')}"
        return self._build_card(theme, 'EXERCISE', content)

    def _build_tool_card(self, theme) -> BoxLayout:
        """Build card showing the associated tool"""
        tool_id = self.current_lesson.get('tool_id')
        tool = TOOLS.get(tool_id, {})

        card = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(80),
            padding=[dp(14), dp(12), dp(14), dp(12)],
            spacing=dp(8)
        )

        with card.canvas.before:
            Color(*get_color_from_hex(theme['accent'] + '20'))
            card._bg = RoundedRectangle(
                pos=card.pos, size=card.size, radius=[dp(10)]
            )
        card.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        header = BoxLayout(size_hint_y=None, height=dp(24))
        label = Label(
            text='TOOL FOR THIS LESSON:',
            font_size=sp(10),
            color=get_color_from_hex(theme['text_dim']),
            halign='left'
        )
        label.bind(size=label.setter('text_size'))
        header.add_widget(label)

        tool_name = Label(
            text=tool.get('name', tool_id),
            font_size=sp(14),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(24),
            halign='left'
        )
        tool_name.bind(size=tool_name.setter('text_size'))

        card.add_widget(header)
        card.add_widget(tool_name)

        return card

    def _build_actions(self, theme) -> BoxLayout:
        """Build bottom action buttons"""
        actions = BoxLayout(
            size_hint_y=None, height=dp(70),
            padding=[dp(16), dp(12), dp(16), dp(16)],
            spacing=dp(12)
        )

        with actions.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            actions._bg = Rectangle(pos=actions.pos, size=actions.size)
        actions.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Try Tool button
        try_btn = Button(
            text='TRY TOOL',
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(12)
        )
        try_btn.bind(on_press=self._on_try_tool)

        # Complete / Next button
        is_last = self.lesson_index >= len(self.current_path['lessons']) - 1
        next_text = 'COMPLETE PATH' if is_last else 'NEXT LESSON'

        next_btn = Button(
            text=next_text,
            background_normal='',
            background_color=get_color_from_hex(theme['accent']),
            color=get_color_from_hex(theme['bg']),
            font_size=sp(12),
            bold=True
        )
        next_btn.bind(on_press=self._on_next)

        actions.add_widget(try_btn)
        actions.add_widget(next_btn)

        return actions

    def _on_try_tool(self, instance):
        """Open the associated tool"""
        tool_id = self.current_lesson.get('tool_id')
        if tool_id and tool_id in TOOLS:
            self.app.show_tool_detail(TOOLS[tool_id])

    def _on_next(self, instance):
        """Go to next lesson or complete path"""
        tracker = get_progress_tracker()

        # Mark current lesson complete
        tracker.complete_lesson(
            self.current_path['id'],
            self.current_lesson['id'],
            self.lesson_index
        )

        # Check if path complete
        if self.lesson_index >= len(self.current_path['lessons']) - 1:
            tracker.complete_path(self.current_path['id'])
            self.app.show_learning_paths()
        else:
            # Go to next lesson
            self.lesson_index += 1
            self.current_lesson = self.current_path['lessons'][self.lesson_index]
            self._build_ui()

    def _on_back(self, instance):
        """Go back to learning paths"""
        self.app.show_learning_paths()

    def refresh(self):
        """Rebuild UI"""
        self._build_ui()
