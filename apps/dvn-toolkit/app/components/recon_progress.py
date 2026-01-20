"""
Recon Progress Component - Multi-tool progress tracker for Identity Recon
Shows overall progress and individual tool status
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.progressbar import ProgressBar
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.animation import Animation


class ReconProgress(BoxLayout):
    """Progress tracker showing overall and per-tool status"""

    def __init__(self, theme, tools=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(200)
        self.spacing = dp(8)
        self.padding = [dp(12), dp(8), dp(12), dp(8)]

        self.theme = theme
        self.tools = tools or []
        self.tool_widgets = {}

        self._build_ui()

    def _build_ui(self):
        """Build the progress component UI"""
        # Background
        with self.canvas.before:
            Color(*get_color_from_hex(self.theme['bg_secondary']))
            self._bg = RoundedRectangle(
                pos=self.pos, size=self.size, radius=[dp(12)]
            )
        self.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Header row
        header = BoxLayout(size_hint_y=None, height=dp(28))

        self.status_label = Label(
            text='Ready to scan',
            font_size=sp(14),
            bold=True,
            color=get_color_from_hex(self.theme['accent']),
            halign='left',
            valign='middle'
        )
        self.status_label.bind(size=self.status_label.setter('text_size'))

        self.count_label = Label(
            text='0/0',
            size_hint=(None, 1),
            width=dp(50),
            font_size=sp(12),
            color=get_color_from_hex(self.theme['text_dim']),
            halign='right',
            valign='middle'
        )
        self.count_label.bind(size=self.count_label.setter('text_size'))

        header.add_widget(self.status_label)
        header.add_widget(self.count_label)

        # Overall progress bar
        self.progress_bar = ProgressBar(
            max=100,
            value=0,
            size_hint_y=None,
            height=dp(8)
        )

        # Tool status list (scrollable)
        scroll = ScrollView(
            size_hint_y=1,
            do_scroll_x=False,
            do_scroll_y=True,
            bar_width=dp(3)
        )

        self.tools_list = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(4),
            padding=[0, dp(8), 0, 0]
        )
        self.tools_list.bind(minimum_height=self.tools_list.setter('height'))

        scroll.add_widget(self.tools_list)

        self.add_widget(header)
        self.add_widget(self.progress_bar)
        self.add_widget(scroll)

        # Populate initial tools
        if self.tools:
            self.set_tools(self.tools)

    def set_tools(self, tools: list):
        """Set the list of tools to track"""
        self.tools = tools
        self.tools_list.clear_widgets()
        self.tool_widgets = {}

        for tool in tools:
            row = self._create_tool_row(tool)
            self.tools_list.add_widget(row)
            self.tool_widgets[tool['id']] = row

        self.count_label.text = f"0/{len(tools)}"

    def _create_tool_row(self, tool: dict) -> BoxLayout:
        """Create a single tool status row"""
        row = BoxLayout(
            size_hint_y=None,
            height=dp(28),
            spacing=dp(8)
        )

        # Status icon
        status_icon = Label(
            text='[ ]',
            size_hint=(None, 1),
            width=dp(24),
            font_size=sp(12),
            color=get_color_from_hex(self.theme['text_dim']),
            halign='center'
        )
        row.status_icon = status_icon

        # Tool name
        name_label = Label(
            text=tool['name'],
            font_size=sp(12),
            color=get_color_from_hex(self.theme['text']),
            halign='left',
            valign='middle'
        )
        name_label.bind(size=name_label.setter('text_size'))
        row.name_label = name_label

        # Status text
        status_text = Label(
            text='pending',
            size_hint=(None, 1),
            width=dp(70),
            font_size=sp(10),
            color=get_color_from_hex(self.theme['text_dim']),
            halign='right',
            valign='middle'
        )
        status_text.bind(size=status_text.setter('text_size'))
        row.status_text = status_text

        row.tool_id = tool['id']
        row.add_widget(status_icon)
        row.add_widget(name_label)
        row.add_widget(status_text)

        return row

    def update_tool_status(self, tool_id: str, status: str):
        """Update status of a specific tool"""
        if tool_id not in self.tool_widgets:
            return

        row = self.tool_widgets[tool_id]

        if status == 'running':
            row.status_icon.text = '[>]'
            row.status_icon.color = get_color_from_hex(self.theme['accent'])
            row.status_text.text = 'running...'
            row.status_text.color = get_color_from_hex(self.theme['accent'])
            self.status_label.text = f"Running: {row.name_label.text}"

        elif status == 'complete':
            row.status_icon.text = '[v]'
            row.status_icon.color = get_color_from_hex(self.theme['success'])
            row.status_text.text = 'complete'
            row.status_text.color = get_color_from_hex(self.theme['success'])

        elif status == 'error':
            row.status_icon.text = '[x]'
            row.status_icon.color = get_color_from_hex(self.theme['danger'])
            row.status_text.text = 'error'
            row.status_text.color = get_color_from_hex(self.theme['danger'])

        elif status == 'skipped':
            row.status_icon.text = '[-]'
            row.status_icon.color = get_color_from_hex(self.theme['text_dim'])
            row.status_text.text = 'skipped'

        # Update overall progress
        self._update_overall_progress()

    def _update_overall_progress(self):
        """Update overall progress bar and count"""
        completed = sum(
            1 for w in self.tool_widgets.values()
            if w.status_text.text in ['complete', 'error', 'skipped']
        )
        total = len(self.tools)

        self.count_label.text = f"{completed}/{total}"

        if total > 0:
            progress = (completed / total) * 100
            anim = Animation(value=progress, duration=0.3)
            anim.start(self.progress_bar)

        if completed == total:
            self.status_label.text = 'Scan complete!'
            self.status_label.color = get_color_from_hex(self.theme['success'])

    def reset(self):
        """Reset all progress"""
        self.progress_bar.value = 0
        self.status_label.text = 'Ready to scan'
        self.status_label.color = get_color_from_hex(self.theme['accent'])
        self.count_label.text = f"0/{len(self.tools)}"

        for row in self.tool_widgets.values():
            row.status_icon.text = '[ ]'
            row.status_icon.color = get_color_from_hex(self.theme['text_dim'])
            row.status_text.text = 'pending'
            row.status_text.color = get_color_from_hex(self.theme['text_dim'])

    def set_error(self, message: str):
        """Show error state"""
        self.status_label.text = f"Error: {message}"
        self.status_label.color = get_color_from_hex(self.theme['danger'])
