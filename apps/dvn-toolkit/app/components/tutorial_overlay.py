"""
Tutorial Overlay Component - Interactive tutorial UI overlay
Displays step-by-step guidance on top of tool screens
"""

from kivy.uix.floatlayout import FloatLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.animation import Animation

from ..data.tutorials_registry import get_tutorial, get_tutorial_for_tool


class TutorialOverlay(FloatLayout):
    """Overlay that guides users through tool tutorials"""

    def __init__(self, theme, on_complete=None, on_skip=None, **kwargs):
        super().__init__(**kwargs)
        self.theme = theme
        self.on_complete_callback = on_complete
        self.on_skip_callback = on_skip

        self.tutorial = None
        self.current_step = 0
        self.is_active = False

    def start_tutorial(self, tool_id: str) -> bool:
        """Start a tutorial for a tool"""
        tutorial = get_tutorial_for_tool(tool_id)
        if not tutorial:
            return False

        self.tutorial = tutorial
        self.current_step = 0
        self.is_active = True
        self._show_current_step()
        return True

    def _show_current_step(self):
        """Display the current tutorial step"""
        self.clear_widgets()

        if not self.tutorial or self.current_step >= len(self.tutorial['steps']):
            self._complete()
            return

        step = self.tutorial['steps'][self.current_step]
        step_type = step.get('type', 'explanation')

        # Semi-transparent backdrop
        backdrop = BoxLayout()
        with backdrop.canvas.before:
            Color(0, 0, 0, 0.7)
            backdrop._bg = Rectangle(pos=backdrop.pos, size=backdrop.size)
        backdrop.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )
        self.add_widget(backdrop)

        # Tutorial card
        card = self._build_step_card(step, step_type)
        self.add_widget(card)

    def _build_step_card(self, step: dict, step_type: str) -> BoxLayout:
        """Build the tutorial step card"""
        card = BoxLayout(
            orientation='vertical',
            size_hint=(0.9, None),
            pos_hint={'center_x': 0.5, 'center_y': 0.5},
            padding=[dp(20), dp(16), dp(20), dp(16)],
            spacing=dp(12)
        )

        with card.canvas.before:
            Color(*get_color_from_hex(self.theme['bg_card']))
            card._bg = RoundedRectangle(
                pos=card.pos, size=card.size, radius=[dp(16)]
            )
        card.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Progress indicator
        progress = self._build_progress()
        card.add_widget(progress)

        # Title
        title = Label(
            text=step.get('title', ''),
            font_size=sp(18),
            bold=True,
            color=get_color_from_hex(self.theme['accent']),
            size_hint_y=None,
            height=dp(30),
            halign='center'
        )
        card.add_widget(title)

        # Content based on type
        if step_type in ['welcome', 'explanation', 'complete']:
            content = Label(
                text=step.get('content', ''),
                font_size=sp(13),
                color=get_color_from_hex(self.theme['text']),
                size_hint_y=None,
                halign='left',
                valign='top'
            )
            content.bind(
                width=lambda i, w: setattr(i, 'text_size', (w - dp(20), None)),
                texture_size=lambda i, s: setattr(i, 'height', max(s[1], dp(60)))
            )
            card.add_widget(content)

        elif step_type == 'input_guide':
            instruction = Label(
                text=step.get('instruction', ''),
                font_size=sp(14),
                color=get_color_from_hex(self.theme['text']),
                size_hint_y=None,
                height=dp(50),
                halign='center'
            )
            card.add_widget(instruction)

            if step.get('hint'):
                hint = Label(
                    text=f"Hint: {step['hint']}",
                    font_size=sp(11),
                    color=get_color_from_hex(self.theme['text_dim']),
                    size_hint_y=None,
                    height=dp(30),
                    halign='center'
                )
                card.add_widget(hint)

            if step.get('highlight'):
                highlight_label = Label(
                    text=f"[Field: {step.get('field', '')}]",
                    font_size=sp(12),
                    color=get_color_from_hex(self.theme['accent']),
                    size_hint_y=None,
                    height=dp(24),
                    halign='center'
                )
                card.add_widget(highlight_label)

        elif step_type == 'run_prompt':
            content = Label(
                text=step.get('content', ''),
                font_size=sp(13),
                color=get_color_from_hex(self.theme['text']),
                size_hint_y=None,
                height=dp(60),
                halign='center'
            )
            card.add_widget(content)

        elif step_type == 'output_guide':
            for pattern in step.get('patterns', []):
                row = BoxLayout(size_hint_y=None, height=dp(32))
                match_label = Label(
                    text=pattern['match'],
                    size_hint=(None, 1),
                    width=dp(80),
                    font_size=sp(12),
                    bold=True,
                    color=get_color_from_hex(self.theme['accent'])
                )
                explain_label = Label(
                    text=f"= {pattern['explain']}",
                    font_size=sp(11),
                    color=get_color_from_hex(self.theme['text_dim']),
                    halign='left'
                )
                explain_label.bind(size=explain_label.setter('text_size'))
                row.add_widget(match_label)
                row.add_widget(explain_label)
                card.add_widget(row)

        # Badge for completion
        if step_type == 'complete' and step.get('badge'):
            badge = Label(
                text=f"Badge: {step['badge']}",
                font_size=sp(14),
                bold=True,
                color=get_color_from_hex(self.theme['success']),
                size_hint_y=None,
                height=dp(30)
            )
            card.add_widget(badge)

        # Action buttons
        buttons = self._build_buttons(step_type)
        card.add_widget(buttons)

        # Calculate height
        card.height = dp(280)

        return card

    def _build_progress(self) -> BoxLayout:
        """Build step progress indicator"""
        progress = BoxLayout(
            size_hint_y=None, height=dp(24),
            spacing=dp(6)
        )
        progress.add_widget(BoxLayout())  # Spacer

        total = len(self.tutorial['steps']) if self.tutorial else 1
        for i in range(total):
            dot = Label(
                text='*' if i == self.current_step else 'o',
                size_hint=(None, 1),
                width=dp(16),
                font_size=sp(10),
                color=get_color_from_hex(
                    self.theme['accent'] if i == self.current_step else self.theme['text_dim']
                )
            )
            progress.add_widget(dot)

        progress.add_widget(BoxLayout())  # Spacer
        return progress

    def _build_buttons(self, step_type: str) -> BoxLayout:
        """Build navigation buttons"""
        buttons = BoxLayout(
            size_hint_y=None, height=dp(44),
            spacing=dp(12)
        )

        # Skip button (always available)
        skip_btn = Button(
            text='SKIP',
            size_hint=(None, 1),
            width=dp(70),
            background_normal='',
            background_color=get_color_from_hex(self.theme['button_bg']),
            color=get_color_from_hex(self.theme['text_dim']),
            font_size=sp(11)
        )
        skip_btn.bind(on_press=self._on_skip)
        buttons.add_widget(skip_btn)

        buttons.add_widget(BoxLayout())  # Spacer

        # Next/Done button
        is_last = self.current_step >= len(self.tutorial['steps']) - 1
        next_text = 'DONE' if is_last or step_type == 'complete' else 'NEXT'

        next_btn = Button(
            text=next_text,
            size_hint=(None, 1),
            width=dp(90),
            background_normal='',
            background_color=get_color_from_hex(self.theme['accent']),
            color=get_color_from_hex(self.theme['bg']),
            font_size=sp(12),
            bold=True
        )
        next_btn.bind(on_press=self._on_next)
        buttons.add_widget(next_btn)

        return buttons

    def _on_next(self, instance):
        """Go to next step"""
        if self.current_step >= len(self.tutorial['steps']) - 1:
            self._complete()
        else:
            self.current_step += 1
            self._show_current_step()

    def _on_skip(self, instance):
        """Skip the tutorial"""
        self.is_active = False
        self.clear_widgets()
        if self.on_skip_callback:
            self.on_skip_callback()

    def _complete(self):
        """Complete the tutorial"""
        self.is_active = False
        self.clear_widgets()
        if self.on_complete_callback:
            self.on_complete_callback(self.tutorial)

    def get_current_field(self) -> str:
        """Get the field name being highlighted (if any)"""
        if not self.tutorial or self.current_step >= len(self.tutorial['steps']):
            return None

        step = self.tutorial['steps'][self.current_step]
        if step.get('type') == 'input_guide' and step.get('highlight'):
            return step.get('field')
        return None
