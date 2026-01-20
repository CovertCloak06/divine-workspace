"""
Recon Input Component - Smart input with auto-detection for Identity Recon
Shows detected input type in real-time with visual feedback
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.clock import Clock

from ..data.input_detector import detect_input_type, get_input_type_info


class ReconInput(BoxLayout):
    """Smart input field with auto-detection of input type"""

    def __init__(self, theme, on_change=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(120)
        self.spacing = dp(8)
        self.padding = [dp(16), dp(12), dp(16), dp(12)]

        self.theme = theme
        self.on_change = on_change
        self.detected_type = None
        self.detected_details = {}
        self.confidence = 0.0

        self._build_ui()

    def _build_ui(self):
        """Build the input component UI"""
        # Input container with border
        input_container = BoxLayout(
            size_hint_y=None,
            height=dp(52)
        )

        with input_container.canvas.before:
            Color(*get_color_from_hex(self.theme['bg_secondary']))
            input_container._bg = RoundedRectangle(
                pos=input_container.pos,
                size=input_container.size,
                radius=[dp(12)]
            )
        input_container.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # The actual input field
        self.input_field = TextInput(
            hint_text='Enter email, username, domain, or IP...',
            multiline=False,
            background_color=[0, 0, 0, 0],
            foreground_color=get_color_from_hex(self.theme['text']),
            hint_text_color=get_color_from_hex(self.theme['text_dim']),
            font_size=sp(16),
            padding=[dp(16), dp(14), dp(50), dp(14)]
        )
        self.input_field.bind(text=self._on_text_change)

        # Clear button
        self.clear_btn = Button(
            text='X',
            size_hint=(None, None),
            size=(dp(36), dp(36)),
            pos_hint={'center_y': 0.5},
            background_normal='',
            background_color=get_color_from_hex(self.theme['button_bg']),
            color=get_color_from_hex(self.theme['text_dim']),
            font_size=sp(14),
            opacity=0
        )
        self.clear_btn.bind(on_press=self._on_clear)

        input_container.add_widget(self.input_field)
        input_container.add_widget(self.clear_btn)

        # Detection indicator row
        self.indicator_row = BoxLayout(
            size_hint_y=None,
            height=dp(32),
            spacing=dp(8)
        )

        # Type badge
        self.type_badge = Label(
            text='',
            size_hint=(None, 1),
            width=dp(100),
            font_size=sp(12),
            bold=True,
            halign='left',
            valign='middle'
        )
        self.type_badge.bind(size=self.type_badge.setter('text_size'))

        # Detected value display
        self.detected_label = Label(
            text='',
            font_size=sp(12),
            color=get_color_from_hex(self.theme['text_dim']),
            halign='left',
            valign='middle'
        )
        self.detected_label.bind(size=self.detected_label.setter('text_size'))

        self.indicator_row.add_widget(self.type_badge)
        self.indicator_row.add_widget(self.detected_label)

        self.add_widget(input_container)
        self.add_widget(self.indicator_row)

    def _on_text_change(self, instance, value):
        """Handle text input changes"""
        # Show/hide clear button
        self.clear_btn.opacity = 1 if value else 0

        # Debounce detection
        Clock.unschedule(self._do_detection)
        Clock.schedule_once(self._do_detection, 0.2)

    def _do_detection(self, dt):
        """Perform input type detection"""
        text = self.input_field.text.strip()

        if not text:
            self._update_indicator(None, 0, {})
            return

        input_type, confidence, details = detect_input_type(text)
        self._update_indicator(input_type, confidence, details)

        # Notify callback
        if self.on_change:
            self.on_change(text, input_type, confidence, details)

    def _update_indicator(self, input_type, confidence, details):
        """Update the detection indicator display"""
        self.detected_type = input_type
        self.confidence = confidence
        self.detected_details = details

        if not input_type or input_type == 'unknown':
            self.type_badge.text = ''
            self.detected_label.text = ''
            return

        info = get_input_type_info(input_type)
        color = info['color']

        # Update badge
        self.type_badge.text = f"[{info['icon']}] {info['name']}"
        self.type_badge.color = get_color_from_hex(color)

        # Update detected details
        if input_type == 'email' and 'domain' in details:
            self.detected_label.text = f"Provider: {details['domain']}"
        elif input_type == 'ip' and details.get('is_private'):
            self.detected_label.text = "Private/Local IP"
        elif input_type == 'domain' and details.get('tld'):
            self.detected_label.text = f"TLD: .{details['tld']}"
        else:
            self.detected_label.text = f"Confidence: {int(confidence * 100)}%"

    def _on_clear(self, instance):
        """Clear the input field"""
        self.input_field.text = ''
        self.input_field.focus = True

    def get_value(self) -> str:
        """Get the current input value"""
        return self.input_field.text.strip()

    def get_detection(self) -> tuple:
        """Get the current detection result"""
        return self.detected_type, self.confidence, self.detected_details

    def set_value(self, text: str):
        """Set the input value programmatically"""
        self.input_field.text = text
