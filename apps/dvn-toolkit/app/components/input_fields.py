"""
Input Fields - Enhanced dynamic form input components
Visual borders, type icons, focus states, required badges
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.uix.checkbox import CheckBox
from kivy.uix.button import Button
from kivy.graphics import Color, RoundedRectangle, Line
from kivy.utils import get_color_from_hex
from kivy.properties import StringProperty, BooleanProperty
from kivy.metrics import dp, sp

from ..utils.theme_manager import INPUT_TYPE_ICONS


class BaseInputField(BoxLayout):
    """Base class for all input fields with enhanced visuals"""

    field_name = StringProperty('')
    field_label = StringProperty('')
    help_text = StringProperty('')
    is_required = BooleanProperty(False)

    def __init__(self, field_config, theme, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.spacing = dp(4)
        self.padding = [0, dp(4), 0, dp(4)]

        self.field_config = field_config
        self.theme = theme
        self.field_type = field_config.get('type', 'text')

        self.field_name = field_config.get('name', '')
        self.field_label = field_config.get('label', '')
        self.help_text = field_config.get('help', '')
        self.is_required = field_config.get('required', False)

    def get_value(self):
        return None

    def set_value(self, value):
        pass

    def _create_label_row(self):
        """Create label row with type icon and required badge"""
        row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(24),
            spacing=dp(6)
        )

        # Type icon
        icon = INPUT_TYPE_ICONS.get(self.field_type, 'Aa')
        icon_label = Label(
            text=icon,
            font_size=sp(12),
            color=get_color_from_hex(self.theme['accent']),
            size_hint_x=None,
            width=dp(24),
            halign='center',
            valign='middle'
        )

        # Field label
        label = Label(
            text=self.field_label,
            font_size=sp(11),
            bold=True,
            color=get_color_from_hex(self.theme['text']),
            halign='left',
            valign='middle'
        )
        label.bind(size=label.setter('text_size'))

        row.add_widget(icon_label)
        row.add_widget(label)

        # Required badge
        if self.is_required:
            req_badge = Label(
                text='REQUIRED',
                font_size=sp(8),
                color=get_color_from_hex(self.theme['danger']),
                size_hint_x=None,
                width=dp(55),
                halign='center',
                valign='middle'
            )
            row.add_widget(req_badge)

        return row

    def _create_help_label(self):
        """Create help text with example format"""
        if not self.help_text:
            return None

        help_label = Label(
            text=f"\u2139 {self.help_text}",
            font_size=sp(9),
            color=get_color_from_hex(self.theme['text_dim']),
            size_hint_y=None,
            height=dp(20),
            halign='left',
            valign='top'
        )
        help_label.bind(width=lambda i, w: setattr(i, 'text_size', (w, None)))
        return help_label


class TextInputField(BaseInputField):
    """Enhanced text input with visible border and focus state"""

    def __init__(self, field_config, theme, **kwargs):
        super().__init__(field_config, theme, **kwargs)
        self.height = dp(90) if self.help_text else dp(72)
        self.is_focused = False

        self.add_widget(self._create_label_row())

        # Input container with border
        self.input_container = BoxLayout(
            size_hint_y=None,
            height=dp(40),
            padding=[dp(2), dp(2), dp(2), dp(2)]
        )

        # Draw background and border
        with self.input_container.canvas.before:
            # Background
            Color(*get_color_from_hex(theme['terminal_bg']))
            self._bg = RoundedRectangle(
                pos=self.input_container.pos,
                size=self.input_container.size,
                radius=[dp(8)]
            )
            # Border
            Color(*get_color_from_hex(theme['card_border']))
            self._border = Line(
                rounded_rectangle=(0, 0, 100, 40, dp(8), dp(8), dp(8), dp(8), 50),
                width=1.5
            )

        self.input_container.bind(pos=self._update_graphics, size=self._update_graphics)

        # Text input
        placeholder = field_config.get('placeholder', '')
        example = field_config.get('format_example', '')
        hint = f"{placeholder}" if placeholder else f"Enter {self.field_label.lower()}..."

        self.text_input = TextInput(
            hint_text=hint,
            text=str(field_config.get('default', '')),
            multiline=False,
            background_color=[0, 0, 0, 0],
            foreground_color=get_color_from_hex(theme['text']),
            hint_text_color=get_color_from_hex(theme['text_dim']),
            cursor_color=get_color_from_hex(theme['accent']),
            font_size=sp(12),
            padding=[dp(12), dp(10), dp(12), dp(10)]
        )
        self.text_input.bind(focus=self._on_focus)

        self.input_container.add_widget(self.text_input)
        self.add_widget(self.input_container)

        help_label = self._create_help_label()
        if help_label:
            self.add_widget(help_label)

    def _update_graphics(self, *args):
        self._bg.pos = self.input_container.pos
        self._bg.size = self.input_container.size
        self._border.rounded_rectangle = (
            self.input_container.pos[0], self.input_container.pos[1],
            self.input_container.size[0], self.input_container.size[1],
            dp(8), dp(8), dp(8), dp(8), 50
        )

    def _on_focus(self, instance, value):
        """Change border color on focus"""
        self.is_focused = value
        # Update border color
        self.input_container.canvas.before.clear()
        with self.input_container.canvas.before:
            Color(*get_color_from_hex(self.theme['terminal_bg']))
            self._bg = RoundedRectangle(
                pos=self.input_container.pos,
                size=self.input_container.size,
                radius=[dp(8)]
            )
            border_color = self.theme['accent'] if value else self.theme['card_border']
            Color(*get_color_from_hex(border_color))
            self._border = Line(
                rounded_rectangle=(
                    self.input_container.pos[0], self.input_container.pos[1],
                    self.input_container.size[0], self.input_container.size[1],
                    dp(8), dp(8), dp(8), dp(8), 50
                ),
                width=2 if value else 1.5
            )

    def get_value(self):
        return self.text_input.text.strip()

    def set_value(self, value):
        self.text_input.text = str(value) if value else ''


class NumberInputField(TextInputField):
    """Number input with numeric filter"""

    def __init__(self, field_config, theme, **kwargs):
        super().__init__(field_config, theme, **kwargs)
        self.text_input.input_filter = 'int'

    def get_value(self):
        text = self.text_input.text.strip()
        if text:
            try:
                return int(text)
            except ValueError:
                return None
        return None


class DropdownField(BaseInputField):
    """Enhanced dropdown with border"""

    def __init__(self, field_config, theme, **kwargs):
        super().__init__(field_config, theme, **kwargs)
        self.field_type = 'dropdown'
        self.height = dp(90) if self.help_text else dp(72)

        self.add_widget(self._create_label_row())

        options = field_config.get('options', [])
        option_labels = [opt.get('label', opt.get('value', '')) for opt in options]
        default = field_config.get('default', '')

        default_label = option_labels[0] if option_labels else ''
        for opt in options:
            if opt.get('value') == default:
                default_label = opt.get('label', default)
                break

        # Container with border
        container = BoxLayout(size_hint_y=None, height=dp(40))
        with container.canvas.before:
            Color(*get_color_from_hex(theme['button_bg']))
            container._bg = RoundedRectangle(radius=[dp(8)])
            Color(*get_color_from_hex(theme['card_border']))
            container._border = Line(
                rounded_rectangle=(0, 0, 100, 40, dp(8), dp(8), dp(8), dp(8), 50),
                width=1.5
            )
        container.bind(
            pos=lambda i, v: self._update_container(i),
            size=lambda i, v: self._update_container(i)
        )

        self.spinner = Spinner(
            text=default_label,
            values=option_labels,
            background_normal='',
            background_color=[0, 0, 0, 0],
            color=get_color_from_hex(theme['text']),
            font_size=sp(12)
        )
        container.add_widget(self.spinner)
        self.add_widget(container)

        help_label = self._create_help_label()
        if help_label:
            self.add_widget(help_label)

        self._options = options
        self._container = container

    def _update_container(self, instance):
        instance._bg.pos = instance.pos
        instance._bg.size = instance.size
        instance._border.rounded_rectangle = (
            instance.pos[0], instance.pos[1],
            instance.size[0], instance.size[1],
            dp(8), dp(8), dp(8), dp(8), 50
        )

    def get_value(self):
        selected_label = self.spinner.text
        for opt in self._options:
            if opt.get('label') == selected_label:
                return opt.get('value', selected_label)
        return selected_label

    def set_value(self, value):
        for opt in self._options:
            if opt.get('value') == value:
                self.spinner.text = opt.get('label', value)
                return
        self.spinner.text = str(value)


class CheckboxField(BaseInputField):
    """Enhanced checkbox with clear label"""

    def __init__(self, field_config, theme, **kwargs):
        super().__init__(field_config, theme, **kwargs)
        self.field_type = 'checkbox'
        self.height = dp(60) if self.help_text else dp(42)

        row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(36),
            spacing=dp(8)
        )

        self.checkbox = CheckBox(
            active=field_config.get('default', False),
            size_hint_x=None,
            width=dp(36),
            color=get_color_from_hex(theme['accent'])
        )

        label = Label(
            text=self.field_label,
            font_size=sp(12),
            color=get_color_from_hex(theme['text']),
            halign='left',
            valign='middle'
        )
        label.bind(size=label.setter('text_size'))

        row.add_widget(self.checkbox)
        row.add_widget(label)

        if self.is_required:
            req_badge = Label(
                text='REQUIRED',
                font_size=sp(8),
                color=get_color_from_hex(theme['danger']),
                size_hint_x=None,
                width=dp(55)
            )
            row.add_widget(req_badge)

        self.add_widget(row)

        help_label = self._create_help_label()
        if help_label:
            self.add_widget(help_label)

    def get_value(self):
        return self.checkbox.active

    def set_value(self, value):
        self.checkbox.active = bool(value)


class FileInputField(BaseInputField):
    """Enhanced file picker with border"""

    def __init__(self, field_config, theme, **kwargs):
        super().__init__(field_config, theme, **kwargs)
        self.field_type = 'file'
        self.height = dp(90) if self.help_text else dp(72)

        self.add_widget(self._create_label_row())

        file_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(40),
            spacing=dp(8)
        )

        # Input with border
        input_container = BoxLayout(size_hint_x=0.7)
        with input_container.canvas.before:
            Color(*get_color_from_hex(theme['terminal_bg']))
            input_container._bg = RoundedRectangle(radius=[dp(8)])
            Color(*get_color_from_hex(theme['card_border']))
            input_container._border = Line(
                rounded_rectangle=(0, 0, 100, 40, dp(8), dp(8), dp(8), dp(8), 50),
                width=1.5
            )
        input_container.bind(
            pos=lambda i, v: self._update_input_container(i),
            size=lambda i, v: self._update_input_container(i)
        )

        self.path_input = TextInput(
            hint_text='Tap Browse to select...',
            multiline=False,
            background_color=[0, 0, 0, 0],
            foreground_color=get_color_from_hex(theme['text']),
            hint_text_color=get_color_from_hex(theme['text_dim']),
            font_size=sp(11),
            padding=[dp(10), dp(10), dp(10), dp(10)]
        )

        input_container.add_widget(self.path_input)
        self._input_container = input_container

        browse_btn = Button(
            text='\U0001F4C1 Browse',
            size_hint_x=0.3,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['accent']),
            font_size=sp(11)
        )
        browse_btn.bind(on_press=self._on_browse)

        file_row.add_widget(input_container)
        file_row.add_widget(browse_btn)
        self.add_widget(file_row)

        help_label = self._create_help_label()
        if help_label:
            self.add_widget(help_label)

    def _update_input_container(self, instance):
        instance._bg.pos = instance.pos
        instance._bg.size = instance.size
        instance._border.rounded_rectangle = (
            instance.pos[0], instance.pos[1],
            instance.size[0], instance.size[1],
            dp(8), dp(8), dp(8), dp(8), 50
        )

    def _on_browse(self, instance):
        pass

    def get_value(self):
        return self.path_input.text.strip()

    def set_value(self, value):
        self.path_input.text = str(value) if value else ''


def create_input_field(field_config, theme):
    """Create an input field based on type"""
    field_type = field_config.get('type', 'text')

    field_classes = {
        'text': TextInputField,
        'ip': TextInputField,
        'url': TextInputField,
        'port_range': TextInputField,
        'number': NumberInputField,
        'dropdown': DropdownField,
        'checkbox': CheckboxField,
        'file': FileInputField,
    }

    field_class = field_classes.get(field_type, TextInputField)
    return field_class(field_config, theme)
