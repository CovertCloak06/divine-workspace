"""
Form Builder - Dynamic form generation from tool metadata
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.graphics import Color, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp

from .input_fields import create_input_field


class PresetButton(Button):
    """Button for applying a preset"""

    def __init__(self, preset, theme, on_apply=None, **kwargs):
        super().__init__(**kwargs)
        self.preset = preset
        self.on_apply_callback = on_apply

        preset_name = preset.get('name', 'Preset')
        self.text = preset_name
        self.size_hint = (None, None)
        # Dynamic width based on text length
        btn_width = max(dp(80), len(preset_name) * dp(9) + dp(20))
        self.size = (btn_width, dp(34))
        self.background_normal = ''
        self.background_color = get_color_from_hex(theme['button_bg'])
        self.color = get_color_from_hex(theme['accent'])
        self.font_size = '11sp'

        self.bind(on_press=self._on_press)

    def _on_press(self, instance):
        if self.on_apply_callback:
            self.on_apply_callback(self.preset.get('values', {}))


class FormBuilder(BoxLayout):
    """Builds dynamic forms from tool input definitions"""

    def __init__(self, tool_data, theme, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 8
        self.padding = [12, 8, 12, 8]

        self.tool_data = tool_data
        self.theme = theme
        self.fields = {}  # name -> field widget

        self._build_form()

    def _build_form(self):
        """Build the form UI"""
        theme = self.theme
        tool = self.tool_data

        # Form container with background
        with self.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            self._bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[10])

        self.bind(pos=self._update_bg, size=self._update_bg)

        # Presets section (if any)
        presets = tool.get('presets', [])
        if presets:
            presets_label = Label(
                text='PRESETS',
                font_size='11sp',
                color=get_color_from_hex(theme['text_dim']),
                size_hint_y=None,
                height=20,
                halign='left',
                valign='middle'
            )
            presets_label.bind(size=presets_label.setter('text_size'))
            self.add_widget(presets_label)

            # Horizontal scroll for presets
            presets_scroll = ScrollView(
                size_hint_y=None,
                height=40,
                do_scroll_x=True,
                do_scroll_y=False
            )

            presets_row = BoxLayout(
                orientation='horizontal',
                size_hint_x=None,
                spacing=8
            )
            presets_row.bind(minimum_width=presets_row.setter('width'))

            for preset in presets:
                btn = PresetButton(preset, theme, on_apply=self.apply_preset)
                presets_row.add_widget(btn)

            presets_scroll.add_widget(presets_row)
            self.add_widget(presets_scroll)

            # Spacer
            self.add_widget(BoxLayout(size_hint_y=None, height=8))

        # Form fields
        inputs = tool.get('inputs', [])
        for input_config in inputs:
            field = create_input_field(input_config, theme)
            self.fields[input_config['name']] = field
            self.add_widget(field)

    def _update_bg(self, *args):
        self._bg.pos = self.pos
        self._bg.size = self.size

    def get_values(self):
        """Get all form values as a dict"""
        values = {}
        for name, field in self.fields.items():
            value = field.get_value()
            if value is not None and value != '':
                values[name] = value
        return values

    def set_values(self, values):
        """Set multiple form values"""
        for name, value in values.items():
            if name in self.fields:
                self.fields[name].set_value(value)

    def apply_preset(self, preset_values):
        """Apply a preset's values to the form"""
        self.set_values(preset_values)

    def reset(self):
        """Reset all fields to defaults"""
        for input_config in self.tool_data.get('inputs', []):
            name = input_config.get('name')
            default = input_config.get('default', '')
            if name in self.fields:
                self.fields[name].set_value(default)

    def validate(self):
        """Validate required fields, returns (is_valid, error_message)"""
        for input_config in self.tool_data.get('inputs', []):
            if input_config.get('required', False):
                name = input_config.get('name')
                if name in self.fields:
                    value = self.fields[name].get_value()
                    if value is None or value == '':
                        return False, f"{input_config.get('label', name)} is required"
        return True, None

    def build_command(self):
        """Build the command string from form values"""
        tool = self.tool_data
        values = self.get_values()

        parts = [tool.get('script', '')]

        for input_config in tool.get('inputs', []):
            name = input_config.get('name')
            value = values.get(name)

            if value is None or value == '':
                continue

            flag = input_config.get('flag')
            input_type = input_config.get('type')

            if input_type == 'checkbox':
                if value:
                    parts.append(flag)
            elif flag:
                # Flag-based argument
                if input_type == 'dropdown':
                    default = input_config.get('default')
                    if value != default:
                        parts.append(f"{flag} {value}")
                else:
                    parts.append(f"{flag} {value}")
            else:
                # Positional argument
                parts.append(str(value))

        return ' '.join(parts)


class CompactFormBuilder(FormBuilder):
    """More compact form for smaller screens"""

    def __init__(self, tool_data, theme, **kwargs):
        kwargs['spacing'] = 4
        kwargs['padding'] = [8, 4, 8, 4]
        super().__init__(tool_data, theme, **kwargs)
