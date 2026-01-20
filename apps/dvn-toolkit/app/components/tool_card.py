"""
Tool Card - Card widget for displaying tools in the dashboard
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.behaviors import ButtonBehavior
from kivy.graphics import Color, RoundedRectangle, Line
from kivy.utils import get_color_from_hex
from kivy.properties import StringProperty, BooleanProperty
from kivy.metrics import dp, sp


class ToolCard(ButtonBehavior, BoxLayout):
    """A card widget representing a tool in the dashboard"""

    tool_id = StringProperty('')
    tool_name = StringProperty('')
    tool_desc = StringProperty('')
    tool_icon = StringProperty('')
    category = StringProperty('')
    is_favorite = BooleanProperty(False)

    def __init__(self, tool_data, theme, on_select=None, on_favorite=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.size_hint_x = 1
        self.height = dp(115)
        self.padding = [dp(8), dp(6), dp(8), dp(6)]
        self.spacing = dp(4)

        self.tool_data = tool_data
        self.theme = theme
        self.on_select_callback = on_select
        self.on_favorite_callback = on_favorite

        self.tool_id = tool_data.get('id', '')
        self.tool_name = tool_data.get('name', 'Unknown')
        self.tool_desc = tool_data.get('docs', {}).get('short_desc', '')
        self.tool_icon = tool_data.get('icon', '')
        self.category = tool_data.get('category', '')

        self._build_card()

    def _build_card(self):
        theme = self.theme

        with self.canvas.before:
            Color(*get_color_from_hex(theme['bg_card']))
            self._bg = RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[dp(10)]
            )
            Color(*get_color_from_hex(theme['card_border']))
            self._border = Line(
                rounded_rectangle=(
                    self.pos[0], self.pos[1],
                    self.size[0], self.size[1],
                    dp(10), dp(10), dp(10), dp(10), 50
                ),
                width=1.2
            )

        self.bind(pos=self._update_canvas, size=self._update_canvas)

        # Top row: icon and favorite
        top_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(24)
        )

        icon_label = Label(
            text=self._get_category_icon(),
            font_size=sp(14),
            color=get_color_from_hex(theme['accent']),
            size_hint_x=0.7,
            halign='left',
            valign='middle'
        )
        icon_label.bind(size=icon_label.setter('text_size'))

        self.fav_btn = Button(
            text='[*]' if self.is_favorite else '[ ]',
            size_hint_x=0.3,
            background_normal='',
            background_color=[0, 0, 0, 0],
            color=get_color_from_hex(theme['favorite'] if self.is_favorite else theme['text_dim']),
            font_size=sp(12),
        )
        self.fav_btn.bind(on_press=self._on_favorite_press)

        top_row.add_widget(icon_label)
        top_row.add_widget(self.fav_btn)

        # Tool name
        name_label = Label(
            text=self.tool_name,
            font_size=sp(12),
            bold=True,
            color=get_color_from_hex(theme['text']),
            size_hint_y=None,
            height=dp(24),
            halign='left',
            valign='middle',
            shorten=True,
            shorten_from='right'
        )
        name_label.bind(width=lambda i, w: setattr(i, 'text_size', (w, None)))

        # Description
        desc_label = Label(
            text=self.tool_desc,
            font_size=sp(9),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=1,
            halign='left',
            valign='top',
            shorten=True,
            shorten_from='right',
            max_lines=3
        )
        desc_label.bind(width=lambda i, w: setattr(i, 'text_size', (w, None)))

        self.add_widget(top_row)
        self.add_widget(name_label)
        self.add_widget(desc_label)

    def _get_category_icon(self):
        icons = {
            'offensive': '[!]',
            'security': '[S]',
            'network': '[N]',
            'pentest': '[P]',
            'android': '[A]',
            'crypto': '[C]',
            'osint': '[O]',
            'forensics': '[F]',
            'web': '[W]',
            'cli': '[>]',
            'dev': '[D]',
            'files': '[f]',
            'system': '[~]',
            'productivity': '[+]',
            'media': '[M]',
            'monitor': '[m]',
            'fun': '[*]',
        }
        return icons.get(self.category, '[.]')

    def _update_canvas(self, *args):
        self._bg.pos = self.pos
        self._bg.size = self.size
        self._border.rounded_rectangle = (
            self.pos[0], self.pos[1],
            self.size[0], self.size[1],
            dp(10), dp(10), dp(10), dp(10), 50
        )

    def _on_favorite_press(self, instance):
        if self.on_favorite_callback:
            self.is_favorite = self.on_favorite_callback(self.tool_id)
            self.fav_btn.text = '[*]' if self.is_favorite else '[ ]'
            self.fav_btn.color = get_color_from_hex(
                self.theme['favorite'] if self.is_favorite else self.theme['text_dim']
            )

    def on_release(self):
        if self.on_select_callback:
            self.on_select_callback(self.tool_data)

    def set_favorite(self, is_fav):
        self.is_favorite = is_fav
        self.fav_btn.text = '[*]' if is_fav else '[ ]'
        self.fav_btn.color = get_color_from_hex(
            self.theme['favorite'] if is_fav else self.theme['text_dim']
        )

    def update_theme(self, theme):
        self.theme = theme
        self.canvas.before.clear()
        self.clear_widgets()
        self._build_card()


class ToolCardSmall(ButtonBehavior, BoxLayout):
    """Smaller card for horizontal scroll (favorites/recents)"""

    def __init__(self, tool_data, theme, on_select=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint = (None, None)
        self.size = (dp(100), dp(70))
        self.padding = [dp(6), dp(6), dp(6), dp(6)]
        self.spacing = dp(4)

        self.tool_data = tool_data
        self.theme = theme
        self.on_select_callback = on_select

        self._build_card()

    def _build_card(self):
        theme = self.theme

        with self.canvas.before:
            Color(*get_color_from_hex(theme['bg_card']))
            self._bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(6)])
        self.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        icon = Label(
            text=self._get_icon(),
            font_size=sp(16),
            color=get_color_from_hex(theme['accent']),
            size_hint_y=0.5
        )

        name = Label(
            text=self.tool_data.get('name', ''),
            font_size=sp(9),
            color=get_color_from_hex(theme['text']),
            size_hint_y=0.5,
            halign='center',
            valign='middle',
            shorten=True,
            shorten_from='right'
        )
        name.bind(size=name.setter('text_size'))

        self.add_widget(icon)
        self.add_widget(name)

    def _get_icon(self):
        icons = {
            'offensive': '[!]',
            'security': '[S]',
            'network': '[N]',
            'pentest': '[P]',
            'android': '[A]',
            'crypto': '[C]',
            'osint': '[O]',
            'forensics': '[F]',
            'web': '[W]',
            'cli': '[>]',
            'dev': '[D]',
            'files': '[f]',
            'system': '[~]',
            'productivity': '[+]',
            'media': '[M]',
            'monitor': '[m]',
            'fun': '[*]',
        }
        return icons.get(self.tool_data.get('category', ''), '[.]')

    def on_release(self):
        if self.on_select_callback:
            self.on_select_callback(self.tool_data)
