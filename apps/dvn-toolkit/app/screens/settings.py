"""
Settings Screen - App configuration and preferences
"""

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.spinner import Spinner
from kivy.uix.switch import Switch
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp

from ..utils.theme_manager import THEMES
from ..data.persistence import get_settings, get_favorites, get_recents


class SettingsScreen(Screen):
    """App settings and preferences"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        """Build the settings UI"""
        self.clear_widgets()
        theme = self.app.theme_manager.current

        main_layout = BoxLayout(orientation='vertical', spacing=0)

        # Background
        with main_layout.canvas.before:
            Color(*get_color_from_hex(theme['bg']))
            self._bg = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(pos=self._update_bg, size=self._update_bg)

        # Header
        main_layout.add_widget(self._build_header(theme))

        # Scrollable content
        scroll = ScrollView(size_hint=(1, 1))
        content = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(12),
            padding=[dp(12), dp(12), dp(12), dp(12)]
        )
        content.bind(minimum_height=content.setter('height'))

        content.add_widget(self._build_theme_section(theme))
        content.add_widget(self._build_display_section(theme))
        content.add_widget(self._build_data_section(theme))
        content.add_widget(self._build_about_section(theme))

        scroll.add_widget(content)
        main_layout.add_widget(scroll)

        self.add_widget(main_layout)

    def _build_header(self, theme):
        """Build header"""
        header = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(48),
            padding=[dp(10), dp(8), dp(10), dp(8)],
            spacing=dp(8)
        )

        with header.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            header._bg = Rectangle(pos=header.pos, size=header.size)
        header.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        back_btn = Button(
            text='<',
            size_hint=(None, 1),
            width=dp(40),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(16)
        )
        back_btn.bind(on_press=self._on_back)

        title = Label(
            text='SETTINGS',
            font_size=sp(16),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            halign='center',
            valign='middle'
        )

        spacer = BoxLayout(size_hint=(None, 1), width=dp(40))

        header.add_widget(back_btn)
        header.add_widget(title)
        header.add_widget(spacer)

        return header

    def _build_section_card(self, theme, title):
        """Build a section card container"""
        card = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=[dp(10), dp(8), dp(10), dp(8)],
            spacing=dp(8)
        )

        with card.canvas.before:
            Color(*get_color_from_hex(theme['bg_card']))
            card._bg = RoundedRectangle(pos=card.pos, size=card.size, radius=[dp(8)])
        card.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        title_label = Label(
            text=title,
            font_size=sp(13),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(22),
            halign='left',
            valign='middle'
        )
        title_label.bind(size=title_label.setter('text_size'))
        card.add_widget(title_label)

        return card

    def _build_theme_section(self, theme):
        """Build theme selection section"""
        card = self._build_section_card(theme, 'APPEARANCE')

        theme_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(36)
        )

        theme_label = Label(
            text='Theme',
            font_size=sp(12),
            color=get_color_from_hex(theme['text']),
            size_hint_x=0.4,
            halign='left',
            valign='middle'
        )
        theme_label.bind(size=theme_label.setter('text_size'))

        theme_spinner = Spinner(
            text=self.app.theme_manager.name,
            values=[t['name'] for t in THEMES.values()],
            size_hint_x=0.6,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(11)
        )
        theme_spinner.bind(text=self._on_theme_change)

        theme_row.add_widget(theme_label)
        theme_row.add_widget(theme_spinner)
        card.add_widget(theme_row)

        card.height = dp(80)
        return card

    def _build_display_section(self, theme):
        """Build display settings section"""
        card = self._build_section_card(theme, 'DISPLAY')
        settings = get_settings()

        desc_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(36)
        )

        desc_label = Label(
            text='Show descriptions',
            font_size=sp(12),
            color=get_color_from_hex(theme['text']),
            size_hint_x=0.7,
            halign='left',
            valign='middle'
        )
        desc_label.bind(size=desc_label.setter('text_size'))

        desc_switch = Switch(
            active=settings.get('show_descriptions', True),
            size_hint_x=0.3
        )
        desc_switch.bind(active=lambda i, v: settings.set('show_descriptions', v))

        desc_row.add_widget(desc_label)
        desc_row.add_widget(desc_switch)
        card.add_widget(desc_row)

        confirm_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(36)
        )

        confirm_label = Label(
            text='Confirm before run',
            font_size=sp(12),
            color=get_color_from_hex(theme['text']),
            size_hint_x=0.7,
            halign='left',
            valign='middle'
        )
        confirm_label.bind(size=confirm_label.setter('text_size'))

        confirm_switch = Switch(
            active=settings.get('confirm_before_run', False),
            size_hint_x=0.3
        )
        confirm_switch.bind(active=lambda i, v: settings.set('confirm_before_run', v))

        confirm_row.add_widget(confirm_label)
        confirm_row.add_widget(confirm_switch)
        card.add_widget(confirm_row)

        card.height = dp(120)
        return card

    def _build_data_section(self, theme):
        """Build data management section"""
        card = self._build_section_card(theme, 'DATA')

        favorites = get_favorites()
        recents = get_recents()

        stats_label = Label(
            text=f"Favorites: {len(favorites.get_all())}  |  Recent: {len(recents.get_all())}",
            font_size=sp(11),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(22),
            halign='left'
        )
        stats_label.bind(size=stats_label.setter('text_size'))
        card.add_widget(stats_label)

        btn_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(36),
            spacing=dp(8)
        )

        clear_recents_btn = Button(
            text='Clear Recents',
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(11)
        )
        clear_recents_btn.bind(on_press=self._clear_recents)

        clear_all_btn = Button(
            text='Reset All',
            background_normal='',
            background_color=get_color_from_hex(theme['danger']),
            color=get_color_from_hex('#ffffff'),
            font_size=sp(11)
        )
        clear_all_btn.bind(on_press=self._reset_all)

        btn_row.add_widget(clear_recents_btn)
        btn_row.add_widget(clear_all_btn)
        card.add_widget(btn_row)

        card.height = dp(110)
        return card

    def _build_about_section(self, theme):
        """Build about section"""
        card = self._build_section_card(theme, 'ABOUT')

        about_text = """DVN Toolkit v2.0.0
130+ Security & Utility Tools

For authorized testing only.

Created for gh0st - 2026"""

        about_label = Label(
            text=about_text,
            font_size=sp(11),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(100),
            halign='left',
            valign='top'
        )
        about_label.bind(size=about_label.setter('text_size'))
        card.add_widget(about_label)

        card.height = dp(150)
        return card

    def _update_bg(self, *args):
        if hasattr(self, '_bg') and self.children:
            self._bg.pos = self.children[0].pos
            self._bg.size = self.children[0].size

    def _on_back(self, instance):
        self.app.go_to_dashboard()

    def _on_theme_change(self, spinner, text):
        for theme_id, theme_data in THEMES.items():
            if theme_data['name'] == text:
                self.app.set_theme(theme_id)
                break

    def _clear_recents(self, instance):
        recents = get_recents()
        recents.clear()
        self._build_ui()

    def _reset_all(self, instance):
        get_favorites()._favorites = set()
        get_favorites()._save()
        get_recents().clear()
        get_settings().reset()
        self._build_ui()

    def refresh(self):
        self._build_ui()
