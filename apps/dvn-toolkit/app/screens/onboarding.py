"""
Onboarding Screen - First-time user experience
4-slide introduction with skill level selection
"""

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, Rectangle, RoundedRectangle, Ellipse
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.animation import Animation

from ..data.persistence import get_settings


SLIDES = [
    {
        'title': 'DVN TOOLKIT',
        'icon': '***',
        'subtitle': '130+ Security & Utility Tools',
        'description': 'Your Swiss Army Knife for\ndigital reconnaissance',
        'highlight': None
    },
    {
        'title': 'TOOL CATEGORIES',
        'icon': '=',
        'subtitle': '',
        'description': None,
        'categories': [
            ('***', 'Offensive', 'Pentest tools'),
            ('(!)', 'Security', 'Defensive tools'),
            ('<->', 'Network', 'Discovery & recon'),
            ('(?)', 'OSINT', 'Intelligence gathering'),
            ('[#]', 'Android', 'Mobile testing'),
        ]
    },
    {
        'title': 'IMPORTANT',
        'icon': '!',
        'subtitle': 'Use Responsibly',
        'description': None,
        'rules': [
            ('v', 'Only scan YOUR systems'),
            ('v', 'Get PERMISSION first'),
            ('v', 'Use for LEARNING'),
            ('v', 'CTFs and authorized testing'),
            ('x', 'Never scan without consent'),
            ('x', "Don't use for malicious acts"),
        ]
    },
    {
        'title': 'CHOOSE YOUR PATH',
        'icon': '*',
        'subtitle': "What's your experience level?",
        'description': None,
        'skill_select': True
    }
]


class OnboardingScreen(Screen):
    """Onboarding screen with 4 slides"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.current_slide = 0
        self._build_ui()

    def _build_ui(self):
        """Build the onboarding UI"""
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

        # Content area
        self.content = BoxLayout(
            orientation='vertical',
            padding=[dp(24), dp(40), dp(24), dp(20)],
            spacing=dp(16)
        )
        self._build_slide(theme)

        # Navigation area
        nav = self._build_nav(theme)

        main_layout.add_widget(self.content)
        main_layout.add_widget(nav)

        self.add_widget(main_layout)

    def _build_slide(self, theme):
        """Build current slide content"""
        self.content.clear_widgets()
        slide = SLIDES[self.current_slide]

        # Icon
        icon = Label(
            text=slide['icon'],
            font_size=sp(48),
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(80)
        )
        self.content.add_widget(icon)

        # Title
        title = Label(
            text=slide['title'],
            font_size=sp(24),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(40)
        )
        self.content.add_widget(title)

        # Subtitle
        if slide['subtitle']:
            subtitle = Label(
                text=slide['subtitle'],
                font_size=sp(14),
                color=get_color_from_hex(theme['text']),
                size_hint_y=None,
                height=dp(30)
            )
            self.content.add_widget(subtitle)

        # Description
        if slide.get('description'):
            desc = Label(
                text=slide['description'],
                font_size=sp(16),
                color=get_color_from_hex(theme['text_dim']),
                size_hint_y=None,
                height=dp(60),
                halign='center'
            )
            desc.bind(size=desc.setter('text_size'))
            self.content.add_widget(desc)

        # Categories list (slide 2)
        if slide.get('categories'):
            self.content.add_widget(BoxLayout(size_hint_y=0.1))
            for icon_txt, name, desc in slide['categories']:
                row = self._build_category_row(theme, icon_txt, name, desc)
                self.content.add_widget(row)

        # Rules list (slide 3)
        if slide.get('rules'):
            self.content.add_widget(BoxLayout(size_hint_y=0.1))
            for check, text in slide['rules']:
                row = self._build_rule_row(theme, check, text)
                self.content.add_widget(row)

        # Skill selection (slide 4)
        if slide.get('skill_select'):
            self.content.add_widget(BoxLayout(size_hint_y=0.1))
            skills = [
                ('beginner', '*', 'BEGINNER', 'New to security tools'),
                ('intermediate', '**', 'INTERMEDIATE', 'Some CLI experience'),
                ('advanced', '***', 'ADVANCED', 'Experienced pentester'),
            ]
            for skill_id, stars, name, desc in skills:
                btn = self._build_skill_button(theme, skill_id, stars, name, desc)
                self.content.add_widget(btn)

        # Spacer
        self.content.add_widget(BoxLayout())

    def _build_category_row(self, theme, icon, name, desc) -> BoxLayout:
        """Build a category row for slide 2"""
        row = BoxLayout(size_hint_y=None, height=dp(36), spacing=dp(12))

        icon_lbl = Label(
            text=icon,
            size_hint=(None, 1),
            width=dp(40),
            font_size=sp(14),
            color=get_color_from_hex(theme['accent'])
        )
        name_lbl = Label(
            text=name,
            size_hint=(None, 1),
            width=dp(90),
            font_size=sp(13),
            bold=True,
            color=get_color_from_hex(theme['text']),
            halign='left'
        )
        name_lbl.bind(size=name_lbl.setter('text_size'))
        desc_lbl = Label(
            text=f"- {desc}",
            font_size=sp(12),
            color=get_color_from_hex(theme['text_dim']),
            halign='left'
        )
        desc_lbl.bind(size=desc_lbl.setter('text_size'))

        row.add_widget(icon_lbl)
        row.add_widget(name_lbl)
        row.add_widget(desc_lbl)
        return row

    def _build_rule_row(self, theme, check, text) -> BoxLayout:
        """Build a rule row for slide 3"""
        row = BoxLayout(size_hint_y=None, height=dp(32), spacing=dp(12))

        color = theme['success'] if check == 'v' else theme['danger']
        icon = Label(
            text=f"[{check}]",
            size_hint=(None, 1),
            width=dp(40),
            font_size=sp(14),
            color=get_color_from_hex(color)
        )
        text_lbl = Label(
            text=text,
            font_size=sp(13),
            color=get_color_from_hex(theme['text']),
            halign='left'
        )
        text_lbl.bind(size=text_lbl.setter('text_size'))

        row.add_widget(icon)
        row.add_widget(text_lbl)
        return row

    def _build_skill_button(self, theme, skill_id, stars, name, desc) -> Button:
        """Build a skill selection button for slide 4"""
        btn = Button(
            text=f"{stars}  {name}\n{desc}",
            size_hint_y=None,
            height=dp(60),
            background_normal='',
            background_color=get_color_from_hex(theme['bg_card']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(13),
            halign='center'
        )
        btn.skill_id = skill_id
        btn.bind(on_press=self._on_skill_select)
        return btn

    def _build_nav(self, theme) -> BoxLayout:
        """Build navigation area with dots and buttons"""
        nav = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(100),
            padding=[dp(24), dp(12), dp(24), dp(24)],
            spacing=dp(16)
        )

        # Dots indicator
        dots = BoxLayout(
            size_hint_y=None,
            height=dp(20),
            spacing=dp(8)
        )
        dots.add_widget(BoxLayout())  # Spacer
        for i in range(len(SLIDES)):
            dot = Label(
                text='*' if i == self.current_slide else 'o',
                size_hint=(None, 1),
                width=dp(20),
                font_size=sp(12),
                color=get_color_from_hex(
                    theme['accent'] if i == self.current_slide else theme['text_dim']
                )
            )
            dots.add_widget(dot)
        dots.add_widget(BoxLayout())  # Spacer

        # Buttons row
        buttons = BoxLayout(spacing=dp(12))

        if self.current_slide > 0:
            back_btn = Button(
                text='< BACK',
                size_hint=(None, 1),
                width=dp(80),
                background_normal='',
                background_color=get_color_from_hex(theme['button_bg']),
                color=get_color_from_hex(theme['text']),
                font_size=sp(12)
            )
            back_btn.bind(on_press=self._on_back)
            buttons.add_widget(back_btn)
        else:
            buttons.add_widget(BoxLayout(size_hint=(None, 1), width=dp(80)))

        buttons.add_widget(BoxLayout())  # Spacer

        if self.current_slide < len(SLIDES) - 1:
            next_btn = Button(
                text='NEXT >',
                size_hint=(None, 1),
                width=dp(80),
                background_normal='',
                background_color=get_color_from_hex(theme['accent']),
                color=get_color_from_hex(theme['bg']),
                font_size=sp(12)
            )
            next_btn.bind(on_press=self._on_next)
            buttons.add_widget(next_btn)

        nav.add_widget(dots)
        nav.add_widget(buttons)
        return nav

    def _on_back(self, instance):
        """Go to previous slide"""
        if self.current_slide > 0:
            self.current_slide -= 1
            self._build_ui()

    def _on_next(self, instance):
        """Go to next slide"""
        if self.current_slide < len(SLIDES) - 1:
            self.current_slide += 1
            self._build_ui()

    def _on_skill_select(self, instance):
        """Handle skill level selection"""
        settings = get_settings()
        settings.set('skill_level', instance.skill_id)
        settings.set('onboarding_complete', True)
        self.app.show_dashboard()

    def refresh(self):
        """Rebuild UI"""
        self._build_ui()
