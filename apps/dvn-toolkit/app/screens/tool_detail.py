"""
Tool Detail Screen - Rich documentation and dynamic form
"""

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp

from ..components.form_builder import FormBuilder
from ..data.persistence import get_favorites, get_recents
from ..utils.theme_manager import SKILL_LEVELS
from ..data.tutorials_registry import has_tutorial, get_tutorial_for_tool


class ToolDetailScreen(Screen):
    """Screen showing tool documentation and input form"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.tool_data = None

    def setup_tool(self, tool_data):
        """Setup screen for a specific tool"""
        self.tool_data = tool_data
        self._build_ui()

    def _build_ui(self):
        """Build the detail screen UI"""
        self.clear_widgets()

        if not self.tool_data:
            return

        theme = self.app.theme_manager.current
        tool = self.tool_data

        # Main layout
        main_layout = BoxLayout(orientation='vertical', spacing=0)

        # Background
        with main_layout.canvas.before:
            Color(*get_color_from_hex(theme['bg']))
            self._bg = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(pos=self._update_bg, size=self._update_bg)

        # Header
        main_layout.add_widget(self._build_header(theme, tool))

        # Scrollable content
        scroll = ScrollView(size_hint=(1, 1))
        content = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(10),
            padding=[dp(12), dp(8), dp(12), dp(8)]
        )
        content.bind(minimum_height=content.setter('height'))

        # Documentation card
        content.add_widget(self._build_docs_card(theme, tool))

        # Warnings card (if any)
        warnings = tool.get('docs', {}).get('warnings', [])
        if warnings:
            content.add_widget(self._build_warnings_card(theme, warnings))

        # Form section
        content.add_widget(self._build_form_section(theme, tool))

        scroll.add_widget(content)
        main_layout.add_widget(scroll)

        # Bottom action bar
        main_layout.add_widget(self._build_action_bar(theme))

        self.add_widget(main_layout)

    def _build_header(self, theme, tool):
        """Build the header with back button, title, skill badge, favorite"""
        header = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(70)
        )

        with header.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            header._bg = Rectangle(pos=header.pos, size=header.size)
        header.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        # Top row: back, title, buttons
        top_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(44),
            padding=[dp(10), dp(6), dp(10), dp(2)],
            spacing=dp(8)
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
            text=tool.get('name', 'Tool').upper(),
            font_size=sp(14),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            halign='center',
            valign='middle',
            shorten=True,
            shorten_from='right'
        )
        title.bind(size=title.setter('text_size'))

        favorites = get_favorites()
        is_fav = favorites.is_favorite(tool.get('id', ''))
        self.fav_btn = Button(
            text='[*]' if is_fav else '[ ]',
            size_hint=(None, 1),
            width=dp(36),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['favorite'] if is_fav else theme['text']),
            font_size=sp(12)
        )
        self.fav_btn.bind(on_press=self._on_favorite)

        help_btn = Button(
            text='?',
            size_hint=(None, 1),
            width=dp(36),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['accent']),
            font_size=sp(14)
        )
        help_btn.bind(on_press=self._on_help)

        top_row.add_widget(back_btn)
        top_row.add_widget(title)
        top_row.add_widget(self.fav_btn)
        top_row.add_widget(help_btn)

        # Bottom row: skill level badge
        bottom_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(24),
            padding=[dp(10), dp(0), dp(10), dp(4)]
        )

        skill_level = tool.get('skill_level', 'beginner')
        skill_config = SKILL_LEVELS.get(skill_level, SKILL_LEVELS['beginner'])

        skill_badge = Label(
            text=f"{skill_config['icon']} {skill_config['label']}",
            font_size=sp(9),
            color=get_color_from_hex(skill_config['color']),
            size_hint_x=None,
            width=dp(100),
            halign='left',
            valign='middle'
        )
        skill_badge.bind(size=skill_badge.setter('text_size'))

        category = tool.get('category', '')
        cat_label = Label(
            text=f"Category: {category.upper()}",
            font_size=sp(9),
            color=get_color_from_hex(theme['text_dim']),
            halign='right',
            valign='middle'
        )
        cat_label.bind(size=cat_label.setter('text_size'))

        bottom_row.add_widget(skill_badge)
        bottom_row.add_widget(cat_label)

        header.add_widget(top_row)
        header.add_widget(bottom_row)

        return header

    def _build_docs_card(self, theme, tool):
        """Build the documentation card with concept explanation"""
        docs = tool.get('docs', {})

        card = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=[dp(10), dp(8), dp(10), dp(8)],
            spacing=dp(6)
        )

        with card.canvas.before:
            Color(*get_color_from_hex(theme['bg_card']))
            card._bg = RoundedRectangle(pos=card.pos, size=card.size, radius=[dp(8)])
        card.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        # Short description
        short_desc = Label(
            text=docs.get('short_desc', 'No description'),
            font_size=sp(12),
            color=get_color_from_hex(theme['text']),
            size_hint_y=None,
            height=dp(36),
            halign='left',
            valign='top'
        )
        short_desc.bind(width=lambda i, w: setattr(i, 'text_size', (w, None)))
        short_desc.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(30), v[1])))
        card.add_widget(short_desc)

        # Concept explanation ("What is this?") - if available
        concept = docs.get('concept_explanation', {})
        if concept:
            concept_header = Label(
                text=f"\u2753 {concept.get('title', 'What is this?')}",
                font_size=sp(11),
                bold=True,
                color=get_color_from_hex(theme['warning']),
                size_hint_y=None,
                height=dp(24),
                halign='left',
                valign='middle'
            )
            concept_header.bind(size=concept_header.setter('text_size'))
            card.add_widget(concept_header)

            simple_text = concept.get('simple', '')[:200]
            if len(concept.get('simple', '')) > 200:
                simple_text += '...'
            concept_text = Label(
                text=simple_text,
                font_size=sp(10),
                color=get_color_from_hex(theme['text_dim']),
                size_hint_y=None,
                height=dp(60),
                halign='left',
                valign='top'
            )
            concept_text.bind(width=lambda i, w: setattr(i, 'text_size', (w, None)))
            concept_text.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(40), v[1])))
            card.add_widget(concept_text)

        # Buttons row
        btn_row = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(32),
            spacing=dp(6)
        )

        # Check if tutorial exists for this tool
        tool_id = tool.get('id', '')
        has_tut = has_tutorial(tool_id)

        if has_tut:
            tutorial_btn = Button(
                text='TUTORIAL',
                size_hint_x=0.35,
                background_normal='',
                background_color=get_color_from_hex(theme['accent']),
                color=get_color_from_hex(theme['bg']),
                font_size=sp(10),
                bold=True
            )
            tutorial_btn.bind(on_press=self._start_tutorial)
            btn_row.add_widget(tutorial_btn)

        full_docs_btn = Button(
            text='FULL GUIDE',
            size_hint_x=0.35 if has_tut else 0.5,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['accent']),
            font_size=sp(10)
        )
        full_docs_btn.bind(on_press=self._show_full_docs)

        steps_btn = Button(
            text='STEPS',
            size_hint_x=0.30 if has_tut else 0.5,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['success']),
            font_size=sp(10)
        )
        steps_btn.bind(on_press=self._show_step_by_step)

        btn_row.add_widget(full_docs_btn)
        btn_row.add_widget(steps_btn)
        card.add_widget(btn_row)

        card.bind(minimum_height=card.setter('height'))
        return card

    def _build_warnings_card(self, theme, warnings):
        """Build the warnings card"""
        card = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=[dp(10), dp(8), dp(10), dp(8)],
            spacing=dp(4)
        )

        with card.canvas.before:
            Color(*get_color_from_hex(theme['danger'] + '33'))
            card._bg = RoundedRectangle(pos=card.pos, size=card.size, radius=[dp(6)])
        card.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        header = Label(
            text='! WARNINGS',
            font_size=sp(11),
            bold=True,
            color=get_color_from_hex(theme['danger']),
            size_hint_y=None,
            height=dp(22),
            halign='left',
            valign='middle'
        )
        header.bind(size=header.setter('text_size'))
        card.add_widget(header)

        for warning in warnings:
            item = Label(
                text=f"  - {warning}",
                font_size=sp(10),
                color=get_color_from_hex(theme['warning']),
                size_hint_y=None,
                height=dp(22),
                halign='left',
                valign='top'
            )
            item.bind(width=lambda i, w: setattr(i, 'text_size', (w, None)))
            item.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(20), v[1])))
            card.add_widget(item)

        card.bind(minimum_height=card.setter('height'))
        return card

    def _build_form_section(self, theme, tool):
        """Build the form section"""
        section = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(6)
        )

        header = Label(
            text='INPUT PARAMETERS',
            font_size=sp(11),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(22),
            halign='left',
            valign='middle'
        )
        header.bind(size=header.setter('text_size'))
        section.add_widget(header)

        self.form = FormBuilder(tool, theme)
        self.form.size_hint_y = None
        self.form.bind(minimum_height=self.form.setter('height'))
        section.add_widget(self.form)

        section.bind(minimum_height=section.setter('height'))
        return section

    def _build_action_bar(self, theme):
        """Build the bottom action bar with RUN button"""
        bar = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(56),
            padding=[dp(12), dp(8), dp(12), dp(8)],
            spacing=dp(10)
        )

        with bar.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            bar._bg = Rectangle(pos=bar.pos, size=bar.size)
        bar.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        reset_btn = Button(
            text='RESET',
            size_hint_x=0.3,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(12)
        )
        reset_btn.bind(on_press=self._on_reset)

        run_btn = Button(
            text='> RUN',
            size_hint_x=0.7,
            background_normal='',
            background_color=get_color_from_hex(theme['success']),
            color=get_color_from_hex('#000000'),
            bold=True,
            font_size=sp(14)
        )
        run_btn.bind(on_press=self._on_run)

        bar.add_widget(reset_btn)
        bar.add_widget(run_btn)

        return bar

    def _update_bg(self, *args):
        if hasattr(self, '_bg') and self.children:
            self._bg.pos = self.children[0].pos
            self._bg.size = self.children[0].size

    def _on_back(self, instance):
        self.app.go_to_dashboard()

    def _on_favorite(self, instance):
        if not self.tool_data:
            return
        favorites = get_favorites()
        theme = self.app.theme_manager.current
        is_fav = favorites.toggle(self.tool_data.get('id', ''))
        self.fav_btn.text = '[*]' if is_fav else '[ ]'
        self.fav_btn.color = get_color_from_hex(
            theme['favorite'] if is_fav else theme['text']
        )

    def _on_help(self, instance):
        self._show_full_docs(instance)

    def _start_tutorial(self, instance):
        """Start interactive tutorial for this tool"""
        if not self.tool_data:
            return

        from ..components.tutorial_overlay import TutorialOverlay

        theme = self.app.theme_manager.current
        tool_id = self.tool_data.get('id', '')

        # Create and add tutorial overlay
        self.tutorial_overlay = TutorialOverlay(
            theme,
            on_complete=self._on_tutorial_complete,
            on_skip=self._on_tutorial_skip
        )
        self.tutorial_overlay.start_tutorial(tool_id)
        self.add_widget(self.tutorial_overlay)

    def _on_tutorial_complete(self, tutorial):
        """Handle tutorial completion"""
        if hasattr(self, 'tutorial_overlay'):
            self.remove_widget(self.tutorial_overlay)
            del self.tutorial_overlay

    def _on_tutorial_skip(self):
        """Handle tutorial skip"""
        if hasattr(self, 'tutorial_overlay'):
            self.remove_widget(self.tutorial_overlay)
            del self.tutorial_overlay

    def _show_full_docs(self, instance):
        if not self.tool_data:
            return

        theme = self.app.theme_manager.current
        docs = self.tool_data.get('docs', {})

        content = BoxLayout(
            orientation='vertical',
            padding=[dp(8), dp(8), dp(8), dp(8)],
            spacing=dp(6)
        )

        scroll = ScrollView(size_hint=(1, 1))
        text_box = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(8)
        )
        text_box.bind(minimum_height=text_box.setter('height'))

        # Full description
        full_desc = docs.get('full_desc', 'No detailed description.')
        desc_lbl = Label(
            text=full_desc,
            font_size=sp(11),
            color=get_color_from_hex(theme['text']),
            size_hint_y=None,
            height=dp(80),
            halign='left',
            valign='top'
        )
        desc_lbl.bind(width=lambda i, w: setattr(i, 'text_size', (w - dp(16), None)))
        desc_lbl.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(50), v[1])))
        text_box.add_widget(desc_lbl)

        # Concept explanation if available
        concept = docs.get('concept_explanation', {})
        if concept:
            analogy = concept.get('analogy', '')
            if analogy:
                analogy_header = Label(
                    text='\U0001F4A1 Think of it like...',
                    font_size=sp(11),
                    bold=True,
                    color=get_color_from_hex(theme['warning']),
                    size_hint_y=None,
                    height=dp(24),
                    halign='left'
                )
                analogy_header.bind(size=analogy_header.setter('text_size'))
                text_box.add_widget(analogy_header)

                analogy_lbl = Label(
                    text=analogy,
                    font_size=sp(10),
                    color=get_color_from_hex(theme['text_dim']),
                    size_hint_y=None,
                    height=dp(60),
                    halign='left',
                    valign='top'
                )
                analogy_lbl.bind(width=lambda i, w: setattr(i, 'text_size', (w - dp(16), None)))
                analogy_lbl.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(40), v[1])))
                text_box.add_widget(analogy_lbl)

        # Common mistakes if available
        mistakes = docs.get('common_mistakes', [])
        if mistakes:
            mistakes_header = Label(
                text='\u26A0 Common Mistakes to Avoid',
                font_size=sp(11),
                bold=True,
                color=get_color_from_hex(theme['danger']),
                size_hint_y=None,
                height=dp(24),
                halign='left'
            )
            mistakes_header.bind(size=mistakes_header.setter('text_size'))
            text_box.add_widget(mistakes_header)

            for m in mistakes[:3]:
                mistake_lbl = Label(
                    text=f"\u2717 {m.get('mistake', '')}\n   \u2713 Fix: {m.get('fix', '')}",
                    font_size=sp(9),
                    color=get_color_from_hex(theme['text_dim']),
                    size_hint_y=None,
                    height=dp(36),
                    halign='left',
                    valign='top'
                )
                mistake_lbl.bind(width=lambda i, w: setattr(i, 'text_size', (w - dp(16), None)))
                mistake_lbl.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(30), v[1])))
                text_box.add_widget(mistake_lbl)

        # Legal note if available
        legal = docs.get('legal_note', '')
        if legal:
            legal_lbl = Label(
                text=f"\u2696 {legal}",
                font_size=sp(9),
                color=get_color_from_hex(theme['warning']),
                size_hint_y=None,
                height=dp(40),
                halign='left',
                valign='top'
            )
            legal_lbl.bind(width=lambda i, w: setattr(i, 'text_size', (w - dp(16), None)))
            legal_lbl.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(30), v[1])))
            text_box.add_widget(legal_lbl)

        scroll.add_widget(text_box)
        content.add_widget(scroll)

        close_btn = Button(
            text='CLOSE',
            size_hint_y=None,
            height=dp(36),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(11)
        )

        popup = Popup(
            title=f'{self.tool_data.get("name", "Tool")} - Full Guide',
            content=content,
            size_hint=(0.92, 0.8),
            background_color=get_color_from_hex(theme['bg'])
        )
        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)

        popup.open()

    def _show_step_by_step(self, instance):
        """Show step-by-step guide popup"""
        if not self.tool_data:
            return

        theme = self.app.theme_manager.current
        docs = self.tool_data.get('docs', {})
        steps = docs.get('step_by_step', [])

        content = BoxLayout(
            orientation='vertical',
            padding=[dp(8), dp(8), dp(8), dp(8)],
            spacing=dp(6)
        )

        scroll = ScrollView(size_hint=(1, 1))
        text_box = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(10)
        )
        text_box.bind(minimum_height=text_box.setter('height'))

        if not steps:
            no_steps = Label(
                text='No step-by-step guide available yet.\nCheck the Full Guide for documentation.',
                font_size=sp(11),
                color=get_color_from_hex(theme['text_dim']),
                size_hint_y=None,
                height=dp(60),
                halign='center',
                valign='middle'
            )
            text_box.add_widget(no_steps)
        else:
            for step in steps:
                step_box = BoxLayout(
                    orientation='vertical',
                    size_hint_y=None,
                    spacing=dp(2)
                )

                step_header = Label(
                    text=f"Step {step.get('step', '?')}: {step.get('title', '')}",
                    font_size=sp(11),
                    bold=True,
                    color=get_color_from_hex(theme['accent']),
                    size_hint_y=None,
                    height=dp(24),
                    halign='left'
                )
                step_header.bind(size=step_header.setter('text_size'))
                step_box.add_widget(step_header)

                instruction = Label(
                    text=step.get('instruction', ''),
                    font_size=sp(10),
                    color=get_color_from_hex(theme['text']),
                    size_hint_y=None,
                    height=dp(40),
                    halign='left',
                    valign='top'
                )
                instruction.bind(width=lambda i, w: setattr(i, 'text_size', (w - dp(16), None)))
                instruction.bind(texture_size=lambda i, v: setattr(i, 'height', max(dp(30), v[1])))
                step_box.add_widget(instruction)

                tip = step.get('tip', '')
                if tip:
                    tip_lbl = Label(
                        text=f"\U0001F4A1 Tip: {tip}",
                        font_size=sp(9),
                        color=get_color_from_hex(theme['success']),
                        size_hint_y=None,
                        height=dp(24),
                        halign='left'
                    )
                    tip_lbl.bind(size=tip_lbl.setter('text_size'))
                    step_box.add_widget(tip_lbl)

                step_box.bind(minimum_height=step_box.setter('height'))
                text_box.add_widget(step_box)

        scroll.add_widget(text_box)
        content.add_widget(scroll)

        close_btn = Button(
            text='GOT IT',
            size_hint_y=None,
            height=dp(36),
            background_normal='',
            background_color=get_color_from_hex(theme['success']),
            color=get_color_from_hex('#000000'),
            font_size=sp(11)
        )

        popup = Popup(
            title=f'{self.tool_data.get("name", "Tool")} - Step by Step',
            content=content,
            size_hint=(0.92, 0.75),
            background_color=get_color_from_hex(theme['bg'])
        )
        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)

        popup.open()

    def _on_reset(self, instance):
        if hasattr(self, 'form'):
            self.form.reset()

    def _on_run(self, instance):
        if not self.tool_data or not hasattr(self, 'form'):
            return

        is_valid, error = self.form.validate()
        if not is_valid:
            self._show_error(error)
            return

        command = self.form.build_command()
        recents = get_recents()
        recents.add(self.tool_data.get('id', ''))

        self.app.run_tool(self.tool_data, self.form.get_values(), command)

    def _show_error(self, message):
        theme = self.app.theme_manager.current
        content = BoxLayout(
            orientation='vertical',
            padding=[dp(16), dp(16), dp(16), dp(16)]
        )

        label = Label(
            text=message,
            font_size=sp(13),
            color=get_color_from_hex(theme['danger'])
        )
        content.add_widget(label)

        ok_btn = Button(
            text='OK',
            size_hint_y=None,
            height=dp(36),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(12)
        )

        popup = Popup(
            title='Error',
            content=content,
            size_hint=(0.7, 0.3),
            background_color=get_color_from_hex(theme['bg'])
        )
        ok_btn.bind(on_press=popup.dismiss)
        content.add_widget(ok_btn)

        popup.open()

    def refresh(self):
        if self.tool_data:
            self._build_ui()
