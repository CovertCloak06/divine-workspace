"""
Profile Card Component - Display result cards for Identity Recon
Organized by category with expandable sections
"""

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.uix.behaviors import ButtonBehavior

from ..data.recon_orchestrator import get_result_categories


class ResultCard(ButtonBehavior, BoxLayout):
    """A single expandable result card"""

    def __init__(self, title, icon, theme, content='', expanded=False, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.padding = [dp(12), dp(10), dp(12), dp(10)]
        self.spacing = dp(6)

        self.theme = theme
        self.title = title
        self.icon = icon
        self.content = content
        self.expanded = expanded

        self._build_ui()
        self._update_height()

    def _build_ui(self):
        """Build the card UI"""
        # Background
        with self.canvas.before:
            Color(*get_color_from_hex(self.theme['bg_card']))
            self._bg = RoundedRectangle(
                pos=self.pos, size=self.size, radius=[dp(10)]
            )
        self.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Header row
        header = BoxLayout(size_hint_y=None, height=dp(28))

        # Icon and title
        self.title_label = Label(
            text=f"{self.icon} {self.title}",
            font_size=sp(13),
            bold=True,
            color=get_color_from_hex(self.theme['accent']),
            halign='left',
            valign='middle'
        )
        self.title_label.bind(size=self.title_label.setter('text_size'))

        # Expand/collapse indicator
        self.expand_label = Label(
            text='v' if self.expanded else '>',
            size_hint=(None, 1),
            width=dp(24),
            font_size=sp(14),
            color=get_color_from_hex(self.theme['text_dim'])
        )

        header.add_widget(self.title_label)
        header.add_widget(self.expand_label)

        # Content area
        self.content_label = Label(
            text=self.content,
            font_size=sp(11),
            color=get_color_from_hex(self.theme['text']),
            halign='left',
            valign='top',
            size_hint_y=None,
            text_size=(None, None)
        )
        self.content_label.bind(texture_size=self._on_texture_size)

        self.add_widget(header)
        self.add_widget(self.content_label)

        self.bind(on_press=self._toggle_expand)

    def _on_texture_size(self, instance, size):
        """Update content label height based on text"""
        if self.expanded:
            instance.height = size[1]
            instance.text_size = (instance.width - dp(10), None)
        self._update_height()

    def _update_height(self):
        """Update card height based on expand state"""
        if self.expanded:
            content_height = self.content_label.texture_size[1] if self.content else dp(20)
            self.height = dp(48) + content_height + dp(10)
            self.content_label.opacity = 1
        else:
            self.height = dp(48)
            self.content_label.opacity = 0

    def _toggle_expand(self, instance):
        """Toggle expanded state"""
        self.expanded = not self.expanded
        self.expand_label.text = 'v' if self.expanded else '>'

        # Update content text_size for wrapping
        if self.expanded:
            self.content_label.text_size = (self.width - dp(34), None)

        self._update_height()

    def set_content(self, content: str):
        """Update the card content"""
        self.content = content
        self.content_label.text = content
        if self.expanded:
            self.content_label.text_size = (self.width - dp(34), None)


class ProfileResults(BoxLayout):
    """Container for all result cards organized by category"""

    def __init__(self, theme, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.spacing = dp(10)
        self.padding = [dp(12), dp(8), dp(12), dp(8)]

        self.theme = theme
        self.category_cards = {}
        self.results = {}

        self.bind(minimum_height=self.setter('height'))
        self._build_categories()

    def _build_categories(self):
        """Build result cards for each category"""
        categories = get_result_categories()

        icons = {
            'identity': '@',
            'social': '*',
            'search': '?',
            'domain': 'www',
            'network': '#',
            'services': '[]'
        }

        for cat_id, cat_info in categories.items():
            icon = icons.get(cat_id, '>')
            card = ResultCard(
                title=cat_info['name'],
                icon=icon,
                theme=self.theme,
                content='No results yet',
                expanded=False
            )
            self.category_cards[cat_id] = card
            self.add_widget(card)

    def update_results(self, results: dict):
        """Update results from tool outputs"""
        self.results = results
        categories = get_result_categories()

        for cat_id, cat_info in categories.items():
            # Gather results from tools in this category
            cat_results = []
            for tool_id in cat_info['tools']:
                if tool_id in results:
                    result = results[tool_id]
                    if result.get('status') == 'complete':
                        output = result.get('output', '')
                        if output:
                            cat_results.append(f"[{tool_id}]\n{output[:500]}")

            # Update card content
            if cat_results:
                content = '\n\n'.join(cat_results)
                self.category_cards[cat_id].set_content(content)
            else:
                self.category_cards[cat_id].set_content('No results')

    def clear_results(self):
        """Clear all results"""
        self.results = {}
        for card in self.category_cards.values():
            card.set_content('No results yet')
            card.expanded = False
            card._update_height()


class ProfileSummary(BoxLayout):
    """Summary header for a profile"""

    def __init__(self, theme, input_value='', input_type='', **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(80)
        self.padding = [dp(16), dp(12), dp(16), dp(12)]
        self.spacing = dp(4)

        self.theme = theme

        # Background
        with self.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            self._bg = RoundedRectangle(
                pos=self.pos, size=self.size, radius=[dp(12)]
            )
        self.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Target value
        self.target_label = Label(
            text=input_value or 'No target',
            font_size=sp(16),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(24),
            halign='left',
            valign='middle'
        )
        self.target_label.bind(size=self.target_label.setter('text_size'))

        # Type badge
        self.type_label = Label(
            text=f"Type: {input_type.upper()}" if input_type else '',
            font_size=sp(12),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(20),
            halign='left',
            valign='middle'
        )
        self.type_label.bind(size=self.type_label.setter('text_size'))

        self.add_widget(self.target_label)
        self.add_widget(self.type_label)

    def update(self, input_value: str, input_type: str):
        """Update the summary display"""
        self.target_label.text = input_value or 'No target'
        self.type_label.text = f"Type: {input_type.upper()}" if input_type else ''
