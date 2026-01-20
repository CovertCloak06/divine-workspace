"""
Dashboard Screen - Card-based main screen with favorites, recents, and search
Architecture: Fixed header/search/tabs/nav with scrollable content area
"""

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.utils import get_color_from_hex
from kivy.clock import Clock
from kivy.metrics import dp, sp

from ..components.tool_card import ToolCard, ToolCardSmall
from ..data.tool_registry import TOOLS, CATEGORIES, get_tools_by_category, search_tools
from ..data.persistence import get_favorites, get_recents


class DashboardScreen(Screen):
    """Main dashboard with card-based tool browser"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.search_query = ''
        self.current_category = 'all'
        self._build_ui()

    def _build_ui(self):
        """Build dashboard with 4 FIXED sections + 1 scrollable area"""
        self.clear_widgets()
        theme = self.app.theme_manager.current

        # Main vertical layout
        main_layout = BoxLayout(orientation='vertical', spacing=0)

        # Background
        with main_layout.canvas.before:
            Color(*get_color_from_hex(theme['bg']))
            self._bg = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(pos=self._update_bg, size=self._update_bg)

        # 1. FIXED: Header
        main_layout.add_widget(self._build_header(theme))

        # 2. FIXED: Search bar
        main_layout.add_widget(self._build_search(theme))

        # 3. FIXED: Category tabs (NOT inside scroll!)
        self.tabs_section = self._build_category_tabs(theme)
        main_layout.add_widget(self.tabs_section)

        # 4. SCROLLABLE: Content (favorites, recents, cards)
        self.content_scroll = self._build_scrollable_content(theme)
        main_layout.add_widget(self.content_scroll)

        # 5. FIXED: Bottom navigation
        main_layout.add_widget(self._build_bottom_nav(theme))

        self.main_layout = main_layout
        self.add_widget(main_layout)

    def _build_header(self, theme):
        """Compact header with title and buttons"""
        header = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(48),
            padding=[dp(12), dp(8), dp(12), dp(8)]
        )

        with header.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            header._bg = Rectangle(pos=header.pos, size=header.size)
        header.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        # Title only - settings accessible via bottom nav
        title = Label(
            text='DVN TOOLKIT',
            font_size=sp(18),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            size_hint_x=1,
            halign='left',
            valign='middle'
        )
        title.bind(size=title.setter('text_size'))

        header.add_widget(title)

        return header

    def _build_search(self, theme):
        """Search bar section"""
        container = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(52),
            padding=[dp(12), dp(6), dp(12), dp(6)]
        )

        # Search background
        search_bg = BoxLayout(size_hint_x=1)
        with search_bg.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            search_bg._bg = RoundedRectangle(
                pos=search_bg.pos, size=search_bg.size, radius=[dp(20)]
            )
        search_bg.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        self.search_input = TextInput(
            hint_text='Search tools...',
            multiline=False,
            background_color=[0, 0, 0, 0],
            foreground_color=get_color_from_hex(theme['text']),
            hint_text_color=get_color_from_hex(theme['text_dim']),
            font_size=sp(14),
            padding=[dp(16), dp(10), dp(16), dp(10)]
        )
        self.search_input.bind(text=self._on_search_text)

        search_bg.add_widget(self.search_input)
        container.add_widget(search_bg)

        return container

    def _build_category_tabs(self, theme):
        """Category filter tabs - FIXED position, always visible"""
        container = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(44),
            padding=[dp(8), dp(4), dp(8), dp(4)]
        )

        # Horizontal scroll for tabs
        scroll = ScrollView(
            size_hint=(1, 1),
            do_scroll_x=True,
            do_scroll_y=False,
            bar_width=0
        )

        # Row of tab buttons
        self.tabs_row = BoxLayout(
            orientation='horizontal',
            size_hint=(None, 1),
            spacing=dp(10),
            padding=[dp(4), 0, dp(4), 0]
        )
        self.tabs_row.bind(minimum_width=self.tabs_row.setter('width'))

        # Build category buttons
        categories = [('all', 'All')]
        for cat_id in ['offensive', 'security', 'network', 'android', 'cli', 'dev']:
            if cat_id in CATEGORIES:
                categories.append((cat_id, CATEGORIES[cat_id]['name']))

        for cat_id, name in categories:
            btn = self._create_tab_button(cat_id, name, theme)
            self.tabs_row.add_widget(btn)

        scroll.add_widget(self.tabs_row)
        container.add_widget(scroll)

        return container

    def _create_tab_button(self, cat_id, name, theme):
        """Create a category tab button with proper sizing"""
        # Width: generous calculation using dp
        btn_width = max(dp(56), len(name) * dp(9) + dp(28))

        selected = (cat_id == self.current_category)
        btn = Button(
            text=name,
            size_hint=(None, None),
            size=(btn_width, dp(32)),
            background_normal='',
            background_color=get_color_from_hex(
                theme['accent'] if selected else theme['button_bg']
            ),
            color=get_color_from_hex(
                theme['bg'] if selected else theme['text']
            ),
            font_size=sp(12)
        )
        btn.cat_id = cat_id
        btn.bind(on_press=self._on_tab_press)

        return btn

    def _build_scrollable_content(self, theme):
        """Scrollable area: favorites, recents, and tool cards"""
        scroll = ScrollView(
            size_hint=(1, 1),
            do_scroll_x=False,
            do_scroll_y=True,
            bar_width=dp(4)
        )

        self.content_layout = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(6),
            padding=[0, dp(4), 0, dp(8)]
        )
        self.content_layout.bind(minimum_height=self.content_layout.setter('height'))

        self._populate_content(theme)

        scroll.add_widget(self.content_layout)
        return scroll

    def _populate_content(self, theme):
        """Fill scrollable content with sections"""
        self.content_layout.clear_widgets()

        # Identity Recon banner (prominent feature)
        recon_banner = self._build_recon_banner(theme)
        self.content_layout.add_widget(recon_banner)

        # Favorites row (if any)
        fav_section = self._build_favorites(theme)
        if fav_section:
            self.content_layout.add_widget(fav_section)

        # Recents row (if any)
        recent_section = self._build_recents(theme)
        if recent_section:
            self.content_layout.add_widget(recent_section)

        # Tool cards grid
        self.cards_grid = self._build_cards_grid(theme)
        self.content_layout.add_widget(self.cards_grid)

    def _build_recon_banner(self, theme):
        """Build Identity Recon feature banner"""
        from kivy.uix.behaviors import ButtonBehavior

        class ReconBanner(ButtonBehavior, BoxLayout):
            pass

        banner = ReconBanner(
            orientation='vertical',
            size_hint_y=None,
            height=dp(80),
            padding=[dp(16), dp(12), dp(16), dp(12)]
        )

        with banner.canvas.before:
            Color(*get_color_from_hex(theme['accent'] + '30'))
            banner._bg = RoundedRectangle(
                pos=banner.pos, size=banner.size, radius=[dp(12)]
            )
        banner.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        # Title row
        title_row = BoxLayout(size_hint_y=None, height=dp(28))
        icon = Label(
            text='[?]',
            size_hint=(None, 1),
            width=dp(30),
            font_size=sp(18),
            color=get_color_from_hex(theme['accent'])
        )
        title = Label(
            text='IDENTITY RECON',
            font_size=sp(16),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            halign='left',
            valign='middle'
        )
        title.bind(size=title.setter('text_size'))
        arrow = Label(
            text='>',
            size_hint=(None, 1),
            width=dp(24),
            font_size=sp(16),
            color=get_color_from_hex(theme['accent'])
        )
        title_row.add_widget(icon)
        title_row.add_widget(title)
        title_row.add_widget(arrow)

        # Subtitle
        subtitle = Label(
            text='Search by email, username, domain, or IP',
            font_size=sp(12),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(20),
            halign='left',
            valign='middle'
        )
        subtitle.bind(size=subtitle.setter('text_size'))

        banner.add_widget(title_row)
        banner.add_widget(subtitle)
        banner.bind(on_press=self._on_recon_press)

        return banner

    def _on_recon_press(self, instance):
        """Navigate to Identity Recon screen"""
        self.app.show_identity_recon()

    def _build_favorites(self, theme):
        """Favorites horizontal scroll row"""
        favorites = get_favorites()
        fav_ids = favorites.get_all()

        if not fav_ids:
            return None

        section = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(95),
            padding=[dp(12), dp(4), dp(12), dp(4)]
        )

        # Header
        header = Label(
            text='* FAVORITES',
            font_size=sp(11),
            color=get_color_from_hex(theme['accent']),
            size_hint_y=None,
            height=dp(20),
            halign='left',
            valign='middle'
        )
        header.bind(size=header.setter('text_size'))
        section.add_widget(header)

        # Horizontal scroll
        scroll = ScrollView(
            size_hint_y=None,
            height=dp(70),
            do_scroll_x=True,
            do_scroll_y=False,
            bar_width=0
        )

        row = BoxLayout(
            orientation='horizontal',
            size_hint=(None, 1),
            spacing=dp(8)
        )
        row.bind(minimum_width=row.setter('width'))

        for tool_id in fav_ids[:10]:
            if tool_id in TOOLS:
                card = ToolCardSmall(TOOLS[tool_id], theme, on_select=self._on_tool_select)
                row.add_widget(card)

        scroll.add_widget(row)
        section.add_widget(scroll)

        return section

    def _build_recents(self, theme):
        """Recents horizontal scroll row"""
        recents = get_recents()
        recent_ids = recents.get_all()

        if not recent_ids:
            return None

        section = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(95),
            padding=[dp(12), dp(4), dp(12), dp(4)]
        )

        # Header
        header = Label(
            text='> RECENT',
            font_size=sp(11),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(20),
            halign='left',
            valign='middle'
        )
        header.bind(size=header.setter('text_size'))
        section.add_widget(header)

        # Horizontal scroll
        scroll = ScrollView(
            size_hint_y=None,
            height=dp(70),
            do_scroll_x=True,
            do_scroll_y=False,
            bar_width=0
        )

        row = BoxLayout(
            orientation='horizontal',
            size_hint=(None, 1),
            spacing=dp(8)
        )
        row.bind(minimum_width=row.setter('width'))

        for tool_id in recent_ids[:5]:
            if tool_id in TOOLS:
                card = ToolCardSmall(TOOLS[tool_id], theme, on_select=self._on_tool_select)
                row.add_widget(card)

        scroll.add_widget(row)
        section.add_widget(scroll)

        return section

    def _build_cards_grid(self, theme):
        """Tool cards grid - returns grid directly (no wrapper)"""
        grid = GridLayout(
            cols=2,
            spacing=dp(10),
            padding=[dp(10), dp(6), dp(10), dp(10)],
            size_hint_y=None,
            row_default_height=dp(120),
            row_force_default=True
        )
        grid.bind(minimum_height=grid.setter('height'))

        self._populate_cards(grid, theme)

        return grid

    def _populate_cards(self, grid, theme):
        """Fill grid with tool cards based on current filter"""
        grid.clear_widgets()

        favorites = get_favorites()

        # Get tools based on filter
        if self.search_query:
            tools = search_tools(self.search_query)
        elif self.current_category == 'all':
            tools = list(TOOLS.values())
        else:
            tools = get_tools_by_category(self.current_category)

        for tool in tools:
            is_fav = favorites.is_favorite(tool['id'])
            card = ToolCard(
                tool, theme,
                on_select=self._on_tool_select,
                on_favorite=self._on_toggle_favorite
            )
            card.set_favorite(is_fav)
            grid.add_widget(card)

    def _build_bottom_nav(self, theme):
        """Bottom navigation bar"""
        nav = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(56),
            padding=[dp(8), dp(6), dp(8), dp(6)],
            spacing=dp(4)
        )

        with nav.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            nav._bg = Rectangle(pos=nav.pos, size=nav.size)
        nav.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        nav_items = [
            ('[H]', 'Home', self._on_nav_home),
            ('[*]', 'Favs', self._on_nav_favorites),
            ('[=]', 'Learn', self._on_nav_learn),
            ('[S]', 'Settings', self._on_settings_press),
        ]

        for icon, label, callback in nav_items:
            btn_box = BoxLayout(orientation='vertical')

            icon_btn = Button(
                text=icon,
                background_normal='',
                background_color=[0, 0, 0, 0],
                color=get_color_from_hex(theme['accent']),
                font_size=sp(16),
                size_hint_y=0.6
            )
            icon_btn.bind(on_press=callback)

            label_lbl = Label(
                text=label,
                font_size=sp(10),
                color=get_color_from_hex(theme['text_dim']),
                size_hint_y=0.4,
                halign='center',
                valign='top'
            )
            label_lbl.bind(size=label_lbl.setter('text_size'))

            btn_box.add_widget(icon_btn)
            btn_box.add_widget(label_lbl)
            nav.add_widget(btn_box)

        return nav

    # --- Event Handlers ---

    def _update_bg(self, *args):
        if hasattr(self, '_bg') and self.children:
            self._bg.pos = self.children[0].pos
            self._bg.size = self.children[0].size

    def _on_search_text(self, instance, value):
        self.search_query = value.strip()
        Clock.unschedule(self._do_search)
        Clock.schedule_once(self._do_search, 0.3)

    def _do_search(self, dt):
        theme = self.app.theme_manager.current
        self._populate_cards(self.cards_grid, theme)

    def _on_tab_press(self, instance):
        self.current_category = instance.cat_id
        self._rebuild_tabs()
        theme = self.app.theme_manager.current
        self._populate_cards(self.cards_grid, theme)

    def _rebuild_tabs(self):
        """Rebuild tabs to update selection state"""
        theme = self.app.theme_manager.current
        self.tabs_row.clear_widgets()

        categories = [('all', 'All')]
        for cat_id in ['offensive', 'security', 'network', 'android', 'cli', 'dev']:
            if cat_id in CATEGORIES:
                categories.append((cat_id, CATEGORIES[cat_id]['name']))

        for cat_id, name in categories:
            btn = self._create_tab_button(cat_id, name, theme)
            self.tabs_row.add_widget(btn)

    def _on_tool_select(self, tool_data):
        self.app.show_tool_detail(tool_data)

    def _on_toggle_favorite(self, tool_id):
        favorites = get_favorites()
        return favorites.toggle(tool_id)

    def _on_settings_press(self, instance):
        self.app.show_settings()

    def _on_nav_home(self, instance):
        self.current_category = 'all'
        self.search_query = ''
        self.search_input.text = ''
        self._build_ui()

    def _on_nav_favorites(self, instance):
        pass

    def _on_nav_learn(self, instance):
        """Navigate to Learning Paths"""
        self.app.show_learning_paths()

    def refresh(self):
        """Rebuild UI (e.g., after theme change)"""
        self._build_ui()
