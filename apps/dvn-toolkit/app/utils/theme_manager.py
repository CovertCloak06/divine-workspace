"""
Theme Manager - Centralized theme definitions and management
"""

from kivy.properties import StringProperty, DictProperty
from kivy.utils import get_color_from_hex

# Theme definitions with all color values
THEMES = {
    'cyberpunk': {
        'name': 'Cyberpunk',
        'bg': '#0a0a12',
        'bg_secondary': '#12121f',
        'bg_card': '#181828',
        'accent': '#00ff9f',
        'accent_secondary': '#ff00ff',
        'text': '#ffffff',
        'text_dim': '#888899',
        'terminal_bg': '#050508',
        'terminal_text': '#00ff9f',
        'button_bg': '#1a1a2e',
        'button_pressed': '#2a2a4e',
        'danger': '#ff4444',
        'warning': '#ffaa00',
        'success': '#00ff9f',
        'card_border': '#00ff9f33',
        'favorite': '#ff00ff',
    },
    'matrix': {
        'name': 'Matrix',
        'bg': '#000000',
        'bg_secondary': '#0a0a0a',
        'bg_card': '#0a150a',
        'accent': '#00ff00',
        'accent_secondary': '#00aa00',
        'text': '#00ff00',
        'text_dim': '#006600',
        'terminal_bg': '#000000',
        'terminal_text': '#00ff00',
        'button_bg': '#001100',
        'button_pressed': '#002200',
        'danger': '#ff0000',
        'warning': '#ffff00',
        'success': '#00ff00',
        'card_border': '#00ff0033',
        'favorite': '#00ff00',
    },
    'hacker': {
        'name': 'Hacker Red',
        'bg': '#0a0000',
        'bg_secondary': '#120000',
        'bg_card': '#180808',
        'accent': '#ff0040',
        'accent_secondary': '#ff4080',
        'text': '#ffffff',
        'text_dim': '#aa6666',
        'terminal_bg': '#050000',
        'terminal_text': '#ff0040',
        'button_bg': '#1a0010',
        'button_pressed': '#2a0020',
        'danger': '#ff0000',
        'warning': '#ff8800',
        'success': '#00ff88',
        'card_border': '#ff004033',
        'favorite': '#ff0040',
    },
    'ocean': {
        'name': 'Ocean Blue',
        'bg': '#0a1628',
        'bg_secondary': '#0f1e30',
        'bg_card': '#122436',
        'accent': '#00d4ff',
        'accent_secondary': '#0088ff',
        'text': '#ffffff',
        'text_dim': '#668899',
        'terminal_bg': '#050d18',
        'terminal_text': '#00d4ff',
        'button_bg': '#102030',
        'button_pressed': '#1a3050',
        'danger': '#ff4466',
        'warning': '#ffcc00',
        'success': '#00ff88',
        'card_border': '#00d4ff33',
        'favorite': '#00d4ff',
    },
    'light': {
        'name': 'Light Mode',
        'bg': '#f5f5f5',
        'bg_secondary': '#ffffff',
        'bg_card': '#ffffff',
        'accent': '#2196F3',
        'accent_secondary': '#1976D2',
        'text': '#212121',
        'text_dim': '#757575',
        'terminal_bg': '#263238',
        'terminal_text': '#80CBC4',
        'button_bg': '#e0e0e0',
        'button_pressed': '#bdbdbd',
        'danger': '#f44336',
        'warning': '#FF9800',
        'success': '#4CAF50',
        'card_border': '#2196F333',
        'favorite': '#E91E63',
    },
    'midnight': {
        'name': 'Midnight Purple',
        'bg': '#0d0a1a',
        'bg_secondary': '#151030',
        'bg_card': '#1a1540',
        'accent': '#b388ff',
        'accent_secondary': '#7c4dff',
        'text': '#e8e0ff',
        'text_dim': '#8878a9',
        'terminal_bg': '#080510',
        'terminal_text': '#b388ff',
        'button_bg': '#201850',
        'button_pressed': '#302870',
        'danger': '#ff5252',
        'warning': '#ffab40',
        'success': '#69f0ae',
        'card_border': '#b388ff33',
        'favorite': '#ea80fc',
    },
    'amber': {
        'name': 'Amber Terminal',
        'bg': '#0a0800',
        'bg_secondary': '#141000',
        'bg_card': '#1a1400',
        'accent': '#ffab00',
        'accent_secondary': '#ff8f00',
        'text': '#ffe0a0',
        'text_dim': '#aa8844',
        'terminal_bg': '#050400',
        'terminal_text': '#ffab00',
        'button_bg': '#1a1200',
        'button_pressed': '#2a2000',
        'danger': '#ff5252',
        'warning': '#ffab00',
        'success': '#76ff03',
        'card_border': '#ffab0033',
        'favorite': '#ffab00',
    },
    'dracula': {
        'name': 'Dracula',
        'bg': '#282a36',
        'bg_secondary': '#343746',
        'bg_card': '#3c3f58',
        'accent': '#bd93f9',
        'accent_secondary': '#ff79c6',
        'text': '#f8f8f2',
        'text_dim': '#6272a4',
        'terminal_bg': '#21222c',
        'terminal_text': '#50fa7b',
        'button_bg': '#44475a',
        'button_pressed': '#555970',
        'danger': '#ff5555',
        'warning': '#ffb86c',
        'success': '#50fa7b',
        'card_border': '#bd93f933',
        'favorite': '#ff79c6',
    },
    'nord': {
        'name': 'Nord',
        'bg': '#2e3440',
        'bg_secondary': '#3b4252',
        'bg_card': '#434c5e',
        'accent': '#88c0d0',
        'accent_secondary': '#81a1c1',
        'text': '#eceff4',
        'text_dim': '#7b88a1',
        'terminal_bg': '#242933',
        'terminal_text': '#a3be8c',
        'button_bg': '#4c566a',
        'button_pressed': '#5e6779',
        'danger': '#bf616a',
        'warning': '#ebcb8b',
        'success': '#a3be8c',
        'card_border': '#88c0d033',
        'favorite': '#b48ead',
    },
    'solarized': {
        'name': 'Solarized Dark',
        'bg': '#002b36',
        'bg_secondary': '#073642',
        'bg_card': '#0a3f4c',
        'accent': '#2aa198',
        'accent_secondary': '#268bd2',
        'text': '#fdf6e3',
        'text_dim': '#657b83',
        'terminal_bg': '#001e26',
        'terminal_text': '#859900',
        'button_bg': '#094652',
        'button_pressed': '#0c5a68',
        'danger': '#dc322f',
        'warning': '#b58900',
        'success': '#859900',
        'card_border': '#2aa19833',
        'favorite': '#d33682',
    },
}

# Input type icons - Visual indicators for different input types
INPUT_TYPE_ICONS = {
    'text': 'Aa',
    'ip': '\u21C4',           # Bidirectional arrow for network
    'url': '\U0001F310',      # Globe
    'port_range': '#',
    'number': '123',
    'file': '\U0001F4C1',     # Folder
    'dropdown': '\u25BC',     # Down triangle
    'checkbox': '\u2611',     # Checked box
}

# Skill level configuration
SKILL_LEVELS = {
    'beginner': {
        'label': 'BEGINNER',
        'color': '#4CAF50',      # Green
        'icon': '\u2605',        # 1 star
        'description': 'Great for learning the basics',
    },
    'intermediate': {
        'label': 'INTERMEDIATE',
        'color': '#FF9800',      # Orange
        'icon': '\u2605\u2605',  # 2 stars
        'description': 'Requires some technical knowledge',
    },
    'advanced': {
        'label': 'ADVANCED',
        'color': '#f44336',      # Red
        'icon': '\u2605\u2605\u2605',  # 3 stars
        'description': 'For experienced users',
    },
}

# Category icons - Unicode symbols for each category
CATEGORY_ICONS = {
    'offensive': '\u2620',  # Skull
    'security': '\u26A0',   # Warning
    'network': '\u21C4',    # Bidirectional arrows
    'pentest': '\u26D4',    # No entry (root)
    'android': '\U0001F4F1',  # Mobile phone
    'crypto': '\U0001F510',   # Lock with key
    'osint': '\U0001F50D',    # Magnifying glass
    'forensics': '\U0001F50E', # Right magnifying glass
    'web': '\U0001F310',      # Globe
    'cli': '\U0001F5A5',      # Desktop computer
    'dev': '\u2699',          # Gear
    'files': '\U0001F4C1',    # Folder
    'system': '\U0001F4BB',   # Laptop
    'productivity': '\u2714', # Check mark
    'media': '\U0001F3A8',    # Palette
    'monitor': '\U0001F4CA',  # Chart
    'fun': '\U0001F389',      # Party popper
    'all': '\u2605',          # Star
}


class ThemeManager:
    """Manages app theming"""

    def __init__(self, initial_theme='cyberpunk'):
        self._current_id = initial_theme
        self._current = THEMES.get(initial_theme, THEMES['cyberpunk'])

    @property
    def current(self):
        """Get current theme dict"""
        return self._current

    @property
    def current_id(self):
        """Get current theme ID"""
        return self._current_id

    @property
    def name(self):
        """Get current theme name"""
        return self._current['name']

    def set_theme(self, theme_id):
        """Change to a different theme"""
        if theme_id in THEMES:
            self._current_id = theme_id
            self._current = THEMES[theme_id]
            return True
        return False

    def get_color(self, key):
        """Get a color value from current theme"""
        return self._current.get(key, '#ffffff')

    def get_color_rgba(self, key):
        """Get a color as RGBA tuple"""
        return get_color_from_hex(self.get_color(key))

    @staticmethod
    def list_themes():
        """Get list of available themes"""
        return [(tid, t['name']) for tid, t in THEMES.items()]

    @staticmethod
    def get_category_icon(category):
        """Get icon for a category"""
        return CATEGORY_ICONS.get(category, '\u2022')  # Bullet as default

    @staticmethod
    def get_input_icon(input_type):
        """Get icon for an input type"""
        return INPUT_TYPE_ICONS.get(input_type, 'Aa')

    @staticmethod
    def get_skill_level(level):
        """Get skill level configuration"""
        return SKILL_LEVELS.get(level, SKILL_LEVELS['beginner'])
