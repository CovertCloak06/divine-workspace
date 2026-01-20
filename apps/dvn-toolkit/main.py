#!/usr/bin/env python3
"""
DVN Toolkit v2.0 - Android App
Modern card-based UI with rich documentation and dynamic forms
130+ security and utility tools
For authorized security testing only
"""

import os

# Kivy configuration - must be before other kivy imports
os.environ['KIVY_LOG_LEVEL'] = 'warning'
from kivy.config import Config
Config.set('graphics', 'width', '400')
Config.set('graphics', 'height', '700')
Config.set('kivy', 'keyboard_mode', 'system')

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.utils import get_color_from_hex

from app.utils.theme_manager import ThemeManager, THEMES
from app.data.persistence import get_settings
from app.screens.dashboard import DashboardScreen
from app.screens.tool_detail import ToolDetailScreen
from app.screens.output import OutputScreen
from app.screens.settings import SettingsScreen
from app.screens.identity_recon import IdentityReconScreen
from app.screens.onboarding import OnboardingScreen
from app.screens.learning_paths import LearningPathsScreen
from app.screens.lesson_view import LessonViewScreen


class DVNToolkitApp(App):
    """Main application class for DVN Toolkit v2"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Initialize theme manager
        settings = get_settings()
        initial_theme = settings.get('theme', 'cyberpunk')
        self.theme_manager = ThemeManager(initial_theme)

    def build(self):
        """Build the application"""
        self.title = 'DVN Toolkit'

        # Screen manager with slide transitions
        self.sm = ScreenManager(transition=SlideTransition())

        # Create screens
        self.dashboard_screen = DashboardScreen(self, name='dashboard')
        self.tool_detail_screen = ToolDetailScreen(self, name='tool_detail')
        self.output_screen = OutputScreen(self, name='output')
        self.settings_screen = SettingsScreen(self, name='settings')
        self.identity_recon_screen = IdentityReconScreen(self, name='identity_recon')
        self.onboarding_screen = OnboardingScreen(self, name='onboarding')
        self.learning_paths_screen = LearningPathsScreen(self, name='learning_paths')
        self.lesson_view_screen = LessonViewScreen(self, name='lesson_view')

        # Add screens
        self.sm.add_widget(self.dashboard_screen)
        self.sm.add_widget(self.tool_detail_screen)
        self.sm.add_widget(self.output_screen)
        self.sm.add_widget(self.settings_screen)
        self.sm.add_widget(self.identity_recon_screen)
        self.sm.add_widget(self.onboarding_screen)
        self.sm.add_widget(self.learning_paths_screen)
        self.sm.add_widget(self.lesson_view_screen)

        # Check if onboarding needed
        settings = get_settings()
        if not settings.get('onboarding_complete', False):
            self.sm.current = 'onboarding'

        return self.sm

    def set_theme(self, theme_id):
        """Change application theme"""
        if self.theme_manager.set_theme(theme_id):
            # Save preference
            settings = get_settings()
            settings.set('theme', theme_id)

            # Refresh all screens
            self.dashboard_screen.refresh()
            self.tool_detail_screen.refresh()
            self.output_screen.refresh()
            self.settings_screen.refresh()
            self.identity_recon_screen.refresh()
            self.onboarding_screen.refresh()
            self.learning_paths_screen.refresh()
            self.lesson_view_screen.refresh()

    def show_tool_detail(self, tool_data):
        """Navigate to tool detail screen"""
        self.tool_detail_screen.setup_tool(tool_data)
        self.sm.transition.direction = 'left'
        self.sm.current = 'tool_detail'

    def run_tool(self, tool_data, values, command):
        """Navigate to output screen and run tool"""
        self.output_screen.setup_execution(tool_data, values, command)
        self.sm.transition.direction = 'left'
        self.sm.current = 'output'
        self.output_screen.start_execution()

    def go_to_dashboard(self):
        """Navigate to dashboard"""
        self.sm.transition.direction = 'right'
        self.sm.current = 'dashboard'

    def show_dashboard(self):
        """Navigate to dashboard (alias for go_to_dashboard)"""
        self.go_to_dashboard()

    def show_identity_recon(self):
        """Navigate to Identity Recon screen"""
        self.identity_recon_screen.refresh()
        self.sm.transition.direction = 'left'
        self.sm.current = 'identity_recon'

    def show_settings(self):
        """Navigate to settings screen"""
        self.settings_screen.refresh()
        self.sm.transition.direction = 'left'
        self.sm.current = 'settings'

    def show_learning_paths(self):
        """Navigate to Learning Paths screen"""
        self.learning_paths_screen.refresh()
        self.sm.transition.direction = 'left'
        self.sm.current = 'learning_paths'

    def show_lesson(self, path_data, lesson_index=None):
        """Navigate to a specific lesson"""
        self.lesson_view_screen.setup_lesson(path_data, lesson_index)
        self.sm.transition.direction = 'left'
        self.sm.current = 'lesson_view'

    def show_theme_picker(self):
        """Show theme picker popup"""
        theme = self.theme_manager.current

        content = BoxLayout(
            orientation='vertical',
            spacing=10,
            padding=[15, 15, 15, 15]
        )

        for theme_id, theme_data in THEMES.items():
            btn = Button(
                text=theme_data['name'],
                size_hint_y=None,
                height=50,
                background_normal='',
                background_color=get_color_from_hex(theme_data['accent']),
                color=get_color_from_hex('#000000' if theme_id == 'light' else '#ffffff'),
                font_size='14sp'
            )

            def on_theme_select(instance, tid=theme_id):
                self.set_theme(tid)
                popup.dismiss()

            btn.bind(on_press=on_theme_select)
            content.add_widget(btn)

        popup = Popup(
            title='Select Theme',
            content=content,
            size_hint=(0.85, 0.6),
            background_color=get_color_from_hex(theme['bg'])
        )
        popup.open()


if __name__ == '__main__':
    DVNToolkitApp().run()
