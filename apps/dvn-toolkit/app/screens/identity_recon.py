"""
Identity Recon Screen - Main screen for multi-tool OSINT reconnaissance
Orchestrates multiple tools to build comprehensive identity profiles
"""

import os
import sys
import threading
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, Rectangle
from kivy.utils import get_color_from_hex
from kivy.metrics import dp, sp
from kivy.clock import Clock

from ..components.recon_input import ReconInput
from ..components.recon_progress import ReconProgress
from ..components.profile_card import ProfileResults, ProfileSummary
from ..data.input_detector import INPUT_UNKNOWN
from ..data.recon_orchestrator import (
    get_tools_for_input, build_tool_args, get_tool_path, SCAN_PROFILES
)
from ..data.recon_profiles import ReconProfile, get_profiles_manager


class IdentityReconScreen(Screen):
    """Identity Recon - Multi-tool OSINT orchestration"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.current_profile = None
        self.scan_thread = None
        self.is_scanning = False

        self._build_ui()

    def _build_ui(self):
        """Build the Identity Recon screen UI"""
        self.clear_widgets()
        theme = self.app.theme_manager.current

        main_layout = BoxLayout(orientation='vertical', spacing=0)

        # Background
        with main_layout.canvas.before:
            Color(*get_color_from_hex(theme['bg']))
            main_layout._bg = Rectangle(pos=main_layout.pos, size=main_layout.size)
        main_layout.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        # Header
        main_layout.add_widget(self._build_header(theme))

        # Warning banner
        main_layout.add_widget(self._build_warning(theme))

        # Scrollable content
        scroll = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self.content = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=dp(12),
            padding=[dp(12), dp(8), dp(12), dp(16)]
        )
        self.content.bind(minimum_height=self.content.setter('height'))

        # Recon input
        self.recon_input = ReconInput(theme, on_change=self._on_input_change)
        self.content.add_widget(self.recon_input)

        # Scan profile selector
        self.content.add_widget(self._build_profile_selector(theme))

        # Tool preview / progress
        self.progress = ReconProgress(theme, tools=[])
        self.content.add_widget(self.progress)

        # Action buttons
        self.content.add_widget(self._build_actions(theme))

        # Results area
        self.results_area = ProfileResults(theme)
        self.content.add_widget(self.results_area)

        scroll.add_widget(self.content)
        main_layout.add_widget(scroll)

        self.add_widget(main_layout)

    def _build_header(self, theme) -> BoxLayout:
        """Build header with back button and title"""
        header = BoxLayout(
            size_hint_y=None, height=dp(52),
            padding=[dp(8), dp(8), dp(8), dp(8)]
        )

        with header.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            header._bg = Rectangle(pos=header.pos, size=header.size)
        header.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        back_btn = Button(
            text='<',
            size_hint=(None, 1), width=dp(44),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(18)
        )
        back_btn.bind(on_press=self._on_back)

        title = Label(
            text='IDENTITY RECON',
            font_size=sp(16), bold=True,
            color=get_color_from_hex(theme['accent']),
            halign='center'
        )

        # Placeholder for symmetry
        spacer = BoxLayout(size_hint=(None, 1), width=dp(44))

        header.add_widget(back_btn)
        header.add_widget(title)
        header.add_widget(spacer)

        return header

    def _build_warning(self, theme) -> BoxLayout:
        """Build legal warning banner"""
        warning = BoxLayout(
            size_hint_y=None, height=dp(36),
            padding=[dp(12), dp(6), dp(12), dp(6)]
        )

        with warning.canvas.before:
            Color(*get_color_from_hex(theme['warning'] + '40'))
            warning._bg = Rectangle(pos=warning.pos, size=warning.size)
        warning.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v) if hasattr(i, '_bg') else None,
            size=lambda i, v: setattr(i._bg, 'size', v) if hasattr(i, '_bg') else None
        )

        label = Label(
            text='! Only scan identities you have permission to research',
            font_size=sp(11),
            color=get_color_from_hex(theme['warning']),
            halign='center'
        )

        warning.add_widget(label)
        return warning

    def _build_profile_selector(self, theme) -> BoxLayout:
        """Build scan profile selector buttons"""
        container = BoxLayout(
            size_hint_y=None, height=dp(44),
            spacing=dp(8)
        )

        self.profile_buttons = {}
        for profile_id, profile_info in SCAN_PROFILES.items():
            btn = Button(
                text=profile_info['name'],
                background_normal='',
                background_color=get_color_from_hex(
                    theme['accent'] if profile_id == 'standard' else theme['button_bg']
                ),
                color=get_color_from_hex(theme['text']),
                font_size=sp(12)
            )
            btn.profile_id = profile_id
            btn.bind(on_press=self._on_profile_select)
            self.profile_buttons[profile_id] = btn
            container.add_widget(btn)

        self.selected_profile = 'standard'
        return container

    def _build_actions(self, theme) -> BoxLayout:
        """Build action buttons"""
        container = BoxLayout(
            size_hint_y=None, height=dp(50),
            spacing=dp(12),
            padding=[dp(4), dp(4), dp(4), dp(4)]
        )

        self.scan_btn = Button(
            text='START SCAN',
            background_normal='',
            background_color=get_color_from_hex(theme['accent']),
            color=get_color_from_hex(theme['bg']),
            font_size=sp(14), bold=True
        )
        self.scan_btn.bind(on_press=self._on_scan)

        self.export_btn = Button(
            text='EXPORT',
            size_hint=(None, 1), width=dp(80),
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(12)
        )
        self.export_btn.bind(on_press=self._on_export)

        container.add_widget(self.scan_btn)
        container.add_widget(self.export_btn)

        return container

    def _on_input_change(self, text, input_type, confidence, details):
        """Handle input changes - update tool preview"""
        if input_type and input_type != INPUT_UNKNOWN:
            tools = get_tools_for_input(input_type, self.selected_profile)
            self.progress.set_tools(tools)
        else:
            self.progress.set_tools([])

    def _on_profile_select(self, instance):
        """Handle scan profile selection"""
        theme = self.app.theme_manager.current

        # Update button colors
        for pid, btn in self.profile_buttons.items():
            if pid == instance.profile_id:
                btn.background_color = get_color_from_hex(theme['accent'])
            else:
                btn.background_color = get_color_from_hex(theme['button_bg'])

        self.selected_profile = instance.profile_id

        # Refresh tool list
        input_type, _, _ = self.recon_input.get_detection()
        if input_type and input_type != INPUT_UNKNOWN:
            tools = get_tools_for_input(input_type, self.selected_profile)
            self.progress.set_tools(tools)

    def _on_scan(self, instance):
        """Start or stop the scan"""
        if self.is_scanning:
            self.is_scanning = False
            self.scan_btn.text = 'START SCAN'
            return

        input_value = self.recon_input.get_value()
        input_type, confidence, details = self.recon_input.get_detection()

        if not input_value or input_type == INPUT_UNKNOWN:
            self.progress.set_error('Enter a valid target')
            return

        # Create profile
        self.current_profile = ReconProfile()
        self.current_profile.input_value = input_value
        self.current_profile.input_type = input_type
        self.current_profile.input_details = details
        self.current_profile.scan_profile = self.selected_profile
        self.current_profile.status = 'running'

        # Get tools
        tools = get_tools_for_input(input_type, self.selected_profile)
        self.current_profile.tools_total = len(tools)

        # Reset UI
        self.progress.set_tools(tools)
        self.results_area.clear_results()

        # Start scan
        self.is_scanning = True
        self.scan_btn.text = 'STOP'

        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(tools, input_value, input_type, details)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _run_scan(self, tools, input_value, input_type, details):
        """Run the scan in background thread"""
        for tool in tools:
            if not self.is_scanning:
                break

            tool_id = tool['id']
            Clock.schedule_once(
                lambda dt, tid=tool_id: self.progress.update_tool_status(tid, 'running')
            )

            try:
                output = self._execute_tool(tool, input_value, input_type, details)
                self.current_profile.add_result(tool_id, output, 'complete')
                Clock.schedule_once(
                    lambda dt, tid=tool_id: self.progress.update_tool_status(tid, 'complete')
                )
            except Exception as e:
                self.current_profile.add_result(tool_id, str(e), 'error')
                Clock.schedule_once(
                    lambda dt, tid=tool_id: self.progress.update_tool_status(tid, 'error')
                )

            # Update results
            Clock.schedule_once(lambda dt: self._update_results())

        # Scan complete
        self.current_profile.status = 'complete'
        get_profiles_manager().save_profile(self.current_profile)

        Clock.schedule_once(lambda dt: self._scan_complete())

    def _execute_tool(self, tool, input_value, input_type, details) -> str:
        """Execute a single tool and capture output"""
        # Build input data
        input_data = {'target': input_value, **details}

        args = build_tool_args(tool['id'], input_data)
        tool_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            get_tool_path(tool['id'])
        )

        if not os.path.exists(tool_path):
            return f"Tool not found: {tool_path}"

        # Capture output
        output = StringIO()
        old_argv = sys.argv

        try:
            with open(tool_path, 'r') as f:
                tool_code = f.read()

            sys.argv = [tool_path] + args.split()

            tool_globals = {
                '__name__': '__main__',
                '__file__': tool_path,
            }

            with redirect_stdout(output), redirect_stderr(output):
                exec(compile(tool_code, tool_path, 'exec'), tool_globals)

        except SystemExit:
            pass
        except Exception as e:
            output.write(f"\nError: {e}")
        finally:
            sys.argv = old_argv

        return output.getvalue()

    def _update_results(self):
        """Update the results display"""
        if self.current_profile:
            self.results_area.update_results(self.current_profile.results)

    def _scan_complete(self):
        """Handle scan completion"""
        self.is_scanning = False
        self.scan_btn.text = 'START SCAN'

    def _on_export(self, instance):
        """Export the current profile"""
        if not self.current_profile:
            return

        # Export as text
        text = self.current_profile.export_text()
        print(text)  # For now, just print (would save to file on device)

    def _on_back(self, instance):
        """Go back to dashboard"""
        self.app.show_dashboard()

    def refresh(self):
        """Rebuild UI (e.g., after theme change)"""
        self._build_ui()
