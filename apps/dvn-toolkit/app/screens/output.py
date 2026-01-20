"""
Output Screen - Visual results with progress and formatting
"""

import os
import sys
import io
import threading
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr

from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, Rectangle
from kivy.utils import get_color_from_hex
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.metrics import dp, sp

from ..components.output_renderer import TerminalOutput, ProgressIndicator
from ..utils.text_utils import clean_output


def _get_tools_base():
    """Get the tools base directory"""
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    tools_path = os.path.join(base, 'tools')

    if os.path.exists(tools_path):
        return tools_path

    try:
        from android.storage import app_storage_path
        android_base = app_storage_path()
        tools_path = os.path.join(android_base, 'app', 'tools')
        if os.path.exists(tools_path):
            return tools_path
    except ImportError:
        pass

    android_paths = [
        '/data/data/com.gh0st.dvntoolkit/files/app/tools',
        '/data/user/0/com.gh0st.dvntoolkit/files/app/tools',
    ]
    for path in android_paths:
        if os.path.exists(path):
            return path

    return os.path.join(base, 'tools')


class OutputScreen(Screen):
    """Screen showing tool execution results"""

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.tool_data = None
        self.values = {}
        self.command = ''
        self.is_running = False
        self._build_ui()

    def setup_execution(self, tool_data, values, command):
        """Setup for tool execution"""
        self.tool_data = tool_data
        self.values = values
        self.command = command
        self._build_ui()

    def _build_ui(self):
        """Build the output screen UI"""
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

        # Progress indicator
        self.progress = ProgressIndicator(theme)
        main_layout.add_widget(self.progress)

        # Command display
        main_layout.add_widget(self._build_command_display(theme))

        # Terminal output
        self.terminal = TerminalOutput(theme, size_hint=(1, 1))
        main_layout.add_widget(self.terminal)

        # Action bar
        main_layout.add_widget(self._build_action_bar(theme))

        self.add_widget(main_layout)

    def _build_header(self, theme):
        """Build header with tool name and status"""
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

        tool_name = self.tool_data.get('name', 'Tool') if self.tool_data else 'Output'
        title = Label(
            text=f'{tool_name} OUTPUT',
            font_size=sp(13),
            bold=True,
            color=get_color_from_hex(theme['accent']),
            halign='center',
            valign='middle'
        )

        self.status_label = Label(
            text='Ready',
            size_hint=(None, 1),
            width=dp(70),
            font_size=sp(10),
            color=get_color_from_hex(theme['text_dim'])
        )

        header.add_widget(back_btn)
        header.add_widget(title)
        header.add_widget(self.status_label)

        return header

    def _build_command_display(self, theme):
        """Build the command display section"""
        container = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(44),
            padding=[dp(12), dp(4), dp(12), dp(4)]
        )

        label = Label(
            text='Command:',
            font_size=sp(9),
            color=get_color_from_hex(theme['text_dim']),
            size_hint_y=None,
            height=dp(14),
            halign='left',
            valign='middle'
        )
        label.bind(size=label.setter('text_size'))

        cmd_text = self.command if self.command else 'No command'
        self.cmd_label = Label(
            text=cmd_text,
            font_size=sp(10),
            color=get_color_from_hex(theme['terminal_text']),
            size_hint_y=None,
            height=dp(24),
            halign='left',
            valign='middle'
        )
        self.cmd_label.bind(size=self.cmd_label.setter('text_size'))

        container.add_widget(label)
        container.add_widget(self.cmd_label)

        return container

    def _build_action_bar(self, theme):
        """Build bottom action bar"""
        bar = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=dp(50),
            padding=[dp(8), dp(6), dp(8), dp(6)],
            spacing=dp(6)
        )

        with bar.canvas.before:
            Color(*get_color_from_hex(theme['bg_secondary']))
            bar._bg = Rectangle(pos=bar.pos, size=bar.size)
        bar.bind(
            pos=lambda i, v: setattr(i._bg, 'pos', v),
            size=lambda i, v: setattr(i._bg, 'size', v)
        )

        clear_btn = Button(
            text='CLEAR',
            size_hint_x=0.25,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(10)
        )
        clear_btn.bind(on_press=self._on_clear)

        copy_btn = Button(
            text='COPY',
            size_hint_x=0.25,
            background_normal='',
            background_color=get_color_from_hex(theme['button_bg']),
            color=get_color_from_hex(theme['text']),
            font_size=sp(10)
        )
        copy_btn.bind(on_press=self._on_copy)

        self.stop_btn = Button(
            text='STOP',
            size_hint_x=0.25,
            background_normal='',
            background_color=get_color_from_hex(theme['danger']),
            color=get_color_from_hex('#ffffff'),
            font_size=sp(10)
        )
        self.stop_btn.bind(on_press=self._on_stop)
        self.stop_btn.disabled = True

        run_again_btn = Button(
            text='RUN',
            size_hint_x=0.25,
            background_normal='',
            background_color=get_color_from_hex(theme['success']),
            color=get_color_from_hex('#000000'),
            font_size=sp(10)
        )
        run_again_btn.bind(on_press=self._on_run_again)

        bar.add_widget(clear_btn)
        bar.add_widget(copy_btn)
        bar.add_widget(self.stop_btn)
        bar.add_widget(run_again_btn)

        return bar

    def _update_bg(self, *args):
        if hasattr(self, '_bg') and self.children:
            self._bg.pos = self.children[0].pos
            self._bg.size = self.children[0].size

    def start_execution(self):
        """Start executing the tool"""
        if not self.tool_data:
            return

        self.is_running = True
        self.stop_btn.disabled = False
        self.status_label.text = 'Running...'

        self.progress.set_status(f"Running {self.tool_data.get('name', 'tool')}...")
        self.progress.start_animation()

        self.terminal.clear_output()
        self.terminal.append(f"Executing: {self.command}")
        self.terminal.append_separator()

        threading.Thread(target=self._execute_tool, daemon=True).start()

    def _execute_tool(self):
        """Execute the tool in background thread"""
        try:
            tool = self.tool_data
            category = tool.get('category', '')
            script = tool.get('script', '')

            tools_base = _get_tools_base()
            tool_path = os.path.join(tools_base, category, script)

            if not os.path.exists(tool_path):
                Clock.schedule_once(
                    lambda dt: self._output_error(f"Tool not found: {tool_path}")
                )
                return

            with open(tool_path, 'r') as f:
                tool_code = f.read()

            parts = self.command.split()
            args = parts[1:] if len(parts) > 1 else []

            old_argv = sys.argv.copy()
            sys.argv = [tool_path] + args

            output_buffer = io.StringIO()
            tool_globals = {
                '__name__': '__main__',
                '__file__': tool_path,
                '__builtins__': __builtins__,
            }

            try:
                with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                    exec(compile(tool_code, tool_path, 'exec'), tool_globals)
            except SystemExit:
                pass
            except Exception as e:
                output_buffer.write(f"\nError: {e}\n")
            finally:
                sys.argv = old_argv

            output = output_buffer.getvalue()
            # Clean ANSI codes before displaying
            output = clean_output(output)
            if output:
                for line in output.split('\n'):
                    if line:
                        Clock.schedule_once(
                            lambda dt, l=line: self.terminal.append_raw(l)
                        )

            Clock.schedule_once(lambda dt: self._execution_complete())

        except Exception as e:
            error_msg = str(e)
            Clock.schedule_once(lambda dt: self._output_error(error_msg))

    def _output_error(self, message):
        self.terminal.append_error(message)
        self._execution_complete()

    def _execution_complete(self):
        self.is_running = False
        self.stop_btn.disabled = True
        self.status_label.text = 'Complete'
        self.progress.complete()
        self.terminal.append_separator()
        self.terminal.append("Done")

    def _on_back(self, instance):
        if self.tool_data:
            self.app.show_tool_detail(self.tool_data)
        else:
            self.app.go_to_dashboard()

    def _on_clear(self, instance):
        self.terminal.clear_output()
        self.terminal.append("Cleared")

    def _on_copy(self, instance):
        Clipboard.copy(self.terminal.text)
        self.terminal.append("Copied")

    def _on_stop(self, instance):
        self.terminal.append_warning("Stop requested")
        self._execution_complete()

    def _on_run_again(self, instance):
        if self.tool_data:
            self.start_execution()

    def refresh(self):
        self._build_ui()
