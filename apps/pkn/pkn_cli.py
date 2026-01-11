#!/usr/bin/env python3
"""
PKN Terminal CLI - Claude-like Terminal Experience
Interactive command-line interface for PKN multi-agent system
"""

import sys
import os
import asyncio
import time
import uuid
from pathlib import Path
from typing import Optional, Dict, Any

# Ensure PKN is in path
sys.path.insert(0, str(Path(__file__).parent))

# Try to import readline for better input experience
try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False

from agent_manager import AgentManager, AgentType
from conversation_memory import ConversationMemory


class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class ProgressIndicator:
    """Animated progress indicator for long-running operations"""

    def __init__(self, message: str = "Processing"):
        self.message = message
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_frame = 0
        self.running = False

    def start(self):
        """Start the progress indicator"""
        self.running = True
        self._show_frame()

    def _show_frame(self):
        """Show current animation frame"""
        if self.running:
            frame = self.frames[self.current_frame]
            print(f'\r{Colors.CYAN}{frame}{Colors.RESET} {self.message}...', end='', flush=True)
            self.current_frame = (self.current_frame + 1) % len(self.frames)

    def update(self, message: str):
        """Update the progress message"""
        self.message = message
        self._show_frame()

    def stop(self, final_message: Optional[str] = None):
        """Stop the progress indicator"""
        self.running = False
        if final_message:
            print(f'\r{Colors.GREEN}✓{Colors.RESET} {final_message}' + ' ' * 20)
        else:
            print('\r' + ' ' * 80 + '\r', end='')


class PKNCLI:
    """PKN Terminal CLI Interface"""

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.session_id = str(uuid.uuid4())
        self.agent_manager = None
        self.conversation_memory = None
        self.planning_enabled = True
        self.show_thinking = True
        self.history_file = self.project_root / ".pkn_cli_history"

        # Initialize readline history if available
        if READLINE_AVAILABLE:
            self._setup_readline()

    def _setup_readline(self):
        """Setup readline for command history and editing"""
        if self.history_file.exists():
            try:
                readline.read_history_file(str(self.history_file))
            except:
                pass

        # Set history length
        readline.set_history_length(1000)

        # Enable tab completion (basic)
        readline.parse_and_bind('tab: complete')

    def _save_history(self):
        """Save command history to file"""
        if READLINE_AVAILABLE:
            try:
                readline.write_history_file(str(self.history_file))
            except:
                pass

    async def initialize(self):
        """Initialize agent manager and conversation memory"""
        progress = ProgressIndicator("Initializing PKN")
        progress.start()

        try:
            # Initialize agent manager
            progress.update("Loading agent manager")
            self.agent_manager = AgentManager(str(self.project_root))

            # Initialize conversation memory
            progress.update("Setting up conversation memory")
            self.conversation_memory = ConversationMemory(str(self.project_root))

            # Create session
            self.conversation_memory.create_session('cli_user')

            progress.stop("PKN initialized")
            return True

        except Exception as e:
            progress.stop()
            print(f"{Colors.RED}✗ Initialization failed: {e}{Colors.RESET}")
            return False

    def print_header(self):
        """Print CLI header"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}  PKN Terminal CLI - Multi-Agent AI System{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"\n{Colors.GRAY}Type your message and press Enter to chat with the AI agents.")
        print(f"Commands: /help, /planning [on|off], /thinking [on|off], /status, /exit{Colors.RESET}\n")

    def print_help(self):
        """Print help message"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}PKN CLI Commands:{Colors.RESET}")
        print(f"  {Colors.GREEN}/help{Colors.RESET}              Show this help message")
        print(f"  {Colors.GREEN}/planning on|off{Colors.RESET}   Enable/disable planning mode for complex tasks")
        print(f"  {Colors.GREEN}/thinking on|off{Colors.RESET}   Show/hide agent thinking process")
        print(f"  {Colors.GREEN}/status{Colors.RESET}            Show agent and service status")
        print(f"  {Colors.GREEN}/clear{Colors.RESET}             Clear screen")
        print(f"  {Colors.GREEN}/exit{Colors.RESET}, {Colors.GREEN}/quit{Colors.RESET}     Exit PKN CLI")
        print(f"\n{Colors.CYAN}{Colors.BOLD}Agent Types:{Colors.RESET}")
        print(f"  {Colors.YELLOW}Coder{Colors.RESET}      - Code writing, debugging, refactoring")
        print(f"  {Colors.YELLOW}Reasoner{Colors.RESET}   - Planning, logic, problem-solving")
        print(f"  {Colors.YELLOW}Researcher{Colors.RESET} - Web research, documentation lookup")
        print(f"  {Colors.YELLOW}Executor{Colors.RESET}   - System commands, file operations")
        print(f"  {Colors.YELLOW}General{Colors.RESET}    - Quick Q&A, simple queries")
        print(f"  {Colors.YELLOW}Consultant{Colors.RESET} - External LLM for complex decisions")
        print()

    async def show_status(self):
        """Show system status"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}System Status:{Colors.RESET}")
        print(f"  Session ID: {Colors.GRAY}{self.session_id[:8]}...{Colors.RESET}")
        print(f"  Planning Mode: {Colors.GREEN if self.planning_enabled else Colors.RED}{'Enabled' if self.planning_enabled else 'Disabled'}{Colors.RESET}")
        print(f"  Show Thinking: {Colors.GREEN if self.show_thinking else Colors.RED}{'Yes' if self.show_thinking else 'No'}{Colors.RESET}")

        # Check service health
        print(f"\n{Colors.CYAN}{Colors.BOLD}Services:{Colors.RESET}")
        import requests

        services = {
            'DivineNode': 'http://localhost:8010/health',
            'llama.cpp': 'http://localhost:8000/v1/models',
        }

        for name, url in services.items():
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    print(f"  {Colors.GREEN}✓{Colors.RESET} {name}")
                else:
                    print(f"  {Colors.RED}✗{Colors.RESET} {name} (status: {response.status_code})")
            except:
                print(f"  {Colors.RED}✗{Colors.RESET} {name} (not responding)")

        # Agent stats
        if self.agent_manager and hasattr(self.agent_manager, 'agent_stats'):
            print(f"\n{Colors.CYAN}{Colors.BOLD}Agent Statistics:{Colors.RESET}")
            for agent, stats in self.agent_manager.agent_stats.items():
                print(f"  {Colors.YELLOW}{agent}{Colors.RESET}: {stats['tasks_completed']} tasks, avg {stats['avg_time']:.1f}s")

        print()

    def stream_text(self, text: str, delay: float = 0.01):
        """Stream text character by character for more interactive feel"""
        for char in text:
            print(char, end='', flush=True)
            time.sleep(delay)
        print()  # Newline at end

    async def handle_message(self, message: str) -> bool:
        """Handle user message and get AI response"""

        # Add to conversation memory
        self.conversation_memory.add_message(self.session_id, 'user', message)

        # Show thinking indicator
        if self.show_thinking:
            print(f"\n{Colors.CYAN}💭 Thinking...{Colors.RESET}")

        start_time = time.time()

        try:
            # Route and execute task
            result = await self.agent_manager.execute_task(message, self.session_id)

            execution_time = time.time() - start_time

            if result['status'] == 'success':
                # Add to conversation memory
                self.conversation_memory.add_message(
                    self.session_id,
                    'assistant',
                    result['response'],
                    agent=result['agent_used'],
                    tools_used=result.get('tools_used', [])
                )

                # Print response header
                agent_name = result.get('agent_name', result['agent_used'])
                agent_emoji = {
                    'coder': '💻',
                    'reasoner': '🧠',
                    'researcher': '🔍',
                    'executor': '⚙️',
                    'general': '💬',
                    'consultant': '🎓'
                }.get(result['agent_used'], '🤖')

                print(f"\n{Colors.BOLD}{agent_emoji} {agent_name}{Colors.RESET} {Colors.GRAY}({execution_time:.1f}s){Colors.RESET}")

                # Show tools used if any
                if result.get('tools_used'):
                    tools_str = ', '.join(result['tools_used'])
                    print(f"{Colors.DIM}└─ Tools: {tools_str}{Colors.RESET}")

                # Print response
                print(f"\n{result['response']}\n")

                return True
            else:
                print(f"\n{Colors.RED}✗ Error: {result.get('error', 'Unknown error')}{Colors.RESET}\n")
                return False

        except Exception as e:
            print(f"\n{Colors.RED}✗ Error executing task: {e}{Colors.RESET}\n")
            import traceback
            if self.show_thinking:
                print(f"{Colors.GRAY}{traceback.format_exc()}{Colors.RESET}")
            return False

    async def run(self):
        """Main interactive loop"""
        # Initialize
        if not await self.initialize():
            print(f"{Colors.RED}Failed to initialize. Exiting.{Colors.RESET}")
            return 1

        # Print header
        self.print_header()

        # Main loop
        while True:
            try:
                # Get user input
                user_input = input(f"{Colors.GREEN}You{Colors.RESET} {Colors.GRAY}»{Colors.RESET} ").strip()

                if not user_input:
                    continue

                # Handle commands
                if user_input.startswith('/'):
                    command = user_input[1:].lower().split()
                    cmd = command[0] if command else ''

                    if cmd in ['exit', 'quit', 'q']:
                        print(f"\n{Colors.CYAN}👋 Goodbye!{Colors.RESET}\n")
                        break

                    elif cmd == 'help':
                        self.print_help()

                    elif cmd == 'planning':
                        if len(command) > 1:
                            if command[1] == 'on':
                                self.planning_enabled = True
                                print(f"{Colors.GREEN}✓ Planning mode enabled{Colors.RESET}")
                            elif command[1] == 'off':
                                self.planning_enabled = False
                                print(f"{Colors.YELLOW}⚠ Planning mode disabled{Colors.RESET}")
                        else:
                            status = "enabled" if self.planning_enabled else "disabled"
                            print(f"Planning mode is {status}")

                    elif cmd == 'thinking':
                        if len(command) > 1:
                            if command[1] == 'on':
                                self.show_thinking = True
                                print(f"{Colors.GREEN}✓ Showing thinking process{Colors.RESET}")
                            elif command[1] == 'off':
                                self.show_thinking = False
                                print(f"{Colors.YELLOW}⚠ Hiding thinking process{Colors.RESET}")
                        else:
                            status = "shown" if self.show_thinking else "hidden"
                            print(f"Thinking process is {status}")

                    elif cmd == 'status':
                        await self.show_status()

                    elif cmd == 'clear':
                        os.system('clear' if os.name != 'nt' else 'cls')
                        self.print_header()

                    else:
                        print(f"{Colors.RED}Unknown command: {cmd}{Colors.RESET}")
                        print(f"Type {Colors.GREEN}/help{Colors.RESET} for available commands")

                    continue

                # Handle regular message
                await self.handle_message(user_input)

            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}Interrupted. Type /exit to quit.{Colors.RESET}\n")
                continue

            except EOFError:
                print(f"\n{Colors.CYAN}👋 Goodbye!{Colors.RESET}\n")
                break

        # Save history
        self._save_history()
        return 0


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='PKN Terminal CLI - Interactive AI Agent Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pkn-cli                    Start interactive session
  pkn-cli --no-planning      Disable planning mode
  pkn-cli --project /path    Use custom project directory
        """
    )

    parser.add_argument(
        '--project-root',
        type=str,
        default='/home/gh0st/pkn',
        help='PKN project root directory (default: /home/gh0st/pkn)'
    )

    parser.add_argument(
        '--no-planning',
        action='store_true',
        help='Disable planning mode for complex tasks'
    )

    parser.add_argument(
        '--no-thinking',
        action='store_true',
        help='Hide agent thinking process'
    )

    args = parser.parse_args()

    # Create CLI instance
    cli = PKNCLI(args.project_root)

    # Apply settings
    if args.no_planning:
        cli.planning_enabled = False
    if args.no_thinking:
        cli.show_thinking = False

    # Run async main loop
    try:
        exit_code = asyncio.run(cli.run())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Interrupted{Colors.RESET}")
        sys.exit(130)


if __name__ == "__main__":
    main()
