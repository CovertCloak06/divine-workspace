#!/usr/bin/env python3
"""
Matrix Rain - Digital rain animation
Usage: matrix.py [--speed N] [--color green|blue|red]
"""

import os
import sys
import time
import random
import argparse
import signal

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Color codes
COLORS = {
    'green': '\033[32m',
    'bright_green': '\033[92m',
    'blue': '\033[34m',
    'bright_blue': '\033[94m',
    'red': '\033[31m',
    'bright_red': '\033[91m',
    'cyan': '\033[36m',
    'bright_cyan': '\033[96m',
    'yellow': '\033[33m',
    'bright_yellow': '\033[93m',
    'white': '\033[37m',
    'bright_white': '\033[97m',
    'magenta': '\033[35m',
    'bright_magenta': '\033[95m',
}

# Characters for the rain
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*(){}[]|;:<>?~"
KATAKANA = "ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロヮワヰヱヲンヴヵヶ"


class Column:
    def __init__(self, x, height, chars_set):
        self.x = x
        self.height = height
        self.chars = chars_set
        self.y = random.randint(-height, 0)
        self.length = random.randint(5, height // 2)
        self.speed = random.choice([1, 1, 1, 2])
        self.trail = []

    def update(self):
        self.y += self.speed

        # Reset if past screen
        if self.y - self.length > self.height:
            self.y = random.randint(-10, 0)
            self.length = random.randint(5, self.height // 2)
            self.speed = random.choice([1, 1, 1, 2])

    def get_char(self):
        return random.choice(self.chars)


def get_terminal_size():
    """Get terminal dimensions"""
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except:
        return 80, 24


def hide_cursor():
    """Hide terminal cursor"""
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()


def show_cursor():
    """Show terminal cursor"""
    sys.stdout.write('\033[?25h')
    sys.stdout.flush()


def clear_screen():
    """Clear terminal screen"""
    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()


def move_cursor(x, y):
    """Move cursor to position"""
    sys.stdout.write(f'\033[{y};{x}H')


def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    show_cursor()
    clear_screen()
    print(f"\n{GREEN}Matrix simulation ended.{RESET}\n")
    sys.exit(0)


def run_matrix(color='green', speed=0.05, density=0.8, katakana=False):
    """Run the matrix rain animation"""
    signal.signal(signal.SIGINT, signal_handler)

    width, height = get_terminal_size()

    # Choose character set
    chars = KATAKANA if katakana else CHARS

    # Get colors
    if color in COLORS:
        dim_color = COLORS[color]
        bright_color = COLORS.get(f'bright_{color}', dim_color)
    else:
        dim_color = COLORS['green']
        bright_color = COLORS['bright_green']

    # Create columns
    num_columns = int(width * density)
    columns = []
    positions = random.sample(range(width), min(num_columns, width))

    for x in positions:
        columns.append(Column(x + 1, height, chars))

    hide_cursor()
    clear_screen()

    try:
        while True:
            # Build screen buffer
            screen = [[' ' for _ in range(width)] for _ in range(height)]
            colors = [[None for _ in range(width)] for _ in range(height)]

            for col in columns:
                head_y = col.y

                # Draw trail
                for i in range(col.length):
                    y = head_y - i
                    if 1 <= y <= height:
                        char = col.get_char()
                        screen[y-1][col.x-1] = char

                        if i == 0:
                            # Head is brightest
                            colors[y-1][col.x-1] = f'{BOLD}{bright_color}'
                        elif i < 3:
                            colors[y-1][col.x-1] = bright_color
                        else:
                            colors[y-1][col.x-1] = dim_color

                col.update()

            # Render screen
            output = []
            for y in range(height):
                line_parts = []
                for x in range(width):
                    char = screen[y][x]
                    color_code = colors[y][x]

                    if color_code:
                        line_parts.append(f'{color_code}{char}{RESET}')
                    else:
                        line_parts.append(char)

                output.append(''.join(line_parts))

            # Move to top and print
            move_cursor(1, 1)
            sys.stdout.write('\n'.join(output))
            sys.stdout.flush()

            time.sleep(speed)

    finally:
        show_cursor()


def main():
    parser = argparse.ArgumentParser(description='Matrix Rain')
    parser.add_argument('--color', '-c', default='green',
                       choices=['green', 'blue', 'red', 'cyan', 'yellow', 'white', 'magenta'],
                       help='Rain color')
    parser.add_argument('--speed', '-s', type=float, default=0.05,
                       help='Animation speed (lower=faster)')
    parser.add_argument('--density', '-d', type=float, default=0.7,
                       help='Column density (0-1)')
    parser.add_argument('--katakana', '-k', action='store_true',
                       help='Use katakana characters')
    parser.add_argument('--demo', action='store_true',
                       help='Show demo message and exit')
    args = parser.parse_args()

    if args.demo:
        print(f"\n{BOLD}{GREEN}╔════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{GREEN}║              🔥 Matrix Rain                               ║{RESET}")
        print(f"{BOLD}{GREEN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

        print(f"  {CYAN}Wake up, Neo...{RESET}")
        print(f"  {CYAN}The Matrix has you...{RESET}")
        print(f"  {CYAN}Follow the white rabbit.{RESET}\n")

        print(f"  {DIM}Press Ctrl+C to exit{RESET}\n")

        print(f"  {BOLD}Usage:{RESET}")
        print(f"  {DIM}matrix.py{RESET}              Default green rain")
        print(f"  {DIM}matrix.py -c blue{RESET}     Blue rain")
        print(f"  {DIM}matrix.py -k{RESET}           Katakana characters")
        print(f"  {DIM}matrix.py -s 0.03{RESET}     Faster animation")
        print()
        return

    run_matrix(
        color=args.color,
        speed=args.speed,
        density=args.density,
        katakana=args.katakana
    )


if __name__ == '__main__':
    main()
