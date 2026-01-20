#!/usr/bin/env python3
"""
Cowsay Clone - ASCII art speaking animals
Usage: cowsay.py [message] [--animal cow|tux|ghost|...]
"""

import sys
import argparse
import textwrap

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

ANIMALS = {
    'cow': r'''
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
''',
    'tux': r'''
       \
        \
            .--.
           |o_o |
           |:_/ |
          //   \ \
         (|     | )
        /'\_   _/`\
        \___)=(___/
''',
    'ghost': r'''
       \
        \     .-"""-.
            /        \
           |  O    O  |
           |    __    |
            \        /
             '------'
              |    |
             /|    |\
            (_|    |_)
''',
    'daemon': r'''
       \         ,        ,
        \       /(        )`
         \      \ \___   / |
                /- _  `-/  '
               (/\/ \ \   /\
               / /   | `    \
               O O   ) /    |
               `-^--'`<     '
              (_.)  _  )   /
               `.___/`    /
                 `-----' /
    <----.     __ / __   \
    <----|====O)))==) \) /====
    <----'    `--' `.__,' \
                 |        |
                  \       /
            ______( (_  / \______
          ,'  ,-----'   |        \
          `--{__________)        \/
''',
    'cat': r'''
       \
        \    /\_/\
            ( o.o )
             > ^ <
            /|   |\
           (_|   |_)
''',
    'bunny': r'''
       \
        \   (\__/)
            (='.'=)
            (")_(")
''',
    'dragon': r'''
      \                    / \  //\
       \    |\___/|      /   \//  \\
            /o  o  \__  /    //  | \ \
           /     /  \/_/    //   |  \  \
           @_^_@'/   \/_   //    |   \   \
           //_^_/     \/_ //     |    \    \
        ( //) |        \///      |     \     \
      ( / /) _|_ /   )  //       |      \     _\
    ( // /) '/,_ _ _/  ( ; -.    |    _ _\.-~        .-~~~^-.
  (( / / )) ,-{        _      `-.|.-~-.           .~         `.
 (( // / ))  '/\      /                 ~-. _ .-~      .-~^-.  \
 (( /// ))      `.   {            }                   /      \  \
  (( / ))     .----~-.\        \-'                 .~         \  `. \^-.
             ///.----..>        \             _ -~             `.  ^-`  ^-_
               ///-._ _ _ _ _ _ _}^ - - - - ~                     ~-- ,.-~
                                                                  /.-~
''',
    'stegosaurus': r'''
       \                             .       .
        \                           / `.   .' "
         \                  .---.  <    > <    >  .---.
          \                 |    \  \ - ~ ~ - /  /    |
                _____          ..-~             ~-..-~
               |     |   \~~~\.'                    `./~~~/
              ---------   \__/                        \__/
             .'  O    \     /               /       \  "
            (_____,    `._.'               |         }  \/~~~/
             `----.          /       }     |        /    \__/
                   `-.      |       /      |       /      `. ,googol.
                       ~-.__|      /_ - ~ ^|      /- _      `./ /
                            |     /        |     /     ~-.     `-....-~
                            |_____|        |_____|         ~- .
                                                             `
''',
    'robot': r'''
       \
        \   _____
           |     |
           | | | |
           |_____|
             | |
            /| |\
           / | | \
          (__|_|__)
''',
    'skull': r'''
       \
        \      ___
             /     \
            | () () |
             \  ^  /
              |||||
              |||||
''',
    'elephant': r'''
       \
        \    ___
            /   \
           |     |-----.
           |     |     |
            \   /   __/
             | |   |
            /   \  |
           |     | |
           |     | |
           (_____)__)
''',
    'cheese': r'''
       \
        \   _____
           /     \
          /       \--------.
         |  o   o  |        \
         |         |_________\
          \_______/
''',
}


def make_bubble(text, width=40):
    """Create speech bubble around text"""
    # Wrap text
    lines = []
    for paragraph in text.split('\n'):
        if paragraph:
            wrapped = textwrap.wrap(paragraph, width=width)
            lines.extend(wrapped)
        else:
            lines.append('')

    if not lines:
        lines = ['']

    max_len = max(len(line) for line in lines)

    # Build bubble
    border_top = ' ' + '_' * (max_len + 2)
    border_bottom = ' ' + '-' * (max_len + 2)

    bubble_lines = [border_top]

    if len(lines) == 1:
        bubble_lines.append(f'< {lines[0]:{max_len}} >')
    else:
        bubble_lines.append(f'/ {lines[0]:{max_len}} \\')
        for line in lines[1:-1]:
            bubble_lines.append(f'| {line:{max_len}} |')
        bubble_lines.append(f'\\ {lines[-1]:{max_len}} /')

    bubble_lines.append(border_bottom)

    return '\n'.join(bubble_lines)


def think_bubble(text, width=40):
    """Create thought bubble around text"""
    lines = []
    for paragraph in text.split('\n'):
        if paragraph:
            wrapped = textwrap.wrap(paragraph, width=width)
            lines.extend(wrapped)
        else:
            lines.append('')

    if not lines:
        lines = ['']

    max_len = max(len(line) for line in lines)

    border_top = ' ' + '_' * (max_len + 2)
    border_bottom = ' ' + '-' * (max_len + 2)

    bubble_lines = [border_top]

    for line in lines:
        bubble_lines.append(f'( {line:{max_len}} )')

    bubble_lines.append(border_bottom)

    return '\n'.join(bubble_lines)


def cowsay(message, animal='cow', think=False):
    """Generate cowsay output"""
    bubble = think_bubble(message) if think else make_bubble(message)

    # Get animal art
    art = ANIMALS.get(animal.lower(), ANIMALS['cow'])

    # Replace thought indicators if thinking
    if think:
        art = art.replace('\\', 'o')

    return bubble + art


def main():
    parser = argparse.ArgumentParser(description='Cowsay Clone')
    parser.add_argument('message', nargs='*', help='Message to say')
    parser.add_argument('--animal', '-a', default='cow',
                       choices=list(ANIMALS.keys()), help='Animal to use')
    parser.add_argument('--think', '-t', action='store_true', help='Thought bubble')
    parser.add_argument('--list', '-l', action='store_true', help='List animals')
    parser.add_argument('--width', '-w', type=int, default=40, help='Bubble width')
    parser.add_argument('--random', '-r', action='store_true', help='Random animal')
    args = parser.parse_args()

    if args.list:
        print(f"\n{BOLD}{CYAN}Available Animals:{RESET}\n")
        for name in sorted(ANIMALS.keys()):
            print(f"  {GREEN}{name}{RESET}")
        print(f"\n{DIM}Use: cowsay.py -a <animal> <message>{RESET}\n")
        return

    # Get message
    if args.message:
        message = ' '.join(args.message)
    elif not sys.stdin.isatty():
        message = sys.stdin.read().strip()
    else:
        print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║              🐮 Cowsay                                     ║{RESET}")
        print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")
        message = input(f"  {CYAN}Message:{RESET} ").strip()

    if not message:
        message = "Moo!"

    # Random animal
    if args.random:
        import random
        args.animal = random.choice(list(ANIMALS.keys()))

    # Generate output
    output = cowsay(message, args.animal, args.think)
    print(output)


if __name__ == '__main__':
    main()
