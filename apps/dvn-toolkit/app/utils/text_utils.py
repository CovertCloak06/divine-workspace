"""
Text Utilities - ANSI stripping and output cleaning for Android display
"""

import re

# Regex to match ANSI escape sequences
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\033\[[0-9;]*[a-zA-Z]')

# Box-drawing character replacements
BOX_CHARS = {
    '\u2550': '=',  # Double horizontal
    '\u2500': '-',  # Light horizontal
    '\u2502': '|',  # Light vertical
    '\u250c': '+',  # Light down and right
    '\u2510': '+',  # Light down and left
    '\u2514': '+',  # Light up and right
    '\u2518': '+',  # Light up and left
    '\u251c': '+',  # Light vertical and right
    '\u2524': '+',  # Light vertical and left
    '\u252c': '+',  # Light down and horizontal
    '\u2534': '+',  # Light up and horizontal
    '\u253c': '+',  # Light vertical and horizontal
    '\u2551': '|',  # Double vertical
    '\u2554': '+',  # Double down and right
    '\u2557': '+',  # Double down and left
    '\u255a': '+',  # Double up and right
    '\u255d': '+',  # Double up and left
    '\u2560': '+',  # Double vertical and right
    '\u2563': '+',  # Double vertical and left
    '\u2566': '+',  # Double down and horizontal
    '\u2569': '+',  # Double up and horizontal
    '\u256c': '+',  # Double vertical and horizontal
    '\u2591': '#',  # Light shade
    '\u2592': '#',  # Medium shade
    '\u2593': '#',  # Dark shade
    '\u2588': '#',  # Full block
}


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text"""
    if not text:
        return text
    return ANSI_ESCAPE.sub('', text)


def replace_box_chars(text: str) -> str:
    """Replace box-drawing characters with ASCII equivalents"""
    if not text:
        return text
    for char, replacement in BOX_CHARS.items():
        text = text.replace(char, replacement)
    return text


def clean_output(text: str) -> str:
    """
    Clean tool output for Android display.
    - Strips ANSI escape codes
    - Replaces box-drawing characters with ASCII
    """
    if not text:
        return text
    text = strip_ansi(text)
    text = replace_box_chars(text)
    return text
