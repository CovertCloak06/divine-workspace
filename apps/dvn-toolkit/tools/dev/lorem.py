#!/usr/bin/env python3
"""
Lorem Ipsum Generator - Generate placeholder text
Usage: lorem.py [--paragraphs N] [--words N] [--sentences N]
"""

import argparse
import random

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Classic Lorem Ipsum words
LOREM_WORDS = [
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
    "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
    "magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud",
    "exercitation", "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo",
    "consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
    "velit", "esse", "cillum", "fugiat", "nulla", "pariatur", "excepteur", "sint",
    "occaecat", "cupidatat", "non", "proident", "sunt", "culpa", "qui", "officia",
    "deserunt", "mollit", "anim", "id", "est", "laborum", "at", "vero", "eos",
    "accusamus", "iusto", "odio", "dignissimos", "ducimus", "blanditiis",
    "praesentium", "voluptatum", "deleniti", "atque", "corrupti", "quos", "dolores",
    "quas", "molestias", "excepturi", "occaecati", "cupiditate", "provident",
    "similique", "mollitia", "animi", "dolorem", "ipsam", "quia", "voluptas",
    "aspernatur", "aut", "odit", "fugit", "consequuntur", "magni", "ratione",
    "sequi", "nesciunt", "neque", "porro", "quisquam", "numquam", "eius", "modi",
    "tempora", "quaerat", "inventore", "veritatis", "quasi", "architecto",
    "beatae", "vitae", "dicta", "explicabo", "nemo", "ipsam", "voluptatem"
]

CLASSIC_FIRST = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"


def generate_sentence(min_words=5, max_words=15, start_with_lorem=False):
    """Generate a single sentence"""
    if start_with_lorem:
        return CLASSIC_FIRST + "."

    num_words = random.randint(min_words, max_words)
    words = [random.choice(LOREM_WORDS) for _ in range(num_words)]
    words[0] = words[0].capitalize()

    # Maybe add comma
    if num_words > 8 and random.random() > 0.5:
        comma_pos = random.randint(3, num_words - 3)
        words[comma_pos] = words[comma_pos] + ","

    return " ".join(words) + "."


def generate_paragraph(num_sentences=5, start_with_lorem=False):
    """Generate a paragraph"""
    sentences = []
    for i in range(num_sentences):
        if i == 0 and start_with_lorem:
            sentences.append(generate_sentence(start_with_lorem=True))
        else:
            sentences.append(generate_sentence())
    return " ".join(sentences)


def generate_words(count):
    """Generate specific number of words"""
    words = []
    for i in range(count):
        if i == 0:
            words.append(LOREM_WORDS[0].capitalize())
        elif i == 1:
            words.append(LOREM_WORDS[1])
        else:
            words.append(random.choice(LOREM_WORDS))
    return " ".join(words)


def generate_list_items(count):
    """Generate bullet points"""
    items = []
    for _ in range(count):
        words = [random.choice(LOREM_WORDS) for _ in range(random.randint(3, 8))]
        words[0] = words[0].capitalize()
        items.append(" ".join(words))
    return items


def main():
    parser = argparse.ArgumentParser(description='Lorem Ipsum Generator')
    parser.add_argument('--paragraphs', '-p', type=int, help='Number of paragraphs')
    parser.add_argument('--sentences', '-s', type=int, help='Number of sentences')
    parser.add_argument('--words', '-w', type=int, help='Number of words')
    parser.add_argument('--list', '-l', type=int, metavar='N', help='Generate N list items')
    parser.add_argument('--copy', '-c', action='store_true', help='Copy to clipboard')
    parser.add_argument('--no-start', action='store_true', help='Do not start with "Lorem ipsum"')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📝 Lorem Ipsum Generator                      ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    start_lorem = not args.no_start
    output = ""

    if args.words:
        print(f"  {BOLD}Generated {args.words} words:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")
        output = generate_words(args.words)

        # Wrap text
        words = output.split()
        lines = []
        current = []
        for word in words:
            current.append(word)
            if len(" ".join(current)) > 60:
                lines.append(" ".join(current))
                current = []
        if current:
            lines.append(" ".join(current))

        for line in lines:
            print(f"  {line}")

    elif args.sentences:
        print(f"  {BOLD}Generated {args.sentences} sentences:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")
        sentences = []
        for i in range(args.sentences):
            if i == 0 and start_lorem:
                sentences.append(generate_sentence(start_with_lorem=True))
            else:
                sentences.append(generate_sentence())
        output = " ".join(sentences)

        # Wrap
        words = output.split()
        line = ""
        for word in words:
            if len(line) + len(word) > 60:
                print(f"  {line}")
                line = word
            else:
                line = line + " " + word if line else word
        if line:
            print(f"  {line}")

    elif args.list:
        print(f"  {BOLD}Generated {args.list} list items:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")
        items = generate_list_items(args.list)
        output = "\n".join(f"• {item}" for item in items)
        for item in items:
            print(f"  {CYAN}•{RESET} {item}")

    else:
        # Default: paragraphs
        num_para = args.paragraphs if args.paragraphs else 3
        print(f"  {BOLD}Generated {num_para} paragraphs:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        paragraphs = []
        for i in range(num_para):
            para = generate_paragraph(
                num_sentences=random.randint(4, 7),
                start_with_lorem=(i == 0 and start_lorem)
            )
            paragraphs.append(para)

            # Wrap and print
            words = para.split()
            line = ""
            for word in words:
                if len(line) + len(word) > 60:
                    print(f"  {line}")
                    line = word
                else:
                    line = line + " " + word if line else word
            if line:
                print(f"  {line}")
            print()

        output = "\n\n".join(paragraphs)

    # Copy to clipboard
    if args.copy:
        try:
            import subprocess
            process = subprocess.Popen(['xclip', '-selection', 'clipboard'],
                                      stdin=subprocess.PIPE)
            process.communicate(output.encode())
            print(f"\n  {GREEN}✓ Copied to clipboard{RESET}")
        except:
            try:
                import subprocess
                process = subprocess.Popen(['xsel', '--clipboard', '--input'],
                                          stdin=subprocess.PIPE)
                process.communicate(output.encode())
                print(f"\n  {GREEN}✓ Copied to clipboard{RESET}")
            except:
                print(f"\n  {YELLOW}Could not copy (xclip/xsel not available){RESET}")

    # Stats
    word_count = len(output.split())
    char_count = len(output)
    print(f"\n  {DIM}Words: {word_count} | Characters: {char_count}{RESET}")
    print()


if __name__ == '__main__':
    main()
