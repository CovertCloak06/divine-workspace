#!/usr/bin/env python3
"""
Typing Test - Test your typing speed
Usage: typing_test.py [--words N] [--time N]
"""

import time
import random
import argparse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Common English words for typing test
WORDS = [
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
    "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
    "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
    "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "when", "make", "can", "like", "time", "no", "just", "him", "know",
    "take", "people", "into", "year", "your", "good", "some", "could",
    "them", "see", "other", "than", "then", "now", "look", "only", "come",
    "its", "over", "think", "also", "back", "after", "use", "two", "how",
    "our", "work", "first", "well", "way", "even", "new", "want", "because",
    "any", "these", "give", "day", "most", "us", "is", "water", "been",
    "call", "oil", "find", "long", "down", "did", "made", "may", "part",
    "sound", "still", "place", "right", "where", "turn", "need", "too",
    "mean", "show", "must", "home", "big", "high", "set", "put", "end",
    "does", "another", "why", "ask", "went", "men", "read", "very", "through",
    "line", "life", "kind", "same", "tell", "boy", "follow", "came", "such",
    "great", "every", "act", "more", "write", "word", "number", "always",
    "move", "seem", "help", "house", "world", "again", "off", "play",
    "spell", "air", "away", "animal", "point", "page", "letter", "answer",
    "found", "study", "learn", "should", "America", "own", "below", "between",
    "city", "tree", "cross", "farm", "hard", "start", "might", "story",
    "far", "sea", "draw", "left", "late", "run", "while", "press", "close",
    "night", "real", "few", "north", "open", "together", "next", "white",
    "children", "begin", "got", "walk", "example", "ease", "paper", "group",
    "important", "often", "keep", "family", "watch", "carry", "state", "once",
    "book", "hear", "stop", "thought", "young", "head", "stand", "under",
    "ready", "school", "nothing", "main", "enough", "sure", "thing", "feet",
]

# Programming words
PROGRAMMING_WORDS = [
    "function", "variable", "const", "let", "return", "class", "import",
    "export", "async", "await", "promise", "array", "object", "string",
    "number", "boolean", "null", "undefined", "typeof", "interface", "type",
    "enum", "module", "package", "require", "include", "define", "struct",
    "method", "property", "value", "key", "index", "loop", "while", "for",
    "if", "else", "switch", "case", "break", "continue", "try", "catch",
    "throw", "finally", "error", "debug", "console", "print", "log",
    "server", "client", "request", "response", "status", "header", "body",
    "json", "xml", "html", "css", "javascript", "python", "java", "rust",
    "database", "query", "insert", "update", "delete", "select", "table",
    "column", "row", "primary", "foreign", "index", "schema", "migration",
    "component", "render", "state", "props", "effect", "hook", "context",
    "redux", "store", "action", "reducer", "dispatch", "selector", "thunk",
    "api", "rest", "graphql", "endpoint", "route", "middleware", "handler",
    "auth", "token", "session", "cookie", "cache", "memory", "storage",
    "file", "stream", "buffer", "pipe", "socket", "event", "listener",
    "callback", "closure", "scope", "prototype", "inheritance", "polymorphism",
    "algorithm", "data", "structure", "tree", "graph", "node", "edge",
    "stack", "queue", "heap", "hash", "map", "set", "list", "linked",
]


def generate_text(word_count, word_list):
    """Generate random text for typing"""
    return ' '.join(random.choice(word_list) for _ in range(word_count))


def calculate_accuracy(original, typed):
    """Calculate typing accuracy"""
    original_words = original.split()
    typed_words = typed.split()

    correct = 0
    total = len(original_words)

    for i, word in enumerate(typed_words[:total]):
        if i < len(original_words) and word == original_words[i]:
            correct += 1

    return (correct / total * 100) if total > 0 else 0


def highlight_differences(original, typed):
    """Highlight correct/incorrect words"""
    original_words = original.split()
    typed_words = typed.split()

    result = []
    for i, orig_word in enumerate(original_words):
        if i < len(typed_words):
            if typed_words[i] == orig_word:
                result.append(f"{GREEN}{orig_word}{RESET}")
            else:
                result.append(f"{RED}{orig_word}{RESET}")
        else:
            result.append(f"{DIM}{orig_word}{RESET}")

    return ' '.join(result)


def run_typing_test(word_count=25, time_limit=None, programming=False):
    """Run the typing test"""
    word_list = PROGRAMMING_WORDS if programming else WORDS
    text = generate_text(word_count, word_list)

    print(f"\n  {BOLD}Type the following text:{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}\n")

    # Display text to type (wrapped)
    words = text.split()
    line = "  "
    for word in words:
        if len(line) + len(word) > 60:
            print(line)
            line = "  " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    print(f"\n  {DIM}{'─' * 55}{RESET}")

    if time_limit:
        print(f"  {YELLOW}Time limit: {time_limit} seconds{RESET}")

    print(f"  {DIM}Press Enter when ready, then type and press Enter when done{RESET}\n")

    input(f"  {CYAN}Ready? Press Enter to start...{RESET}")

    start_time = time.time()
    print(f"\n  {GREEN}GO!{RESET}\n")

    try:
        typed = input("  > ").strip()
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Test cancelled{RESET}\n")
        return

    end_time = time.time()
    elapsed = end_time - start_time

    # Check time limit
    if time_limit and elapsed > time_limit:
        print(f"\n  {RED}Time's up! ({elapsed:.1f}s > {time_limit}s){RESET}")
        elapsed = time_limit

    # Calculate results
    typed_words = typed.split()
    char_count = len(typed)
    word_count_typed = len(typed_words)

    # Words per minute
    wpm = (word_count_typed / elapsed) * 60 if elapsed > 0 else 0

    # Characters per minute
    cpm = (char_count / elapsed) * 60 if elapsed > 0 else 0

    # Accuracy
    accuracy = calculate_accuracy(text, typed)

    # Adjusted WPM (accounting for errors)
    adjusted_wpm = wpm * (accuracy / 100)

    # Display results
    print(f"\n  {BOLD}Results:{RESET}")
    print(f"  {DIM}{'─' * 45}{RESET}\n")

    print(f"  {CYAN}Time:{RESET}         {elapsed:.1f} seconds")
    print(f"  {CYAN}Words typed:{RESET}  {word_count_typed}")
    print(f"  {CYAN}Characters:{RESET}   {char_count}")

    print(f"\n  {CYAN}Raw WPM:{RESET}      {wpm:.1f}")
    print(f"  {CYAN}Adjusted WPM:{RESET} {adjusted_wpm:.1f}")
    print(f"  {CYAN}CPM:{RESET}          {cpm:.0f}")

    # Accuracy with color
    if accuracy >= 95:
        acc_color = GREEN
        rating = "Excellent!"
    elif accuracy >= 85:
        acc_color = CYAN
        rating = "Good"
    elif accuracy >= 75:
        acc_color = YELLOW
        rating = "Average"
    else:
        acc_color = RED
        rating = "Needs practice"

    print(f"  {CYAN}Accuracy:{RESET}     {acc_color}{accuracy:.1f}%{RESET} - {rating}")

    # Show comparison
    print(f"\n  {BOLD}Comparison:{RESET}")
    print(f"  {DIM}{'─' * 45}{RESET}\n")
    print(f"  {highlight_differences(text, typed)}\n")

    # WPM rating
    print(f"  {BOLD}Speed Rating:{RESET}")
    if adjusted_wpm >= 80:
        print(f"  {GREEN}Professional typist!{RESET}")
    elif adjusted_wpm >= 60:
        print(f"  {CYAN}Above average{RESET}")
    elif adjusted_wpm >= 40:
        print(f"  {YELLOW}Average typist{RESET}")
    else:
        print(f"  {DIM}Keep practicing!{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Typing Test')
    parser.add_argument('--words', '-w', type=int, default=25, help='Number of words')
    parser.add_argument('--time', '-t', type=int, help='Time limit in seconds')
    parser.add_argument('--programming', '-p', action='store_true', help='Use programming words')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              ⌨️  Typing Test                                ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}")

    while True:
        run_typing_test(
            word_count=args.words,
            time_limit=args.time,
            programming=args.programming
        )

        again = input(f"  {CYAN}Try again? (y/n):{RESET} ").strip().lower()
        if again != 'y':
            break

    print(f"  {GREEN}Thanks for practicing!{RESET}\n")


if __name__ == '__main__':
    main()
