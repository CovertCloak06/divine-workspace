#!/usr/bin/env python3
"""
Password Generator - Secure password/passphrase generator
Usage: pwgen [length] [--count 5] [--passphrase] [--no-symbols]
"""

import argparse
import secrets
import string
import math

# Common English words for passphrases
WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt",
    "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
    "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha",
    "already", "also", "alter", "always", "amateur", "amazing", "among", "amount",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce",
    "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart",
    "apple", "april", "arch", "arctic", "area", "arena", "argue", "arm",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid",
    "awake", "aware", "away", "awesome", "awful", "axis", "baby", "bachelor",
    "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
    "battle", "beach", "bean", "beauty", "because", "become", "beef", "before",
    "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
    "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse",
    "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone",
    "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom",
    "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave",
    "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk",
    "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy",
    "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker",
    "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer",
    "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "canal", "cancel", "candy", "cannon", "canoe",
    "canvas", "canyon", "capable", "capital", "captain", "carbon", "card", "cargo",
    "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
    "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave",
    "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair",
    "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chunk", "church", "cigar", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay",
    "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic",
    "clip", "clock", "close", "cloth", "cloud", "clown", "club", "clump",
    "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil",
    "coin", "collect", "color", "column", "combine", "come", "comfort", "comic",
    "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "coral", "core", "corn",
    "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "crane", "crash", "crater",
    "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
    "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel",
    "cruise", "crumble", "crunch", "crush", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute",
    "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash",
    "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december",
    "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy",
    "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert",
    "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device",
    "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet",
    "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt",
    "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double",
    "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress",
    "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck",
    "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
    "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology",
    "economy", "edge", "edit", "educate", "effort", "eight", "either", "elbow",
    "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
    "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty",
    "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce",
    "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll",
    "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
    "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence",
    "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact",
    "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise",
    "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect"
]

def generate_password(length=16, use_symbols=True, use_numbers=True, use_upper=True):
    """Generate a random password"""
    chars = string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Ensure at least one of each required type
    password = []
    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()_+-="))

    # Fill the rest
    remaining = length - len(password)
    password.extend(secrets.choice(chars) for _ in range(remaining))

    # Shuffle
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)

def generate_passphrase(word_count=4, separator='-', capitalize=True):
    """Generate a random passphrase"""
    words = [secrets.choice(WORDS) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return separator.join(words)

def calculate_entropy(password, charset_size=None):
    """Calculate password entropy in bits"""
    if charset_size:
        return len(password) * math.log2(charset_size)
    # Estimate charset from password
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += 32
    return len(password) * math.log2(charset) if charset else 0

def strength_rating(entropy):
    """Rate password strength"""
    if entropy < 28:
        return ("Very Weak", "\033[91m")
    elif entropy < 36:
        return ("Weak", "\033[91m")
    elif entropy < 60:
        return ("Moderate", "\033[93m")
    elif entropy < 80:
        return ("Strong", "\033[92m")
    else:
        return ("Very Strong", "\033[92m")

def main():
    parser = argparse.ArgumentParser(description='Password Generator')
    parser.add_argument('length', nargs='?', type=int, default=16, help='Password length')
    parser.add_argument('--count', '-c', type=int, default=5, help='Number of passwords')
    parser.add_argument('--passphrase', '-p', action='store_true', help='Generate passphrase instead')
    parser.add_argument('--words', '-w', type=int, default=4, help='Words in passphrase')
    parser.add_argument('--no-symbols', '-S', action='store_true', help='Exclude symbols')
    parser.add_argument('--no-numbers', '-N', action='store_true', help='Exclude numbers')
    parser.add_argument('--no-upper', '-U', action='store_true', help='Exclude uppercase')
    parser.add_argument('--separator', '-s', default='-', help='Passphrase separator')
    args = parser.parse_args()

    print("\n\033[1m\033[96mPassword Generator\033[0m\n")

    for i in range(args.count):
        if args.passphrase:
            pwd = generate_passphrase(args.words, args.separator)
            entropy = args.words * math.log2(len(WORDS))
        else:
            pwd = generate_password(
                args.length,
                use_symbols=not args.no_symbols,
                use_numbers=not args.no_numbers,
                use_upper=not args.no_upper
            )
            entropy = calculate_entropy(pwd)

        rating, color = strength_rating(entropy)
        print(f"  {i+1}. {pwd}")
        print(f"     {color}{rating}\033[0m ({entropy:.0f} bits)\n")

    print("\033[2mTip: Use --passphrase for memorable but secure passwords\033[0m\n")

if __name__ == '__main__':
    main()
