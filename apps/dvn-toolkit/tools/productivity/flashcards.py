#!/usr/bin/env python3
"""
Flashcards - Create and study flashcards
Usage: flashcards.py [add|study|list|deck]
"""

import os
import json
import random
import argparse
from datetime import datetime, timedelta

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

FLASHCARDS_FILE = os.path.expanduser('~/.dvn_flashcards.json')


def load_data():
    """Load flashcards data"""
    if os.path.exists(FLASHCARDS_FILE):
        try:
            with open(FLASHCARDS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'decks': {'Default': []}, 'stats': {}}


def save_data(data):
    """Save flashcards data"""
    with open(FLASHCARDS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def add_card(front, back, deck='Default', tags=None):
    """Add a new flashcard"""
    data = load_data()

    if deck not in data['decks']:
        data['decks'][deck] = []

    card = {
        'id': sum(len(d) for d in data['decks'].values()) + 1,
        'front': front,
        'back': back,
        'tags': tags or [],
        'created': datetime.now().isoformat(),
        'reviews': 0,
        'correct': 0,
        'last_review': None,
        'next_review': datetime.now().isoformat(),
        'ease': 2.5,  # Spaced repetition ease factor
        'interval': 1,  # Days until next review
    }

    data['decks'][deck].append(card)
    save_data(data)
    return card


def delete_card(card_id, deck=None):
    """Delete a flashcard"""
    data = load_data()

    for deck_name, cards in data['decks'].items():
        if deck and deck_name != deck:
            continue

        for i, card in enumerate(cards):
            if card['id'] == int(card_id):
                cards.pop(i)
                save_data(data)
                return True

    return False


def get_cards_for_review(deck=None, limit=20):
    """Get cards due for review"""
    data = load_data()
    now = datetime.now().isoformat()

    due_cards = []

    for deck_name, cards in data['decks'].items():
        if deck and deck_name != deck:
            continue

        for card in cards:
            card['deck'] = deck_name
            if card.get('next_review', now) <= now:
                due_cards.append(card)

    # Sort by next_review (oldest first)
    due_cards.sort(key=lambda x: x.get('next_review', ''))

    return due_cards[:limit]


def update_card_review(card_id, correct, deck=None):
    """Update card after review using SM-2 algorithm"""
    data = load_data()

    for deck_name, cards in data['decks'].items():
        if deck and deck_name != deck:
            continue

        for card in cards:
            if card['id'] == int(card_id):
                card['reviews'] += 1
                card['last_review'] = datetime.now().isoformat()

                if correct:
                    card['correct'] += 1

                    # SM-2 algorithm
                    if card['reviews'] == 1:
                        card['interval'] = 1
                    elif card['reviews'] == 2:
                        card['interval'] = 6
                    else:
                        card['interval'] = int(card['interval'] * card['ease'])

                    # Increase ease for correct answers
                    card['ease'] = min(2.5, card['ease'] + 0.1)
                else:
                    # Reset on wrong answer
                    card['interval'] = 1
                    card['ease'] = max(1.3, card['ease'] - 0.2)

                next_date = datetime.now() + timedelta(days=card['interval'])
                card['next_review'] = next_date.isoformat()

                save_data(data)
                return True

    return False


def create_deck(name):
    """Create a new deck"""
    data = load_data()

    if name in data['decks']:
        return False

    data['decks'][name] = []
    save_data(data)
    return True


def delete_deck(name):
    """Delete a deck"""
    data = load_data()

    if name in data['decks'] and name != 'Default':
        del data['decks'][name]
        save_data(data)
        return True

    return False


def main():
    parser = argparse.ArgumentParser(description='Flashcards')
    parser.add_argument('action', nargs='?', default='study',
                       choices=['add', 'study', 'list', 'deck', 'delete', 'stats', 'import'])
    parser.add_argument('content', nargs='?', help='Card content or deck name')
    parser.add_argument('--deck', '-d', default='Default', help='Deck name')
    parser.add_argument('--back', '-b', help='Back of card')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📚 Flashcards                                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    data = load_data()

    if args.action == 'add':
        front = args.content or input(f"  {CYAN}Front (question):{RESET} ").strip()

        if not front:
            print(f"  {RED}Front content required{RESET}\n")
            return

        back = args.back or input(f"  {CYAN}Back (answer):{RESET} ").strip()

        if not back:
            print(f"  {RED}Back content required{RESET}\n")
            return

        card = add_card(front, back, args.deck)
        print(f"\n  {GREEN}✓ Card added to {args.deck}{RESET}")
        print(f"  {DIM}ID: {card['id']}{RESET}\n")

    elif args.action == 'study':
        deck = args.content or args.deck

        cards = get_cards_for_review(deck if deck != 'Default' else None)

        if not cards:
            print(f"  {GREEN}✓ No cards due for review!{RESET}")
            print(f"  {DIM}Come back later or add more cards{RESET}\n")
            return

        print(f"  {BOLD}Study Session ({len(cards)} cards due){RESET}")
        print(f"  {DIM}Press Enter to reveal, then rate 1-4{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")

        correct = 0
        reviewed = 0

        random.shuffle(cards)

        for card in cards:
            reviewed += 1

            print(f"  {CYAN}Card {reviewed}/{len(cards)}{RESET} {DIM}[{card.get('deck', 'Default')}]{RESET}\n")
            print(f"  {BOLD}Q: {card['front']}{RESET}\n")

            input(f"  {DIM}Press Enter to reveal...{RESET}")

            print(f"\n  {GREEN}A: {card['back']}{RESET}\n")

            # Get rating
            print(f"  {DIM}How well did you know it?{RESET}")
            print(f"  {RED}1{RESET}=Forgot  {YELLOW}2{RESET}=Hard  {CYAN}3{RESET}=Good  {GREEN}4{RESET}=Easy")

            while True:
                rating = input(f"\n  {CYAN}Rating (1-4, q=quit):{RESET} ").strip()

                if rating.lower() == 'q':
                    break

                if rating in ['1', '2', '3', '4']:
                    is_correct = int(rating) >= 3
                    update_card_review(card['id'], is_correct, card.get('deck'))

                    if is_correct:
                        correct += 1

                    break

            if rating.lower() == 'q':
                break

            print(f"\n  {DIM}{'─' * 45}{RESET}\n")

        # Summary
        print(f"\n  {BOLD}Session Complete!{RESET}")
        print(f"  {DIM}{'─' * 30}{RESET}")
        print(f"  {CYAN}Reviewed:{RESET} {reviewed} cards")
        if reviewed > 0:
            accuracy = (correct / reviewed) * 100
            print(f"  {CYAN}Accuracy:{RESET} {accuracy:.0f}%")
        print()

    elif args.action == 'list':
        deck = args.content or args.deck

        print(f"  {BOLD}Decks:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")

        for deck_name, cards in data['decks'].items():
            due = len([c for c in cards if c.get('next_review', '') <= datetime.now().isoformat()])
            print(f"  {GREEN}{deck_name}{RESET}")
            print(f"     Cards: {len(cards)} | Due: {due}")
            print()

        # If specific deck requested, show cards
        if deck and deck in data['decks']:
            print(f"  {BOLD}Cards in {deck}:{RESET}")
            print(f"  {DIM}{'─' * 40}{RESET}\n")

            for card in data['decks'][deck][:20]:
                accuracy = f"{(card['correct']/card['reviews']*100):.0f}%" if card['reviews'] > 0 else "New"
                print(f"  {CYAN}{card['id']:>3}.{RESET} {card['front'][:35]}")
                print(f"       {DIM}→ {card['back'][:35]} ({accuracy}){RESET}")
                print()

    elif args.action == 'deck':
        name = args.content or input(f"  {CYAN}Deck name:{RESET} ").strip()

        if not name:
            print(f"  {RED}Deck name required{RESET}\n")
            return

        if create_deck(name):
            print(f"  {GREEN}✓ Deck created: {name}{RESET}\n")
        else:
            print(f"  {YELLOW}Deck already exists{RESET}\n")

    elif args.action == 'delete':
        identifier = args.content or input(f"  {CYAN}Card ID or deck name:{RESET} ").strip()

        if not identifier:
            print(f"  {RED}ID or deck name required{RESET}\n")
            return

        if identifier.isdigit():
            if delete_card(identifier):
                print(f"  {GREEN}✓ Card deleted{RESET}\n")
            else:
                print(f"  {RED}Card not found{RESET}\n")
        else:
            if delete_deck(identifier):
                print(f"  {GREEN}✓ Deck deleted{RESET}\n")
            else:
                print(f"  {RED}Cannot delete deck{RESET}\n")

    elif args.action == 'stats':
        total_cards = sum(len(d) for d in data['decks'].values())
        total_reviews = sum(c.get('reviews', 0) for d in data['decks'].values() for c in d)
        due_cards = len(get_cards_for_review(limit=1000))

        print(f"  {BOLD}Statistics:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")
        print(f"  {CYAN}Total Decks:{RESET}    {len(data['decks'])}")
        print(f"  {CYAN}Total Cards:{RESET}    {total_cards}")
        print(f"  {CYAN}Total Reviews:{RESET}  {total_reviews}")
        print(f"  {CYAN}Due Today:{RESET}      {due_cards}")
        print()

    elif args.action == 'import':
        print(f"  {CYAN}Enter cards (format: front | back), empty line to finish:{RESET}\n")

        count = 0
        while True:
            line = input(f"  {DIM}>{RESET} ").strip()
            if not line:
                break

            if '|' in line:
                front, back = line.split('|', 1)
                add_card(front.strip(), back.strip(), args.deck)
                count += 1

        print(f"\n  {GREEN}✓ Imported {count} cards to {args.deck}{RESET}\n")


if __name__ == '__main__':
    main()
