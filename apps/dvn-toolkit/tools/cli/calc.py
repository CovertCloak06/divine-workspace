#!/usr/bin/env python3
"""
Calculator - Scientific calculator with unit conversions
Usage: calc.py [expression] or interactive mode
"""

import math
import argparse
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Constants
CONSTANTS = {
    'pi': math.pi,
    'e': math.e,
    'tau': math.tau,
    'phi': (1 + math.sqrt(5)) / 2,  # Golden ratio
    'c': 299792458,  # Speed of light m/s
    'g': 9.80665,    # Gravity m/s²
}

# Unit conversions
CONVERSIONS = {
    # Length
    'km_to_mi': lambda x: x * 0.621371,
    'mi_to_km': lambda x: x * 1.60934,
    'm_to_ft': lambda x: x * 3.28084,
    'ft_to_m': lambda x: x * 0.3048,
    'cm_to_in': lambda x: x * 0.393701,
    'in_to_cm': lambda x: x * 2.54,

    # Weight
    'kg_to_lb': lambda x: x * 2.20462,
    'lb_to_kg': lambda x: x * 0.453592,
    'g_to_oz': lambda x: x * 0.035274,
    'oz_to_g': lambda x: x * 28.3495,

    # Temperature
    'c_to_f': lambda x: (x * 9/5) + 32,
    'f_to_c': lambda x: (x - 32) * 5/9,
    'c_to_k': lambda x: x + 273.15,
    'k_to_c': lambda x: x - 273.15,

    # Volume
    'l_to_gal': lambda x: x * 0.264172,
    'gal_to_l': lambda x: x * 3.78541,
    'ml_to_floz': lambda x: x * 0.033814,
    'floz_to_ml': lambda x: x * 29.5735,

    # Area
    'sqm_to_sqft': lambda x: x * 10.7639,
    'sqft_to_sqm': lambda x: x * 0.092903,
    'ha_to_acre': lambda x: x * 2.47105,
    'acre_to_ha': lambda x: x * 0.404686,

    # Speed
    'kmh_to_mph': lambda x: x * 0.621371,
    'mph_to_kmh': lambda x: x * 1.60934,
    'ms_to_kmh': lambda x: x * 3.6,
    'kmh_to_ms': lambda x: x / 3.6,

    # Data
    'mb_to_gb': lambda x: x / 1024,
    'gb_to_mb': lambda x: x * 1024,
    'gb_to_tb': lambda x: x / 1024,
    'tb_to_gb': lambda x: x * 1024,

    # Time
    'hr_to_min': lambda x: x * 60,
    'min_to_hr': lambda x: x / 60,
    'day_to_hr': lambda x: x * 24,
    'hr_to_day': lambda x: x / 24,
}


def safe_eval(expression):
    """Safely evaluate mathematical expression"""
    # Replace constants
    for name, value in CONSTANTS.items():
        expression = re.sub(rf'\b{name}\b', str(value), expression, flags=re.IGNORECASE)

    # Add math functions
    allowed_names = {
        'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
        'asin': math.asin, 'acos': math.acos, 'atan': math.atan,
        'sinh': math.sinh, 'cosh': math.cosh, 'tanh': math.tanh,
        'sqrt': math.sqrt, 'log': math.log, 'log10': math.log10,
        'log2': math.log2, 'exp': math.exp, 'pow': pow,
        'abs': abs, 'round': round, 'floor': math.floor,
        'ceil': math.ceil, 'factorial': math.factorial,
        'degrees': math.degrees, 'radians': math.radians,
        'gcd': math.gcd, 'lcm': math.lcm if hasattr(math, 'lcm') else lambda a, b: abs(a * b) // math.gcd(a, b),
    }

    # Replace ^ with ** for power
    expression = expression.replace('^', '**')

    # Handle percentages
    expression = re.sub(r'(\d+)%', r'(\1/100)', expression)

    try:
        # Only allow safe operations
        result = eval(expression, {"__builtins__": {}}, allowed_names)
        return result
    except Exception as e:
        return None


def convert_unit(value, conversion):
    """Convert between units"""
    conversion = conversion.lower().replace(' ', '_')

    if conversion in CONVERSIONS:
        return CONVERSIONS[conversion](value)

    # Try alternate formats
    alt_formats = [
        conversion,
        conversion.replace('to', '_to_'),
        conversion.replace('2', '_to_'),
    ]

    for fmt in alt_formats:
        if fmt in CONVERSIONS:
            return CONVERSIONS[fmt](value)

    return None


def format_result(value):
    """Format result for display"""
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        elif abs(value) < 0.0001 or abs(value) > 1000000:
            return f"{value:.6e}"
        else:
            return f"{value:.10g}"
    return str(value)


def interactive_mode():
    """Interactive calculator"""
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🔢 Calculator                                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {DIM}Commands: 'conv' for conversions, 'const' for constants, 'quit' to exit{RESET}")
    print(f"  {DIM}Functions: sin, cos, tan, sqrt, log, exp, pow, factorial...{RESET}\n")

    history = []
    ans = 0

    while True:
        try:
            expr = input(f"  {CYAN}>{RESET} ").strip()
        except EOFError:
            break

        if not expr:
            continue

        if expr.lower() in ['q', 'quit', 'exit']:
            break

        if expr.lower() == 'const':
            print(f"\n  {BOLD}Constants:{RESET}")
            for name, value in CONSTANTS.items():
                print(f"    {CYAN}{name:6}{RESET} = {value}")
            print()
            continue

        if expr.lower() == 'conv':
            print(f"\n  {BOLD}Conversions:{RESET}")
            print(f"  {DIM}Format: <value> <from>_to_<to> (e.g., 100 km_to_mi){RESET}\n")

            categories = {
                'Length': ['km_to_mi', 'm_to_ft', 'cm_to_in'],
                'Weight': ['kg_to_lb', 'g_to_oz'],
                'Temp': ['c_to_f', 'f_to_c', 'c_to_k'],
                'Volume': ['l_to_gal', 'ml_to_floz'],
                'Speed': ['kmh_to_mph', 'ms_to_kmh'],
            }

            for cat, convs in categories.items():
                print(f"  {CYAN}{cat}:{RESET} {', '.join(convs)}")
            print()
            continue

        if expr.lower() == 'hist':
            print(f"\n  {BOLD}History:{RESET}")
            for h in history[-10:]:
                print(f"    {h}")
            print()
            continue

        # Handle 'ans' for previous answer
        expr = re.sub(r'\bans\b', str(ans), expr, flags=re.IGNORECASE)

        # Check for unit conversion
        conv_match = re.match(r'([\d.]+)\s*(\w+_to_\w+)', expr)
        if conv_match:
            value = float(conv_match.group(1))
            conversion = conv_match.group(2)
            result = convert_unit(value, conversion)

            if result is not None:
                print(f"  {GREEN}= {format_result(result)}{RESET}")
                ans = result
                history.append(f"{expr} = {format_result(result)}")
            else:
                print(f"  {RED}Unknown conversion: {conversion}{RESET}")
            continue

        # Evaluate expression
        result = safe_eval(expr)

        if result is not None:
            print(f"  {GREEN}= {format_result(result)}{RESET}")
            ans = result
            history.append(f"{expr} = {format_result(result)}")
        else:
            print(f"  {RED}Error: Invalid expression{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Calculator')
    parser.add_argument('expression', nargs='*', help='Expression to evaluate')
    parser.add_argument('--convert', '-c', help='Unit conversion (e.g., 100 km_to_mi)')
    args = parser.parse_args()

    if args.convert:
        # Parse conversion
        parts = args.convert.split()
        if len(parts) >= 2:
            try:
                value = float(parts[0])
                conversion = '_'.join(parts[1:])
                result = convert_unit(value, conversion)

                if result is not None:
                    print(f"{format_result(result)}")
                else:
                    print(f"Unknown conversion")
            except ValueError:
                print("Invalid number")
        return

    if args.expression:
        expr = ' '.join(args.expression)
        result = safe_eval(expr)

        if result is not None:
            print(format_result(result))
        else:
            print("Error")
    else:
        interactive_mode()


if __name__ == '__main__':
    main()
