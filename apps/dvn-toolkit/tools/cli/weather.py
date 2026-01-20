#!/usr/bin/env python3
"""
Weather - Check current weather conditions
Usage: weather.py [location]
"""

import urllib.request
import json
import argparse
import os

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
BLUE = '\033[94m'

# Weather condition icons
WEATHER_ICONS = {
    'clear': '☀️',
    'sunny': '☀️',
    'partly cloudy': '⛅',
    'cloudy': '☁️',
    'overcast': '☁️',
    'mist': '🌫️',
    'fog': '🌫️',
    'rain': '🌧️',
    'light rain': '🌦️',
    'heavy rain': '🌧️',
    'drizzle': '🌦️',
    'showers': '🌧️',
    'thunderstorm': '⛈️',
    'thunder': '⛈️',
    'snow': '🌨️',
    'light snow': '🌨️',
    'heavy snow': '❄️',
    'sleet': '🌨️',
    'hail': '🌨️',
    'wind': '💨',
    'windy': '💨',
}


def get_weather_icon(condition):
    """Get weather icon for condition"""
    condition_lower = condition.lower()
    for key, icon in WEATHER_ICONS.items():
        if key in condition_lower:
            return icon
    return '🌡️'


def get_weather_wttr(location):
    """Get weather from wttr.in"""
    try:
        # URL encode the location
        location_encoded = urllib.parse.quote(location)
        url = f'https://wttr.in/{location_encoded}?format=j1'

        req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.68.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data
    except Exception as e:
        return None


def get_simple_weather(location):
    """Get simple one-line weather"""
    try:
        location_encoded = urllib.parse.quote(location)
        url = f'https://wttr.in/{location_encoded}?format=%l:+%c+%t+%h+%w'

        req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.68.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode().strip()
    except:
        return None


def display_weather(data):
    """Display weather data"""
    if not data:
        return

    # Current conditions
    current = data.get('current_condition', [{}])[0]
    location = data.get('nearest_area', [{}])[0]

    # Location info
    city = location.get('areaName', [{}])[0].get('value', 'Unknown')
    country = location.get('country', [{}])[0].get('value', '')
    region = location.get('region', [{}])[0].get('value', '')

    print(f"  {BOLD}Location:{RESET} {city}", end='')
    if region:
        print(f", {region}", end='')
    if country:
        print(f", {country}", end='')
    print()

    # Current weather
    temp_c = current.get('temp_C', 'N/A')
    temp_f = current.get('temp_F', 'N/A')
    feels_c = current.get('FeelsLikeC', temp_c)
    feels_f = current.get('FeelsLikeF', temp_f)
    condition = current.get('weatherDesc', [{}])[0].get('value', 'Unknown')
    humidity = current.get('humidity', 'N/A')
    wind_kph = current.get('windspeedKmph', 'N/A')
    wind_dir = current.get('winddir16Point', '')
    pressure = current.get('pressure', 'N/A')
    visibility = current.get('visibility', 'N/A')
    uv_index = current.get('uvIndex', 'N/A')

    icon = get_weather_icon(condition)

    print(f"\n  {BOLD}Current Conditions:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")

    # Temperature
    print(f"\n      {icon}  {BOLD}{temp_c}°C{RESET} / {temp_f}°F")
    print(f"         {condition}")

    if feels_c != temp_c:
        print(f"         {DIM}Feels like {feels_c}°C{RESET}")

    print(f"\n  {CYAN}Humidity:{RESET}    {humidity}%")
    print(f"  {CYAN}Wind:{RESET}        {wind_kph} km/h {wind_dir}")
    print(f"  {CYAN}Pressure:{RESET}    {pressure} mb")
    print(f"  {CYAN}Visibility:{RESET}  {visibility} km")
    print(f"  {CYAN}UV Index:{RESET}    {uv_index}")

    # Forecast
    weather = data.get('weather', [])
    if len(weather) >= 3:
        print(f"\n  {BOLD}3-Day Forecast:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")

        for day in weather[:3]:
            date = day.get('date', '')
            max_c = day.get('maxtempC', 'N/A')
            min_c = day.get('mintempC', 'N/A')
            max_f = day.get('maxtempF', 'N/A')
            min_f = day.get('mintempF', 'N/A')

            hourly = day.get('hourly', [{}])
            # Get midday condition
            midday = hourly[4] if len(hourly) > 4 else hourly[0]
            day_condition = midday.get('weatherDesc', [{}])[0].get('value', '')
            day_icon = get_weather_icon(day_condition)

            # Parse date
            from datetime import datetime
            try:
                dt = datetime.strptime(date, '%Y-%m-%d')
                day_name = dt.strftime('%a %b %d')
            except:
                day_name = date

            print(f"\n  {CYAN}{day_name}{RESET}")
            print(f"  {day_icon} {day_condition}")
            print(f"  {RED}↑{max_c}°C{RESET} / {BLUE}↓{min_c}°C{RESET}")

    # Astronomy
    if weather:
        astro = weather[0].get('astronomy', [{}])[0]
        sunrise = astro.get('sunrise', '')
        sunset = astro.get('sunset', '')
        moon_phase = astro.get('moon_phase', '')

        if sunrise or sunset:
            print(f"\n  {BOLD}Sun & Moon:{RESET}")
            print(f"  {DIM}{'─' * 40}{RESET}")
            print(f"  {YELLOW}☀️ Sunrise:{RESET} {sunrise}  {YELLOW}Sunset:{RESET} {sunset}")
            if moon_phase:
                moon_icons = {
                    'New Moon': '🌑',
                    'Waxing Crescent': '🌒',
                    'First Quarter': '🌓',
                    'Waxing Gibbous': '🌔',
                    'Full Moon': '🌕',
                    'Waning Gibbous': '🌖',
                    'Last Quarter': '🌗',
                    'Waning Crescent': '🌘',
                }
                moon_icon = moon_icons.get(moon_phase, '🌙')
                print(f"  {moon_icon} Moon: {moon_phase}")


def main():
    parser = argparse.ArgumentParser(description='Weather')
    parser.add_argument('location', nargs='*', help='Location (city name, zip code, etc.)')
    parser.add_argument('--simple', '-s', action='store_true', help='Simple one-line output')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🌤️  Weather                                    ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Get location
    if args.location:
        location = ' '.join(args.location)
    else:
        location = input(f"  {CYAN}Location:{RESET} ").strip()
        if not location:
            location = ''  # Will use IP-based location

    if args.simple:
        result = get_simple_weather(location)
        if result:
            print(f"  {result}")
        else:
            print(f"  {RED}Could not fetch weather{RESET}")
        print()
        return

    print(f"  {DIM}Fetching weather data...{RESET}")

    data = get_weather_wttr(location)

    if data:
        display_weather(data)
    else:
        print(f"\n  {RED}Could not fetch weather data{RESET}")
        print(f"  {DIM}Check your internet connection or try a different location{RESET}")

    print()


if __name__ == '__main__':
    main()
