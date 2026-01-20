#!/usr/bin/env python3
"""
YouTube Downloader Helper - Download videos using yt-dlp
Usage: ytdl.py <url> [--audio] [--quality best]
"""

import subprocess
import argparse
import os
import sys
import re

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def check_ytdlp():
    """Check if yt-dlp is installed"""
    try:
        result = subprocess.run(['yt-dlp', '--version'], capture_output=True, text=True)
        return result.returncode == 0, result.stdout.strip()
    except FileNotFoundError:
        return False, None


def get_video_info(url):
    """Get video information"""
    try:
        result = subprocess.run([
            'yt-dlp', '--dump-json', '--no-download', url
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            import json
            return json.loads(result.stdout)
    except:
        pass
    return None


def list_formats(url):
    """List available formats"""
    try:
        result = subprocess.run([
            'yt-dlp', '-F', url
        ], capture_output=True, text=True, timeout=30)
        return result.stdout
    except:
        return None


def download_video(url, options):
    """Download video with given options"""
    cmd = ['yt-dlp']

    # Output template
    output_dir = options.get('output_dir', '.')
    cmd.extend(['-o', os.path.join(output_dir, '%(title)s.%(ext)s')])

    # Format selection
    if options.get('audio_only'):
        cmd.extend(['-x', '--audio-format', 'mp3'])
    elif options.get('format'):
        cmd.extend(['-f', options['format']])
    elif options.get('quality'):
        quality_map = {
            'best': 'bestvideo+bestaudio/best',
            '1080': 'bestvideo[height<=1080]+bestaudio/best[height<=1080]',
            '720': 'bestvideo[height<=720]+bestaudio/best[height<=720]',
            '480': 'bestvideo[height<=480]+bestaudio/best[height<=480]',
            '360': 'bestvideo[height<=360]+bestaudio/best[height<=360]',
        }
        fmt = quality_map.get(options['quality'], 'best')
        cmd.extend(['-f', fmt])

    # Additional options
    if options.get('subtitles'):
        cmd.extend(['--write-sub', '--sub-lang', 'en'])

    if options.get('thumbnail'):
        cmd.append('--write-thumbnail')

    if options.get('metadata'):
        cmd.append('--add-metadata')

    # URL
    cmd.append(url)

    # Execute
    print(f"\n  {DIM}Running: {' '.join(cmd[:5])}...{RESET}\n")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    for line in process.stdout:
        line = line.strip()
        if '[download]' in line and '%' in line:
            # Progress line
            print(f"\r  {CYAN}{line}{RESET}", end='')
        elif line:
            print(f"  {line}")

    process.wait()
    print()

    return process.returncode == 0


def format_duration(seconds):
    """Format duration"""
    if not seconds:
        return 'Unknown'

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


def format_views(views):
    """Format view count"""
    if not views:
        return 'Unknown'

    if views >= 1_000_000_000:
        return f"{views / 1_000_000_000:.1f}B"
    elif views >= 1_000_000:
        return f"{views / 1_000_000:.1f}M"
    elif views >= 1_000:
        return f"{views / 1_000:.1f}K"
    return str(views)


def main():
    parser = argparse.ArgumentParser(description='YouTube Downloader Helper')
    parser.add_argument('url', nargs='?', help='Video URL')
    parser.add_argument('--audio', '-a', action='store_true', help='Download audio only (MP3)')
    parser.add_argument('--quality', '-q', choices=['best', '1080', '720', '480', '360'],
                        default='best', help='Video quality')
    parser.add_argument('--format', '-f', help='Specific format code')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--list-formats', '-F', action='store_true', help='List available formats')
    parser.add_argument('--subtitles', '-s', action='store_true', help='Download subtitles')
    parser.add_argument('--thumbnail', '-t', action='store_true', help='Download thumbnail')
    parser.add_argument('--info', '-i', action='store_true', help='Show video info only')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              📺 YouTube Downloader                         ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    # Check for yt-dlp
    installed, version = check_ytdlp()

    if not installed:
        print(f"  {RED}yt-dlp not installed{RESET}")
        print(f"\n  {BOLD}Install with:{RESET}")
        print(f"  {CYAN}pip install yt-dlp{RESET}")
        print(f"  {DIM}or{RESET}")
        print(f"  {CYAN}sudo apt install yt-dlp{RESET}")
        print()
        return

    print(f"  {DIM}yt-dlp version: {version}{RESET}")

    if not args.url:
        # Interactive mode
        args.url = input(f"\n  {CYAN}Video URL:{RESET} ").strip()

        if not args.url:
            print(f"  {RED}URL required{RESET}\n")
            return

        print(f"\n  {BOLD}Options:{RESET}")
        print(f"  {CYAN}1.{RESET} Download video (best quality)")
        print(f"  {CYAN}2.{RESET} Download audio only (MP3)")
        print(f"  {CYAN}3.{RESET} Choose quality")
        print(f"  {CYAN}4.{RESET} List formats")
        print(f"  {CYAN}5.{RESET} Video info")

        choice = input(f"\n  {CYAN}Choice [1]:{RESET} ").strip() or '1'

        if choice == '2':
            args.audio = True
        elif choice == '3':
            print(f"\n  {CYAN}Quality:{RESET}")
            print(f"    1. Best")
            print(f"    2. 1080p")
            print(f"    3. 720p")
            print(f"    4. 480p")
            print(f"    5. 360p")
            q_choice = input(f"  {CYAN}Choice [1]:{RESET} ").strip() or '1'
            quality_map = {'1': 'best', '2': '1080', '3': '720', '4': '480', '5': '360'}
            args.quality = quality_map.get(q_choice, 'best')
        elif choice == '4':
            args.list_formats = True
        elif choice == '5':
            args.info = True

    # Validate URL
    if not re.match(r'https?://', args.url):
        args.url = 'https://' + args.url

    # List formats
    if args.list_formats:
        print(f"\n  {BOLD}Available Formats:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        formats = list_formats(args.url)
        if formats:
            print(formats)
        else:
            print(f"  {RED}Could not retrieve formats{RESET}")
        print()
        return

    # Get video info
    print(f"\n  {DIM}Fetching video info...{RESET}")
    info = get_video_info(args.url)

    if info:
        print(f"\n  {BOLD}Video Info:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        print(f"  {CYAN}Title:{RESET}    {info.get('title', 'Unknown')[:50]}")
        print(f"  {CYAN}Channel:{RESET}  {info.get('uploader', 'Unknown')}")
        print(f"  {CYAN}Duration:{RESET} {format_duration(info.get('duration'))}")
        print(f"  {CYAN}Views:{RESET}    {format_views(info.get('view_count'))}")

        if info.get('upload_date'):
            date = info['upload_date']
            formatted_date = f"{date[:4]}-{date[4:6]}-{date[6:8]}"
            print(f"  {CYAN}Uploaded:{RESET} {formatted_date}")

        if args.info:
            # Show more details
            if info.get('description'):
                desc = info['description'][:200]
                print(f"\n  {BOLD}Description:{RESET}")
                print(f"  {DIM}{desc}...{RESET}")

            if info.get('formats'):
                print(f"\n  {BOLD}Available:{RESET} {len(info['formats'])} formats")
            print()
            return

    elif args.info:
        print(f"\n  {RED}Could not fetch video info{RESET}\n")
        return

    # Download
    print(f"\n  {BOLD}Downloading...{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    options = {
        'audio_only': args.audio,
        'quality': args.quality,
        'format': args.format,
        'output_dir': args.output or '.',
        'subtitles': args.subtitles,
        'thumbnail': args.thumbnail,
        'metadata': True
    }

    if args.audio:
        print(f"  Mode: {YELLOW}Audio Only (MP3){RESET}")
    else:
        print(f"  Mode: {GREEN}Video ({args.quality}){RESET}")

    success = download_video(args.url, options)

    if success:
        print(f"  {GREEN}✓ Download complete{RESET}")
    else:
        print(f"  {RED}✗ Download failed{RESET}")

    print()


if __name__ == '__main__':
    main()
