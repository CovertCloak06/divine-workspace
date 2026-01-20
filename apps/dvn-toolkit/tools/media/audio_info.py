#!/usr/bin/env python3
"""
Audio Info - Display audio file information
Usage: audio_info.py <file>
"""

import os
import sys
import struct
import argparse

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def format_duration(seconds):
    """Format duration in human readable"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    else:
        return f"{minutes}:{secs:02d}"


def format_size(size):
    """Format size in human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def read_wav_info(filepath):
    """Read WAV file information"""
    info = {'format': 'WAV'}

    try:
        with open(filepath, 'rb') as f:
            # RIFF header
            riff = f.read(4)
            if riff != b'RIFF':
                return None

            file_size = struct.unpack('<I', f.read(4))[0]
            wave = f.read(4)
            if wave != b'WAVE':
                return None

            # Find fmt chunk
            while True:
                chunk_id = f.read(4)
                if len(chunk_id) < 4:
                    break

                chunk_size = struct.unpack('<I', f.read(4))[0]

                if chunk_id == b'fmt ':
                    audio_format = struct.unpack('<H', f.read(2))[0]
                    channels = struct.unpack('<H', f.read(2))[0]
                    sample_rate = struct.unpack('<I', f.read(4))[0]
                    byte_rate = struct.unpack('<I', f.read(4))[0]
                    block_align = struct.unpack('<H', f.read(2))[0]
                    bits_per_sample = struct.unpack('<H', f.read(2))[0]

                    info['channels'] = channels
                    info['sample_rate'] = sample_rate
                    info['bit_depth'] = bits_per_sample
                    info['bitrate'] = byte_rate * 8

                    format_names = {1: 'PCM', 3: 'IEEE Float', 6: 'A-law', 7: 'μ-law'}
                    info['encoding'] = format_names.get(audio_format, f'Unknown ({audio_format})')

                    # Skip remaining fmt data
                    if chunk_size > 16:
                        f.read(chunk_size - 16)

                elif chunk_id == b'data':
                    info['data_size'] = chunk_size
                    if 'byte_rate' in dir() and byte_rate > 0:
                        info['duration'] = chunk_size / byte_rate
                    break
                else:
                    f.read(chunk_size)

    except Exception as e:
        return None

    return info


def read_mp3_info(filepath):
    """Read MP3 file information (basic)"""
    info = {'format': 'MP3'}

    bitrate_table = {
        0x0: 'free', 0x1: 32, 0x2: 40, 0x3: 48, 0x4: 56, 0x5: 64,
        0x6: 80, 0x7: 96, 0x8: 112, 0x9: 128, 0xa: 160, 0xb: 192,
        0xc: 224, 0xd: 256, 0xe: 320, 0xf: 'bad'
    }

    sample_rate_table = {0x0: 44100, 0x1: 48000, 0x2: 32000, 0x3: 'reserved'}

    try:
        with open(filepath, 'rb') as f:
            # Skip ID3v2 tag if present
            header = f.read(3)
            if header == b'ID3':
                f.read(3)  # Version and flags
                size_bytes = f.read(4)
                # ID3v2 size is encoded as 4 7-bit bytes
                size = ((size_bytes[0] & 0x7f) << 21 |
                       (size_bytes[1] & 0x7f) << 14 |
                       (size_bytes[2] & 0x7f) << 7 |
                       (size_bytes[3] & 0x7f))
                f.seek(size + 10)
            else:
                f.seek(0)

            # Find MP3 frame header
            while True:
                byte = f.read(1)
                if not byte:
                    break

                if byte[0] == 0xff:
                    next_byte = f.read(1)
                    if next_byte and (next_byte[0] & 0xe0) == 0xe0:
                        # Found sync
                        header_data = f.read(2)
                        if len(header_data) < 2:
                            break

                        bitrate_idx = (header_data[0] >> 4) & 0x0f
                        sample_idx = (header_data[0] >> 2) & 0x03
                        channel_mode = (header_data[1] >> 6) & 0x03

                        bitrate = bitrate_table.get(bitrate_idx, 'unknown')
                        sample_rate = sample_rate_table.get(sample_idx, 'unknown')

                        if isinstance(bitrate, int) and isinstance(sample_rate, int):
                            info['bitrate'] = bitrate * 1000
                            info['sample_rate'] = sample_rate

                        channel_modes = ['Stereo', 'Joint Stereo', 'Dual Channel', 'Mono']
                        info['channels'] = 1 if channel_mode == 3 else 2
                        info['channel_mode'] = channel_modes[channel_mode]

                        # Estimate duration
                        f.seek(0, 2)
                        file_size = f.tell()
                        if isinstance(bitrate, int) and bitrate > 0:
                            info['duration'] = (file_size * 8) / (bitrate * 1000)

                        break

    except Exception as e:
        return None

    return info


def read_flac_info(filepath):
    """Read FLAC file information"""
    info = {'format': 'FLAC'}

    try:
        with open(filepath, 'rb') as f:
            # Check fLaC marker
            marker = f.read(4)
            if marker != b'fLaC':
                return None

            # Read STREAMINFO block
            block_header = f.read(4)
            is_last = (block_header[0] >> 7) & 1
            block_type = block_header[0] & 0x7f
            block_size = (block_header[1] << 16) | (block_header[2] << 8) | block_header[3]

            if block_type == 0:  # STREAMINFO
                data = f.read(block_size)

                min_block = (data[0] << 8) | data[1]
                max_block = (data[2] << 8) | data[3]

                sample_rate = (data[10] << 12) | (data[11] << 4) | (data[12] >> 4)
                channels = ((data[12] >> 1) & 0x07) + 1
                bits = ((data[12] & 1) << 4) | (data[13] >> 4) + 1
                total_samples = ((data[13] & 0x0f) << 32) | (data[14] << 24) | \
                               (data[15] << 16) | (data[16] << 8) | data[17]

                info['sample_rate'] = sample_rate
                info['channels'] = channels
                info['bit_depth'] = bits

                if sample_rate > 0:
                    info['duration'] = total_samples / sample_rate
                    info['bitrate'] = int((os.path.getsize(filepath) * 8) / info['duration'])

    except Exception as e:
        return None

    return info


def read_ogg_info(filepath):
    """Read OGG/Vorbis file information"""
    info = {'format': 'OGG Vorbis'}

    try:
        with open(filepath, 'rb') as f:
            # Check OggS marker
            marker = f.read(4)
            if marker != b'OggS':
                return None

            # Skip to capture pattern
            f.seek(0)
            content = f.read(8192)

            # Find vorbis header
            vorbis_pos = content.find(b'\x01vorbis')
            if vorbis_pos != -1:
                f.seek(vorbis_pos + 7)
                data = f.read(23)

                if len(data) >= 23:
                    version = struct.unpack('<I', data[0:4])[0]
                    channels = data[4]
                    sample_rate = struct.unpack('<I', data[5:9])[0]
                    bitrate_max = struct.unpack('<i', data[9:13])[0]
                    bitrate_nom = struct.unpack('<i', data[13:17])[0]
                    bitrate_min = struct.unpack('<i', data[17:21])[0]

                    info['channels'] = channels
                    info['sample_rate'] = sample_rate

                    if bitrate_nom > 0:
                        info['bitrate'] = bitrate_nom

                    # Estimate duration
                    file_size = os.path.getsize(filepath)
                    if bitrate_nom > 0:
                        info['duration'] = (file_size * 8) / bitrate_nom

    except Exception as e:
        return None

    return info


def get_audio_info(filepath):
    """Get audio file information"""
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.wav':
        return read_wav_info(filepath)
    elif ext == '.mp3':
        return read_mp3_info(filepath)
    elif ext == '.flac':
        return read_flac_info(filepath)
    elif ext in ['.ogg', '.oga']:
        return read_ogg_info(filepath)
    else:
        return {'format': ext.upper()[1:], 'note': 'Limited info available'}


def main():
    parser = argparse.ArgumentParser(description='Audio Info')
    parser.add_argument('files', nargs='*', help='Audio file(s)')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🎵 Audio Info                                 ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if not args.files:
        args.files = [input(f"  {CYAN}Audio file:{RESET} ").strip()]

    for filepath in args.files:
        if not filepath or not os.path.exists(filepath):
            print(f"  {RED}File not found: {filepath}{RESET}\n")
            continue

        info = get_audio_info(filepath)

        print(f"  {BOLD}File: {GREEN}{os.path.basename(filepath)}{RESET}")
        print(f"  {DIM}{'─' * 45}{RESET}\n")

        print(f"  {CYAN}Format:{RESET}      {info.get('format', 'Unknown')}")
        print(f"  {CYAN}Size:{RESET}        {format_size(os.path.getsize(filepath))}")

        if 'duration' in info:
            print(f"  {CYAN}Duration:{RESET}    {format_duration(info['duration'])}")

        if 'sample_rate' in info:
            print(f"  {CYAN}Sample Rate:{RESET} {info['sample_rate']:,} Hz")

        if 'channels' in info:
            ch = info['channels']
            ch_str = 'Mono' if ch == 1 else 'Stereo' if ch == 2 else f'{ch} channels'
            print(f"  {CYAN}Channels:{RESET}    {ch_str}")

        if 'bit_depth' in info:
            print(f"  {CYAN}Bit Depth:{RESET}   {info['bit_depth']} bit")

        if 'bitrate' in info:
            br = info['bitrate']
            if br > 1000:
                print(f"  {CYAN}Bitrate:{RESET}     {br // 1000} kbps")
            else:
                print(f"  {CYAN}Bitrate:{RESET}     {br} bps")

        if 'encoding' in info:
            print(f"  {CYAN}Encoding:{RESET}    {info['encoding']}")

        if 'channel_mode' in info:
            print(f"  {CYAN}Mode:{RESET}        {info['channel_mode']}")

        if info.get('note'):
            print(f"  {YELLOW}{info['note']}{RESET}")

        print()

    # Format reference
    print(f"  {BOLD}Common Audio Formats:{RESET}")
    print(f"  {DIM}{'─' * 45}{RESET}")
    print(f"  {CYAN}WAV:{RESET}  Uncompressed, lossless, large files")
    print(f"  {CYAN}FLAC:{RESET} Compressed, lossless, ~50% of WAV")
    print(f"  {CYAN}MP3:{RESET}  Compressed, lossy, widely compatible")
    print(f"  {CYAN}OGG:{RESET}  Compressed, lossy, open format")
    print(f"  {CYAN}AAC:{RESET}  Compressed, lossy, better than MP3")
    print()


if __name__ == '__main__':
    main()
