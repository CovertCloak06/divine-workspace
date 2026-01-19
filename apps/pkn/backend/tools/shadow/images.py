#!/usr/bin/env python3
"""
Shadow OSINT - Image Reconnaissance
EXIF extraction, reverse image search, OCR, and image hashing
"""

import os
import io
import json
import hashlib
import base64
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

# Try to import optional dependencies
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

try:
    import imagehash
    IMAGEHASH_AVAILABLE = True
except ImportError:
    IMAGEHASH_AVAILABLE = False


class ImageRecon:
    """Image-based OSINT reconnaissance."""

    def __init__(self):
        self.supported_formats = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']

    def full_analysis(self, image_path: str) -> Dict[str, Any]:
        """
        Complete image analysis.

        Extracts: EXIF, GPS, hashes, reverse search URLs.
        """
        if not PIL_AVAILABLE:
            return {"error": "PIL/Pillow not installed. Run: pip install Pillow"}

        path = Path(image_path)
        if not path.exists():
            return {"error": f"File not found: {image_path}"}

        results = {
            "file": str(path),
            "filename": path.name,
            "analysis_time": datetime.utcnow().isoformat(),
        }

        # Basic file info
        results["file_info"] = self._get_file_info(path)

        # EXIF data
        results["exif"] = self.extract_exif(image_path)

        # GPS coordinates
        results["gps"] = self.extract_gps(image_path)

        # Image hashes
        results["hashes"] = self.calculate_hashes(image_path)

        # Reverse search URLs
        results["reverse_search"] = self.get_reverse_search_urls(image_path)

        # OCR (if available)
        if OCR_AVAILABLE:
            results["ocr"] = self.extract_text(image_path)

        return results

    def _get_file_info(self, path: Path) -> Dict[str, Any]:
        """Get basic file information."""
        stat = path.stat()

        info = {
            "size_bytes": stat.st_size,
            "size_human": self._human_size(stat.st_size),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "extension": path.suffix.lower(),
        }

        if PIL_AVAILABLE:
            try:
                with Image.open(path) as img:
                    info["dimensions"] = {
                        "width": img.width,
                        "height": img.height,
                    }
                    info["format"] = img.format
                    info["mode"] = img.mode
            except Exception as e:
                info["image_error"] = str(e)

        return info

    def _human_size(self, size: int) -> str:
        """Convert bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def extract_exif(self, image_path: str) -> Dict[str, Any]:
        """
        Extract EXIF metadata from image.

        Returns: camera model, software, dates, settings, etc.
        """
        if not PIL_AVAILABLE:
            return {"error": "PIL not available"}

        try:
            with Image.open(image_path) as img:
                exif_data = img._getexif()

                if not exif_data:
                    return {"message": "No EXIF data found"}

                exif = {}
                interesting_tags = [
                    'Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal',
                    'DateTimeDigitized', 'ExposureTime', 'FNumber', 'ISOSpeedRatings',
                    'FocalLength', 'Flash', 'Orientation', 'ImageWidth', 'ImageLength',
                    'Artist', 'Copyright', 'ExifImageWidth', 'ExifImageHeight',
                    'LensModel', 'LensMake', 'BodySerialNumber', 'LensSerialNumber'
                ]

                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)

                    if tag in interesting_tags:
                        # Clean up value for JSON serialization
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except:
                                value = str(value)

                        exif[tag] = value

                # Add intelligence notes
                notes = []
                if 'Make' in exif and 'Model' in exif:
                    notes.append(f"Camera: {exif['Make']} {exif['Model']}")
                if 'Software' in exif:
                    notes.append(f"Edited with: {exif['Software']}")
                if 'DateTimeOriginal' in exif:
                    notes.append(f"Photo taken: {exif['DateTimeOriginal']}")
                if 'BodySerialNumber' in exif:
                    notes.append(f"⚠️ Camera serial number exposed: {exif['BodySerialNumber']}")

                exif['_notes'] = notes
                return exif

        except Exception as e:
            return {"error": str(e)}

    def extract_gps(self, image_path: str) -> Dict[str, Any]:
        """
        Extract GPS coordinates from image EXIF.

        Returns: latitude, longitude, altitude, Google Maps link.
        """
        if not PIL_AVAILABLE:
            return {"error": "PIL not available"}

        try:
            with Image.open(image_path) as img:
                exif_data = img._getexif()

                if not exif_data:
                    return {"found": False, "message": "No EXIF data"}

                gps_info = {}
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == 'GPSInfo':
                        for gps_tag_id, gps_value in value.items():
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_info[gps_tag] = gps_value

                if not gps_info:
                    return {"found": False, "message": "No GPS data in EXIF"}

                # Parse coordinates
                lat = self._convert_gps_coords(
                    gps_info.get('GPSLatitude'),
                    gps_info.get('GPSLatitudeRef')
                )
                lon = self._convert_gps_coords(
                    gps_info.get('GPSLongitude'),
                    gps_info.get('GPSLongitudeRef')
                )

                if lat is None or lon is None:
                    return {"found": False, "message": "Could not parse GPS coordinates"}

                result = {
                    "found": True,
                    "latitude": lat,
                    "longitude": lon,
                    "coordinates": f"{lat}, {lon}",
                    "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
                    "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15",
                }

                # Add altitude if available
                if 'GPSAltitude' in gps_info:
                    try:
                        alt = float(gps_info['GPSAltitude'])
                        result["altitude_meters"] = alt
                    except:
                        pass

                # Add timestamp if available
                if 'GPSDateStamp' in gps_info:
                    result["gps_date"] = str(gps_info['GPSDateStamp'])

                result["_warning"] = "⚠️ GPS COORDINATES FOUND - Photo location exposed!"

                return result

        except Exception as e:
            return {"found": False, "error": str(e)}

    def _convert_gps_coords(self, coords, ref) -> Optional[float]:
        """Convert GPS coordinates to decimal degrees."""
        if not coords or not ref:
            return None

        try:
            degrees = float(coords[0])
            minutes = float(coords[1])
            seconds = float(coords[2])

            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

            if ref in ['S', 'W']:
                decimal = -decimal

            return round(decimal, 6)
        except:
            return None

    def calculate_hashes(self, image_path: str) -> Dict[str, str]:
        """
        Calculate various hashes for image comparison/search.

        Returns: MD5, SHA256, and perceptual hashes.
        """
        hashes = {}

        # File hashes
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            hashes['file_hash_error'] = str(e)

        # Perceptual hashes (for finding similar images)
        if IMAGEHASH_AVAILABLE and PIL_AVAILABLE:
            try:
                with Image.open(image_path) as img:
                    hashes['phash'] = str(imagehash.phash(img))  # Perceptual hash
                    hashes['ahash'] = str(imagehash.average_hash(img))  # Average hash
                    hashes['dhash'] = str(imagehash.dhash(img))  # Difference hash
            except Exception as e:
                hashes['perceptual_error'] = str(e)
        else:
            hashes['perceptual_note'] = "Install imagehash for perceptual hashing: pip install imagehash"

        return hashes

    def get_reverse_search_urls(self, image_path: str) -> Dict[str, str]:
        """
        Generate reverse image search URLs for major search engines.

        Note: Most require uploading the image manually or using base64.
        Returns URLs for manual upload.
        """
        urls = {
            "google_images": "https://images.google.com/",
            "google_lens": "https://lens.google.com/",
            "tineye": "https://tineye.com/",
            "yandex": "https://yandex.com/images/",
            "bing": "https://www.bing.com/visualsearch",
            "baidu": "https://image.baidu.com/",
            "sogou": "https://pic.sogou.com/",
        }

        # Add instructions
        urls["_instructions"] = [
            "1. Open the URL",
            "2. Click the camera/upload icon",
            "3. Upload or drag the image",
            "4. Review results for matches",
        ]

        urls["_tips"] = [
            "Yandex often finds results Google misses",
            "TinEye shows exact matches and modifications",
            "Baidu is best for images from China/Asia",
            "Try multiple engines for best coverage",
        ]

        # If image is accessible via URL, we could add direct search links
        # For local files, user needs to upload manually

        return urls

    def extract_text(self, image_path: str) -> Dict[str, Any]:
        """
        Extract text from image using OCR.

        Requires: pytesseract and tesseract-ocr installed.
        """
        if not OCR_AVAILABLE:
            return {
                "available": False,
                "message": "OCR not available. Install: pip install pytesseract",
                "note": "Also need tesseract-ocr: apt install tesseract-ocr"
            }

        if not PIL_AVAILABLE:
            return {"error": "PIL not available"}

        try:
            with Image.open(image_path) as img:
                # Extract text
                text = pytesseract.image_to_string(img)

                # Clean up
                text = text.strip()
                lines = [l.strip() for l in text.split('\n') if l.strip()]

                result = {
                    "available": True,
                    "text_found": len(text) > 0,
                    "raw_text": text,
                    "lines": lines,
                    "line_count": len(lines),
                    "char_count": len(text),
                }

                # Try to identify interesting patterns
                patterns = self._identify_patterns(text)
                if patterns:
                    result["patterns_found"] = patterns

                return result

        except Exception as e:
            return {"available": True, "error": str(e)}

    def _identify_patterns(self, text: str) -> List[Dict[str, str]]:
        """Identify interesting patterns in extracted text."""
        import re
        patterns = []

        # Email
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            patterns.append({"type": "email", "values": emails})

        # Phone numbers (basic)
        phones = re.findall(r'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}', text)
        if phones:
            patterns.append({"type": "phone", "values": phones})

        # URLs
        urls = re.findall(r'https?://[^\s]+', text)
        if urls:
            patterns.append({"type": "url", "values": urls})

        # Social media handles
        handles = re.findall(r'@[a-zA-Z0-9_]{1,15}', text)
        if handles:
            patterns.append({"type": "social_handle", "values": handles})

        # Dates
        dates = re.findall(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', text)
        if dates:
            patterns.append({"type": "date", "values": dates})

        return patterns

    def compare_images(self, image1_path: str, image2_path: str) -> Dict[str, Any]:
        """
        Compare two images for similarity.

        Uses perceptual hashing to detect if images are similar
        even if resized, cropped, or slightly modified.
        """
        if not IMAGEHASH_AVAILABLE:
            return {"error": "imagehash not installed. Run: pip install imagehash"}

        if not PIL_AVAILABLE:
            return {"error": "PIL not available"}

        try:
            with Image.open(image1_path) as img1, Image.open(image2_path) as img2:
                # Calculate perceptual hashes
                hash1 = imagehash.phash(img1)
                hash2 = imagehash.phash(img2)

                # Calculate difference (0 = identical, higher = more different)
                difference = hash1 - hash2

                # Determine similarity
                if difference == 0:
                    similarity = "identical"
                    match_percent = 100
                elif difference <= 5:
                    similarity = "very_similar"
                    match_percent = 95 - (difference * 2)
                elif difference <= 10:
                    similarity = "similar"
                    match_percent = 80 - (difference * 2)
                elif difference <= 20:
                    similarity = "somewhat_similar"
                    match_percent = 60 - difference
                else:
                    similarity = "different"
                    match_percent = max(0, 40 - difference)

                return {
                    "image1": image1_path,
                    "image2": image2_path,
                    "hash1": str(hash1),
                    "hash2": str(hash2),
                    "hash_difference": difference,
                    "similarity": similarity,
                    "match_percent": match_percent,
                    "interpretation": self._interpret_similarity(similarity)
                }

        except Exception as e:
            return {"error": str(e)}

    def _interpret_similarity(self, similarity: str) -> str:
        """Provide interpretation of similarity result."""
        interpretations = {
            "identical": "Images are exactly the same or have only minor compression differences",
            "very_similar": "Images are likely the same photo with minor edits (crop, resize, filter)",
            "similar": "Images may be related - same scene or subject with different processing",
            "somewhat_similar": "Images share some visual elements but are not the same",
            "different": "Images are visually distinct"
        }
        return interpretations.get(similarity, "Unknown")

    def strip_metadata(self, image_path: str, output_path: str = None) -> Dict[str, Any]:
        """
        Create a copy of image with all metadata removed.

        Useful for privacy - removes EXIF, GPS, camera info.
        """
        if not PIL_AVAILABLE:
            return {"error": "PIL not available"}

        if output_path is None:
            path = Path(image_path)
            output_path = str(path.parent / f"{path.stem}_clean{path.suffix}")

        try:
            with Image.open(image_path) as img:
                # Create new image without metadata
                data = list(img.getdata())
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)
                clean_img.save(output_path)

                return {
                    "success": True,
                    "original": image_path,
                    "cleaned": output_path,
                    "message": "Metadata stripped successfully"
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def image_to_base64(self, image_path: str) -> Dict[str, str]:
        """
        Convert image to base64 for API uploads.
        """
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
                b64 = base64.b64encode(data).decode('utf-8')

                # Determine mime type
                ext = Path(image_path).suffix.lower()
                mime_types = {
                    '.jpg': 'image/jpeg',
                    '.jpeg': 'image/jpeg',
                    '.png': 'image/png',
                    '.gif': 'image/gif',
                    '.webp': 'image/webp',
                    '.bmp': 'image/bmp',
                }
                mime = mime_types.get(ext, 'image/jpeg')

                return {
                    "success": True,
                    "base64": b64,
                    "data_uri": f"data:{mime};base64,{b64}",
                    "mime_type": mime,
                    "size_bytes": len(data),
                }

        except Exception as e:
            return {"success": False, "error": str(e)}
