#!/usr/bin/env python3
"""
PKN Shadow - OSINT Intelligence Suite
Advanced reconnaissance and intelligence gathering toolkit

Features:
- Username enumeration across 200+ platforms
- Email/phone reconnaissance
- Google/GitHub/Shodan dork generation
- Domain intelligence
- Network/IP analysis
- Person search by name, age, location
- Profile building with confidence ratings
- Image reconnaissance (EXIF, GPS, OCR)
- Report generation

⚠️ LEGAL NOTICE: Authorized use only.
"""

from .sources import DATA_SOURCES, USERNAME_PLATFORMS
from .person import PersonRecon
from .domain import DomainRecon
from .network import NetworkRecon
from .dorks import DorkGenerator
from .engine import ShadowEngine
from .people import PeopleSearch
from .profiler import Profiler, PersonProfile
from .images import ImageRecon
from .tools import TOOLS, TOOL_DESCRIPTIONS

__version__ = "1.1.0"
__all__ = [
    "ShadowEngine",
    "PersonRecon",
    "DomainRecon",
    "NetworkRecon",
    "DorkGenerator",
    "PeopleSearch",
    "Profiler",
    "PersonProfile",
    "ImageRecon",
    "DATA_SOURCES",
    "USERNAME_PLATFORMS",
    "TOOLS",
    "TOOL_DESCRIPTIONS",
]
