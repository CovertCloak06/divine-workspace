"""
Mobile PKN Configuration
Settings optimized for mobile deployment (Termux)
"""

import os
from dotenv import load_dotenv

load_dotenv()

# OpenAI API Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# Server Configuration
SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "8010"))

# Features (disabled for mobile)
ENABLE_IMAGE_GEN = False
ENABLE_LOCAL_LLM = False
ENABLE_MULTI_AGENT = False

# Memory Configuration (SHARED with desktop PKN)
MEMORY_DIR = os.path.join(os.path.dirname(__file__), "../../data/memory")

# Frontend Configuration
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "../../frontend")
