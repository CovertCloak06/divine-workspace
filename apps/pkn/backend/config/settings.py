"""
PKN Configuration Settings
Global configuration values and helper functions
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# LLM Backend URLs
OLLAMA_BASE = os.environ.get('OLLAMA_BASE', 'http://127.0.0.1:11434')
LOCAL_LLM_BASE = os.environ.get('LOCAL_LLM_BASE', 'http://127.0.0.1:8000/v1')

def join_url(base: str, *parts: str) -> str:
    """Join a base URL with path parts, avoiding double slashes."""
    if not base:
        return '/'.join(p.strip('/') for p in parts)
    base = base.rstrip('/')
    paths = [p.strip('/') for p in parts if p]
    if not paths:
        return base
    return base + '/' + '/'.join(paths)

# Alias for backward compatibility
_join_url = join_url
