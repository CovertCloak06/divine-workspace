"""
PKN Model Configuration
Optimized uncensored/abliterated models for each agent type
Separated by device (mobile/PC) and backend (local/cloud)
"""

from enum import Enum
from typing import Dict, Any
import os


class BackendType(Enum):
    """AI backend type"""
    LOCAL = "local"      # Ollama / llama.cpp
    CLOUD = "cloud"      # Groq / OpenAI / Claude


class DeviceType(Enum):
    """Device type for model selection"""
    MOBILE = "mobile"    # Termux/Android - lighter models
    PC = "pc"            # Desktop - heavier models


# ============================================================
# MOBILE MODELS (Termux/Android) - Optimized for speed
# Focus: 3B-7B uncensored models, fast inference
# ============================================================

MOBILE_LOCAL_MODELS = {
    "coder": {
        "model": "ollama:deepseek-coder:6.7b",
        "name": "DeepSeek Coder 6.7B",
        "description": "Fast, excellent code quality",
        "speed": "fast",
        "quality": "high",
        "uncensored": True,
    },
    "general": {
        "model": "ollama:artifish/llama3.2-uncensored:latest",
        "name": "Llama 3.2 Uncensored 3.6B",
        "description": "Fast, uncensored general assistant",
        "speed": "very_fast",
        "quality": "medium",
        "uncensored": True,
    },
    "reasoner": {
        "model": "ollama:huihui_ai/qwen3-abliterated:4b-v2-q4_K_M",
        "name": "Qwen3 Abliterated 4B",
        "description": "Quick abliterated reasoning",
        "speed": "very_fast",
        "quality": "medium",
        "uncensored": True,
    },
    "security": {
        "model": "ollama:hf.co/TheBloke/dolphin-2.6-mistral-7B-GGUF:Q4_K_M",
        "name": "Dolphin Mistral 7B",
        "description": "Uncensored security specialist",
        "speed": "medium",
        "quality": "high",
        "uncensored": True,
    },
    "researcher": {
        "model": "ollama:mistral:latest",
        "name": "Mistral 7B",
        "description": "Research and documentation",
        "speed": "medium",
        "quality": "high",
        "uncensored": False,
    },
    "executor": {
        "model": "ollama:deepseek-coder:6.7b",
        "name": "DeepSeek Coder 6.7B",
        "description": "System commands, file operations",
        "speed": "fast",
        "quality": "high",
        "uncensored": True,
    },
    "vision": {
        "model": "ollama:llava:latest",
        "name": "LLaVA Vision",
        "description": "Image analysis (if available)",
        "speed": "medium",
        "quality": "medium",
        "uncensored": False,
    },
}

# ============================================================
# PC MODELS (Desktop) - Optimized for quality
# Focus: 14B+ models, best reasoning
# ============================================================

PC_LOCAL_MODELS = {
    "coder": {
        "model": "ollama:qwen3:14b",
        "name": "Qwen3 14B",
        "description": "Best local coder (pull qwen2.5-coder:14b for better)",
        "speed": "slow",
        "quality": "very_high",
        "uncensored": False,  # Need abliterated version
        "alternative": "qwen2.5-coder:14b-instruct-abliterated",
    },
    "general": {
        "model": "ollama:mannix/llama3.1-8b-lexi:q4_0",
        "name": "Llama 3.1 8B Lexi",
        "description": "Quality general assistant",
        "speed": "medium",
        "quality": "high",
        "uncensored": True,
    },
    "reasoner": {
        "model": "ollama:qwen3:14b",
        "name": "Qwen3 14B",
        "description": "Best local reasoning",
        "speed": "slow",
        "quality": "very_high",
        "uncensored": False,
    },
    "security": {
        "model": "ollama:hf.co/TheBloke/dolphin-2.6-mistral-7B-GGUF:Q4_K_M",
        "name": "Dolphin Mistral 7B",
        "description": "Uncensored security (same as mobile)",
        "speed": "medium",
        "quality": "high",
        "uncensored": True,
    },
    "researcher": {
        "model": "ollama:qwen3:14b",
        "name": "Qwen3 14B",
        "description": "Deep research capability",
        "speed": "slow",
        "quality": "very_high",
        "uncensored": False,
    },
    "executor": {
        "model": "ollama:deepseek-coder:6.7b",
        "name": "DeepSeek Coder 6.7B",
        "description": "System commands (fast)",
        "speed": "fast",
        "quality": "high",
        "uncensored": True,
    },
    "vision": {
        "model": "ollama:llava:latest",
        "name": "LLaVA Vision",
        "description": "Local image analysis",
        "speed": "medium",
        "quality": "medium",
        "uncensored": False,
    },
}

# ============================================================
# CLOUD MODELS - Fast fallback (Groq free tier)
# Same for mobile and PC
# ============================================================

CLOUD_MODELS = {
    "coder": {
        "model": "groq:llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B (Groq)",
        "description": "Fast cloud coder, free",
        "speed": "very_fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "general": {
        "model": "groq:llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B (Groq)",
        "description": "Fast cloud general, free",
        "speed": "very_fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "reasoner": {
        "model": "groq:llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B (Groq)",
        "description": "Fast cloud reasoning, free",
        "speed": "very_fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "security": {
        "model": "groq:llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B (Groq)",
        "description": "Cloud security (may be filtered)",
        "speed": "very_fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "researcher": {
        "model": "groq:llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B (Groq)",
        "description": "Fast cloud research",
        "speed": "very_fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "executor": {
        "model": "groq:llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B (Groq)",
        "description": "Fast cloud executor",
        "speed": "very_fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "vision": {
        "model": "groq:llama-3.2-90b-vision-preview",
        "name": "Llama 3.2 90B Vision (Groq)",
        "description": "Free cloud vision, excellent",
        "speed": "fast",
        "quality": "very_high",
        "uncensored": False,
        "provider": "groq",
    },
    "consultant": {
        "model": "claude:claude-3-5-sonnet-20241022",
        "name": "Claude 3.5 Sonnet",
        "description": "Premium reasoning (requires API key)",
        "speed": "medium",
        "quality": "exceptional",
        "uncensored": False,
        "provider": "anthropic",
    },
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_model_config(
    agent_type: str,
    device: DeviceType = DeviceType.MOBILE,
    backend: BackendType = BackendType.LOCAL
) -> Dict[str, Any]:
    """
    Get optimal model configuration for an agent.

    Args:
        agent_type: Type of agent (coder, general, reasoner, etc.)
        device: Device type (mobile or pc)
        backend: Backend type (local or cloud)

    Returns:
        Model configuration dict
    """
    agent_type = agent_type.lower()

    if backend == BackendType.CLOUD:
        return CLOUD_MODELS.get(agent_type, CLOUD_MODELS["general"])

    if device == DeviceType.MOBILE:
        return MOBILE_LOCAL_MODELS.get(agent_type, MOBILE_LOCAL_MODELS["general"])
    else:
        return PC_LOCAL_MODELS.get(agent_type, PC_LOCAL_MODELS["general"])


def get_all_models_for_device(device: DeviceType) -> Dict[str, Dict]:
    """Get all local models for a device type."""
    if device == DeviceType.MOBILE:
        return MOBILE_LOCAL_MODELS.copy()
    return PC_LOCAL_MODELS.copy()


def get_recommended_pulls(device: DeviceType) -> list:
    """
    Get list of recommended models to pull for a device.

    Returns:
        List of ollama pull commands
    """
    if device == DeviceType.MOBILE:
        return [
            "ollama pull deepseek-coder:6.7b",
            "ollama pull artifish/llama3.2-uncensored",
            "ollama pull huihui_ai/qwen3-abliterated:4b-v2-q4_K_M",
            "ollama pull cognitivecomputations/dolphin-mistral:7b",
        ]
    else:
        return [
            "ollama pull qwen2.5-coder:14b",
            "ollama pull qwen3:14b",
            "ollama pull dolphin-llama3:8b",
            "ollama pull mannix/llama3.1-8b-lexi",
        ]


# Cloud API endpoints
CLOUD_ENDPOINTS = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "env_key": "GROQ_API_KEY",
        "free": True,
        "rate_limit": "30 req/min",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "env_key": "OPENAI_API_KEY",
        "free": False,
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "env_key": "ANTHROPIC_API_KEY",
        "free": False,
    },
}


def is_cloud_available(provider: str = "groq") -> bool:
    """Check if a cloud provider API key is configured."""
    endpoint = CLOUD_ENDPOINTS.get(provider, {})
    env_key = endpoint.get("env_key", "")
    return bool(os.getenv(env_key, ""))


def get_cloud_status() -> Dict[str, bool]:
    """Get availability status of all cloud providers."""
    return {
        provider: is_cloud_available(provider)
        for provider in CLOUD_ENDPOINTS
    }
