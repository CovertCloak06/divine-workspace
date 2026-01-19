"""
Groq Cloud Chat Integration
FREE and FAST LLM API for PKN agents
Uses Llama 3.3 70B for text, Llama 3.2 90B for vision
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List, Generator
from pathlib import Path


class GroqCloud:
    """
    Groq cloud API client for fast, free LLM inference.

    Features:
    - FREE (no credit card needed)
    - FAST (~1-3s responses vs 20-30s local)
    - 30 req/min rate limit (free tier)
    - Supports streaming
    """

    def __init__(self):
        self.api_key = self._load_api_key()
        self.base_url = "https://api.groq.com/openai/v1"
        # Best free model for text
        self.default_model = "llama-3.3-70b-versatile"
        # Fast model for quick tasks
        self.fast_model = "llama-3.1-8b-instant"
        # Vision model
        self.vision_model = "llama-3.2-90b-vision-preview"

    def _load_api_key(self) -> str:
        """Load Groq API key from environment or .env files."""
        # Try environment first
        api_key = os.getenv("GROQ_API_KEY", "")

        if api_key:
            return api_key

        # Try various .env locations
        env_paths = [
            Path(__file__).parent.parent / ".env",
            Path(__file__).parent.parent.parent / ".env",
            Path.home() / ".env",
        ]

        for env_path in env_paths:
            if env_path.exists():
                try:
                    with open(env_path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("GROQ_API_KEY"):
                                api_key = line.split("=", 1)[1].strip().strip('"\'')
                                if api_key:
                                    return api_key
                except Exception:
                    continue

        return ""

    def is_available(self) -> bool:
        """Check if Groq API is configured."""
        return bool(self.api_key)

    def chat(
        self,
        message: str,
        system_prompt: str = None,
        model: str = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        conversation_history: List[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Send a chat request to Groq.

        Args:
            message: User message
            system_prompt: Optional system prompt
            model: Model to use (default: llama-3.3-70b-versatile)
            temperature: Sampling temperature
            max_tokens: Maximum response tokens
            conversation_history: Previous messages for context

        Returns:
            {
                'success': bool,
                'response': str,
                'model': str,
                'execution_time': float,
                'tokens_used': int,
                'provider': 'groq'
            }
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "Groq API not configured. Get free key at https://console.groq.com",
                "provider": "groq",
            }

        start_time = time.time()
        model = model or self.default_model

        try:
            # Build messages
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            else:
                messages.append({
                    "role": "system",
                    "content": "You are a helpful AI assistant. Always respond in English."
                })

            # Add conversation history
            if conversation_history:
                messages.extend(conversation_history)

            # Add current message
            messages.append({"role": "user", "content": message})

            # Make request
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60,
            )

            response.raise_for_status()
            data = response.json()

            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})

                return {
                    "success": True,
                    "response": content,
                    "model": model,
                    "execution_time": time.time() - start_time,
                    "tokens_used": usage.get("total_tokens", 0),
                    "provider": "groq",
                }
            else:
                return {
                    "success": False,
                    "error": "No response from Groq",
                    "execution_time": time.time() - start_time,
                    "provider": "groq",
                }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Groq request timed out",
                "execution_time": time.time() - start_time,
                "provider": "groq",
            }
        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get("error", {}).get("message", str(e))
                except Exception:
                    pass
            return {
                "success": False,
                "error": f"Groq API error: {error_msg}",
                "execution_time": time.time() - start_time,
                "provider": "groq",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error: {str(e)}",
                "execution_time": time.time() - start_time,
                "provider": "groq",
            }

    def chat_stream(
        self,
        message: str,
        system_prompt: str = None,
        model: str = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Stream a chat response from Groq.

        Yields:
            {'type': 'chunk', 'content': str}
            {'type': 'done', 'execution_time': float}
            {'type': 'error', 'content': str}
        """
        if not self.is_available():
            yield {
                "type": "error",
                "content": "Groq API not configured"
            }
            return

        start_time = time.time()
        model = model or self.default_model

        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": message})

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60,
                stream=True,
            )
            response.raise_for_status()

            for line in response.iter_lines():
                if line:
                    line = line.decode("utf-8")
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            yield {
                                "type": "done",
                                "execution_time": time.time() - start_time
                            }
                            return

                        try:
                            import json
                            chunk = json.loads(data)
                            delta = chunk.get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield {"type": "chunk", "content": content}
                        except Exception:
                            continue

        except Exception as e:
            yield {"type": "error", "content": str(e)}

    def quick_chat(self, message: str) -> str:
        """
        Simple chat for quick responses.
        Uses faster 8B model for speed.

        Returns:
            Response text or error message
        """
        result = self.chat(message, model=self.fast_model)
        if result["success"]:
            return result["response"]
        return f"Error: {result.get('error', 'Unknown error')}"


# Global instance
groq_cloud = GroqCloud()


# Convenience functions
def groq_chat(message: str, **kwargs) -> Dict[str, Any]:
    """Send a chat message to Groq."""
    return groq_cloud.chat(message, **kwargs)


def groq_quick(message: str) -> str:
    """Quick chat with Groq (fast model)."""
    return groq_cloud.quick_chat(message)


def is_groq_available() -> bool:
    """Check if Groq is available."""
    return groq_cloud.is_available()


if __name__ == "__main__":
    print("=" * 60)
    print("GROQ CLOUD API TEST")
    print("=" * 60)

    if groq_cloud.is_available():
        print("Groq API configured")
        print(f"Default model: {groq_cloud.default_model}")

        print("\nTesting chat...")
        result = groq_cloud.chat("What is 2+2? Reply in one word.")
        if result["success"]:
            print(f"Response: {result['response']}")
            print(f"Time: {result['execution_time']:.2f}s")
            print(f"Tokens: {result['tokens_used']}")
        else:
            print(f"Error: {result['error']}")
    else:
        print("Groq API not configured")
        print("Get free key at: https://console.groq.com")
        print("Add to .env: GROQ_API_KEY=your_key_here")
