"""
OpenAI API Client
Handles communication with OpenAI API for mobile PKN
"""

import os
import requests
from typing import Generator


class OpenAIClient:
    """Client for OpenAI API (streaming chat completions)."""

    def __init__(self):
        """Initialize OpenAI client."""
        self.api_key = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

        self.api_base = "https://api.openai.com/v1"
        self.model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    def chat_completion(
        self, messages: list, stream: bool = True, temperature: float = 0.7
    ) -> Generator[str, None, None]:
        """
        Send chat completion request to OpenAI.

        Args:
            messages: List of message dicts with 'role' and 'content'
            stream: Whether to stream the response
            temperature: Sampling temperature (0-2)

        Yields:
            Response chunks as strings
        """
        url = f"{self.api_base}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
        }

        response = requests.post(
            url, json=payload, headers=headers, stream=stream, timeout=30
        )

        response.raise_for_status()

        if stream:
            # Stream response chunks
            for line in response.iter_lines():
                if line:
                    line = line.decode("utf-8")
                    if line.startswith("data: "):
                        data = line[6:]  # Remove 'data: ' prefix
                        if data == "[DONE]":
                            break
                        try:
                            import json

                            chunk = json.loads(data)
                            delta = chunk["choices"][0]["delta"]
                            if "content" in delta:
                                yield delta["content"]
                        except Exception:
                            continue
        else:
            # Non-streaming response
            data = response.json()
            yield data["choices"][0]["message"]["content"]
