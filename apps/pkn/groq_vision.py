"""
Groq Cloud Vision Integration
FREE and FAST vision API using Llama-3.2-Vision models
"""

import os
import requests
from typing import Dict, Any, Optional
from pathlib import Path


class GroqVision:
    """
    Groq cloud vision API client.

    Features:
    - FREE (no credit card needed)
    - FAST (~1-3s responses)
    - English-only responses
    - Uncensored
    - Supports images via URL or base64
    """

    def __init__(self):
        self.api_key = self._load_api_key()
        self.base_url = "https://api.groq.com/openai/v1"
        # Use the powerful 90B vision model (still free!)
        self.model = "llama-3.2-90b-vision-preview"

    def _load_api_key(self) -> str:
        """Load Groq API key from environment or .env"""
        # Try environment first
        api_key = os.getenv('GROQ_API_KEY', '')

        # Try .env file
        if not api_key:
            env_file = Path(__file__).parent / '.env'
            if env_file.exists():
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith('GROQ_API_KEY'):
                                api_key = line.split('=', 1)[1].strip().strip('"').strip("'")
                                break

        return api_key

    def is_available(self) -> bool:
        """Check if Groq API is configured and available"""
        return bool(self.api_key and self.api_key != '')

    def analyze_image(self, image_url: str, prompt: str = "Describe this image in detail.") -> Dict[str, Any]:
        """
        Analyze an image using Groq's vision model.

        Args:
            image_url: URL to the image (http/https)
            prompt: Question or instruction about the image

        Returns:
            {
                'success': bool,
                'response': str,
                'model': str,
                'execution_time': float,
                'error': str (if failed)
            }
        """
        import time

        if not self.is_available():
            return {
                'success': False,
                'error': 'Groq API key not configured. Get a free key at https://console.groq.com'
            }

        start_time = time.time()

        try:
            # Build vision request
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            # Groq uses OpenAI-compatible format
            payload = {
                'model': self.model,
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a vision analysis expert. Always respond in English only. Provide clear, detailed descriptions.'
                    },
                    {
                        'role': 'user',
                        'content': [
                            {
                                'type': 'text',
                                'text': prompt
                            },
                            {
                                'type': 'image_url',
                                'image_url': {
                                    'url': image_url
                                }
                            }
                        ]
                    }
                ],
                'temperature': 0.3,
                'max_tokens': 1024
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            # Extract response
            if 'choices' in data and len(data['choices']) > 0:
                content = data['choices'][0]['message']['content']

                return {
                    'success': True,
                    'response': content,
                    'model': self.model,
                    'execution_time': time.time() - start_time,
                    'provider': 'groq_cloud'
                }
            else:
                return {
                    'success': False,
                    'error': 'No response from Groq API',
                    'execution_time': time.time() - start_time
                }

        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Groq API request failed: {str(e)}',
                'execution_time': time.time() - start_time
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error: {str(e)}',
                'execution_time': time.time() - start_time
            }

    def analyze_text(self, prompt: str) -> Dict[str, Any]:
        """
        Simple text analysis (no image) using Groq's text model.
        Falls back to text-only Llama for vision-related questions without images.

        Args:
            prompt: The text prompt

        Returns:
            Same format as analyze_image()
        """
        import time

        if not self.is_available():
            return {
                'success': False,
                'error': 'Groq API key not configured'
            }

        start_time = time.time()

        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            # Use fast text model for non-vision queries
            payload = {
                'model': 'llama-3.3-70b-versatile',  # Faster for text-only
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a helpful assistant. Always respond in English only.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.3,
                'max_tokens': 1024
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            if 'choices' in data and len(data['choices']) > 0:
                content = data['choices'][0]['message']['content']

                return {
                    'success': True,
                    'response': content,
                    'model': 'llama-3.3-70b-versatile',
                    'execution_time': time.time() - start_time,
                    'provider': 'groq_cloud'
                }
            else:
                return {
                    'success': False,
                    'error': 'No response from Groq',
                    'execution_time': time.time() - start_time
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }


# Global instance
groq_vision = GroqVision()


if __name__ == '__main__':
    # Test the API
    print("=" * 60)
    print("GROQ VISION API TEST")
    print("=" * 60)

    if groq_vision.is_available():
        print("✓ Groq API configured")
        print(f"  Model: {groq_vision.model}")

        # Test text query
        print("\nTesting text query...")
        result = groq_vision.analyze_text("What is the capital of France?")
        if result['success']:
            print(f"✓ Response: {result['response'][:100]}...")
            print(f"  Time: {result['execution_time']:.2f}s")
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print("✗ Groq API not configured")
        print("  Get a free API key at: https://console.groq.com")
        print("  Add to .env: GROQ_API_KEY=your_key_here")
