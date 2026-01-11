"""
External LLM Integration for High-Level Decision Making
Supports Claude (Anthropic API) and GPT (OpenAI API)
"""

import os
import json
import time
from typing import Dict, Any, List, Optional
from pathlib import Path


class ExternalLLM:
    """Interface for external LLM APIs (Claude, GPT)"""

    def __init__(self):
        self.api_keys = self._load_api_keys()
        self.available_models = self._detect_available_models()

    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment or .env file"""
        keys = {}

        # Try environment variables first
        keys['claude'] = os.getenv('ANTHROPIC_API_KEY', '')
        keys['openai'] = os.getenv('OPENAI_API_KEY', '')

        # Try .env file
        env_file = Path(__file__).parent / '.env'
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key == 'ANTHROPIC_API_KEY':
                                keys['claude'] = value
                            elif key == 'OPENAI_API_KEY':
                                keys['openai'] = value

        return keys

    def _detect_available_models(self) -> List[str]:
        """Detect which external LLMs are available"""
        available = []

        if self.api_keys.get('claude'):
            available.append('claude')
        if self.api_keys.get('openai'):
            available.append('gpt')

        return available

    def is_available(self, provider: str = None) -> bool:
        """Check if external LLMs are available"""
        if provider:
            return provider in self.available_models
        return len(self.available_models) > 0

    async def query_claude(self, prompt: str, system_prompt: str = None,
                          model: str = "claude-sonnet-4-5-20250929") -> Dict[str, Any]:
        """Query Claude API (Anthropic)"""
        if not self.api_keys.get('claude'):
            return {
                'error': 'Claude API key not found',
                'available': False
            }

        try:
            # Use anthropic library if available
            try:
                from anthropic import Anthropic

                client = Anthropic(api_key=self.api_keys['claude'])

                messages = [{"role": "user", "content": prompt}]

                kwargs = {
                    "model": model,
                    "max_tokens": 4096,
                    "messages": messages
                }

                if system_prompt:
                    kwargs["system"] = system_prompt

                response = client.messages.create(**kwargs)

                return {
                    'provider': 'claude',
                    'model': model,
                    'response': response.content[0].text,
                    'usage': {
                        'input_tokens': response.usage.input_tokens,
                        'output_tokens': response.usage.output_tokens
                    },
                    'available': True
                }

            except ImportError:
                # Fallback to requests
                import requests

                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": self.api_keys['claude'],
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }

                data = {
                    "model": model,
                    "max_tokens": 4096,
                    "messages": [{"role": "user", "content": prompt}]
                }

                if system_prompt:
                    data["system"] = system_prompt

                response = requests.post(url, headers=headers, json=data, timeout=120)
                response.raise_for_status()

                result = response.json()

                return {
                    'provider': 'claude',
                    'model': model,
                    'response': result['content'][0]['text'],
                    'usage': result.get('usage', {}),
                    'available': True
                }

        except Exception as e:
            return {
                'error': str(e),
                'provider': 'claude',
                'available': False
            }

    async def query_gpt(self, prompt: str, system_prompt: str = None,
                       model: str = "gpt-4o") -> Dict[str, Any]:
        """Query GPT API (OpenAI)"""
        if not self.api_keys.get('openai'):
            return {
                'error': 'OpenAI API key not found',
                'available': False
            }

        try:
            # Use openai library if available
            try:
                from openai import OpenAI

                client = OpenAI(api_key=self.api_keys['openai'])

                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=4096
                )

                return {
                    'provider': 'gpt',
                    'model': model,
                    'response': response.choices[0].message.content,
                    'usage': {
                        'prompt_tokens': response.usage.prompt_tokens,
                        'completion_tokens': response.usage.completion_tokens,
                        'total_tokens': response.usage.total_tokens
                    },
                    'available': True
                }

            except ImportError:
                # Fallback to requests
                import requests

                url = "https://api.openai.com/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.api_keys['openai']}",
                    "Content-Type": "application/json"
                }

                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                data = {
                    "model": model,
                    "messages": messages,
                    "max_tokens": 4096
                }

                response = requests.post(url, headers=headers, json=data, timeout=120)
                response.raise_for_status()

                result = response.json()

                return {
                    'provider': 'gpt',
                    'model': model,
                    'response': result['choices'][0]['message']['content'],
                    'usage': result.get('usage', {}),
                    'available': True
                }

        except Exception as e:
            return {
                'error': str(e),
                'provider': 'gpt',
                'available': False
            }

    async def query_best_available(self, prompt: str, system_prompt: str = None,
                                   prefer: str = 'claude') -> Dict[str, Any]:
        """Query the best available external LLM"""

        if not self.is_available():
            return {
                'error': 'No external LLM APIs available',
                'available': False,
                'suggestion': 'Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env file'
            }

        # Try preferred provider first
        if prefer == 'claude' and self.is_available('claude'):
            return await self.query_claude(prompt, system_prompt)
        elif prefer == 'gpt' and self.is_available('gpt'):
            return await self.query_gpt(prompt, system_prompt)

        # Fallback to any available
        if self.is_available('claude'):
            return await self.query_claude(prompt, system_prompt)
        elif self.is_available('gpt'):
            return await self.query_gpt(prompt, system_prompt)

        return {
            'error': 'No external LLM APIs available',
            'available': False
        }

    async def vote_on_decision(self, question: str, options: List[str],
                              context: str = "") -> Dict[str, Any]:
        """
        Use external LLM for voting on complex decisions.

        Args:
            question: The decision question
            options: List of possible choices
            context: Additional context for the decision

        Returns:
            {
                'choice': str,  # The selected option
                'reasoning': str,  # Why this choice was made
                'confidence': float,  # 0-1 confidence score
                'provider': str  # Which LLM was used
            }
        """

        system_prompt = """You are an expert decision-making assistant.
Your task is to analyze options and provide a well-reasoned choice.
Always respond in JSON format with: choice, reasoning, confidence (0-1)."""

        options_text = "\n".join([f"{i+1}. {opt}" for i, opt in enumerate(options)])

        prompt = f"""Question: {question}

Context: {context}

Available options:
{options_text}

Analyze these options and select the best one. Respond in JSON format:
{{
    "choice": "the exact text of your chosen option",
    "reasoning": "detailed explanation of why this is the best choice",
    "confidence": 0.85
}}"""

        result = await self.query_best_available(prompt, system_prompt)

        if not result.get('available'):
            # Fallback: simple heuristic choice
            return {
                'choice': options[0],
                'reasoning': 'External LLM unavailable, selected first option as default',
                'confidence': 0.3,
                'provider': 'fallback',
                'error': result.get('error')
            }

        try:
            # Parse JSON response
            response_text = result['response']

            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{[^{}]*"choice"[^{}]*\}', response_text, re.DOTALL)
            if json_match:
                decision_data = json.loads(json_match.group(0))
            else:
                decision_data = json.loads(response_text)

            return {
                'choice': decision_data.get('choice', options[0]),
                'reasoning': decision_data.get('reasoning', response_text),
                'confidence': float(decision_data.get('confidence', 0.7)),
                'provider': result['provider'],
                'model': result['model']
            }

        except Exception as e:
            # Fallback parsing
            response_text = result['response']

            # Try to find which option was mentioned most
            choice = options[0]
            for opt in options:
                if opt.lower() in response_text.lower():
                    choice = opt
                    break

            return {
                'choice': choice,
                'reasoning': response_text,
                'confidence': 0.6,
                'provider': result['provider'],
                'parse_error': str(e)
            }


# Global instance
external_llm = ExternalLLM()


if __name__ == '__main__':
    # Test
    import asyncio

    async def test():
        llm = ExternalLLM()

        print(f"Available models: {llm.available_models}")
        print(f"Claude available: {llm.is_available('claude')}")
        print(f"GPT available: {llm.is_available('gpt')}")

        if llm.is_available():
            # Test voting
            result = await llm.vote_on_decision(
                question="Which programming language is best for web scraping?",
                options=["Python", "JavaScript", "Ruby"],
                context="Need to scrape data from modern websites with JavaScript"
            )

            print(f"\nVoting result:")
            print(f"  Choice: {result['choice']}")
            print(f"  Reasoning: {result['reasoning'][:100]}...")
            print(f"  Confidence: {result['confidence']}")
            print(f"  Provider: {result['provider']}")
        else:
            print("\nNo external LLM APIs configured")
            print("Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env file")

    asyncio.run(test())
