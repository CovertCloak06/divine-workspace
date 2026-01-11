"""
Claude API Integration
Provides access to Anthropic's Claude API for ultimate reasoning power.

Use this for the CONSULTANT agent when maximum intelligence is needed.
"""

import os
import json
from typing import Dict, Any, Optional, List
from pathlib import Path


class ClaudeAPI:
    """
    Anthropic Claude API integration for PKN.

    Supports:
    - Claude Sonnet 4 (balanced, fast)
    - Claude Opus 4 (maximum intelligence)
    - Claude Haiku (fastest, cheapest)
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Claude API.

        Args:
            api_key: Anthropic API key (or set ANTHROPIC_API_KEY env var)
        """
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        self.client = None
        self.available = False

        if self.api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.available = True
            except ImportError:
                print("Warning: anthropic package not installed. Run: pip install anthropic")
            except Exception as e:
                print(f"Warning: Claude API initialization failed: {e}")

    def is_available(self) -> bool:
        """Check if Claude API is available"""
        return self.available

    async def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Query Claude API.

        Args:
            prompt: User message/question
            system_prompt: System instructions
            model: Claude model to use
                - "claude-sonnet-4-20250514" (recommended, balanced)
                - "claude-opus-4-20250514" (maximum intelligence)
                - "claude-3-5-haiku-20241022" (fastest, cheapest)
            max_tokens: Maximum response length
            temperature: Creativity (0-1, default 0.7)
            tools: Optional tool definitions for tool use

        Returns:
            {
                'response': str,
                'model': str,
                'usage': dict,
                'available': bool,
                'error': str (if failed)
            }
        """
        if not self.available:
            return {
                'response': '',
                'available': False,
                'error': 'Claude API not available (no API key or anthropic not installed)'
            }

        try:
            # Build messages
            messages = [{"role": "user", "content": prompt}]

            # Call Claude API
            if tools:
                # With tools
                response = self.client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt if system_prompt else "You are a helpful AI assistant.",
                    messages=messages,
                    tools=tools
                )
            else:
                # Without tools
                response = self.client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt if system_prompt else "You are a helpful AI assistant.",
                    messages=messages
                )

            # Extract response text
            response_text = ""
            for block in response.content:
                if hasattr(block, 'text'):
                    response_text += block.text

            return {
                'response': response_text,
                'model': model,
                'usage': {
                    'input_tokens': response.usage.input_tokens,
                    'output_tokens': response.usage.output_tokens,
                },
                'available': True
            }

        except Exception as e:
            return {
                'response': '',
                'available': False,
                'error': str(e)
            }

    async def query_with_tools(
        self,
        prompt: str,
        tools: List[Dict],
        system_prompt: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_iterations: int = 5
    ) -> Dict[str, Any]:
        """
        Query Claude with tool use (agentic mode).

        Claude will decide which tools to use and execute them.

        Args:
            prompt: User message
            tools: List of tool definitions (Anthropic format)
            system_prompt: System instructions
            model: Claude model
            max_iterations: Max tool calling loops

        Returns:
            {
                'response': str,
                'tools_used': list,
                'iterations': int,
                'available': bool
            }
        """
        if not self.available:
            return {
                'response': '',
                'available': False,
                'error': 'Claude API not available'
            }

        messages = [{"role": "user", "content": prompt}]
        tools_used = []

        for iteration in range(max_iterations):
            try:
                response = self.client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=system_prompt if system_prompt else "You are a helpful AI assistant with access to tools.",
                    messages=messages,
                    tools=tools
                )

                # Check if Claude wants to use tools
                if response.stop_reason == "tool_use":
                    # Execute tools
                    for block in response.content:
                        if block.type == "tool_use":
                            tool_name = block.name
                            tool_input = block.input
                            tools_used.append(tool_name)

                            # Tool execution would happen here
                            # For now, just acknowledge
                            tool_result = f"Tool {tool_name} called with {tool_input}"

                            # Add assistant response and tool result to messages
                            messages.append({"role": "assistant", "content": response.content})
                            messages.append({
                                "role": "user",
                                "content": [{
                                    "type": "tool_result",
                                    "tool_use_id": block.id,
                                    "content": tool_result
                                }]
                            })
                else:
                    # No more tool use, return final response
                    response_text = ""
                    for block in response.content:
                        if hasattr(block, 'text'):
                            response_text += block.text

                    return {
                        'response': response_text,
                        'tools_used': tools_used,
                        'iterations': iteration + 1,
                        'available': True,
                        'usage': {
                            'input_tokens': response.usage.input_tokens,
                            'output_tokens': response.usage.output_tokens,
                        }
                    }

            except Exception as e:
                return {
                    'response': '',
                    'available': False,
                    'error': str(e)
                }

        # Max iterations reached
        return {
            'response': "Max iterations reached",
            'tools_used': tools_used,
            'iterations': max_iterations,
            'available': True
        }


# Global instance
claude_api = ClaudeAPI()


async def query_claude(
    prompt: str,
    system_prompt: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514"
) -> Dict[str, Any]:
    """
    Convenience function to query Claude.

    Examples:
        result = await query_claude("Explain quantum computing")
        result = await query_claude("Write a Python function", model="claude-opus-4-20250514")
    """
    return await claude_api.query(prompt, system_prompt, model)


async def query_claude_smart(prompt: str) -> Dict[str, Any]:
    """
    Smart query that tries Claude Sonnet, falls back if unavailable.

    Returns best available response.
    """
    result = await claude_api.query(prompt, model="claude-sonnet-4-20250514")

    if result.get('available'):
        result['provider'] = 'claude_sonnet_4'
        return result
    else:
        # Claude not available
        return {
            'response': '',
            'available': False,
            'error': result.get('error', 'Claude API not available'),
            'fallback_needed': True
        }


# Model information
MODELS = {
    'sonnet-4': {
        'id': 'claude-sonnet-4-20250514',
        'name': 'Claude Sonnet 4',
        'speed': 'fast',
        'intelligence': 'very_high',
        'cost': 'medium',
        'recommended': True,
        'description': 'Best balance of speed and intelligence'
    },
    'opus-4': {
        'id': 'claude-opus-4-20250514',
        'name': 'Claude Opus 4',
        'speed': 'medium',
        'intelligence': 'maximum',
        'cost': 'high',
        'recommended': False,
        'description': 'Maximum intelligence for complex reasoning'
    },
    'haiku-3.5': {
        'id': 'claude-3-5-haiku-20241022',
        'name': 'Claude 3.5 Haiku',
        'speed': 'very_fast',
        'intelligence': 'high',
        'cost': 'low',
        'recommended': False,
        'description': 'Fastest and cheapest, still very capable'
    }
}


def get_model_info(model_key: str = 'sonnet-4') -> Dict[str, Any]:
    """Get information about a Claude model"""
    return MODELS.get(model_key, MODELS['sonnet-4'])
