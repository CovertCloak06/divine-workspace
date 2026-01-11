"""
Chat Route
Handles chat requests using OpenAI API
"""

from flask import Blueprint, request, Response, stream_with_context
import json

from ..api.openai_client import OpenAIClient

chat_bp = Blueprint('chat', __name__)

# Initialize OpenAI client (will fail gracefully if no API key)
try:
    openai_client = OpenAIClient()
    print("✅ OpenAI client initialized")
except ValueError as e:
    print(f"⚠️  OpenAI client not available: {e}")
    openai_client = None


@chat_bp.route('/multi-agent/chat', methods=['POST'])
def handle_chat():
    """
    Handle chat request with OpenAI API.

    Request JSON:
        {
            "message": "user message",
            "context": [previous messages],
            "stream": true/false
        }

    Response:
        Streaming text or JSON depending on stream parameter
    """
    if not openai_client:
        return {
            'error': 'OpenAI API not configured',
            'details': 'Set OPENAI_API_KEY environment variable'
        }, 500

    data = request.json
    user_message = data.get('message', '')
    context = data.get('context', [])
    stream = data.get('stream', True)

    if not user_message:
        return {'error': 'No message provided'}, 400

    # Build messages array
    messages = context + [
        {'role': 'user', 'content': user_message}
    ]

    if stream:
        # Streaming response
        def generate():
            """Generate streaming response chunks."""
            try:
                for chunk in openai_client.chat_completion(
                    messages=messages,
                    stream=True
                ):
                    # Send as newline-delimited JSON
                    yield f"data: {json.dumps({'text': chunk})}\n\n"

                yield "data: [DONE]\n\n"

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream'
        )
    else:
        # Non-streaming response
        try:
            response_text = ''.join(openai_client.chat_completion(
                messages=messages,
                stream=False
            ))

            return {
                'response': response_text,
                'agent': 'openai',
                'model': openai_client.model
            }

        except Exception as e:
            return {'error': str(e)}, 500
