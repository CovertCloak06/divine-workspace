"""
Images Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json
import time

# Optional image generation (requires torch)
try:
    from ..image_gen import local_image_gen

    IMAGE_GEN_AVAILABLE = True
except ImportError:
    IMAGE_GEN_AVAILABLE = False
    local_image_gen = None


# Create blueprint
images_bp = Blueprint("images", __name__)


@images_bp.route("/api/generate-image", methods=["POST"])
def generate_image():
    """
    Generate images using LOCAL Stable Diffusion
    100% private - runs on your machine, no external APIs
    """
    if not IMAGE_GEN_AVAILABLE:
        return jsonify(
            {"error": "Image generation not available (torch not installed)"}
        ), 503

    try:
        data = request.json
        prompt = data.get("prompt", "")

        if not prompt:
            return jsonify({"error": "Prompt is required"}), 400

        print(f"🎨 [Image Gen] Generating locally: {prompt[:50]}...")

        # Use local image generator (completely private)
        # Euler scheduler: 30-50 steps recommended
        # CPU mode: 30 steps (~2.5 min), GPU mode: 50 steps (~30 sec)
        image_data = local_image_gen.generate_image(
            prompt=prompt,
            num_inference_steps=30,  # Euler works well with 30 steps
            width=512,
            height=512,
        )

        print(f"✓ [Image Gen] Generated successfully")
        return jsonify({"image": image_data}), 200

    except Exception as e:
        print(f"✗ [Image Gen] Error: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": f"Local generation failed: {str(e)}"}), 500


@images_bp.route("/api/generate-image-stream", methods=["POST"])
def generate_image_stream():
    """
    Generate images with Server-Sent Events for real-time progress updates
    """
    import json
    from flask import Response, stream_with_context

    data = request.json
    prompt = data.get("prompt", "")

    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400

    def generate_with_progress():
        """Generator function that yields SSE events"""
        try:
            print(f"🎨 [Image Gen SSE] Starting: {prompt[:50]}...")

            # Send initial status
            yield f"data: {json.dumps({'status': 'starting', 'message': 'Initializing image generator...'})}\n\n"

            # Progress callback
            def progress_callback(step, total_steps):
                progress = step / total_steps
                data = {
                    "status": "progress",
                    "step": step,
                    "total_steps": total_steps,
                    "progress": progress,
                    "message": f"Generating... {step}/{total_steps} steps ({int(progress * 100)}%)",
                }
                return f"data: {json.dumps(data)}\n\n"

            # Storage for progress events
            progress_events = []

            def store_progress(step, total_steps):
                event = progress_callback(step, total_steps)
                progress_events.append(event)

            # Generate image with progress callback
            image_data = local_image_gen.generate_image(
                prompt=prompt,
                num_inference_steps=30,
                width=512,
                height=512,
                callback=store_progress,
            )

            # Yield all progress events
            for event in progress_events:
                yield event

            # Send completion event with image
            yield f"data: {json.dumps({'status': 'complete', 'image': image_data, 'message': 'Image generated successfully!'})}\n\n"

            print(f"✓ [Image Gen SSE] Completed successfully")

        except Exception as e:
            print(f"✗ [Image Gen SSE] Error: {str(e)}")
            import traceback

            traceback.print_exc()
            yield f"data: {json.dumps({'status': 'error', 'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate_with_progress()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
