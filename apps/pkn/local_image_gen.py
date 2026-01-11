#!/usr/bin/env python3
"""
Local Image Generator for PKN - 100% Private
Uses Stable Diffusion running locally on your machine
No internet required, no external APIs, completely private
"""

import torch
from diffusers import StableDiffusionPipeline, PNDMScheduler
import base64
from io import BytesIO
import os
import sys

class LocalImageGenerator:
    def __init__(self):
        self.pipe = None
        self.device = "cpu"  # Will check for CUDA but default to CPU

    def initialize(self):
        """Initialize the Stable Diffusion pipeline"""
        print("🎨 Initializing local image generator...")

        # Check for CUDA
        if torch.cuda.is_available():
            self.device = "cuda"
            print("✓ Using GPU acceleration")
        else:
            print("⚠️  Using CPU (slower but works)")

        # Load the model
        # Using SD 1.5 - fully uncensored when safety_checker is disabled
        model_path = "runwayml/stable-diffusion-v1-5"

        print(f"Loading model: {model_path}")
        print("⚠️  Safety filters DISABLED - uncensored generation")

        # Load pipeline WITHOUT safety checker (truly uncensored)
        self.pipe = StableDiffusionPipeline.from_pretrained(
            model_path,
            torch_dtype=torch.float32 if self.device == "cpu" else torch.float16,
            safety_checker=None,  # DISABLED - No censorship
            requires_safety_checker=False  # Fully uncensored
        )

        # Use Euler Discrete scheduler (most stable, works with any step count)
        from diffusers import EulerDiscreteScheduler
        self.pipe.scheduler = EulerDiscreteScheduler.from_config(
            self.pipe.scheduler.config
        )

        # Move to device
        self.pipe = self.pipe.to(self.device)

        # Enable optimizations for CPU
        if self.device == "cpu":
            # Enable attention slicing to reduce memory usage
            self.pipe.enable_attention_slicing()

        print("✓ Image generator ready!")

    def generate(self, prompt, negative_prompt="", num_inference_steps=25, width=512, height=512, callback=None):
        """
        Generate an image from a text prompt

        Args:
            prompt: Text description of image to generate
            negative_prompt: Things to avoid in the image
            num_inference_steps: Quality vs speed (20-50, lower=faster)
            width, height: Image dimensions (512x512 is standard)
            callback: Optional function called with (step, total_steps) for progress

        Returns:
            Base64 encoded PNG image
        """
        if not self.pipe:
            self.initialize()

        print(f"🎨 Generating: {prompt[:50]}...")

        # Default negative prompt for better quality
        if not negative_prompt:
            negative_prompt = "blurry, low quality, distorted, deformed, ugly"

        # Progress callback wrapper
        def progress_callback(pipe, step_index, timestep, callback_kwargs):
            if callback:
                callback(step_index + 1, num_inference_steps)
            return callback_kwargs

        # Generate image
        with torch.no_grad():
            result = self.pipe(
                prompt=prompt,
                negative_prompt=negative_prompt,
                num_inference_steps=num_inference_steps,
                width=width,
                height=height,
                guidance_scale=7.5,
                callback_on_step_end=progress_callback if callback else None
            )

        # Get the image
        image = result.images[0]

        # Convert to base64
        buffered = BytesIO()
        image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        print("✓ Image generated successfully!")
        return f"data:image/png;base64,{img_str}"

# Global instance (lazy loaded)
_generator = None

def get_generator():
    """Get or create the global generator instance"""
    global _generator
    if _generator is None:
        _generator = LocalImageGenerator()
    return _generator

def generate_image(prompt, **kwargs):
    """
    Quick function to generate an image

    Args:
        prompt: Text description
        **kwargs: Additional arguments for generate()

    Returns:
        Base64 encoded image data URL
    """
    gen = get_generator()
    return gen.generate(prompt, **kwargs)

if __name__ == '__main__':
    # CLI usage
    if len(sys.argv) < 2:
        print("Usage: python3 local_image_gen.py '<prompt>'")
        print("\nExample:")
        print("  python3 local_image_gen.py 'a cyberpunk city at night'")
        print("\n⚠️  First run will download the model (~4GB)")
        print("✓ 100% local and private - no internet needed after download")
        sys.exit(1)

    prompt = ' '.join(sys.argv[1:])

    # Generate
    gen = LocalImageGenerator()
    gen.initialize()

    # Generate with faster settings for CLI
    image_data = gen.generate(
        prompt,
        num_inference_steps=20,  # Faster for testing
        width=512,
        height=512
    )

    # Save to file
    import re
    safe_name = re.sub(r'[^\w\s-]', '', prompt[:30]).strip().replace(' ', '_')
    output_file = f"/home/gh0st/pkn/images/{safe_name}.html"

    os.makedirs("/home/gh0st/pkn/images", exist_ok=True)

    with open(output_file, 'w') as f:
        f.write(f'''<!DOCTYPE html>
<html>
<head><title>{prompt}</title></head>
<body style="margin:0;padding:20px;background:#000;color:#0ff;font-family:monospace;">
<h2>{prompt}</h2>
<img src="{image_data}" style="max-width:100%;border:2px solid #0ff;">
</body>
</html>''')

    print(f"✓ Saved to: {output_file}")
    print(f"  Open in browser to view!")
