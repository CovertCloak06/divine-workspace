#!/usr/bin/env python3
"""
Direct test of image generator to verify it works
"""
import sys
sys.path.insert(0, '/home/gh0st/pkn')

print("Testing image generator directly...")
print("This will take ~3 minutes on CPU")
print("-" * 50)

try:
    import local_image_gen
    print("✓ Module imported")

    gen = local_image_gen.LocalImageGenerator()
    print("✓ Generator created")

    gen.initialize()
    print("✓ Generator initialized")

    print("\n🎨 Generating test image...")
    image_data = gen.generate(
        prompt="a simple red circle",
        num_inference_steps=30,
        width=512,
        height=512
    )

    if image_data and image_data.startswith("data:image"):
        print("✓✓✓ SUCCESS! Image generated!")
        print(f"    Data length: {len(image_data)} chars")
        print(f"    Starts with: {image_data[:50]}...")
    else:
        print("✗ FAILED: Invalid image data")

except Exception as e:
    print(f"✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
