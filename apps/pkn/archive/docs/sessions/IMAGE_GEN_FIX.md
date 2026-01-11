# PKN Image Generator - Fixed & Upgraded

## Problems Fixed

### 1. **Recursion Error** ✓ FIXED
**Problem**: "Too much recursion" error when generating images
**Cause**: Old monolithic `app.js` conflicting with new modular JavaScript system
**Fix**:
- Disabled old `app.js` in `pkn.html`
- Exposed `addMessage` and `renderHistory` functions to `window` object in `js/main.js`

### 2. **Privacy Violation** ✓ FIXED
**Problem**: Image generator was using **Pollinations.ai** (external API)
- Your prompts were being sent to their servers
- Completely defeated the privacy goal of PKN
- Hit token limits and rate limiting

**Fix**: Replaced with **100% LOCAL image generation**
- Uses Stable Diffusion running on YOUR machine
- No internet required after initial setup
- Zero external API calls
- Completely private

---

## New Local Image Generator

### How It Works
- **Model**: Stable Diffusion v1.5 (you already had it downloaded!)
- **Location**: Runs locally on your machine via `local_image_gen.py`
- **Privacy**: 100% - prompts never leave your computer
- **Quality**: Professional AI-generated images at 512x512

### Performance
- **CPU Mode**: ~20-60 seconds per image (no GPU needed)
- **First Run**: Will download model if needed (~4GB)
- **After Setup**: No internet required

### Files Modified
1. `/home/gh0st/pkn/pkn.html` - Disabled old app.js
2. `/home/gh0st/pkn/js/main.js` - Exposed functions to window
3. `/home/gh0st/pkn/divinenode_server.py` - Uses local generator
4. `/home/gh0st/pkn/local_image_gen.py` - NEW: Local image generation

---

## Testing the Fix

### Quick Test
1. Open PKN in your browser: `http://localhost:8010/pkn.html`
2. Click the image generation button (camera icon)
3. Enter a prompt: `"cyberpunk city at night"`
4. Wait 30-60 seconds for first generation
5. Image will appear in chat - **completely private!**

### What You'll See
```
🎨 Generating: cyberpunk city at night...
✓ Image generated successfully!
```

### Performance Notes
- **First image**: Slower (model initialization ~30s)
- **Subsequent images**: Faster (model stays loaded)
- **CPU only**: Will be slower than GPU, but works fine
- **Quality**: Adjustable in `divinenode_server.py` (num_inference_steps)

---

## Advanced Usage

### Adjust Generation Speed/Quality
Edit `/home/gh0st/pkn/divinenode_server.py` line 833:

```python
num_inference_steps=25,  # Lower = faster, Higher = better quality
                         # Range: 15-50
                         # 15 = ~15s but lower quality
                         # 25 = ~30s balanced (default)
                         # 50 = ~60s best quality
```

### Change Image Size
Edit lines 834-835:
```python
width=512,   # 256, 512, 768, or 1024
height=512,  # Keep same as width for best results
```

**Note**: Larger images take MUCH longer on CPU (1024x1024 = 4x slower)

### CLI Testing
Test the generator directly:
```bash
cd /home/gh0st/pkn
source .venv/bin/activate
python3 local_image_gen.py "a dragon flying over mountains"
```

Saves HTML file to `/home/gh0st/pkn/images/`

---

## What's Different Now

### Before (Pollinations.ai)
❌ Prompts sent to external servers
❌ Rate limited
❌ No privacy
❌ Internet required
❌ Token limits

### After (Local Stable Diffusion)
✅ 100% private - runs on your machine
✅ No rate limits
✅ No external servers
✅ Works offline
✅ Unlimited generation

---

## Troubleshooting

### "Generation is slow"
**Normal for CPU!** 30-60 seconds is expected without GPU.
- Lower `num_inference_steps` to 15-20 for faster (but lower quality)
- Keep image size at 512x512

### "Out of memory"
- Close other applications
- The generator uses `attention_slicing` for CPU efficiency
- If still fails, reduce image size to 256x256

### "Module not found: diffusers"
Already installed! But if needed:
```bash
source .venv/bin/activate
pip install diffusers transformers accelerate
```

---

## Future Upgrades (Optional)

### If You Get a GPU Later
The generator will automatically detect and use it:
- Generation drops from 60s → 5s per image
- Can increase quality and resolution
- CUDA will be auto-detected

### Better Models
Replace model in `local_image_gen.py` line 37:
```python
model_path = "runwayml/stable-diffusion-v1-5"  # Current
# model_path = "stabilityai/stable-diffusion-2-1"  # Better quality
# model_path = "stabilityai/sdxl-turbo"  # Super fast
```

---

## Summary

**Both issues are now completely fixed:**
1. ✅ No more recursion errors
2. ✅ 100% private local image generation

Your PKN system now has **true privacy** for image generation - exactly as it should be!

**Next time you generate an image, it stays on YOUR machine. No external APIs. No tracking. No limits.**

---

## Need Help?

Test the system:
```bash
./pkn_control.sh status    # Check all services
tail -f divinenode.log     # Watch generation logs
```

Everything should work now! 🎨
