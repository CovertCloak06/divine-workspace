# Image Generator Fix Summary

## Issues Fixed

### 1. Frontend Timeout Too Short (PRIMARY ISSUE)
**Problem:** JavaScript was aborting requests after 60 seconds, but CPU-based Stable Diffusion takes 2-3 minutes

**Fixed in:** `js/images.js`
- Line 43: Increased timeout from `60000ms` (60s) to `240000ms` (4 minutes)
- Line 36: Updated status message to show realistic time: "CPU: 2-3 min, GPU: 30s"
- Line 104: Updated error message to reflect 4-minute timeout

### 2. Backend Performance Optimization
**Fixed in:** `divinenode_server.py`
- Line 944: Reduced inference steps from 50 to 25 for faster CPU generation
- Still maintains good image quality with PNDM scheduler
- Expected time: ~2.5 minutes on CPU vs 5 minutes before

### 3. Dependencies Added
**Fixed in:** `requirements.txt`
- Added: `torch>=2.0.0`
- Added: `diffusers>=0.25.0`
- Added: `transformers>=4.35.0`

## How to Test

### Method 1: Via Web UI
1. Open http://localhost:8010 in browser
2. Click the image icon (🖼️) in the input area
3. Enter a prompt: "a futuristic cyberpunk city at night"
4. Click "Generate" button
5. Wait 2-3 minutes (you'll see progress in status)
6. Image will appear in chat and be saved to Images sidebar

### Method 2: Via CLI Test
```bash
cd /home/gh0st/pkn
source .venv/bin/activate
python3 local_image_gen.py "a cyberpunk crown with neon circuits"
```

### Method 3: Via API
```bash
curl -X POST http://localhost:8010/api/generate-image \
  -H "Content-Type: application/json" \
  -d '{"prompt": "test image"}' \
  --max-time 300
```

## Performance Expectations

| Hardware | Inference Steps | Expected Time |
|----------|----------------|---------------|
| CPU Only | 25 steps | 2-3 minutes |
| GPU (CUDA) | 50 steps | 30-45 seconds |

## Troubleshooting

### "Image generation timed out"
- You have CPU only and need more time
- Try a simpler prompt with fewer details
- Or reduce steps further in `divinenode_server.py` line 944

### "Module 'torch' not found"
```bash
source .venv/bin/activate
pip install torch diffusers transformers
```

### First Generation Takes Longer
- Model downloads from HuggingFace (~4GB)
- Cached in `~/.cache/huggingface/`
- Subsequent generations are faster

### Images Not Appearing
- Check browser console (F12) for JavaScript errors
- Verify localStorage is enabled
- Check divinenode.log for backend errors

## Architecture

```
User clicks Generate
    ↓
js/images.js:generateImage() [4min timeout]
    ↓
POST /api/generate-image
    ↓
divinenode_server.py:generate_image()
    ↓
local_image_gen.py:LocalImageGenerator [25 steps, CPU]
    ↓
Stable Diffusion v1.5 (runwayml/stable-diffusion-v1-5)
    ↓
Returns base64 PNG
    ↓
Saved to localStorage + displayed in chat
```

## Files Modified

1. `/home/gh0st/pkn/js/images.js`
   - Timeout: 60s → 240s
   - Status messages updated

2. `/home/gh0st/pkn/divinenode_server.py`
   - Inference steps: 50 → 25

3. `/home/gh0st/pkn/requirements.txt`
   - Added torch, diffusers, transformers

4. `/home/gh0st/pkn/css/main.css`
   - Fixed cyan theme circular reference (unrelated but also fixed)

## Notes

- Image generator is 100% local and private (no external APIs)
- Safety checker disabled for uncensored generation
- Uses PNDM scheduler for better quality
- Images stored in browser localStorage as base64
- No images saved to disk unless explicitly downloaded
