# Uncensored Image Generation Models for PKN

## Current Setup: ✅ UNCENSORED

Your PKN system is now configured for **completely uncensored image generation**:
- ✅ Safety checker: **DISABLED**
- ✅ Content filters: **DISABLED**
- ✅ 100% local and private
- ✅ No external censorship

## Current Model
**Stable Diffusion 1.5** (runwayml/stable-diffusion-v1-5)
- Safety checker disabled in code
- Generates anything without filters
- Good quality, fast on CPU

---

## Upgrade to More Uncensored Models (Optional)

If you want even better uncensored models, here are your options:

### Option 1: Stable Diffusion 2.1 (Better Quality)
Edit `/home/gh0st/pkn/local_image_gen.py` line 33:
```python
model_path = "stabilityai/stable-diffusion-2-1"
```
**Pros**: Better quality, more detailed
**Cons**: Slower on CPU (~60-90s per image)

### Option 2: Community Uncensored Models
Popular uncensored models from HuggingFace:

#### Protogen x3.4 (Photorealistic)
```python
model_path = "darkstorm2150/Protogen_x3.4_Official_Release"
```
Great for realistic images, anime, sci-fi

#### Anything V4.5 (Anime/Versatile)
```python
model_path = "andite/anything-v4.0"
```
Popular for anime, illustration, creative art

#### Deliberate v2 (Realistic)
```python
model_path = "XpucT/Deliberate"
```
High quality realistic images

### Option 3: SDXL Models (Best Quality, Requires Good Hardware)
```python
model_path = "stabilityai/stable-diffusion-xl-base-1.0"
```
**Warning**: SDXL is MUCH slower on CPU (3-5 minutes per image)
**Recommended**: Only if you have a GPU

---

## How to Change Models

### Step 1: Edit the Model Path
Edit `/home/gh0st/pkn/local_image_gen.py` around line 33:
```python
model_path = "YOUR_CHOSEN_MODEL_HERE"
```

### Step 2: Restart the Server
```bash
./pkn_control.sh restart-divinenode
```

### Step 3: Generate First Image
- First generation will download the new model (~2-7GB depending on model)
- Subsequent generations use cached model

---

## Advanced: Using Local .safetensors Files

If you download models manually (to avoid HuggingFace):

### Step 1: Download Model
Download `.safetensors` or `.ckpt` files from:
- CivitAI.com (largest uncensored model library)
- HuggingFace.co/models

### Step 2: Save to Directory
```bash
mkdir -p /home/gh0st/pkn/models
# Move your downloaded .safetensors file there
```

### Step 3: Load from Local Path
Edit `local_image_gen.py` line 33:
```python
from diffusers import StableDiffusionPipeline
# ... then in initialize():
model_path = "/home/gh0st/pkn/models/YOUR_MODEL.safetensors"
self.pipe = StableDiffusionPipeline.from_single_file(
    model_path,
    torch_dtype=torch.float32 if self.device == "cpu" else torch.float16,
    safety_checker=None,
    requires_safety_checker=False
)
```

---

## Recommended Uncensored Models from CivitAI

Visit civitai.com and search for:
1. **Realistic Vision** - photorealistic, uncensored
2. **DreamShaper** - versatile, great quality
3. **AbyssOrangeMix** - anime/creative
4. **Protogen** - sci-fi/realistic hybrid
5. **Deliberate** - artistic realistic

All are uncensored by default, just disable safety_checker in code (already done).

---

## Performance Tips

### For CPU Users (No GPU)
Stick with:
- SD 1.5 (current) - 30-60s per image
- Protogen x3.4 - 40-70s per image

Avoid:
- SDXL - Too slow (3-5 min)
- SD 2.1 - Slower (60-90s)

### For GPU Users
Any model will work great:
- SD 1.5 - ~5s per image
- SDXL - ~15s per image
- Community models - ~5-10s

---

## Testing Uncensored Generation

Your current setup is **already uncensored**. To verify:

1. Generate an image with a test prompt
2. Check the logs for: `⚠️  Safety filters DISABLED`
3. No censorship or black images should appear

The safety checker is completely bypassed in your config.

---

## FAQ

**Q: Will this get me in trouble?**
A: It's 100% local, private, on your machine. No one knows what you generate.

**Q: Is this legal?**
A: Generating images locally for personal use is legal. Distribution of certain content may have legal restrictions depending on your jurisdiction.

**Q: Why are some models censored?**
A: Corporate models like OpenAI DALL-E have safety filters. Open source models like SD can be run uncensored.

**Q: Can I mix models?**
A: Yes! Change the model path anytime. First run downloads it.

**Q: Do I need to keep both models?**
A: Models are cached in `~/.cache/huggingface/hub/`. You can delete old ones to save space.

---

## Current Status

✅ Uncensored: YES
✅ Local: YES
✅ Private: YES
✅ No filters: YES
✅ Safety checker: DISABLED

Your PKN image generator is **fully uncensored** and ready to use!
