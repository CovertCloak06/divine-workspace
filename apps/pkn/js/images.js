/**
 * Images Module
 * Handles image generation and image gallery management
 */

import { showToast, escapeHtml } from './utils.js';

// Storage key for images
const IMAGES_STORAGE_KEY = 'parakleon_images_v1';

/**
 * Generate an image using AI
 */
export async function generateImage() {
    const prompt = document.getElementById('imagePrompt')?.value.trim();
    const status = document.getElementById('imageGenStatus');
    const generateBtn = document.querySelector('#imageGeneratorModal button[onclick="generateImage()"]');

    if (!prompt) {
        if (status) {
            status.textContent = '⚠ Please enter a description';
            status.style.display = 'block';
            status.style.color = '#ff6b6b';
        }
        showToast('Please enter an image description', 3000, 'error');
        return;
    }

    // Disable button during generation
    if (generateBtn) {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Generating...';
    }

    if (status) {
        status.textContent = '🎨 Generating image (CPU: ~3 min, GPU: ~30s)...';
        status.style.display = 'block';
        const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary').trim() || '#00ffff';
        status.style.color = themeColor;
    }

    // Add timeout (4 minutes for CPU-based image generation)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 240000);

    try {
        // Use the URL from the config file
        const url = window.PARAKLEON_CONFIG?.LOCAL_IMAGE_GEN_URL;
        if (!url) {
            throw new Error('LOCAL_IMAGE_GEN_URL is not configured in config.js');
        }

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                prompt: prompt
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: `Server error: ${response.status}` }));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }

        const data = await response.json();
        const base64Image = data.image;

        if (!base64Image) {
            throw new Error('No image data received from server.');
        }

        // Create an attachment object for the new image
        const imageAttachment = {
            type: 'image/png',
            url: base64Image,
            previewUrl: base64Image,
            name: `${prompt.slice(0, 20).replace(/\s/g, '_')}.png`
        };

        // Add to chat as an assistant message with the image
        if (window.addMessage) {
            window.addMessage(`Generated image for: "${prompt}"`, 'ai', true, [imageAttachment]);
        }

        // Auto-save to Images gallery
        saveGeneratedImages([imageAttachment], prompt);

        showToast('Image generated successfully!', 3000, 'success');

        // Close modal
        closeImageGenerator();

    } catch (error) {
        clearTimeout(timeoutId);
        console.error('Image generation error:', error);

        let errorMsg = error.message;
        if (error.name === 'AbortError') {
            errorMsg = 'Image generation timed out after 4 minutes. Please try again or reduce image complexity.';
        }

        if (status) {
            status.textContent = `❌ Error: ${errorMsg}`;
            status.style.color = '#ff6b6b';
        }
        showToast(errorMsg, 5000, 'error');
    } finally {
        // Re-enable button
        if (generateBtn) {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate Image';
        }
    }
}

/**
 * Open the image generator modal
 */
export function openImageGenerator() {
    const modal = document.getElementById('imageGenModal');
    const prompt = document.getElementById('imagePrompt');
    const status = document.getElementById('imageGenStatus');

    if (modal) modal.style.display = 'flex';
    if (prompt) {
        prompt.value = '';
        prompt.focus();
    }
    if (status) status.style.display = 'none';
}

/**
 * Close the image generator modal
 */
export function closeImageGenerator() {
    const modal = document.getElementById('imageGenModal');
    if (modal) modal.style.display = 'none';
}

/**
 * Save generated images to localStorage
 * @param {Array} imageAttachments - Array of image attachment objects
 * @param {string} prompt - The prompt used to generate the images
 */
export function saveGeneratedImages(imageAttachments, prompt) {
    let images = [];

    try {
        const raw = localStorage.getItem(IMAGES_STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }

    imageAttachments.forEach(img => {
        images.unshift({
            id: 'img_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
            url: img.url,
            name: img.name,
            prompt: prompt,
            projectId: window.currentProjectId || null,
            chatId: window.currentChatId || null,
            createdAt: Date.now()
        });
    });

    try {
        localStorage.setItem(IMAGES_STORAGE_KEY, JSON.stringify(images));
        renderImages();
    } catch (e) {
        console.error('Failed to save images', e);
    }
}

/**
 * Render images in the sidebar images list
 */
export function renderImages() {
    const imagesList = document.getElementById('imagesList');

    if (!imagesList) return;

    let images = [];
    try {
        const raw = localStorage.getItem(IMAGES_STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }

    imagesList.innerHTML = '';

    if (images.length === 0) {
        imagesList.innerHTML = '<div style="padding: 12px; text-align: center; color: #666; font-size: 11px;">No images yet</div>';
        return;
    }

    images.forEach(img => {
        const item = document.createElement('div');
        item.className = 'image-item';
        item.style.cssText = 'padding: 8px; border-bottom: 1px solid #222; cursor: pointer; transition: background 0.2s;';

        const thumb = document.createElement('img');
        thumb.src = img.url;
        thumb.style.cssText = 'width: 100%; height: 80px; object-fit: cover; border-radius: 4px; border: 1px solid #00FFFF; margin-bottom: 4px;';
        thumb.alt = img.name;

        const info = document.createElement('div');
        info.style.cssText = 'font-size: 10px; color: #999; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
        info.textContent = img.name;

        item.appendChild(thumb);
        item.appendChild(info);

        item.onmouseover = () => item.style.background = '#1a1a1a';
        item.onmouseout = () => item.style.background = '';

        item.onclick = () => openImageModal(img);

        imagesList.appendChild(item);
    });
}

/**
 * Render images gallery (full view)
 */
export function renderImagesGallery() {
    const grid = document.getElementById('imagesGalleryGrid');

    if (!grid) return;

    let images = [];
    try {
        const raw = localStorage.getItem(IMAGES_STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }

    grid.innerHTML = '';

    if (images.length === 0) {
        grid.innerHTML = '<div style="grid-column: 1/-1; padding: 40px; text-align: center; color: #666; font-size: 13px;">No images yet. Click "Generate New" to create one!</div>';
        return;
    }

    images.forEach(img => {
        const item = document.createElement('div');
        item.style.cssText = 'position: relative; border: 1px solid #00FFFF; border-radius: 6px; overflow: hidden; cursor: pointer; transition: all 0.2s ease;';

        const thumb = document.createElement('img');
        thumb.src = img.url;
        thumb.style.cssText = 'width: 100%; height: 100px; object-fit: cover;';
        thumb.alt = img.name;

        const info = document.createElement('div');
        info.style.cssText = 'padding: 6px; background: rgba(0,0,0,0.8); font-size: 10px; color: #999; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
        info.textContent = img.name;

        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = '×';
        deleteBtn.style.cssText = 'position: absolute; top: 4px; right: 4px; background: rgba(255,0,0,0.8); border: none; color: #fff; width: 20px; height: 20px; border-radius: 50%; cursor: pointer; font-size: 14px; line-height: 1; opacity: 0; transition: opacity 0.2s;';
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            deleteImageFromGallery(img.id);
        };

        item.appendChild(thumb);
        item.appendChild(info);
        item.appendChild(deleteBtn);

        item.onmouseover = () => {
            const themeGlow = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary-glow').trim() || 'rgba(0, 255, 255, 0.4)';
            item.style.boxShadow = `0 0 8px ${themeGlow}`;
            deleteBtn.style.opacity = '1';
        };
        item.onmouseout = () => {
            item.style.boxShadow = '';
            deleteBtn.style.opacity = '0';
        };

        item.onclick = () => {
            closeImagesGallery();
            openImageModal(img);
        };

        grid.appendChild(item);
    });
}

/**
 * Open image detail modal
 * @param {Object} img - Image object
 */
export function openImageModal(img) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 10000; padding: 20px;';

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '×';
    closeBtn.style.cssText = 'position: absolute; top: 20px; right: 30px; background: transparent; border: 2px solid #00FFFF; color: #00FFFF; font-size: 32px; cursor: pointer; padding: 5px 15px; border-radius: 4px;';
    closeBtn.onclick = () => document.body.removeChild(modal);

    const image = document.createElement('img');
    image.src = img.url;
    image.style.cssText = 'max-width: 90%; max-height: 70%; border: 2px solid #00FFFF; border-radius: 8px; object-fit: contain;';

    const info = document.createElement('div');
    info.style.cssText = 'margin-top: 20px; color: #00FFFF; text-align: center; max-width: 600px;';
    info.innerHTML = `
        <div style="font-size: 14px; margin-bottom: 8px;"><strong>${escapeHtml(img.name)}</strong></div>
        <div style="font-size: 12px; color: #999; margin-bottom: 12px;">Generated: ${new Date(img.createdAt).toLocaleString()}</div>
        ${img.prompt ? `<div style="font-size: 11px; color: #666; font-style: italic;">"${escapeHtml(img.prompt.substring(0, 100))}${img.prompt.length > 100 ? '...' : ''}"</div>` : ''}
    `;

    const actions = document.createElement('div');
    actions.style.cssText = 'margin-top: 12px; display: flex; gap: 12px; justify-content: center;';

    const downloadBtn = document.createElement('a');
    downloadBtn.href = img.url;
    downloadBtn.download = img.name;
    downloadBtn.textContent = '⬇ Download';
    downloadBtn.style.cssText = 'padding: 8px 16px; background: #00FFFF; color: #000; text-decoration: none; border-radius: 4px; font-size: 12px;';

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = '🗑 Delete';
    deleteBtn.style.cssText = 'padding: 8px 16px; background: transparent; border: 1px solid #ff0000; color: #ff0000; border-radius: 4px; font-size: 12px; cursor: pointer;';
    deleteBtn.onclick = () => {
        if (confirm('Delete this image?')) {
            deleteImage(img.id);
            document.body.removeChild(modal);
        }
    };

    actions.appendChild(downloadBtn);
    actions.appendChild(deleteBtn);

    modal.appendChild(closeBtn);
    modal.appendChild(image);
    modal.appendChild(info);
    modal.appendChild(actions);

    document.body.appendChild(modal);
}

/**
 * Delete an image from storage
 * @param {string} imageId - The image ID to delete
 */
export function deleteImage(imageId) {
    let images = [];

    try {
        const raw = localStorage.getItem(IMAGES_STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
        return;
    }

    images = images.filter(img => img.id !== imageId);

    try {
        localStorage.setItem(IMAGES_STORAGE_KEY, JSON.stringify(images));
        renderImages();
    } catch (e) {
        console.error('Failed to save images', e);
    }
}

/**
 * Delete an image from the gallery view
 * @param {string} imageId - The image ID to delete
 */
export function deleteImageFromGallery(imageId) {
    if (!confirm('Delete this image?')) return;

    let images = [];
    try {
        const raw = localStorage.getItem(IMAGES_STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
        images = images.filter(img => img.id !== imageId);
        localStorage.setItem(IMAGES_STORAGE_KEY, JSON.stringify(images));
        renderImagesGallery();
    } catch (e) {
        console.error('Failed to delete image', e);
    }
}

/**
 * Open the images gallery
 */
export function openImagesGallery() {
    const modal = document.getElementById('imagesGalleryModal');
    if (modal) {
        modal.style.display = 'flex';
        renderImagesGallery();
    }
}

/**
 * Close the images gallery
 */
export function closeImagesGallery() {
    const modal = document.getElementById('imagesGalleryModal');
    if (modal) modal.style.display = 'none';
}

/**
 * Clear all generated images
 */
export function clearGeneratedImages() {
    if (confirm('Delete all generated images from storage?')) {
        localStorage.removeItem(IMAGES_STORAGE_KEY);
        renderImages();
        alert('All generated images cleared.');
    }
}
