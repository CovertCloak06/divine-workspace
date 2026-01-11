/**
 * Voice Input/Output Plugin
 * Speech-to-text input and text-to-speech output
 */

import { PluginBase } from '../../features/plugin-base.js';

export class VoiceIOPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.recognition = null;
        this.synthesis = window.speechSynthesis;
        this.isListening = false;
        this.isSpeaking = false;
    }

    async init() {
        await super.init();

        // Check browser support
        if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
            console.warn(`[${this.name}] Speech recognition not supported in this browser`);
            this.supported = false;
            return;
        }

        this.supported = true;

        // Initialize speech recognition
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        this.recognition = new SpeechRecognition();
        this.recognition.continuous = false;
        this.recognition.interimResults = true;
        this.recognition.lang = 'en-US';

        // Set up recognition events
        this.recognition.onresult = (event) => this.handleRecognitionResult(event);
        this.recognition.onerror = (event) => this.handleRecognitionError(event);
        this.recognition.onend = () => this.handleRecognitionEnd();

        // Load settings
        const defaults = {
            autoSpeak: false,
            voiceSpeed: 1.0,
            voicePitch: 1.0
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        if (!this.supported) {
            this.showToast('Speech not supported in this browser', 3000, 'error');
            return;
        }

        // Add mic button to input area
        this.addVoiceButton();

        // Subscribe to message events for TTS
        this.subscribe('message:received', (data) => {
            if (this.getSetting('autoSpeak', false)) {
                this.speak(data.content);
            }
        });

        console.log(`[${this.name}] Voice I/O active`);
    }

    async disable() {
        await super.disable();
        this.stopListening();
        this.stopSpeaking();
        this.removeVoiceButton();
    }

    /**
     * Add voice button to UI
     */
    addVoiceButton() {
        const inputRow = document.querySelector('.input-row');
        if (!inputRow) return;

        const micButton = document.createElement('button');
        micButton.id = 'voiceMicButton';
        micButton.className = 'voice-mic-btn';
        micButton.title = 'Voice input (click to speak)';
        micButton.innerHTML = '🎤';
        micButton.onclick = () => this.toggleListening();

        const sendBtn = document.getElementById('sendBtn');
        if (sendBtn) {
            inputRow.insertBefore(micButton, sendBtn);
        } else {
            inputRow.appendChild(micButton);
        }
    }

    /**
     * Remove voice button
     */
    removeVoiceButton() {
        const button = document.getElementById('voiceMicButton');
        if (button) button.remove();
    }

    /**
     * Toggle listening
     */
    toggleListening() {
        if (this.isListening) {
            this.stopListening();
        } else {
            this.startListening();
        }
    }

    /**
     * Start listening
     */
    startListening() {
        if (!this.recognition || this.isListening) return;

        try {
            this.recognition.start();
            this.isListening = true;
            this.updateMicButton(true);
            this.showToast('Listening...', 2000, 'info');
        } catch (error) {
            console.error(`[${this.name}] Start listening error:`, error);
        }
    }

    /**
     * Stop listening
     */
    stopListening() {
        if (!this.recognition || !this.isListening) return;

        try {
            this.recognition.stop();
            this.isListening = false;
            this.updateMicButton(false);
        } catch (error) {
            console.error(`[${this.name}] Stop listening error:`, error);
        }
    }

    /**
     * Handle recognition result
     */
    handleRecognitionResult(event) {
        const transcript = Array.from(event.results)
            .map(result => result[0].transcript)
            .join('');

        // Update input with transcript
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.value = transcript;
            messageInput.dispatchEvent(new Event('input', { bubbles: true }));
        }

        // If final result, stop listening
        if (event.results[event.results.length - 1].isFinal) {
            this.stopListening();
        }
    }

    /**
     * Handle recognition error
     */
    handleRecognitionError(event) {
        console.error(`[${this.name}] Recognition error:`, event.error);
        this.stopListening();

        if (event.error !== 'no-speech') {
            this.showToast(`Voice error: ${event.error}`, 3000, 'error');
        }
    }

    /**
     * Handle recognition end
     */
    handleRecognitionEnd() {
        this.isListening = false;
        this.updateMicButton(false);
    }

    /**
     * Update mic button state
     */
    updateMicButton(isListening) {
        const button = document.getElementById('voiceMicButton');
        if (!button) return;

        if (isListening) {
            button.classList.add('listening');
            button.innerHTML = '🔴';
            button.title = 'Listening... (click to stop)';
        } else {
            button.classList.remove('listening');
            button.innerHTML = '🎤';
            button.title = 'Voice input (click to speak)';
        }
    }

    /**
     * Speak text
     */
    speak(text) {
        if (!text || this.isSpeaking) return;

        // Cancel any ongoing speech
        this.synthesis.cancel();

        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = this.getSetting('voiceSpeed', 1.0);
        utterance.pitch = this.getSetting('voicePitch', 1.0);

        utterance.onstart = () => {
            this.isSpeaking = true;
            this.emit('voice:speakingStarted', { text });
        };

        utterance.onend = () => {
            this.isSpeaking = false;
            this.emit('voice:speakingEnded');
        };

        utterance.onerror = (event) => {
            console.error(`[${this.name}] Speech error:`, event);
            this.isSpeaking = false;
        };

        this.synthesis.speak(utterance);
    }

    /**
     * Stop speaking
     */
    stopSpeaking() {
        if (this.synthesis) {
            this.synthesis.cancel();
            this.isSpeaking = false;
        }
    }

    getCSS() {
        return `
            .voice-mic-btn {
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 8px;
                width: 48px;
                height: 48px;
                font-size: 20px;
                cursor: pointer;
                transition: all 0.2s;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                margin-left: 8px;
            }
            .voice-mic-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 255, 255, 0.3);
            }
            .voice-mic-btn.listening {
                background: rgba(255, 0, 0, 0.2);
                border-color: #ff0000;
                animation: pulse-red 1.5s ease-in-out infinite;
            }
            @keyframes pulse-red {
                0%, 100% {
                    box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.7);
                }
                50% {
                    box-shadow: 0 0 0 10px rgba(255, 0, 0, 0);
                }
            }
        `;
    }
}

export default VoiceIOPlugin;
