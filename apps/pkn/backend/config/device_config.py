#!/usr/bin/env python3
"""
PKN Device Auto-Configuration
Detects device type and loads appropriate model configuration
"""

import os
import sys
import json
import platform
from pathlib import Path

class DeviceConfig:
    """Automatically configure PKN based on device type"""

    def __init__(self):
        self.device_type = self.detect_device()
        self.config_dir = Path(__file__).parent
        self.config = self.load_config()

    def detect_device(self):
        """
        Detect if running on Android (Termux) or PC

        Returns:
            'android' or 'pc'
        """
        # Check for Termux environment
        if os.path.exists('/data/data/com.termux'):
            return 'android'

        # Check for Android-specific paths
        if 'TERMUX_VERSION' in os.environ:
            return 'android'

        # Check if PREFIX points to Termux
        prefix = os.environ.get('PREFIX', '')
        if 'com.termux' in prefix:
            return 'android'

        # Check architecture (Android is usually ARM)
        machine = platform.machine().lower()
        if machine.startswith('arm') or machine.startswith('aarch'):
            # Could be ARM PC (like Raspberry Pi) or Android
            # Check for termux-specific binaries
            if os.path.exists(os.path.expanduser('~/storage')):
                return 'android'

        # Default to PC
        return 'pc'

    def get_config_for_device(self):
        """
        Get optimal configuration for detected device

        Returns:
            dict with model, settings, and optimizations
        """
        if self.device_type == 'android':
            return {
                'device': 'android',
                'model': {
                    'path': 'llama.cpp/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf',
                    'name': 'Mistral-7B-Instruct-v0.2',
                    'size_gb': 4.1,
                    'context_length': 32768,
                    'uncensored': True,
                },
                'llm_settings': {
                    'n_ctx': 4096,  # Reduced for mobile
                    'n_batch': 256,  # Smaller batch
                    'n_threads': 4,  # Adjust based on phone cores
                    'n_gpu_layers': 0,  # No GPU on most phones
                },
                'image_generation': {
                    'enabled': False,  # Disable on Android
                    'reason': 'Too resource-intensive for mobile',
                    'alternative': 'Use PC remotely or sync generated images'
                },
                'optimizations': {
                    'low_memory_mode': True,
                    'reduced_agent_count': False,  # Keep all agents
                    'cache_size_mb': 512,  # Smaller cache
                },
                'max_memory_gb': 4,  # Assume 4GB available for AI
            }
        else:  # PC
            return {
                'device': 'pc',
                'model': {
                    'path': 'llama.cpp/models/Qwen2.5-Coder-14B-Instruct-abliterated-Q4_K_M.gguf',
                    'name': 'Qwen2.5-Coder-14B-Instruct-Abliterated',
                    'size_gb': 8.4,
                    'context_length': 32768,
                    'uncensored': True,
                },
                'llm_settings': {
                    'n_ctx': 8192,
                    'n_batch': 512,
                    'n_threads': os.cpu_count() - 2 if os.cpu_count() > 2 else 2,
                    'n_gpu_layers': 45,  # Try GPU if available
                },
                'image_generation': {
                    'enabled': True,
                    'model': 'stable-diffusion-v1-5',
                    'num_inference_steps': 50,
                    'width': 512,
                    'height': 512,
                },
                'optimizations': {
                    'low_memory_mode': False,
                    'reduced_agent_count': False,
                    'cache_size_mb': 2048,
                },
                'max_memory_gb': 16,  # Assume 16GB available for AI
            }

    def load_config(self):
        """Load or create device-specific configuration"""
        config = self.get_config_for_device()

        # Save to file for reference
        config_file = self.config_dir / f'config_{self.device_type}.json'
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✓ Device detected: {self.device_type.upper()}")
        print(f"✓ Configuration saved: {config_file}")

        return config

    def get_model_path(self):
        """Get full path to model file"""
        model_rel_path = self.config['model']['path']
        return str(self.config_dir / model_rel_path)

    def get_startup_command(self):
        """
        Generate llama.cpp startup command for this device

        Returns:
            str: Command to start llama.cpp server
        """
        model_path = self.get_model_path()
        settings = self.config['llm_settings']

        # Determine chat format based on model
        if 'phi' in model_path.lower():
            chat_format = 'chatml'
        elif 'mistral' in model_path.lower():
            chat_format = 'mistral-instruct'
        else:
            chat_format = 'qwen'

        cmd = f"""python3 -m llama_cpp.server \\
  --model "{model_path}" \\
  --host 0.0.0.0 \\
  --port 8000 \\
  --chat_format {chat_format} \\
  --n_ctx {settings['n_ctx']} \\
  --n_batch {settings['n_batch']} \\
  --n_threads {settings['n_threads']}"""

        if settings['n_gpu_layers'] > 0:
            cmd += f" \\\n  --n_gpu_layers {settings['n_gpu_layers']}"

        return cmd

    def print_summary(self):
        """Print configuration summary"""
        print("\n" + "="*60)
        print(f"PKN AUTO-CONFIGURATION: {self.device_type.upper()}")
        print("="*60)

        print(f"\n📱 Device Type: {self.device_type.upper()}")
        print(f"🤖 Model: {self.config['model']['name']}")
        print(f"💾 Size: {self.config['model']['size_gb']}GB")
        print(f"🔓 Uncensored: {'YES' if self.config['model']['uncensored'] else 'NO'}")
        print(f"🧠 Context: {self.config['model']['context_length']:,} tokens")

        print(f"\n⚙️  LLM Settings:")
        for key, value in self.config['llm_settings'].items():
            print(f"   {key}: {value}")

        print(f"\n🖼️  Image Generation: {'ENABLED' if self.config['image_generation']['enabled'] else 'DISABLED'}")
        if not self.config['image_generation']['enabled']:
            print(f"   Reason: {self.config['image_generation']['reason']}")
            print(f"   Alternative: {self.config['image_generation']['alternative']}")

        print(f"\n🔧 Optimizations:")
        for key, value in self.config['optimizations'].items():
            print(f"   {key}: {value}")

        print(f"\n💻 Max Memory: {self.config['max_memory_gb']}GB")

        print("\n" + "="*60)

    def check_model_exists(self):
        """Check if configured model file exists"""
        model_path = self.get_model_path()

        if os.path.exists(model_path):
            size_bytes = os.path.getsize(model_path)
            size_gb = size_bytes / (1024**3)
            print(f"✓ Model found: {model_path}")
            print(f"  Size: {size_gb:.2f}GB")
            return True
        else:
            print(f"✗ Model NOT found: {model_path}")
            print(f"\n📥 Download instructions:")

            if self.device_type == 'android':
                print(f"""
# On Android (Termux):
cd ~/pkn/llama.cpp/models
wget https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf
""")
            else:
                print(f"""
# Model already configured for PC
# You're using: {self.config['model']['name']}
# Path: {model_path}
""")
            return False


def main():
    """Main entry point"""
    print("PKN Device Auto-Configuration")
    print("-" * 60)

    config = DeviceConfig()
    config.print_summary()
    print()
    config.check_model_exists()

    print("\n📋 Startup Command:")
    print(config.get_startup_command())

    return config


if __name__ == '__main__':
    config = main()
