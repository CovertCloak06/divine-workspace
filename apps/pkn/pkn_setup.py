#!/usr/bin/env python3
"""
PKN Self-Setup & Dependency Manager
Ensures all dependencies are installed and configured correctly
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path

class PKNSetup:
    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.venv_path = self.project_root / ".venv"
        self.issues = []
        self.warnings = []

    def print_header(self, text: str):
        """Print section header"""
        print(f"\n{'='*60}")
        print(f"  {text}")
        print('='*60)

    def print_step(self, text: str):
        """Print step"""
        print(f"📋 {text}")

    def print_success(self, text: str):
        """Print success message"""
        print(f"✅ {text}")

    def print_error(self, text: str):
        """Print error message"""
        print(f"❌ {text}")
        self.issues.append(text)

    def print_warning(self, text: str):
        """Print warning message"""
        print(f"⚠️  {text}")
        self.warnings.append(text)

    def check_python_version(self) -> bool:
        """Verify Python version"""
        self.print_step("Checking Python version...")

        version = sys.version_info
        if version.major == 3 and version.minor >= 8:
            self.print_success(f"Python {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            self.print_error(f"Python 3.8+ required, found {version.major}.{version.minor}")
            return False

    def check_venv(self) -> bool:
        """Ensure virtual environment exists"""
        self.print_step("Checking virtual environment...")

        if not self.venv_path.exists():
            self.print_warning("Virtual environment not found")
            self.print_step("Creating virtual environment...")

            try:
                subprocess.run(
                    [sys.executable, "-m", "venv", str(self.venv_path)],
                    check=True,
                    capture_output=True
                )
                self.print_success("Virtual environment created")
                return True
            except subprocess.CalledProcessError as e:
                self.print_error(f"Failed to create venv: {e}")
                return False
        else:
            self.print_success("Virtual environment exists")
            return True

    def install_dependencies(self) -> bool:
        """Install all required dependencies"""
        self.print_step("Installing dependencies...")

        pip = self.venv_path / "bin" / "pip"
        requirements = self.project_root / "requirements.txt"

        if not requirements.exists():
            self.print_error("requirements.txt not found")
            return False

        try:
            # Upgrade pip first
            subprocess.run(
                [str(pip), "install", "--upgrade", "pip"],
                check=True,
                capture_output=True
            )

            # Install requirements
            result = subprocess.run(
                [str(pip), "install", "-r", str(requirements)],
                check=True,
                capture_output=False  # Show output
            )

            self.print_success("Dependencies installed")
            return True

        except subprocess.CalledProcessError as e:
            self.print_error(f"Failed to install dependencies: {e}")
            return False

    def verify_dependencies(self) -> bool:
        """Verify critical dependencies are installed"""
        self.print_step("Verifying dependencies...")

        pip = self.venv_path / "bin" / "pip"

        critical_packages = [
            'flask',
            'requests',
            'python-dotenv',
            'phonenumbers'
        ]

        optional_packages = [
            'chromadb',
            'sentence-transformers',
            'docker'
        ]

        try:
            result = subprocess.run(
                [str(pip), "list"],
                capture_output=True,
                text=True,
                check=True
            )

            installed = result.stdout.lower()

            # Check critical packages
            all_critical_ok = True
            for pkg in critical_packages:
                if pkg.lower() in installed:
                    self.print_success(f"{pkg} installed")
                else:
                    self.print_error(f"{pkg} NOT installed")
                    all_critical_ok = False

            # Check optional packages
            for pkg in optional_packages:
                if pkg.lower() in installed:
                    self.print_success(f"{pkg} installed (optional)")
                else:
                    self.print_warning(f"{pkg} not installed (optional - advanced features disabled)")

            return all_critical_ok

        except subprocess.CalledProcessError as e:
            self.print_error(f"Failed to verify dependencies: {e}")
            return False

    def check_model_exists(self) -> bool:
        """Check if GGUF model is downloaded"""
        self.print_step("Checking for GGUF model...")

        model_dir = self.project_root / "llama.cpp" / "models"

        if not model_dir.exists():
            self.print_error("llama.cpp/models directory not found")
            return False

        gguf_files = list(model_dir.glob("*.gguf"))

        if not gguf_files:
            self.print_error("No GGUF model found in llama.cpp/models/")
            print("\n   📥 To download a model:")
            print("   1. Visit https://huggingface.co/models")
            print("   2. Search for 'Qwen2.5-Coder GGUF'")
            print("   3. Download Q4_K_M quantization")
            print("   4. Place in llama.cpp/models/")
            return False

        model_name = gguf_files[0].name
        model_size = gguf_files[0].stat().st_size / (1024**3)  # GB

        self.print_success(f"Model found: {model_name} ({model_size:.1f} GB)")
        return True

    def check_config(self) -> bool:
        """Validate configuration"""
        self.print_step("Checking configuration...")

        env_file = self.project_root / ".env"

        if not env_file.exists():
            self.print_warning("No .env file found")

            example = self.project_root / ".env.example"
            if example.exists():
                self.print_step("Copying from .env.example...")
                shutil.copy(example, env_file)
                self.print_success("Created .env file")

                print("\n   ⚙️  Edit .env to add your API keys:")
                print("   - ANTHROPIC_API_KEY (for Claude consultant agent)")
                print("   - OPENAI_API_KEY (for GPT consultant agent)")
            else:
                self.print_error("No .env.example found")
                return False
        else:
            self.print_success(".env file exists")

        return True

    def check_llama_cpp_built(self) -> bool:
        """Check if llama.cpp is built"""
        self.print_step("Checking llama.cpp build...")

        llama_server = self.project_root / "llama.cpp" / "build" / "bin" / "llama-server"

        # Try alternate location
        if not llama_server.exists():
            llama_server = self.project_root / "llama.cpp" / "llama-server"

        if not llama_server.exists():
            self.print_warning("llama.cpp not built")
            print("\n   🔨 To build llama.cpp:")
            print("   cd llama.cpp")
            print("   mkdir build && cd build")
            print("   cmake ..")
            print("   make -j$(nproc)")
            return False

        self.print_success("llama.cpp is built")
        return True

    def check_pkn_control(self) -> bool:
        """Verify pkn_control.sh exists and is executable"""
        self.print_step("Checking pkn_control.sh...")

        control_script = self.project_root / "pkn_control.sh"

        if not control_script.exists():
            self.print_error("pkn_control.sh not found")
            return False

        if not os.access(control_script, os.X_OK):
            self.print_warning("pkn_control.sh not executable")
            self.print_step("Making executable...")
            control_script.chmod(0o755)
            self.print_success("Made pkn_control.sh executable")

        self.print_success("pkn_control.sh ready")
        return True

    def run_full_setup(self) -> bool:
        """Run complete setup process"""
        self.print_header("PKN Self-Setup Starting")

        all_ok = True

        # 1. Python version
        self.print_header("Step 1: Python Environment")
        all_ok &= self.check_python_version()

        # 2. Virtual environment
        self.print_header("Step 2: Virtual Environment")
        all_ok &= self.check_venv()

        # 3. Dependencies
        if all_ok:
            self.print_header("Step 3: Dependencies")
            self.install_dependencies()
            all_ok &= self.verify_dependencies()

        # 4. Configuration
        self.print_header("Step 4: Configuration")
        all_ok &= self.check_config()

        # 5. llama.cpp
        self.print_header("Step 5: LLM Infrastructure")
        has_llama = self.check_llama_cpp_built()
        has_model = self.check_model_exists()

        # 6. Control script
        self.print_header("Step 6: Control Scripts")
        all_ok &= self.check_pkn_control()

        # Final summary
        self.print_header("Setup Summary")

        if self.issues:
            print("\n❌ Issues Found:")
            for issue in self.issues:
                print(f"   • {issue}")

        if self.warnings:
            print("\n⚠️  Warnings:")
            for warning in self.warnings:
                print(f"   • {warning}")

        print("\n" + "="*60)

        if all_ok and has_llama and has_model:
            print("✅ PKN is fully configured and ready to use!")
            print("\n🚀 Start services with:")
            print("   ./pkn_control.sh start-all")
            print("\n💡 Test health with:")
            print("   python3 pkn_health.py --once")
            return True
        elif all_ok:
            print("⚠️  PKN is partially configured")
            print("   Some optional features may not work")
            print("\n   See warnings above for details")
            return False
        else:
            print("❌ Setup incomplete - see issues above")
            return False


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='PKN Self-Setup')
    parser.add_argument(
        '--project-root',
        type=str,
        default='/home/gh0st/pkn',
        help='PKN project root directory'
    )

    args = parser.parse_args()

    setup = PKNSetup(args.project_root)
    success = setup.run_full_setup()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
