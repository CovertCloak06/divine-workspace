"""
Invoke tasks for automation
Better than shell scripts - Python-based task automation

Usage:
    invoke --list              # List all tasks
    invoke build               # Build project
    invoke deploy              # Deploy to production
    invoke setup               # Setup project
"""

from invoke import task
import os
import shutil


@task
def clean(c):
    """Clean build artifacts and caches"""
    print("🧹 Cleaning build artifacts...")
    dirs_to_remove = ['dist', 'build', 'coverage', 'playwright-report', '.nyc_output', '__pycache__']

    for dir_name in dirs_to_remove:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"   Removed {dir_name}/")

    # Remove log files
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.log'):
                os.remove(os.path.join(root, file))
                print(f"   Removed {file}")

    print("✅ Clean complete!")


@task
def install(c):
    """Install all dependencies"""
    print("📦 Installing dependencies...")
    c.run("npm ci")
    if os.path.exists("requirements.txt"):
        c.run("pip3 install --user -r requirements.txt")
    print("✅ Installation complete!")


@task
def dev(c):
    """Start development server"""
    print("🚀 Starting development server...")
    c.run("npm run dev")


@task
def build(c):
    """Build for production"""
    print("🏗️  Building for production...")
    c.run("npm run build")
    print("✅ Build complete!")


@task
def test(c):
    """Run all tests"""
    print("🧪 Running tests...")
    c.run("npm run test")
    c.run("npm run test:e2e")
    print("✅ Tests complete!")


@task
def lint(c, fix=False):
    """Lint code (use --fix to auto-fix)"""
    print("🔍 Linting code...")
    if fix:
        c.run("npm run lint:fix")
    else:
        c.run("npm run lint")
    print("✅ Lint complete!")


@task
def format_code(c):
    """Format code with Biome"""
    print("💅 Formatting code...")
    c.run("npm run format")
    print("✅ Format complete!")


@task
def docker_build(c):
    """Build Docker image"""
    print("🐳 Building Docker image...")
    c.run("docker-compose build app")
    print("✅ Docker build complete!")


@task
def docker_up(c):
    """Start Docker containers"""
    print("🐳 Starting Docker containers...")
    c.run("docker-compose up -d app")
    print("✅ Containers started!")


@task
def docker_down(c):
    """Stop Docker containers"""
    print("🐳 Stopping Docker containers...")
    c.run("docker-compose down")
    print("✅ Containers stopped!")


@task
def security(c):
    """Run security audits"""
    print("🔒 Running security audit...")
    c.run("npm audit --production", warn=True)
    c.run("pre-commit run detect-secrets --all-files", warn=True)
    print("✅ Security audit complete!")


@task
def ci(c):
    """Run full CI check locally"""
    print("🤖 Running CI checks...")
    lint(c)
    c.run("npm run format:check")
    test(c)
    build(c)
    print("✅ CI checks passed!")


@task
def setup(c):
    """Initial project setup"""
    print("⚙️  Setting up project...")
    install(c)
    c.run("pre-commit install")
    c.run("pre-commit install --hook-type commit-msg")
    print("✅ Setup complete! Run 'invoke dev' to start developing.")


@task
def deploy_vercel(c):
    """Deploy to Vercel"""
    print("🚀 Deploying to Vercel...")
    c.run("npm run build")
    c.run("vercel deploy --prod")
    print("✅ Deployed to Vercel!")


@task
def deploy_netlify(c):
    """Deploy to Netlify"""
    print("🚀 Deploying to Netlify...")
    c.run("npm run build")
    c.run("netlify deploy --prod")
    print("✅ Deployed to Netlify!")


@task
def health(c):
    """Check project health"""
    print("📊 Project Health Check\n")

    checks = [
        ("Node.js", "node --version"),
        ("npm", "npm --version"),
        ("Python", "python3 --version"),
        ("pre-commit", "pre-commit --version"),
        ("task", "task --version"),
        ("invoke", "invoke --version"),
    ]

    for name, cmd in checks:
        try:
            result = c.run(cmd, hide=True)
            version = result.stdout.strip()
            print(f"✅ {name:15} {version}")
        except:
            print(f"❌ {name:15} Not installed")

    print("\n✅ Health check complete!")


@task
def generate_lesson(c, lesson_id, title, category="html"):
    """Generate new lesson from template"""
    print(f"📝 Generating lesson: {lesson_id}...")
    c.run(f"npm run generate:lesson -- {lesson_id} --title '{title}' --category {category}")
    print(f"✅ Lesson {lesson_id} created!")


@task
def lighthouse(c):
    """Run Lighthouse CI"""
    print("🏮 Running Lighthouse CI...")
    c.run("npm run build")
    c.run("npm run lighthouse")
    print("✅ Lighthouse complete!")
