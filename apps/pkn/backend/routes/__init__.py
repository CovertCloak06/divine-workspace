"""
PKN Backend Routes
Registers all Flask blueprints for modular route handling
"""

def register_all_routes(app):
    """Register all route blueprints with the Flask app"""

    # Import blueprints (imported here to avoid circular imports)
    from .health import health_bp
    from .phonescan import phonescan_bp
    from .network import network_bp
    from .osint import osint_bp
    from .files import files_bp
    from .editor import editor_bp
    from .images import images_bp
    from .models import models_bp
    from .chat import chat_bp
    from .code import code_bp
    from .multi_agent import multi_agent_bp
    from .rag import rag_bp
    from .planning import planning_bp
    from .delegation import delegation_bp
    from .sandbox import sandbox_bp
    from .metrics import metrics_bp
    from .session import session_bp

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(phonescan_bp, url_prefix='/api')
    app.register_blueprint(network_bp, url_prefix='/api/network')
    app.register_blueprint(osint_bp, url_prefix='/api/osint')
    app.register_blueprint(files_bp, url_prefix='/api/files')
    app.register_blueprint(editor_bp, url_prefix='/api/editor')
    app.register_blueprint(images_bp, url_prefix='/api')
    app.register_blueprint(models_bp, url_prefix='/api/models')
    app.register_blueprint(chat_bp, url_prefix='/api')
    app.register_blueprint(code_bp, url_prefix='/api/code')
    app.register_blueprint(multi_agent_bp, url_prefix='/api/multi-agent')
    app.register_blueprint(rag_bp, url_prefix='/api/rag')
    app.register_blueprint(planning_bp, url_prefix='/api/planning')
    app.register_blueprint(delegation_bp, url_prefix='/api/delegation')
    app.register_blueprint(sandbox_bp, url_prefix='/api/sandbox')
    app.register_blueprint(metrics_bp, url_prefix='/api/metrics')
    app.register_blueprint(session_bp, url_prefix='/api/session')

    print(f"✅ Registered {17} route blueprints")
