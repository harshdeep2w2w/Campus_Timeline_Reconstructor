import os
from flask import Flask
from config import Config
from database.db import init_app


def create_app(test_config=None):
    """
    Application factory pattern for Flask application.
    Initializes configuration, ensures required directories exist,
    attaches database lifecycle hooks, and registers route blueprints.
    """
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=os.path.join(Config.BASE_DIR, 'templates'),
        static_folder=os.path.join(Config.BASE_DIR, 'static')
    )
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)

    init_app(app)

    from routes.pages import pages_bp
    from routes.api import api_bp
    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    return app


if __name__ == '__main__':
    app = create_app()
    print('\n=== Campus Network Attack - Timeline Reconstructor ===')
    print('Starting server at http://127.0.0.1:5000')
    print('Press Ctrl+C to stop\n')
    app.run(debug=True, host='127.0.0.1', port=5000)
