import os
import sys
from urllib.parse import parse_qs, urlencode

# Ensure project root directory is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app

flask_app = create_app()


class VercelPathFix:
    """WSGI middleware to normalize PATH_INFO forwarded by Vercel serverless functions."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # 1. Check if passed via __path query param from vercel.json rewrite
        query_string = environ.get('QUERY_STRING', '')
        qs = parse_qs(query_string, keep_blank_values=True)

        if '__path' in qs:
            original_path = qs.pop('__path')[0]
            if not original_path.startswith('/'):
                original_path = '/' + original_path
            environ['PATH_INFO'] = original_path
            environ['QUERY_STRING'] = urlencode(qs, doseq=True)
        elif environ.get('HTTP_X_MATCHED_PATH'):
            matched = environ.get('HTTP_X_MATCHED_PATH', '').split('?')[0]
            if matched and not matched.startswith('/api/index'):
                environ['PATH_INFO'] = matched
        else:
            path = environ.get('PATH_INFO', '')
            for prefix in ['/api/index.py', '/api/index']:
                if path.startswith(prefix):
                    environ['PATH_INFO'] = path[len(prefix):] or '/'
                    break

        return self.wsgi_app(environ, start_response)


flask_app.wsgi_app = VercelPathFix(flask_app.wsgi_app)
app = flask_app
