import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Detect Vercel serverless environment (only /tmp is writable)
IS_VERCEL = os.environ.get('VERCEL', False)


class Config:
    """Application configuration for Campus Network Attack Timeline Reconstructor."""
    BASE_DIR = BASE_DIR
    SECRET_KEY = os.environ.get('SECRET_KEY', 'campus-timeline-dev-key-2024')

    if IS_VERCEL:
        DATABASE = '/tmp/campus_timeline.db'
        UPLOAD_FOLDER = '/tmp/uploads'
    else:
        DATABASE = os.path.join(BASE_DIR, 'instance', 'campus_timeline.db')
        UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'csv', 'json', 'log', 'tsv'}
    REPEATED_CONNECTION_THRESHOLD = 10
    PORT_SCAN_THRESHOLD = 5
    TRAFFIC_BURST_THRESHOLD = 50
    TIME_WINDOW_SECONDS = 300
    DNS_QUERY_THRESHOLD = 20
    SUSPICIOUS_PORTS = [4444, 5555, 6666, 6667, 8888, 9999, 1337, 31337, 12345]
