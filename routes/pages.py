from flask import Blueprint, render_template, redirect, url_for

pages_bp = Blueprint('pages', __name__)


@pages_bp.route('/')
def index():
    """Redirect home route directly to the interactive dashboard."""
    return redirect(url_for('pages.dashboard'))


@pages_bp.route('/dashboard')
def dashboard():
    """Render executive overview dashboard."""
    return render_template('dashboard.html', active_page='dashboard')


@pages_bp.route('/upload')
def upload():
    """Render file upload and dataset ingestion page."""
    return render_template('upload.html', active_page='upload')


@pages_bp.route('/timeline')
def timeline():
    """Render interactive event timeline reconstruction interface."""
    return render_template('timeline.html', active_page='timeline')


@pages_bp.route('/network-graph')
def network_graph():
    """Render interactive network node-link graph visualization."""
    return render_template('network_graph.html', active_page='network_graph')


@pages_bp.route('/alerts')
def alerts():
    """Render threat detection alerts management view."""
    return render_template('alerts.html', active_page='alerts')


@pages_bp.route('/investigations')
def investigations():
    """Render list of ongoing and historical case investigations."""
    return render_template('investigations.html', active_page='investigations')


@pages_bp.route('/investigations/<int:id>')
def investigation_detail(id: int):
    """Render detailed view for an individual incident investigation."""
    return render_template('investigation_detail.html', active_page='investigations', investigation_id=id)


@pages_bp.route('/reports')
def reports():
    """Render reporting and forensic evidence export page."""
    return render_template('reports.html', active_page='reports')


@pages_bp.route('/datasets')
def datasets():
    """Render dataset inventory and management view."""
    return render_template('datasets.html', active_page='datasets')


@pages_bp.route('/settings')
def settings():
    """Render system settings and detection threshold configuration."""
    return render_template('settings.html', active_page='settings')
