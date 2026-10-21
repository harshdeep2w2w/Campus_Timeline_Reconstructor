# 🛡️ Campus Network Attack – Timeline Reconstructor

> A cybersecurity investigation platform for analyzing campus network logs, correlating events, detecting suspicious activity, and reconstructing attack timelines.

**B.Tech CSE (Cyber Security) Academic Project**

---

## 📋 Table of Contents

- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Prerequisites](#-prerequisites)
- [Installation (Windows)](#-installation-windows)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Usage Guide](#-usage-guide)
- [Running Tests](#-running-tests)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **SOC Dashboard** | Real-time statistics, charts, alert summaries, and host activity overview |
| **Log Upload & Parsing** | Import CSV, JSON, and Zeek-format log files with automatic validation |
| **Timeline Reconstruction** | Chronological event display with filters for IP, protocol, severity, and time range |
| **Event Correlation Engine** | Identifies related events via shared hosts, DNS chains, scanning patterns, and traffic bursts |
| **Suspicious Activity Detection** | Rule-based detection for port scanning, network sweeps, DNS anomalies, and more |
| **Interactive Network Graph** | Cytoscape.js visualization of host communications with search, filtering, and detail panels |
| **Investigation Workspace** | Create cases, attach events and hosts, document findings, and track investigation status |
| **Report Generation** | Export to CSV, JSON, or professional PDF incident reports |
| **Synthetic Dataset** | Built-in campus network simulation with realistic attack scenarios for demonstration |
| **Dark SOC Theme** | Professional Security Operations Center interface with responsive design |

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.9+, Flask 3.0 |
| **Database** | SQLite (built-in `sqlite3` module) |
| **Data Processing** | Pandas |
| **PDF Reports** | ReportLab |
| **Frontend** | HTML5, CSS3, JavaScript (ES6+) |
| **UI Framework** | Bootstrap 5.3 |
| **Charts** | Chart.js 4.4 |
| **Network Graph** | Cytoscape.js 3.27 |
| **Icons** | Bootstrap Icons 1.11 |
| **Testing** | pytest |

---

## 📦 Prerequisites

- **Operating System:** Windows 10 or Windows 11
- **Python:** Version 3.9 or higher ([Download Python](https://www.python.org/downloads/))
- **Editor:** Visual Studio Code (recommended)
- **Browser:** Chrome, Firefox, or Edge (modern version)

> [!NOTE]
> During Python installation, make sure to check **"Add Python to PATH"**. This allows you to run `python` from any terminal.

---

## 🚀 Installation (Windows)

### Step 1: Open the Project in VS Code

Open Visual Studio Code, then open the `Campus_Timeline_Reconstructor` folder:

```
File → Open Folder → Select Campus_Timeline_Reconstructor
```

### Step 2: Open the Terminal

Press `` Ctrl+` `` (backtick) to open the integrated terminal in VS Code.

### Step 3: Create a Virtual Environment

```powershell
python -m venv .venv
```

> If `python` is not recognized, try `py -m venv .venv` instead.

### Step 4: Activate the Virtual Environment

```powershell
.venv\Scripts\activate
```

You should see `(.venv)` appear at the beginning of your terminal prompt.

### Step 5: Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### Step 6: Start the Application

```powershell
python app.py
```

You should see:

```
=== Campus Network Attack - Timeline Reconstructor ===
Starting server at http://127.0.0.1:5000
Press Ctrl+C to stop
```

### Step 7: Open in Browser

Open your web browser and navigate to:

```
http://127.0.0.1:5000
```

The database initializes automatically on first run. No additional setup is required.

---

## 📖 Quick Start

Once the application is running, follow these steps to explore all features:

### 1. Load Sample Data

- Go to **Datasets** from the sidebar
- Click **"Load Synthetic Campus Dataset"**
- This loads ~360 synthetic network events including DHCP, DNS, HTTP, TLS connections, plus simulated attack activity

### 2. Explore the Dashboard

- Navigate to **Dashboard**
- View total events, host counts, suspicious activity alerts, and severity breakdown
- Examine the Activity Over Time chart and Protocol Distribution
- Review the Top Communicating Hosts and Recent Alerts

### 3. Investigate the Timeline

- Go to **Timeline**
- Browse events in chronological order
- Use filters to narrow by IP address, protocol, severity, or time range
- Click any event to see full details and correlated events

### 4. Examine the Network Graph

- Open **Network Graph**
- See host-to-host communications visualized as an interactive graph
- Click nodes to view host details, connections, and recent events
- Use layout options (cose, circle, grid) and zoom controls
- Red nodes indicate suspicious hosts

### 5. Review Alerts

- Go to **Alerts**
- Browse detected suspicious activity (port scanning, traffic bursts, DNS anomalies)
- Filter by severity (Critical, High, Medium, Low)
- Click alerts to see evidence and associated events
- Update alert status (Acknowledge, Resolve, False Positive)

### 6. Create an Investigation

- Navigate to **Investigations**
- Click **"New Investigation"**
- Add a title, select the dataset, and set a time window
- Attach relevant events and hosts
- Document your findings and analyst notes

### 7. Generate a Report

- Go to **Reports**
- Select a dataset or investigation
- Export as **CSV**, **JSON**, or generate a **PDF Report**
- The PDF report includes investigation overview, timeline, alerts, and analyst notes

---

## 📁 Project Structure

```
Campus_Timeline_Reconstructor/
│
├── app.py                      # Flask application entry point
├── config.py                   # Application configuration
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── database/                   # Database module
│   ├── __init__.py
│   └── db.py                   # SQLite schema, CRUD operations, query helpers
│
├── parsers/                    # Log file parsers
│   ├── __init__.py
│   ├── csv_parser.py           # CSV/TSV log parser
│   ├── json_parser.py          # JSON & NDJSON parser
│   └── zeek_parser.py          # Zeek tab-separated log parser
│
├── engine/                     # Core analysis engine
│   ├── __init__.py
│   ├── normalizer.py           # Timestamp, IP, port, protocol normalization
│   ├── timeline.py             # Chronological event reconstruction
│   ├── correlator.py           # Event correlation (shared hosts, DNS chains, scans)
│   └── detector.py             # Suspicious activity detection rules
│
├── synthetic/                  # Synthetic data generation
│   ├── __init__.py
│   └── generator.py            # Campus network traffic simulator
│
├── reports/                    # Report generation
│   ├── __init__.py
│   └── generator.py            # CSV, JSON, and PDF report exports
│
├── routes/                     # Flask route blueprints
│   ├── __init__.py
│   ├── pages.py                # HTML page routes
│   └── api.py                  # REST API endpoints
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Base layout (sidebar, navbar, theme)
│   ├── dashboard.html          # SOC dashboard with charts
│   ├── upload.html             # Log file upload page
│   ├── timeline.html           # Event timeline view
│   ├── network_graph.html      # Interactive network graph
│   ├── alerts.html             # Security alerts list
│   ├── investigations.html     # Investigation case list
│   ├── investigation_detail.html # Investigation workspace
│   ├── reports.html            # Report generation page
│   ├── datasets.html           # Dataset management
│   └── settings.html           # Detection threshold settings
│
├── static/                     # Static assets
│   ├── css/
│   │   └── style.css           # SOC dark theme stylesheet
│   └── js/
│       ├── main.js             # Shared utilities and API helpers
│       ├── dashboard.js        # Dashboard charts and stats
│       ├── upload.js           # File upload handling
│       ├── timeline.js         # Timeline rendering and filtering
│       ├── network_graph.js    # Cytoscape.js graph logic
│       ├── investigations.js   # Investigation CRUD and tabs
│       └── reports.js          # Export and download handling
│
├── tests/                      # Automated test suite
│   ├── __init__.py
│   ├── conftest.py             # pytest fixtures
│   ├── test_parsers.py         # Parser tests (CSV, JSON)
│   ├── test_normalizer.py      # Normalization tests
│   ├── test_timeline.py        # Timeline reconstruction tests
│   ├── test_correlator.py      # Correlation engine tests
│   ├── test_detector.py        # Detection rule tests
│   ├── test_reports.py         # Report generation tests
│   └── test_api.py             # API endpoint integration tests
│
├── instance/                   # Auto-created at runtime
│   └── campus_timeline.db      # SQLite database file
│
└── uploads/                    # Auto-created at runtime
    └── (uploaded log files)
```

---

## 🧪 Running Tests

Run the full test suite from the project root:

```powershell
python -m pytest tests/ -v
```

Expected output: **68 tests passed** covering:

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_parsers.py` | 9 | CSV, JSON parsing with valid/invalid/edge cases |
| `test_normalizer.py` | 13 | Timestamps, IPs, ports, protocols, severity, categorization |
| `test_timeline.py` | 6 | Chronological ordering, filters, event details, related events |
| `test_correlator.py` | 8 | Port scans, DNS chains, shared hosts, time windows |
| `test_detector.py` | 9 | All 6 detection rules, custom thresholds, false positive avoidance |
| `test_reports.py` | 7 | CSV/JSON export, PDF generation |
| `test_api.py` | 16 | All REST API endpoints (dashboard, upload, timeline, alerts, investigations, datasets, settings) |

To run a specific test file:

```powershell
python -m pytest tests/test_detector.py -v
```

---

## 📡 API Reference

All API endpoints are prefixed with `/api/`. Below are the main endpoint groups:

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | Aggregated statistics |
| GET | `/api/dashboard/activity-over-time` | Event counts by hour |
| GET | `/api/dashboard/top-hosts` | Most active source/destination IPs |
| GET | `/api/dashboard/protocol-distribution` | Event counts by protocol |
| GET | `/api/dashboard/recent-alerts` | Latest security alerts |

### Upload & Datasets
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload and parse a log file |
| GET | `/api/datasets` | List all datasets |
| POST | `/api/datasets/load-sample` | Load synthetic campus data |
| GET | `/api/datasets/<id>/preview` | Preview dataset records |
| DELETE | `/api/datasets/<id>` | Delete a dataset |

### Timeline & Correlation
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/timeline/events` | Query events with filters |
| GET | `/api/timeline/event/<id>` | Event details with related events |
| GET | `/api/correlation/related/<id>` | Find events related to a specific event |
| GET | `/api/correlation/groups` | Get all correlation groups |

### Network Graph
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/network/graph` | Graph data (nodes and edges) |
| GET | `/api/network/host/<ip>` | Host details with connections |

### Alerts & Investigations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts with filters |
| PATCH | `/api/alerts/<id>` | Update alert status |
| GET/POST | `/api/investigations` | List or create investigations |
| GET/PUT/DELETE | `/api/investigations/<id>` | Manage a specific investigation |
| POST | `/api/investigations/<id>/events` | Add events to investigation |
| POST | `/api/investigations/<id>/hosts` | Add hosts to investigation |

### Reports & Settings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/export/csv` | Download events as CSV |
| GET | `/api/reports/export/json` | Download events as JSON |
| POST | `/api/reports/export/pdf` | Generate PDF incident report |
| GET/PUT | `/api/settings` | View or update detection thresholds |

All endpoints accept an optional `dataset_id` query parameter to scope results.

---

## 🔧 Troubleshooting

### "python" is not recognized

Try using the Python launcher instead:

```powershell
py -m venv .venv
py app.py
```

Or verify Python is in your PATH:

```powershell
python --version
```

If not, reinstall Python and check **"Add Python to PATH"** during installation.

### Port 5000 is already in use

Another application is using port 5000. Either:

1. Stop the other application, or
2. Change the port in `app.py`:

```python
app.run(debug=True, host='127.0.0.1', port=8080)
```

Then open `http://127.0.0.1:8080` in your browser.

### ModuleNotFoundError

Make sure your virtual environment is activated:

```powershell
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

### Database errors

Delete the database file and restart the application to reinitialize:

```powershell
Remove-Item instance\campus_timeline.db
python app.py
```

### Upload fails or file too large

The maximum upload size is 16 MB. Supported formats are `.csv`, `.json`, `.log`, and `.tsv`.

### Charts or graphs not displaying

- Ensure you have an active internet connection (CDN libraries are loaded from the internet)
- Try a different browser or clear the browser cache
- Check the browser's developer console (F12) for JavaScript errors

### Virtual environment won't activate (execution policy error)

If you see a PowerShell execution policy error:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then try activating again:

```powershell
.venv\Scripts\activate
```

---

## ⚠️ Disclaimer

This application is an **academic project** developed for educational purposes.

- All network data included is **synthetic** and does not represent real campus network traffic
- The application does **not** connect to real networks, scan systems, or capture live traffic
- Suspicious activity detection is **rule-based** — flagged indicators are not confirmed attacks
- This tool is designed for **authorized log analysis** of provided data files only
- Do **not** use this tool to scan, exploit, or attack real campus systems

---

## ⚖️ License

This project is developed as an academic submission for B.Tech CSE (Cyber Security).

MIT License — see individual library licenses for third-party dependencies.

---

<p align="center">
  <strong>Campus Network Attack – Timeline Reconstructor</strong><br>
  Built with Python · Flask · SQLite · Chart.js · Cytoscape.js<br>
  B.Tech CSE (Cyber Security) Academic Project
</p>
