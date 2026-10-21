/**
 * Campus Network Attack – Timeline Reconstructor
 * Shared Utilities & Application State Manager (main.js)
 */

// Application namespace
window.CTR = window.CTR || {};

// Dataset Storage Key
CTR.STORAGE_DATASET_KEY = 'ctr_selected_dataset_id';

/**
 * Get current active dataset ID from localStorage
 */
CTR.getCurrentDatasetId = function() {
    const stored = localStorage.getItem(CTR.STORAGE_DATASET_KEY);
    if (stored && stored !== 'null' && stored !== 'undefined') {
        const parsed = parseInt(stored, 10);
        return isNaN(parsed) ? null : parsed;
    }
    return null;
};

/**
 * Set active dataset ID and optionally dispatch change event
 */
CTR.setCurrentDatasetId = function(datasetId, triggerEvent = true) {
    if (datasetId === null || datasetId === undefined || datasetId === '') {
        localStorage.removeItem(CTR.STORAGE_DATASET_KEY);
    } else {
        localStorage.setItem(CTR.STORAGE_DATASET_KEY, datasetId.toString());
    }

    // Sync select elements across the DOM
    const selects = document.querySelectorAll('#globalDatasetSelect, #sidebarDatasetSelect');
    selects.forEach(select => {
        if (select) {
            select.value = datasetId ? datasetId.toString() : '';
        }
    });

    if (triggerEvent) {
        const event = new CustomEvent('datasetChanged', {
            detail: { datasetId: datasetId ? parseInt(datasetId, 10) : null }
        });
        document.dispatchEvent(event);
    }
};

/**
 * Universal API fetch wrapper with JSON handling and robust error messaging
 */
CTR.apiCall = async function(url, options = {}) {
    try {
        const fetchOptions = { credentials: 'same-origin', ...options };

        // Auto add Content-Type for JSON payloads if body is not FormData
        if (fetchOptions.body && !(fetchOptions.body instanceof FormData)) {
            fetchOptions.headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...(fetchOptions.headers || {})
            };
            if (typeof fetchOptions.body === 'object') {
                fetchOptions.body = JSON.stringify(fetchOptions.body);
            }
        }

        const response = await fetch(url, fetchOptions);

        // Check if response is file download
        const disposition = response.headers.get('Content-Disposition');
        const contentType = response.headers.get('Content-Type') || '';
        
        if (disposition && disposition.indexOf('attachment') !== -1 || contentType.includes('text/csv') || contentType.includes('application/pdf')) {
            if (!response.ok) {
                throw new Error(`File download failed with status ${response.status}`);
            }
            return await response.blob();
        }

        let data = null;
        if (contentType.includes('application/json')) {
            data = await response.json();
        } else {
            const text = await response.text();
            try {
                data = JSON.parse(text);
            } catch (e) {
                data = text;
            }
        }

        if (!response.ok) {
            const errorMsg = (data && data.error) || (data && data.message) || `HTTP ${response.status}: ${response.statusText}`;
            const err = new Error(errorMsg);
            err.status = response.status;
            err.data = data;
            throw err;
        }

        return data;
    } catch (error) {
        console.error(`API Call failed [${url}]:`, error);
        throw error;
    }
};

/**
 * Show Toast Notification (using Bootstrap Toast component)
 */
CTR.showToast = function(message, type = 'info', title = null) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    let icon = 'bi-info-circle';
    let typeClass = 'toast-info';
    let defaultTitle = 'Notification';

    if (type === 'success') {
        icon = 'bi-check-circle-fill text-success';
        typeClass = 'toast-success';
        defaultTitle = 'Success';
    } else if (type === 'error' || type === 'danger') {
        icon = 'bi-exclamation-triangle-fill text-danger';
        typeClass = 'toast-danger';
        defaultTitle = 'System Alert';
    } else if (type === 'warning') {
        icon = 'bi-exclamation-circle-fill text-warning';
        typeClass = 'toast-warning';
        defaultTitle = 'Warning';
    }

    const toastId = 'toast_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    const toastHtml = `
        <div id="${toastId}" class="toast soc-toast ${typeClass}" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-transparent border-0 pb-0 pt-2 px-3 text-light">
                <i class="bi ${icon} me-2"></i>
                <strong class="me-auto text-uppercase small">${title || defaultTitle}</strong>
                <small class="text-secondary">Just now</small>
                <button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body pt-1 pb-2 px-3 text-light small">
                ${message}
            </div>
        </div>
    `;

    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastEl = document.getElementById(toastId);
    if (toastEl && window.bootstrap) {
        const bsToast = new bootstrap.Toast(toastEl, { delay: 4500 });
        bsToast.show();
        toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
    }
};

/**
 * Format ISO timestamp into clean SOC date-time representation
 */
CTR.formatTimestamp = function(isoStr) {
    if (!isoStr) return '--';
    try {
        const date = new Date(isoStr);
        if (isNaN(date.getTime())) return isoStr;
        // Format: YYYY-MM-DD HH:mm:ss
        const pad = (n) => String(n).padStart(2, '0');
        const year = date.getFullYear();
        const month = pad(date.getMonth() + 1);
        const day = pad(date.getDate());
        const hours = pad(date.getHours());
        const minutes = pad(date.getMinutes());
        const seconds = pad(date.getSeconds());
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    } catch (e) {
        return isoStr;
    }
};

/**
 * Format IP address with optional timeline filter link
 */
CTR.formatIP = function(ip, withLink = false) {
    if (!ip) return '<span class="text-muted">N/A</span>';
    const cleanIP = String(ip).trim();
    if (withLink) {
        return `<span class="ip-badge"><a href="/timeline?src_ip=${encodeURIComponent(cleanIP)}" class="ip-link" title="Filter events for ${cleanIP}">${cleanIP}</a></span>`;
    }
    return `<span class="ip-badge">${cleanIP}</span>`;
};

/**
 * Generate HTML severity badge
 */
CTR.severityBadge = function(severity) {
    const sev = (severity || 'informational').toLowerCase();
    const label = sev.charAt(0).toUpperCase() + sev.slice(1);
    let iconClass = 'bi-info-circle';
    if (sev === 'critical') iconClass = 'bi-fire';
    else if (sev === 'high') iconClass = 'bi-exclamation-triangle-fill';
    else if (sev === 'medium') iconClass = 'bi-exclamation-circle';
    else if (sev === 'low') iconClass = 'bi-shield-check';

    return `<span class="badge badge-severity badge-${sev}">
        <i class="bi ${iconClass}"></i> ${label}
    </span>`;
};

/**
 * Generate HTML status badge
 */
CTR.statusBadge = function(status) {
    const st = (status || 'open').toLowerCase().replace(' ', '_');
    const label = st.replace(/_/g, ' ').toUpperCase();
    return `<span class="badge badge-status badge-status-${st}">${label}</span>`;
};

/**
 * Render loading spinner inside target container
 */
CTR.showLoading = function(container, message = 'Loading SOC data...') {
    if (!container) return;
    container.style.position = 'relative';
    container.dataset.originalMinHeight = container.style.minHeight;
    if (container.offsetHeight < 120) {
        container.style.minHeight = '140px';
    }
    const existing = container.querySelector('.soc-loading-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'soc-loading-overlay';
    overlay.innerHTML = `
        <div class="soc-spinner-cyan mb-2"></div>
        <div class="small text-cyan fw-medium tracking-wider">${message}</div>
    `;
    container.appendChild(overlay);
};

/**
 * Remove loading spinner from target container
 */
CTR.hideLoading = function(container) {
    if (!container) return;
    const overlay = container.querySelector('.soc-loading-overlay');
    if (overlay) overlay.remove();
    if (container.dataset.originalMinHeight !== undefined) {
        container.style.minHeight = container.dataset.originalMinHeight;
    }
};

/**
 * Render standard empty state in container
 */
CTR.showEmptyState = function(container, message, actionText = null, actionCallback = null) {
    if (!container) return;
    const btnHtml = actionText ? `<button class="btn btn-sm soc-btn-outline-cyan mt-3 empty-state-btn">${actionText}</button>` : '';
    container.innerHTML = `
        <div class="soc-empty-state">
            <div class="empty-icon-circle">
                <i class="bi bi-inbox"></i>
            </div>
            <h5 class="text-light mb-1">No Data Available</h5>
            <p class="text-secondary small mb-0" style="max-width: 420px; margin: 0 auto;">${message}</p>
            ${btnHtml}
        </div>
    `;
    if (actionText && typeof actionCallback === 'function') {
        const btn = container.querySelector('.empty-state-btn');
        if (btn) btn.addEventListener('click', actionCallback);
    }
};

/**
 * Debounce helper for search and filter inputs
 */
CTR.debounce = function(fn, delay = 300) {
    let timer = null;
    return function(...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
};

/**
 * Load available datasets from /api/datasets and populate dropdowns
 */
CTR.loadDatasets = async function() {
    try {
        const datasets = await CTR.apiCall('/api/datasets');
        const selects = document.querySelectorAll('#globalDatasetSelect, #sidebarDatasetSelect');
        const currentActiveId = CTR.getCurrentDatasetId();
        let selectedId = null;

        selects.forEach(select => {
            select.innerHTML = '';
            if (!datasets || datasets.length === 0) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = 'No datasets available';
                select.appendChild(opt);
                select.disabled = true;
            } else {
                select.disabled = false;
                datasets.forEach(ds => {
                    const opt = document.createElement('option');
                    opt.value = ds.id.toString();
                    opt.textContent = `${ds.name || 'Dataset #' + ds.id} (${ds.record_count || 0} events)`;
                    if (currentActiveId && currentActiveId === ds.id) {
                        opt.selected = true;
                        selectedId = ds.id;
                    }
                    select.appendChild(opt);
                });
            }
        });

        const sidebarInfo = document.getElementById('sidebarDatasetInfo');

        if (datasets && datasets.length > 0) {
            // If current selection is not valid, pick the first dataset
            if (!selectedId) {
                selectedId = datasets[0].id;
                CTR.setCurrentDatasetId(selectedId, true);
            }
            const activeDs = datasets.find(d => d.id === selectedId) || datasets[0];
            if (sidebarInfo) {
                sidebarInfo.textContent = `${activeDs.record_count || 0} Events`;
            }
        } else {
            CTR.setCurrentDatasetId(null, true);
            if (sidebarInfo) {
                sidebarInfo.textContent = 'No Logs';
            }
        }

        // Also update alert counts
        CTR.refreshAlertNotifications();

        return datasets;
    } catch (error) {
        console.error('Failed to load datasets:', error);
        const sidebarInfo = document.getElementById('sidebarDatasetInfo');
        if (sidebarInfo) sidebarInfo.textContent = 'Offline';
        return [];
    }
};

/**
 * Load Sample Synthetic Dataset via API
 */
CTR.loadSampleData = async function() {
    try {
        CTR.showToast('Generating synthetic campus network attack telemetry...', 'info', 'Dataset Generator');
        const result = await CTR.apiCall('/api/datasets/load-sample', { method: 'POST' });
        CTR.showToast(result.message || 'Sample campus dataset loaded successfully!', 'success', 'Telemetry Loaded');
        await CTR.loadDatasets();
        if (result.dataset_id) {
            CTR.setCurrentDatasetId(result.dataset_id, true);
        }
    } catch (error) {
        CTR.showToast('Failed to load sample dataset: ' + error.message, 'error', 'Error');
    }
};

/**
 * Refresh Recent Alerts in topbar notification dropdown and update badge count
 */
CTR.refreshAlertNotifications = async function() {
    const datasetId = CTR.getCurrentDatasetId();
    const alertDot = document.getElementById('alertNotificationDot');
    const sidebarCount = document.getElementById('sidebarAlertCount');
    const notifList = document.getElementById('notificationList');
    if (!datasetId) {
        if (alertDot) alertDot.style.display = 'none';
        if (sidebarCount) sidebarCount.style.display = 'none';
        return;
    }

    try {
        const alerts = await CTR.apiCall(`/api/dashboard/recent-alerts?dataset_id=${datasetId}&limit=5`);
        if (alerts && alerts.length > 0) {
            if (alertDot) alertDot.style.display = 'block';
            if (sidebarCount) {
                sidebarCount.style.display = 'inline-block';
                sidebarCount.textContent = alerts.length;
            }

            if (notifList) {
                let html = `
                    <div class="dropdown-header text-uppercase text-secondary fw-semibold border-bottom border-secondary-subtle pb-2 mb-2 d-flex justify-content-between align-items-center">
                        <span>Recent Active Alerts</span>
                        <a href="/alerts" class="text-cyan small">View All</a>
                    </div>
                `;
                alerts.forEach(a => {
                    html += `
                        <a href="/alerts" class="dropdown-item p-2 mb-1 rounded soc-card text-decoration-none">
                            <div class="d-flex align-items-center justify-content-between mb-1">
                                <span class="badge badge-severity badge-${(a.severity||'info').toLowerCase()}">${(a.severity||'').toUpperCase()}</span>
                                <span class="fs-xs text-muted font-monospace">${CTR.formatTimestamp(a.timestamp)}</span>
                            </div>
                            <div class="small fw-semibold text-light text-truncate">${a.rule_name || a.reason || 'Security Alert'}</div>
                            <div class="fs-xs text-secondary font-monospace">${a.src_ip || 'Any'} &rarr; ${a.dst_ip || 'Any'}</div>
                        </a>
                    `;
                });
                notifList.innerHTML = html;
            }
        } else {
            if (alertDot) alertDot.style.display = 'none';
            if (sidebarCount) sidebarCount.style.display = 'none';
            if (notifList) {
                notifList.innerHTML = `
                    <div class="dropdown-header text-uppercase text-secondary fw-semibold border-bottom border-secondary-subtle pb-2 mb-2">
                        Recent Active Alerts
                    </div>
                    <div class="text-center py-3 text-secondary small">
                        <i class="bi bi-shield-check fs-4 d-block mb-1 text-success"></i>
                        No active alerts pending
                    </div>
                `;
            }
        }
    } catch (e) {
        // Silent fail for notification check
    }
};

/**
 * Initialize event listeners on DOMContentLoaded
 */
document.addEventListener('DOMContentLoaded', () => {
    // 1. Mobile Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarBackdrop = document.getElementById('sidebarBackdrop');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            document.body.classList.toggle('sidebar-open');
        });
    }
    if (sidebarBackdrop) {
        sidebarBackdrop.addEventListener('click', () => {
            document.body.classList.remove('sidebar-open');
        });
    }

    // 2. Global Dataset Select Listeners
    const globalSelect = document.getElementById('globalDatasetSelect');
    const sidebarSelect = document.getElementById('sidebarDatasetSelect');

    const handleSelectChange = (e) => {
        const newId = e.target.value ? parseInt(e.target.value, 10) : null;
        CTR.setCurrentDatasetId(newId, true);
    };

    if (globalSelect) globalSelect.addEventListener('change', handleSelectChange);
    if (sidebarSelect) sidebarSelect.addEventListener('change', handleSelectChange);

    // 3. Quick Load Sample Buttons
    const quickSampleBtn = document.getElementById('quickSampleBtn');
    const sidebarSampleBtn = document.getElementById('sidebarSampleBtn');
    if (quickSampleBtn) quickSampleBtn.addEventListener('click', CTR.loadSampleData);
    if (sidebarSampleBtn) sidebarSampleBtn.addEventListener('click', CTR.loadSampleData);

    // 4. Sidebar Refresh Button
    const refreshBtn = document.getElementById('sidebarRefreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            refreshBtn.classList.add('rotate-spin');
            await CTR.loadDatasets();
            CTR.showToast('Dataset index refreshed', 'info');
            refreshBtn.classList.remove('rotate-spin');
        });
    }

    // 5. Initialize Bootstrap Tooltips
    if (window.bootstrap && bootstrap.Tooltip) {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltipTriggerList.forEach(el => new bootstrap.Tooltip(el));
    }

    // 6. Initial dataset load
    CTR.loadDatasets();
});
