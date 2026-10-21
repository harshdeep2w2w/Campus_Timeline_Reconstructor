/**
 * Campus Network Attack – Timeline Reconstructor
 * Reports & Forensic Export Logic (reports.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    const datasetSelect = document.getElementById('reportDatasetSelect');
    const invSelect = document.getElementById('reportInvestigationSelect');
    const timeStartInput = document.getElementById('reportTimeStart');
    const timeEndInput = document.getElementById('reportTimeEnd');
    const severitySelect = document.getElementById('reportSeverity');
    const protocolSelect = document.getElementById('reportProtocol');
    const spinner = document.getElementById('reportLoadingSpinner');
    const statusMsg = document.getElementById('reportStatusMessage');
    const recentList = document.getElementById('recentExportsList');

    const btnPDF = document.getElementById('btnExportPDF');
    const btnCSV = document.getElementById('btnExportCSV');
    const btnJSON = document.getElementById('btnExportJSON');

    /**
     * Load Dropdowns for Datasets and Investigations
     */
    async function initSelectors() {
        try {
            const datasets = await CTR.apiCall('/api/datasets');
            const activeId = CTR.getCurrentDatasetId();

            if (datasets && datasets.length > 0) {
                datasetSelect.innerHTML = datasets.map(d => `
                    <option value="${d.id}" ${activeId === d.id ? 'selected' : ''}>
                        ${d.name || 'Dataset #' + d.id} (${d.record_count || 0} events)
                    </option>
                `).join('');
            } else {
                datasetSelect.innerHTML = '<option value="" disabled selected>No datasets found</option>';
            }

            const investigations = await CTR.apiCall('/api/investigations').catch(() => []);
            if (investigations && investigations.length > 0) {
                invSelect.innerHTML = '<option value="">All Dataset Telemetry (Whole Log)</option>' +
                    investigations.map(inv => `
                        <option value="${inv.id}">Case #${inv.id}: ${inv.title || 'Untitled Case'}</option>
                    `).join('');
            }
        } catch (error) {
            console.error('Failed to initialize report selectors:', error);
        }
    }

    /**
     * Build query string parameters for report filters
     */
    function buildFilterParams() {
        const datasetId = datasetSelect.value ? parseInt(datasetSelect.value, 10) : CTR.getCurrentDatasetId();
        const invId = invSelect.value ? parseInt(invSelect.value, 10) : null;
        const timeStart = timeStartInput.value ? new Date(timeStartInput.value).toISOString() : null;
        const timeEnd = timeEndInput.value ? new Date(timeEndInput.value).toISOString() : null;
        const severity = severitySelect.value;
        const protocol = protocolSelect.value;

        const params = new URLSearchParams();
        if (datasetId) params.append('dataset_id', datasetId.toString());
        if (invId) params.append('investigation_id', invId.toString());
        if (timeStart) params.append('time_start', timeStart);
        if (timeEnd) params.append('time_end', timeEnd);
        if (severity) params.append('severity', severity);
        if (protocol) params.append('protocol', protocol);

        return {
            datasetId,
            invId,
            timeStart,
            timeEnd,
            severity,
            protocol,
            queryString: params.toString()
        };
    }

    function addRecentAuditItem(title, format, desc) {
        if (!recentList) return;
        let badgeClass = 'bg-info-subtle text-info border border-info';
        if (format === 'PDF') badgeClass = 'bg-danger-subtle text-danger border border-danger';
        else if (format === 'CSV') badgeClass = 'bg-success-subtle text-success border border-success';
        else if (format === 'JSON') badgeClass = 'bg-warning-subtle text-warning border border-warning';

        const itemHtml = `
            <div class="p-2 mb-2 rounded soc-card border-secondary text-start animate-fade-in" style="background: rgba(15, 23, 42, 0.4);">
                <div class="d-flex align-items-center justify-content-between mb-1">
                    <span class="badge ${badgeClass}">${format} Export</span>
                    <span class="fs-xs text-muted">Just now</span>
                </div>
                <div class="small fw-semibold text-light text-truncate">${title}</div>
                <div class="fs-xs text-secondary">${desc}</div>
            </div>
        `;
        recentList.insertAdjacentHTML('afterbegin', itemHtml);
    }

    /**
     * Export CSV Action
     */
    async function exportCSV() {
        const { datasetId, invId, queryString } = buildFilterParams();
        if (!datasetId && !invId) {
            CTR.showToast('Please select a dataset or investigation to export', 'warning');
            return;
        }

        CTR.showToast('Initiating CSV export...', 'info', 'CSV Stream');
        const url = `/api/reports/export/csv?${queryString}`;
        window.location.href = url;
        addRecentAuditItem(`telemetry_export_${Date.now()}.csv`, 'CSV', `Dataset #${datasetId || '--'} data stream`);
    }

    /**
     * Export JSON Action
     */
    async function exportJSON() {
        const { datasetId, invId, queryString } = buildFilterParams();
        if (!datasetId && !invId) {
            CTR.showToast('Please select a dataset or investigation to export', 'warning');
            return;
        }

        CTR.showToast('Initiating JSON export...', 'info', 'JSON Stream');
        const url = `/api/reports/export/json?${queryString}`;
        window.location.href = url;
        addRecentAuditItem(`events_feed_${Date.now()}.json`, 'JSON', `Structured records export`);
    }

    /**
     * Generate PDF Incident Dossier Action
     */
    async function generatePDF() {
        const { datasetId, invId, timeStart, timeEnd, severity, protocol } = buildFilterParams();
        if (!datasetId && !invId) {
            CTR.showToast('Please select a target dataset or investigation', 'warning');
            return;
        }

        spinner.style.display = 'block';
        statusMsg.textContent = 'Analyzing multi-stage events & synthesizing PDF executive report...';
        btnPDF.disabled = true;

        try {
            const bodyPayload = {};
            if (invId) bodyPayload.investigation_id = invId;
            if (datasetId) bodyPayload.dataset_id = datasetId;
            if (timeStart) bodyPayload.time_range_start = timeStart;
            if (timeEnd) bodyPayload.time_range_end = timeEnd;
            if (severity) bodyPayload.severity = severity;
            if (protocol) bodyPayload.protocol = protocol;

            const blob = await CTR.apiCall('/api/reports/export/pdf', {
                method: 'POST',
                body: bodyPayload
            });

            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            const fileName = invId ? `Campus_Incident_Report_Case_${invId}.pdf` : `Campus_Attack_Forensic_Report_DS_${datasetId}.pdf`;
            a.href = downloadUrl;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(downloadUrl);

            CTR.showToast('Forensic PDF Report compiled and downloaded!', 'success');
            addRecentAuditItem(fileName, 'PDF', `Generated executive briefing document`);
        } catch (error) {
            console.error('PDF export failed:', error);
            CTR.showToast('PDF generation failed: ' + error.message, 'error');
        } finally {
            spinner.style.display = 'none';
            btnPDF.disabled = false;
        }
    }

    if (btnCSV) btnCSV.addEventListener('click', exportCSV);
    if (btnJSON) btnJSON.addEventListener('click', exportJSON);
    if (btnPDF) btnPDF.addEventListener('click', generatePDF);

    document.addEventListener('datasetChanged', () => {
        const activeId = CTR.getCurrentDatasetId();
        if (datasetSelect && activeId) {
            datasetSelect.value = activeId.toString();
        }
    });

    initSelectors();
});
