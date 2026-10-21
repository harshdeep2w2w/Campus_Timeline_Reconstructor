/**
 * Campus Network Attack – Timeline Reconstructor
 * Investigation Management & Dossier Logic (investigations.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    const detailContainer = document.getElementById('investigationDetailContainer');

    if (detailContainer) {
        initInvestigationDetail();
    } else {
        initInvestigationsList();
    }

    // =========================================================================
    // LIST VIEW CONTROLLER
    // =========================================================================
    function initInvestigationsList() {
        const tableBody = document.getElementById('investigationsTableBody');
        const emptyState = document.getElementById('investigationsEmptyState');
        const countBadge = document.getElementById('invCountBadge');
        const newForm = document.getElementById('newInvestigationForm');
        const datasetSelect = document.getElementById('invDatasetSelect');

        // Populate Datasets in modal
        async function loadModalDatasets() {
            if (!datasetSelect) return;
            try {
                const datasets = await CTR.apiCall('/api/datasets');
                const activeId = CTR.getCurrentDatasetId();
                if (!datasets || datasets.length === 0) {
                    datasetSelect.innerHTML = '<option value="" disabled selected>No datasets found</option>';
                } else {
                    datasetSelect.innerHTML = datasets.map(d => `
                        <option value="${d.id}" ${activeId === d.id ? 'selected' : ''}>
                            ${d.name || 'Dataset #' + d.id} (${d.record_count || 0} events)
                        </option>
                    `).join('');
                }
            } catch (e) {
                console.error(e);
            }
        }

        async function loadInvestigations() {
            CTR.showLoading(document.getElementById('investigationsWrapper'), 'Loading cases...');
            try {
                const investigations = await CTR.apiCall('/api/investigations');
                if (!investigations || investigations.length === 0) {
                    tableBody.innerHTML = '';
                    emptyState.style.display = 'block';
                    countBadge.textContent = '0 Cases';
                    return;
                }

                emptyState.style.display = 'none';
                countBadge.textContent = `${investigations.length} Cases`;

                tableBody.innerHTML = investigations.map(inv => {
                    const status = inv.status || 'open';
                    return `
                        <tr>
                            <td class="font-monospace text-cyan fw-bold">#${inv.id}</td>
                            <td>
                                <a href="/investigations/${inv.id}" class="text-light fw-semibold text-decoration-none">
                                    ${inv.title || 'Untitled Case'}
                                </a>
                                <div class="text-secondary small text-truncate" style="max-width: 380px;">
                                    ${inv.description || 'No initial summary entered.'}
                                </div>
                            </td>
                            <td>${CTR.statusBadge(status)}</td>
                            <td class="font-monospace fs-xs text-muted">${CTR.formatTimestamp(inv.created_at)}</td>
                            <td class="text-center">
                                <span class="badge bg-dark border border-secondary text-cyan">${inv.event_count || 0}</span>
                            </td>
                            <td class="text-end">
                                <a href="/investigations/${inv.id}" class="btn btn-xs soc-btn-outline-cyan me-1">
                                    <i class="bi bi-folder2-open me-1"></i>Open Case
                                </a>
                                <button class="btn btn-xs btn-outline-danger" onclick="window.CTR_DeleteInvestigation(${inv.id})">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (error) {
                console.error('Failed to load investigations:', error);
                tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger">Failed to load cases: ${error.message}</td></tr>`;
            } finally {
                CTR.hideLoading(document.getElementById('investigationsWrapper'));
            }
        }

        // Form Submit -> Create Case
        if (newForm) {
            newForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const title = document.getElementById('invTitleInput').value.trim();
                const description = document.getElementById('invDescInput').value.trim();
                const datasetId = datasetSelect ? parseInt(datasetSelect.value, 10) : CTR.getCurrentDatasetId();
                const status = document.getElementById('invStatusSelect').value;
                const timeStart = document.getElementById('invTimeStart').value;
                const timeEnd = document.getElementById('invTimeEnd').value;

                try {
                    const result = await CTR.apiCall('/api/investigations', {
                        method: 'POST',
                        body: {
                            title,
                            description,
                            dataset_id: datasetId,
                            status,
                            time_range_start: timeStart ? new Date(timeStart).toISOString() : null,
                            time_range_end: timeEnd ? new Date(timeEnd).toISOString() : null
                        }
                    });

                    CTR.showToast('Investigation case created successfully!', 'success');
                    const modalEl = document.getElementById('newInvestigationModal');
                    if (modalEl && window.bootstrap) {
                        const modal = bootstrap.Modal.getInstance(modalEl);
                        if (modal) modal.hide();
                    }

                    if (result.id) {
                        window.location.href = `/investigations/${result.id}`;
                    } else {
                        loadInvestigations();
                    }
                } catch (error) {
                    CTR.showToast('Failed to create case: ' + error.message, 'error');
                }
            });
        }

        window.CTR_DeleteInvestigation = async function(id) {
            if (!confirm(`Are you sure you want to permanently delete investigation #${id}?`)) return;
            try {
                await CTR.apiCall(`/api/investigations/${id}`, { method: 'DELETE' });
                CTR.showToast(`Case #${id} deleted`, 'info');
                loadInvestigations();
            } catch (error) {
                CTR.showToast('Failed to delete case: ' + error.message, 'error');
            }
        };

        loadModalDatasets();
        loadInvestigations();
    }

    // =========================================================================
    // DETAIL VIEW CONTROLLER
    // =========================================================================
    function initInvestigationDetail() {
        let invId = detailContainer.dataset.investigationId;
        if (!invId) {
            // Parse from URL /investigations/123
            const parts = window.location.pathname.split('/');
            invId = parts[parts.length - 1];
        }

        if (!invId || isNaN(parseInt(invId, 10))) {
            CTR.showToast('Invalid investigation case identifier', 'error');
            return;
        }

        const titleInput = document.getElementById('invTitleEdit');
        const statusDropdown = document.getElementById('invStatusDropdown');
        const descTextarea = document.getElementById('invDescriptionEdit');
        const scopeStart = document.getElementById('invScopeStart');
        const scopeEnd = document.getElementById('invScopeEnd');
        const notesTextarea = document.getElementById('invNotesTextarea');
        const findingsTextarea = document.getElementById('invFindingsTextarea');
        const eventsTableBody = document.getElementById('invEventsTableBody');
        const hostsContainer = document.getElementById('invHostsListContainer');
        const correlationContainer = document.getElementById('invCorrelationContainer');

        const addEventsModalEl = document.getElementById('addEventsModal');
        const bsAddEventsModal = addEventsModalEl && window.bootstrap ? new bootstrap.Modal(addEventsModalEl) : null;
        const addHostModalEl = document.getElementById('addHostModal');
        const bsAddHostModal = addHostModalEl && window.bootstrap ? new bootstrap.Modal(addHostModalEl) : null;

        let currentInvestigationData = null;

        /**
         * Load full investigation dossier
         */
        async function loadInvestigation() {
            CTR.showLoading(detailContainer, 'Loading case dossier...');
            try {
                const data = await CTR.apiCall(`/api/investigations/${invId}`);
                const inv = data.investigation || data;
                currentInvestigationData = inv;

                // Populate Header & Overview
                if (titleInput) titleInput.value = inv.title || `Investigation #${inv.id}`;
                if (statusDropdown) statusDropdown.value = inv.status || 'open';
                if (descTextarea) descTextarea.value = inv.description || '';
                if (notesTextarea) notesTextarea.value = inv.analyst_notes || '';
                if (findingsTextarea) findingsTextarea.value = inv.findings || '';

                if (scopeStart && inv.time_range_start) {
                    scopeStart.value = inv.time_range_start.slice(0, 19);
                }
                if (scopeEnd && inv.time_range_end) {
                    scopeEnd.value = inv.time_range_end.slice(0, 19);
                }

                // Metrics
                const events = data.events || inv.events || [];
                const hosts = data.hosts || inv.hosts || [];
                const alertCount = data.alert_count !== undefined ? data.alert_count : (inv.alert_count || 0);

                document.getElementById('metricEventCount').textContent = events.length.toLocaleString();
                document.getElementById('metricHostCount').textContent = hosts.length.toLocaleString();
                document.getElementById('metricAlertCount').textContent = alertCount.toLocaleString();
                document.getElementById('metricDatasetLabel').textContent = '#' + (inv.dataset_id || 'Global');

                // Render Events Tab
                renderInvestigationEvents(events);

                // Render Hosts Tab
                renderInvestigationHosts(hosts);

                // Render Correlation Tab
                loadInvestigationCorrelation(inv.dataset_id);

            } catch (error) {
                console.error('Failed to load investigation dossier:', error);
                CTR.showToast('Failed to load investigation: ' + error.message, 'error');
            } finally {
                CTR.hideLoading(detailContainer);
            }
        }

        /**
         * Render Events attached to investigation
         */
        function renderInvestigationEvents(events) {
            if (!eventsTableBody) return;
            if (events.length === 0) {
                eventsTableBody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-secondary">No events attached to this case. Click "Add Events" to associate telemetry.</td></tr>';
                return;
            }

            eventsTableBody.innerHTML = events.map(ev => `
                <tr>
                    <td class="font-monospace text-cyan fw-bold">#${ev.id}</td>
                    <td class="font-monospace fs-xs">${CTR.formatTimestamp(ev.timestamp)}</td>
                    <td class="font-monospace fs-xs">
                        ${ev.src_ip || 'Any'}${ev.src_port ? ':' + ev.src_port : ''}
                        <span class="text-secondary mx-1">&rarr;</span>
                        ${ev.dst_ip || 'Any'}${ev.dst_port ? ':' + ev.dst_port : ''}
                    </td>
                    <td><span class="badge-protocol">${(ev.protocol || 'TCP').toUpperCase()}</span></td>
                    <td><span class="badge bg-secondary">${ev.event_category || 'traffic'}</span></td>
                    <td>${CTR.severityBadge(ev.severity)}</td>
                    <td class="text-end">
                        <button class="btn btn-xs btn-outline-danger" onclick="window.CTR_RemoveEventFromInv(${ev.id})" title="Remove from investigation">
                            <i class="bi bi-x-lg"></i>
                        </button>
                    </td>
                </tr>
            `).join('');
        }

        /**
         * Render Hosts attached to investigation
         */
        function renderInvestigationHosts(hosts) {
            if (!hostsContainer) return;
            if (hosts.length === 0) {
                hostsContainer.innerHTML = '<div class="col-12 text-center py-4 text-secondary">No endpoints added to this case yet. Click "Add Host IP" above.</div>';
                return;
            }

            hostsContainer.innerHTML = hosts.map(h => {
                const ip = typeof h === 'object' ? (h.ip || h.host_ip) : h;
                const hostname = typeof h === 'object' ? h.hostname : 'Host';
                return `
                    <div class="col-12 col-sm-6 col-lg-4">
                        <div class="soc-card p-3 border-secondary">
                            <div class="d-flex align-items-center justify-content-between mb-2">
                                <div class="font-monospace text-cyan fw-bold fs-6">${ip}</div>
                                <span class="badge soc-badge-cyan">Tagged Host</span>
                            </div>
                            <div class="text-secondary small mb-3">Host descriptor: ${hostname || 'Network endpoint'}</div>
                            <div class="d-flex gap-2">
                                <a href="/timeline?src_ip=${encodeURIComponent(ip)}" class="btn btn-xs soc-btn-outline-cyan flex-fill text-center">
                                    <i class="bi bi-clock-history me-1"></i>Timeline
                                </a>
                                <a href="/network-graph" class="btn btn-xs soc-btn-outline-cyan flex-fill text-center">
                                    <i class="bi bi-diagram-3 me-1"></i>Topology
                                </a>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        /**
         * Load Correlation Groups for this case
         */
        async function loadInvestigationCorrelation(datasetId) {
            if (!correlationContainer) return;
            try {
                const dsId = datasetId || CTR.getCurrentDatasetId();
                const groups = await CTR.apiCall(`/api/correlation/groups?dataset_id=${dsId}`).catch(() => []);
                if (!groups || groups.length === 0) {
                    correlationContainer.innerHTML = '<div class="text-secondary small py-3">No automated correlation clusters found for current dataset.</div>';
                    return;
                }

                correlationContainer.innerHTML = groups.map(g => `
                    <div class="p-3 mb-3 rounded soc-card border-secondary" style="background: rgba(15, 23, 42, 0.4);">
                        <div class="d-flex align-items-center justify-content-between mb-2">
                            <span class="badge bg-purple text-light border border-purple">Cluster #${g.group_id || '1'} — ${g.correlation_type || 'Attack Stage Pattern'}</span>
                            <span class="badge bg-dark border border-secondary text-cyan">${(g.events || []).length} Correlated Events</span>
                        </div>
                        <p class="text-light small mb-2">${g.reason || 'Multiple concurrent connections with matching signature attributes.'}</p>
                    </div>
                `).join('');
            } catch (e) {
                correlationContainer.innerHTML = '<div class="text-danger small py-3">Failed to load correlation clusters</div>';
            }
        }

        /**
         * Update investigation fields via PUT /api/investigations/<id>
         */
        async function updateInvestigation(payload) {
            try {
                await CTR.apiCall(`/api/investigations/${invId}`, {
                    method: 'PUT',
                    body: payload
                });
                CTR.showToast('Investigation case saved successfully', 'success');
            } catch (error) {
                CTR.showToast('Save failed: ' + error.message, 'error');
            }
        }

        // Header listeners
        if (titleInput) {
            titleInput.addEventListener('change', () => {
                updateInvestigation({ title: titleInput.value.trim() });
            });
        }
        if (statusDropdown) {
            statusDropdown.addEventListener('change', () => {
                updateInvestigation({ status: statusDropdown.value });
            });
        }

        // Save Overview
        document.getElementById('saveOverviewBtn').addEventListener('click', () => {
            updateInvestigation({
                description: descTextarea.value.trim(),
                time_range_start: scopeStart.value ? new Date(scopeStart.value).toISOString() : null,
                time_range_end: scopeEnd.value ? new Date(scopeEnd.value).toISOString() : null
            });
        });

        // Save Notes
        document.getElementById('saveNotesBtn').addEventListener('click', () => {
            updateInvestigation({ analyst_notes: notesTextarea.value });
        });

        // Save Findings
        document.getElementById('saveFindingsBtn').addEventListener('click', () => {
            updateInvestigation({ findings: findingsTextarea.value });
        });

        // Delete Case
        document.getElementById('invDeleteBtn').addEventListener('click', async () => {
            if (!confirm(`Are you sure you want to permanently delete investigation case #${invId}?`)) return;
            try {
                await CTR.apiCall(`/api/investigations/${invId}`, { method: 'DELETE' });
                CTR.showToast('Investigation deleted', 'info');
                window.location.href = '/investigations';
            } catch (e) {
                CTR.showToast('Failed to delete case: ' + e.message, 'error');
            }
        });

        // Generate Report PDF
        document.getElementById('invGenerateReportBtn').addEventListener('click', async () => {
            CTR.showToast('Compiling investigation forensic PDF report...', 'info', 'PDF Engine');
            try {
                const blob = await CTR.apiCall('/api/reports/export/pdf', {
                    method: 'POST',
                    body: { investigation_id: parseInt(invId, 10) }
                });

                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = `Investigation_Report_Case_${invId}.pdf`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(downloadUrl);
                CTR.showToast('PDF report downloaded successfully!', 'success');
            } catch (error) {
                CTR.showToast('Failed to compile PDF report: ' + error.message, 'error');
            }
        });

        // Remove Event Global Handler
        window.CTR_RemoveEventFromInv = async function(eventId) {
            if (!confirm(`Detach event #${eventId} from this investigation?`)) return;
            try {
                await CTR.apiCall(`/api/investigations/${invId}/events/${eventId}`, {
                    method: 'DELETE'
                });
                CTR.showToast(`Event #${eventId} detached`, 'info');
                loadInvestigation();
            } catch (error) {
                CTR.showToast('Failed to detach event: ' + error.message, 'error');
            }
        };

        // Open Add Events Modal
        document.getElementById('openAddEventsModalBtn').addEventListener('click', async () => {
            if (bsAddEventsModal) bsAddEventsModal.show();
            const tbody = document.getElementById('availableEventsTableBody');
            tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-secondary">Loading dataset telemetry...</td></tr>';

            try {
                const datasetId = (currentInvestigationData && currentInvestigationData.dataset_id) || CTR.getCurrentDatasetId();
                const res = await CTR.apiCall(`/api/timeline/events?dataset_id=${datasetId}&per_page=50`);
                const events = res.events || [];

                if (events.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-secondary">No unlinked events found in dataset</td></tr>';
                    return;
                }

                tbody.innerHTML = events.map(e => `
                    <tr>
                        <td><input type="checkbox" class="event-attach-checkbox" value="${e.id}"></td>
                        <td class="font-monospace text-cyan">#${e.id}</td>
                        <td class="font-monospace fs-xs">${CTR.formatTimestamp(e.timestamp)}</td>
                        <td class="font-monospace fs-xs">${e.src_ip} &rarr; ${e.dst_ip}</td>
                        <td><span class="badge-protocol">${(e.protocol || 'TCP').toUpperCase()}</span></td>
                        <td>${CTR.severityBadge(e.severity)}</td>
                    </tr>
                `).join('');
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger">Error querying events: ${e.message}</td></tr>`;
            }
        });

        // Confirm Add Events
        document.getElementById('confirmAddSelectedEventsBtn').addEventListener('click', async () => {
            const checked = document.querySelectorAll('.event-attach-checkbox:checked');
            const ids = Array.from(checked).map(cb => parseInt(cb.value, 10));
            if (ids.length === 0) {
                CTR.showToast('No events selected', 'warning');
                return;
            }

            try {
                await CTR.apiCall(`/api/investigations/${invId}/events`, {
                    method: 'POST',
                    body: { event_ids: ids }
                });
                CTR.showToast(`Attached ${ids.length} events to investigation`, 'success');
                if (bsAddEventsModal) bsAddEventsModal.hide();
                loadInvestigation();
            } catch (e) {
                CTR.showToast('Failed to attach events: ' + e.message, 'error');
            }
        });

        // Open Add Host Modal
        document.getElementById('openAddHostModalBtn').addEventListener('click', () => {
            if (bsAddHostModal) bsAddHostModal.show();
        });

        // Confirm Add Host
        document.getElementById('confirmAddHostBtn').addEventListener('click', async () => {
            const ipInput = document.getElementById('newHostIpInput');
            const ip = ipInput.value.trim();
            if (!ip) {
                CTR.showToast('Please enter an IP address', 'warning');
                return;
            }

            try {
                await CTR.apiCall(`/api/investigations/${invId}/hosts`, {
                    method: 'POST',
                    body: { host_ips: [ip] }
                });
                CTR.showToast(`Host ${ip} attached to case file`, 'success');
                ipInput.value = '';
                if (bsAddHostModal) bsAddHostModal.hide();
                loadInvestigation();
            } catch (e) {
                CTR.showToast('Failed to add host: ' + e.message, 'error');
            }
        });

        loadInvestigation();
    }
});
