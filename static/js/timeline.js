/**
 * Campus Network Attack – Timeline Reconstructor
 * Timeline Page Logic (timeline.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    let currentPage = 1;
    let currentPerPage = 50;
    let currentSelectedEventId = null;

    const streamEl = document.getElementById('timelineStream');
    const emptyStateEl = document.getElementById('timelineEmptyState');
    const wrapperEl = document.getElementById('timelineContainerWrapper');
    const paginationEl = document.getElementById('timelinePagination');
    const paginationSummary = document.getElementById('paginationSummary');
    const eventMatchBadge = document.getElementById('eventMatchBadge');
    const filterForm = document.getElementById('timelineFilterForm');
    const perPageSelect = document.getElementById('perPageSelect');

    const detailModalEl = document.getElementById('eventDetailModal');
    let bsDetailModal = null;
    function getDetailModal() {
        if (!bsDetailModal && detailModalEl && window.bootstrap) {
            bsDetailModal = bootstrap.Modal.getOrCreateInstance(detailModalEl);
        }
        return bsDetailModal;
    }

    const addToInvModalEl = document.getElementById('addToInvModal');
    let bsAddToInvModal = null;
    function getAddToInvModal() {
        if (!bsAddToInvModal && addToInvModalEl && window.bootstrap) {
            bsAddToInvModal = bootstrap.Modal.getOrCreateInstance(addToInvModalEl);
        }
        return bsAddToInvModal;
    }

    // Direct close handler function that ALWAYS works regardless of Bootstrap state
    function forceCloseDetailModal() {
        const modalInstance = getDetailModal();
        if (modalInstance) {
            modalInstance.hide();
        }
        if (detailModalEl) {
            detailModalEl.classList.remove('show');
            detailModalEl.style.display = 'none';
            detailModalEl.setAttribute('aria-hidden', 'true');
            detailModalEl.removeAttribute('aria-modal');
        }
        cleanupModalBackdrop();
    }

    function forceCloseAddToInvModal() {
        const modalInstance = getAddToInvModal();
        if (modalInstance) {
            modalInstance.hide();
        }
        if (addToInvModalEl) {
            addToInvModalEl.classList.remove('show');
            addToInvModalEl.style.display = 'none';
            addToInvModalEl.setAttribute('aria-hidden', 'true');
            addToInvModalEl.removeAttribute('aria-modal');
        }
        cleanupModalBackdrop();
    }

    // Attach direct click events to Close buttons
    const closeDetailX = document.getElementById('eventDetailModalCloseX');
    const closeDetailBtn = document.getElementById('eventDetailModalCloseBtn');
    if (closeDetailX) closeDetailX.addEventListener('click', forceCloseDetailModal);
    if (closeDetailBtn) closeDetailBtn.addEventListener('click', forceCloseDetailModal);

    const closeInvX = document.getElementById('addToInvModalCloseX');
    const closeInvBtn = document.getElementById('addToInvModalCloseBtn');
    if (closeInvX) closeInvX.addEventListener('click', forceCloseAddToInvModal);
    if (closeInvBtn) closeInvBtn.addEventListener('click', forceCloseAddToInvModal);

    // Close when clicking outside the dialogs
    if (detailModalEl) {
        detailModalEl.addEventListener('click', function(e) {
            if (e.target === detailModalEl) forceCloseDetailModal();
        });
    }
    if (addToInvModalEl) {
        addToInvModalEl.addEventListener('click', function(e) {
            if (e.target === addToInvModalEl) forceCloseAddToInvModal();
        });
    }

    // Close on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            if (addToInvModalEl && addToInvModalEl.classList.contains('show')) {
                forceCloseAddToInvModal();
            } else if (detailModalEl && detailModalEl.classList.contains('show')) {
                forceCloseDetailModal();
            }
        }
    });

    // Ensure modal backdrops are fully cleaned up when hidden
    function cleanupModalBackdrop() {
        document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
        document.body.classList.remove('modal-open');
        document.body.style.removeProperty('overflow');
        document.body.style.removeProperty('padding-right');
    }
    if (detailModalEl) detailModalEl.addEventListener('hidden.bs.modal', cleanupModalBackdrop);
    if (addToInvModalEl) addToInvModalEl.addEventListener('hidden.bs.modal', cleanupModalBackdrop);

    // Check URL query parameters for initial filters (e.g. ?src_ip=192.168.1.10)
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('src_ip')) document.getElementById('filterSrcIp').value = urlParams.get('src_ip');
    if (urlParams.get('dst_ip')) document.getElementById('filterDstIp').value = urlParams.get('dst_ip');
    if (urlParams.get('protocol')) document.getElementById('filterProtocol').value = urlParams.get('protocol');
    if (urlParams.get('severity')) document.getElementById('filterSeverity').value = urlParams.get('severity');
    if (urlParams.get('category')) document.getElementById('filterCategory').value = urlParams.get('category');

    /**
     * Build query string from filter inputs
     */
    function getFilterParams(page = 1) {
        const datasetId = CTR.getCurrentDatasetId();
        const params = new URLSearchParams();
        if (datasetId) params.append('dataset_id', datasetId);

        const timeStart = document.getElementById('filterTimeStart').value;
        const timeEnd = document.getElementById('filterTimeEnd').value;
        const srcIp = document.getElementById('filterSrcIp').value.trim();
        const dstIp = document.getElementById('filterDstIp').value.trim();
        const protocol = document.getElementById('filterProtocol').value;
        const severity = document.getElementById('filterSeverity').value;
        const category = document.getElementById('filterCategory').value;

        if (timeStart) params.append('time_start', new Date(timeStart).toISOString());
        if (timeEnd) params.append('time_end', new Date(timeEnd).toISOString());
        if (srcIp) params.append('src_ip', srcIp);
        if (dstIp) params.append('dst_ip', dstIp);
        if (protocol) params.append('protocol', protocol);
        if (severity) params.append('severity', severity);
        if (category) params.append('category', category);

        params.append('page', page.toString());
        params.append('per_page', currentPerPage.toString());

        return params.toString();
    }

    /**
     * Load events from /api/timeline/events
     */
    async function loadEvents(page = 1) {
        currentPage = page;
        const datasetId = CTR.getCurrentDatasetId();

        if (!datasetId) {
            streamEl.innerHTML = '';
            emptyStateEl.style.display = 'block';
            eventMatchBadge.textContent = '0 events';
            paginationSummary.textContent = 'Select or load a dataset to view timeline';
            return;
        }

        CTR.showLoading(wrapperEl, 'Reconstructing event sequence...');
        emptyStateEl.style.display = 'none';

        try {
            const queryString = getFilterParams(page);
            const data = await CTR.apiCall(`/api/timeline/events?${queryString}`);

            const events = data.events || [];
            const total = data.total !== undefined ? data.total : events.length;
            const pages = data.pages || Math.ceil(total / currentPerPage) || 1;

            eventMatchBadge.textContent = `${total.toLocaleString()} Events`;
            paginationSummary.textContent = `Showing ${events.length > 0 ? (page - 1) * currentPerPage + 1 : 0} - ${Math.min(page * currentPerPage, total)} of ${total.toLocaleString()} events`;

            if (events.length === 0) {
                streamEl.innerHTML = '';
                emptyStateEl.style.display = 'block';
                paginationEl.innerHTML = '';
            } else {
                emptyStateEl.style.display = 'none';
                renderTimeline(events);
                renderPagination(total, page, pages);
            }
        } catch (error) {
            console.error('Failed to load timeline events:', error);
            streamEl.innerHTML = `<div class="p-4 text-center text-danger">Failed to fetch events: ${error.message}</div>`;
            CTR.showToast('Error querying timeline telemetry', 'error');
        } finally {
            CTR.hideLoading(wrapperEl);
        }
    }

    /**
     * Render vertical timeline items
     */
    function renderTimeline(events) {
        streamEl.innerHTML = events.map(ev => {
            const sev = (ev.severity || 'informational').toLowerCase();
            const proto = (ev.protocol || 'TCP').toUpperCase();
            const category = ev.event_category || ev.category || 'telemetry';
            const srcPort = ev.src_port ? `:${ev.src_port}` : '';
            const dstPort = ev.dst_port ? `:${ev.dst_port}` : '';

            return `
                <div class="timeline-event-item sev-${sev}" data-event-id="${ev.id}">
                    <div class="timeline-node-dot"></div>
                    <div class="timeline-card sev-${sev}" onclick="window.CTR_OpenEventDetail(${ev.id})">
                        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2">
                            <div class="d-flex align-items-center gap-2 flex-wrap">
                                ${CTR.severityBadge(ev.severity)}
                                <span class="badge-protocol">${proto}</span>
                                <span class="badge bg-secondary-subtle text-light border border-secondary">${category}</span>
                            </div>
                            <span class="timeline-time-badge">
                                <i class="bi bi-clock me-1 text-cyan"></i>${CTR.formatTimestamp(ev.timestamp)}
                            </span>
                        </div>

                        <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
                            <div class="font-monospace fs-sm text-light">
                                <span class="text-info">${ev.src_ip || 'N/A'}${srcPort}</span>
                                <span class="text-secondary mx-2">&rarr;</span>
                                <span class="text-warning">${ev.dst_ip || 'N/A'}${dstPort}</span>
                            </div>
                            <button class="btn btn-xs soc-btn-outline-cyan" onclick="event.stopPropagation(); window.CTR_OpenEventDetail(${ev.id})">
                                <i class="bi bi-search me-1"></i>Inspect
                            </button>
                        </div>

                        <div class="small text-secondary text-truncate-2">
                            ${ev.description || ev.rule_name || 'Standard network transmission detected on monitored campus segment.'}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    /**
     * Render pagination controls
     */
    function renderPagination(total, page, totalPages) {
        if (totalPages <= 1) {
            paginationEl.innerHTML = '';
            return;
        }

        let html = '';
        // Previous Button
        html += `<li class="page-item ${page <= 1 ? 'disabled' : ''}">
            <button class="page-link" onclick="window.CTR_GoToPage(${page - 1})" aria-label="Previous">&laquo;</button>
        </li>`;

        // Sliding window of page numbers
        const maxButtons = 5;
        let startPage = Math.max(1, page - 2);
        let endPage = Math.min(totalPages, startPage + maxButtons - 1);
        if (endPage - startPage < maxButtons - 1) {
            startPage = Math.max(1, endPage - maxButtons + 1);
        }

        if (startPage > 1) {
            html += `<li class="page-item"><button class="page-link" onclick="window.CTR_GoToPage(1)">1</button></li>`;
            if (startPage > 2) html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }

        for (let p = startPage; p <= endPage; p++) {
            html += `<li class="page-item ${p === page ? 'active' : ''}">
                <button class="page-link" onclick="window.CTR_GoToPage(${p})">${p}</button>
            </li>`;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
            html += `<li class="page-item"><button class="page-link" onclick="window.CTR_GoToPage(${totalPages})">${totalPages}</button></li>`;
        }

        // Next Button
        html += `<li class="page-item ${page >= totalPages ? 'disabled' : ''}">
            <button class="page-link" onclick="window.CTR_GoToPage(${page + 1})" aria-label="Next">&raquo;</button>
        </li>`;

        paginationEl.innerHTML = html;
    }

    // Global hook for page jump
    window.CTR_GoToPage = function(p) {
        loadEvents(p);
        wrapperEl.scrollIntoView({ behavior: 'smooth' });
    };

    /**
     * Inspect Single Event Details & Correlation Chains
     */
    window.CTR_OpenEventDetail = async function(eventId) {
        currentSelectedEventId = eventId;
        const modalBody = document.getElementById('eventDetailModalBody');
        const badge = document.getElementById('modalEventIdBadge');
        if (badge) badge.textContent = `#${eventId}`;

        modalBody.innerHTML = '<div class="p-5 text-center"><div class="soc-spinner-cyan mb-2"></div><div class="text-cyan small">Fetching event details &amp; correlation graph...</div></div>';
        const modalInstance = getDetailModal();
        if (modalInstance) {
            modalInstance.show();
        } else if (detailModalEl) {
            detailModalEl.classList.add('show');
            detailModalEl.style.display = 'block';
        }

        try {
            // Fetch event details
            const eventData = await CTR.apiCall(`/api/timeline/event/${eventId}`);
            const relatedData = await CTR.apiCall(`/api/correlation/related/${eventId}`).catch(() => ({ related_events: [] }));

            const ev = eventData.event || eventData;
            const relatedEvents = (relatedData && relatedData.related_events) || ev.related_events || [];

            let rawDataFormatted = '';
            if (ev.raw_data) {
                rawDataFormatted = typeof ev.raw_data === 'object' ? JSON.stringify(ev.raw_data, null, 2) : ev.raw_data;
            }

            let relatedHtml = '';
            if (relatedEvents.length === 0) {
                relatedHtml = '<div class="text-secondary small py-2">No automatically correlated multi-stage events detected for this record.</div>';
            } else {
                relatedHtml = relatedEvents.map(item => {
                    const rEv = item.event || item;
                    const reason = item.reason || 'Correlated by temporal proximity &amp; IP association';
                    return `
                        <div class="p-2 mb-2 rounded soc-card border-secondary" style="background: rgba(15, 23, 42, 0.6);">
                            <div class="d-flex align-items-center justify-content-between mb-1">
                                <span class="badge bg-purple text-light border border-purple">${item.correlation_type || 'Attack Chain Step'}</span>
                                <span class="font-monospace fs-xs text-muted">${CTR.formatTimestamp(rEv.timestamp)}</span>
                            </div>
                            <div class="small fw-semibold text-cyan mb-1">${reason}</div>
                            <div class="font-monospace fs-xs text-secondary">
                                ${rEv.src_ip || ''} &rarr; ${rEv.dst_ip || ''} (${(rEv.protocol || '').toUpperCase()})
                            </div>
                        </div>
                    `;
                }).join('');
            }

            modalBody.innerHTML = `
                <div class="row g-3 mb-3">
                    <div class="col-sm-6">
                        <label class="form-label">Timestamp</label>
                        <div class="font-monospace text-light bg-dark p-2 rounded border border-secondary">${CTR.formatTimestamp(ev.timestamp)}</div>
                    </div>
                    <div class="col-sm-3">
                        <label class="form-label">Protocol</label>
                        <div class="font-monospace text-info bg-dark p-2 rounded border border-secondary">${(ev.protocol || 'TCP').toUpperCase()}</div>
                    </div>
                    <div class="col-sm-3">
                        <label class="form-label">Severity</label>
                        <div>${CTR.severityBadge(ev.severity)}</div>
                    </div>
                </div>

                <div class="row g-3 mb-3">
                    <div class="col-sm-6">
                        <label class="form-label">Source Host</label>
                        <div class="font-monospace text-light bg-dark p-2 rounded border border-secondary d-flex justify-content-between">
                            <span>${ev.src_ip || 'N/A'}${ev.src_port ? ':' + ev.src_port : ''}</span>
                            <a href="/timeline?src_ip=${encodeURIComponent(ev.src_ip)}" class="text-cyan small">Filter</a>
                        </div>
                    </div>
                    <div class="col-sm-6">
                        <label class="form-label">Destination Host</label>
                        <div class="font-monospace text-light bg-dark p-2 rounded border border-secondary d-flex justify-content-between">
                            <span>${ev.dst_ip || 'N/A'}${ev.dst_port ? ':' + ev.dst_port : ''}</span>
                            <a href="/timeline?dst_ip=${encodeURIComponent(ev.dst_ip)}" class="text-cyan small">Filter</a>
                        </div>
                    </div>
                </div>

                <div class="mb-3">
                    <label class="form-label">Description / Analyst Note</label>
                    <div class="p-2 rounded soc-card border-secondary text-light small">
                        ${ev.description || 'Raw telemetry logged from campus network sensor.'}
                    </div>
                </div>

                ${rawDataFormatted ? `
                    <div class="mb-3">
                        <label class="form-label">Raw Telemetry Data</label>
                        <pre class="p-2 rounded bg-dark border border-secondary font-monospace text-info fs-xs" style="max-height: 140px; overflow-y: auto;">${rawDataFormatted}</pre>
                    </div>
                ` : ''}

                <div class="mt-4 pt-3 border-top border-secondary-subtle">
                    <h6 class="text-light fw-bold mb-2 d-flex align-items-center gap-2">
                        <i class="bi bi-diagram-2 text-cyan"></i> Correlated Attack Chain Telemetry (${relatedEvents.length})
                    </h6>
                    ${relatedHtml}
                </div>
            `;
        } catch (error) {
            console.error('Failed to load event details:', error);
            modalBody.innerHTML = `<div class="p-4 text-center text-danger">Error retrieving telemetry detail: ${error.message}</div>`;
        }
    };

    // Add to Investigation Button in Modal
    const modalAddInvBtn = document.getElementById('modalAddInvestigationBtn');
    if (modalAddInvBtn) {
        modalAddInvBtn.addEventListener('click', async () => {
            if (!currentSelectedEventId) return;
            const select = document.getElementById('targetInvestigationSelect');
            select.innerHTML = '<option value="" disabled selected>Loading open investigations...</option>';
            const modalInstance = getAddToInvModal();
            if (modalInstance) {
                modalInstance.show();
            } else if (addToInvModalEl) {
                addToInvModalEl.classList.add('show');
                addToInvModalEl.style.display = 'block';
            }

            try {
                const investigations = await CTR.apiCall('/api/investigations');
                if (!investigations || investigations.length === 0) {
                    select.innerHTML = '<option value="" disabled selected>No investigations open (Create one first)</option>';
                } else {
                    select.innerHTML = investigations.map(inv => `
                        <option value="${inv.id}">${inv.title || 'Investigation #' + inv.id} (${inv.status || 'open'})</option>
                    `).join('');
                }
            } catch (e) {
                select.innerHTML = '<option value="" disabled selected>Failed to fetch investigations</option>';
            }
        });
    }

    // Confirm Add Event to Investigation
    const confirmAddBtn = document.getElementById('confirmAddToInvBtn');
    if (confirmAddBtn) {
        confirmAddBtn.addEventListener('click', async () => {
            const select = document.getElementById('targetInvestigationSelect');
            const invId = select.value;
            if (!invId) {
                CTR.showToast('Please select a target investigation case', 'warning');
                return;
            }

            try {
                await CTR.apiCall(`/api/investigations/${invId}/events`, {
                    method: 'POST',
                    body: { event_ids: [currentSelectedEventId] }
                });
                CTR.showToast(`Event #${currentSelectedEventId} attached to investigation #${invId}`, 'success');
                forceCloseAddToInvModal();
            } catch (error) {
                CTR.showToast('Failed to attach event: ' + error.message, 'error');
            }
        });
    }

    // Filter Form Submission
    if (filterForm) {
        filterForm.addEventListener('submit', (e) => {
            e.preventDefault();
            loadEvents(1);
        });
    }

    // Reset Filters Button
    const resetBtn = document.getElementById('resetFiltersBtn');
    const emptyClearBtn = document.getElementById('clearFiltersEmptyBtn');
    const handleReset = () => {
        filterForm.reset();
        loadEvents(1);
    };
    if (resetBtn) resetBtn.addEventListener('click', handleReset);
    if (emptyClearBtn) emptyClearBtn.addEventListener('click', handleReset);

    // Per page select change
    if (perPageSelect) {
        perPageSelect.addEventListener('change', (e) => {
            currentPerPage = parseInt(e.target.value, 10) || 50;
            loadEvents(1);
        });
    }

    // Listen for global dataset change
    document.addEventListener('datasetChanged', () => {
        loadEvents(1);
    });

    // Initial load
    loadEvents(1);
});
