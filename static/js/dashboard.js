/**
 * Campus Network Attack – Timeline Reconstructor
 * Dashboard Page Logic (dashboard.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    let activityChartInstance = null;
    let protocolChartInstance = null;

    const emptyStateEl = document.getElementById('dashboardEmptyState');
    const activeViewEl = document.getElementById('dashboardActiveView');
    const sampleBtn = document.getElementById('dashboardLoadSampleBtn');

    if (sampleBtn) {
        sampleBtn.addEventListener('click', CTR.loadSampleData);
    }

    /**
     * Animate numeric stat counter
     */
    function animateValue(element, start, end, duration = 800) {
        if (!element) return;
        if (start === end) {
            element.textContent = Number(end).toLocaleString();
            return;
        }
        const range = end - start;
        let current = start;
        const increment = range / (duration / 16);
        const timer = setInterval(() => {
            current += increment;
            if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
                current = end;
                clearInterval(timer);
            }
            element.textContent = Math.round(current).toLocaleString();
        }, 16);
    }

    /**
     * Load Top Dashboard Metrics & Severity Breakdown
     */
    async function loadStats(datasetId) {
        try {
            const stats = await CTR.apiCall(`/api/dashboard/stats?dataset_id=${datasetId}`);
            
            const total = stats.total_events || 0;
            if (total === 0) {
                emptyStateEl.style.display = 'block';
                activeViewEl.style.display = 'none';
                return false;
            }

            emptyStateEl.style.display = 'none';
            activeViewEl.style.display = 'block';

            animateValue(document.getElementById('statTotalEvents'), 0, total);
            animateValue(document.getElementById('statUniqueHosts'), 0, stats.unique_hosts || 0);
            animateValue(document.getElementById('statSuspiciousEvents'), 0, stats.suspicious_events || 0);
            animateValue(document.getElementById('statActiveInvestigations'), 0, stats.active_investigations || 0);

            // Severity breakdown counts
            const sev = stats.alerts_by_severity || {};
            document.getElementById('sevCriticalCount').textContent = (sev.critical || 0).toLocaleString();
            document.getElementById('sevHighCount').textContent = (sev.high || 0).toLocaleString();
            document.getElementById('sevMediumCount').textContent = (sev.medium || 0).toLocaleString();
            document.getElementById('sevLowCount').textContent = (sev.low || 0).toLocaleString();
            document.getElementById('sevInfoCount').textContent = (sev.informational || sev.info || 0).toLocaleString();

            return true;
        } catch (error) {
            console.error('Failed to load dashboard stats:', error);
            emptyStateEl.style.display = 'block';
            activeViewEl.style.display = 'none';
            return false;
        }
    }

    /**
     * Load and render Network Activity Over Time (Chart.js Line Chart)
     */
    async function loadActivityChart(datasetId) {
        const canvas = document.getElementById('activityChart');
        if (!canvas) return;

        try {
            const data = await CTR.apiCall(`/api/dashboard/activity-over-time?dataset_id=${datasetId}`);
            if (!Array.isArray(data) || data.length === 0) {
                return;
            }

            const labels = data.map(item => {
                const t = item.time_bucket;
                if (!t) return '';
                // If it's ISO datetime, format to HH:mm or MM-DD HH:mm
                if (t.includes('T')) {
                    const parts = t.split('T');
                    return parts[1] ? parts[1].substring(0, 5) : t;
                }
                return t;
            });
            const counts = data.map(item => item.count || 0);

            if (activityChartInstance) {
                activityChartInstance.destroy();
            }

            const ctx = canvas.getContext('2d');
            const gradient = ctx.createLinearGradient(0, 0, 0, 260);
            gradient.addColorStop(0, 'rgba(0, 242, 254, 0.4)');
            gradient.addColorStop(1, 'rgba(0, 242, 254, 0.0)');

            activityChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Events / Time Window',
                        data: counts,
                        borderColor: '#00f2fe',
                        borderWidth: 3,
                        backgroundColor: gradient,
                        fill: true,
                        tension: 0.38,
                        pointBackgroundColor: '#00f2fe',
                        pointBorderColor: '#07090e',
                        pointBorderWidth: 2,
                        pointRadius: counts.length > 30 ? 1.5 : 4,
                        pointHoverRadius: 7,
                        pointHoverBackgroundColor: '#ffffff',
                        pointHoverBorderColor: '#00f2fe'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.95)',
                            titleColor: '#ffffff',
                            titleFont: { family: 'Plus Jakarta Sans', weight: '700', size: 12 },
                            bodyColor: '#00f2fe',
                            bodyFont: { family: 'JetBrains Mono', weight: '600', size: 13 },
                            borderColor: 'rgba(0, 242, 254, 0.4)',
                            borderWidth: 1,
                            padding: 12,
                            displayColors: false,
                            cornerRadius: 8
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.04)' },
                            ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 12 }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255, 255, 255, 0.04)' },
                            ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Failed to render activity chart:', error);
        }
    }

    /**
     * Load and render Protocol Distribution (Chart.js Doughnut Chart)
     */
    async function loadProtocolChart(datasetId) {
        const canvas = document.getElementById('protocolChart');
        if (!canvas) return;

        try {
            const data = await CTR.apiCall(`/api/dashboard/protocol-distribution?dataset_id=${datasetId}`);
            if (!Array.isArray(data) || data.length === 0) return;

            const labels = data.map(item => (item.protocol || 'UNKNOWN').toUpperCase());
            const counts = data.map(item => item.count || 0);

            const colors = [
                '#00f2fe', '#8b5cf6', '#3b82f6', '#10b981', '#f59e0b', '#ff3366', '#d946ef', '#06b6d4'
            ];

            if (protocolChartInstance) {
                protocolChartInstance.destroy();
            }

            const ctx = canvas.getContext('2d');
            protocolChartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: counts,
                        backgroundColor: colors.slice(0, labels.length),
                        borderColor: '#07090e',
                        borderWidth: 3,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#cbd5e1',
                                font: { size: 11, family: 'Plus Jakarta Sans', weight: '600' },
                                boxWidth: 10,
                                padding: 14,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.95)',
                            titleColor: '#ffffff',
                            titleFont: { family: 'Plus Jakarta Sans', weight: '700' },
                            bodyColor: '#00f2fe',
                            bodyFont: { family: 'JetBrains Mono', weight: '600' },
                            borderColor: 'rgba(0, 242, 254, 0.4)',
                            borderWidth: 1,
                            padding: 10,
                            cornerRadius: 8
                        }
                    },
                    cutout: '72%'
                }
            });
        } catch (error) {
            console.error('Failed to render protocol chart:', error);
        }
    }

    /**
     * Load Top Communicating Hosts
     */
    async function loadTopHosts(datasetId) {
        const srcBody = document.getElementById('topSourcesTableBody');
        const dstBody = document.getElementById('topDestTableBody');

        try {
            const data = await CTR.apiCall(`/api/dashboard/top-hosts?dataset_id=${datasetId}&limit=10`);
            
            // Sources Table
            if (srcBody) {
                const sources = data.top_sources || [];
                if (sources.length === 0) {
                    srcBody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-secondary">No source telemetry found</td></tr>';
                } else {
                    srcBody.innerHTML = sources.map((s, idx) => `
                        <tr>
                            <td><span class="badge bg-dark border border-secondary text-secondary">${idx + 1}</span></td>
                            <td>${CTR.formatIP(s.ip)}</td>
                            <td class="text-end fw-semibold text-light">${Number(s.count || 0).toLocaleString()}</td>
                            <td class="text-end">
                                <a href="/timeline?src_ip=${encodeURIComponent(s.ip)}" class="btn btn-xs soc-btn-outline-cyan me-1" title="Filter Timeline">
                                    <i class="bi bi-clock-history"></i>
                                </a>
                                <a href="/network-graph" class="btn btn-xs soc-btn-outline-cyan" title="Network Graph">
                                    <i class="bi bi-diagram-3"></i>
                                </a>
                            </td>
                        </tr>
                    `).join('');
                }
            }

            // Destinations Table
            if (dstBody) {
                const dests = data.top_destinations || [];
                if (dests.length === 0) {
                    dstBody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-secondary">No destination telemetry found</td></tr>';
                } else {
                    dstBody.innerHTML = dests.map((d, idx) => `
                        <tr>
                            <td><span class="badge bg-dark border border-secondary text-secondary">${idx + 1}</span></td>
                            <td>${CTR.formatIP(d.ip)}</td>
                            <td class="text-end fw-semibold text-light">${Number(d.count || 0).toLocaleString()}</td>
                            <td class="text-end">
                                <a href="/timeline?dst_ip=${encodeURIComponent(d.ip)}" class="btn btn-xs soc-btn-outline-cyan me-1" title="Filter Timeline">
                                    <i class="bi bi-clock-history"></i>
                                </a>
                                <a href="/network-graph" class="btn btn-xs soc-btn-outline-cyan" title="Network Graph">
                                    <i class="bi bi-diagram-3"></i>
                                </a>
                            </td>
                        </tr>
                    `).join('');
                }
            }
        } catch (error) {
            console.error('Failed to load top hosts:', error);
            if (srcBody) srcBody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-danger">Error loading sources</td></tr>';
            if (dstBody) dstBody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-danger">Error loading destinations</td></tr>';
        }
    }

    /**
     * Load Recent Alerts
     */
    async function loadRecentAlerts(datasetId) {
        const container = document.getElementById('recentAlertsContainer');
        if (!container) return;

        try {
            const alerts = await CTR.apiCall(`/api/dashboard/recent-alerts?dataset_id=${datasetId}&limit=10`);
            if (!Array.isArray(alerts) || alerts.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 text-secondary">
                        <i class="bi bi-shield-check fs-2 text-success d-block mb-2"></i>
                        No alerts detected in this dataset.
                    </div>
                `;
                return;
            }

            container.innerHTML = alerts.map(alert => `
                <div class="p-3 mb-2 rounded soc-card border-start-3" style="border-left: 4px solid var(--sev-${(alert.severity||'info').toLowerCase()}); background-color: rgba(15, 23, 42, 0.4);">
                    <div class="d-flex align-items-center justify-content-between mb-1">
                        <div>
                            ${CTR.severityBadge(alert.severity)}
                            <span class="ms-2 fw-bold text-light">${alert.rule_name || 'Network Anomaly Detected'}</span>
                        </div>
                        <span class="fs-xs text-muted font-monospace">${CTR.formatTimestamp(alert.timestamp)}</span>
                    </div>
                    <p class="text-secondary small mb-2">${alert.reason || 'Heuristic threat pattern matched network traffic logs.'}</p>
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="fs-xs font-monospace text-secondary">
                            <span>Src: ${CTR.formatIP(alert.src_ip)}</span>
                            <span class="mx-1 text-muted">&rarr;</span>
                            <span>Dst: ${CTR.formatIP(alert.dst_ip)}</span>
                        </div>
                        <a href="/alerts" class="btn btn-xs soc-btn-outline-cyan">Investigate</a>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Failed to load recent alerts:', error);
            container.innerHTML = '<div class="text-center py-4 text-danger">Failed to load active alerts</div>';
        }
    }

    /**
     * Refresh all dashboard widgets for active dataset
     */
    async function refreshDashboard() {
        const datasetId = CTR.getCurrentDatasetId();
        if (!datasetId) {
            emptyStateEl.style.display = 'block';
            activeViewEl.style.display = 'none';
            return;
        }

        const hasEvents = await loadStats(datasetId);
        if (hasEvents) {
            loadActivityChart(datasetId);
            loadProtocolChart(datasetId);
            loadTopHosts(datasetId);
            loadRecentAlerts(datasetId);
        }
    }

    // Listen for dataset changes across app
    document.addEventListener('datasetChanged', (e) => {
        refreshDashboard();
    });

    // Initial load
    refreshDashboard();
});
