/**
 * Campus Network Attack – Timeline Reconstructor
 * Cytoscape Network Graph Logic (network_graph.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    let cy = null;
    const cyContainer = document.getElementById('cyNetwork');
    const drawer = document.getElementById('hostDetailDrawer');
    const closeDrawerBtn = document.getElementById('closeDrawerBtn');
    const drawerHostIp = document.getElementById('drawerHostIp');
    const drawerBody = document.getElementById('drawerBody');
    const nodeEdgeCountBadge = document.getElementById('graphNodeEdgeCount');
    const layoutSelect = document.getElementById('graphLayoutSelect');
    const categorySelect = document.getElementById('graphCategoryFilter');
    const searchInput = document.getElementById('graphSearchInput');
    const searchBtn = document.getElementById('graphSearchBtn');
    const zoomInBtn = document.getElementById('zoomInBtn');
    const zoomOutBtn = document.getElementById('zoomOutBtn');
    const fitBtn = document.getElementById('fitGraphBtn');
    const legendCloseBtn = document.getElementById('legendCloseBtn');
    const legendBox = document.getElementById('graphLegend');

    /**
     * Initialize Cytoscape Instance
     */
    function initCytoscape() {
        if (!cyContainer || !window.cytoscape) return;

        cy = cytoscape({
            container: cyContainer,
            boxSelectionEnabled: false,
            autounselectify: false,
            style: [
                {
                    selector: 'node',
                    style: {
                        'content': 'data(label)',
                        'text-valign': 'bottom',
                        'text-margin-y': 7,
                        'color': '#cbd5e1',
                        'font-size': '10px',
                        'font-weight': '600',
                        'font-family': 'JetBrains Mono, Plus Jakarta Sans, monospace',
                        'background-color': '#00f2fe',
                        'border-width': 2.5,
                        'border-color': 'rgba(10, 15, 26, 0.9)',
                        'border-opacity': 1.0,
                        'width': 'mapData(event_count, 1, 300, 26, 58)',
                        'height': 'mapData(event_count, 1, 300, 26, 58)',
                        'transition-property': 'background-color, line-color, target-arrow-color, width, height, border-width',
                        'transition-duration': '0.2s'
                    }
                },
                {
                    selector: 'node[?is_suspicious]',
                    style: {
                        'background-color': '#ff3366',
                        'border-color': 'rgba(255, 51, 102, 0.5)',
                        'border-width': 3.5,
                        'color': '#ff8da1'
                    }
                },
                {
                    selector: 'node[type = "server"]',
                    style: {
                        'background-color': '#3b82f6',
                        'shape': 'round-rectangle',
                        'border-color': 'rgba(59, 130, 246, 0.6)',
                        'border-width': 3
                    }
                },
                {
                    selector: 'node:selected, node.highlighted',
                    style: {
                        'border-color': '#ffffff',
                        'border-width': 4,
                        'underlay-color': '#00f2fe',
                        'underlay-padding': 6,
                        'underlay-opacity': 0.35
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'curve-style': 'bezier',
                        'target-arrow-shape': 'triangle',
                        'target-arrow-color': '#00f2fe',
                        'line-color': 'rgba(71, 85, 105, 0.6)',
                        'width': 'mapData(count, 1, 100, 1.5, 6)',
                        'opacity': 0.8,
                        'arrow-scale': 0.85
                    }
                },
                {
                    selector: 'edge.highlighted',
                    style: {
                        'line-color': '#00f2fe',
                        'target-arrow-color': '#38bdf8',
                        'opacity': 1.0,
                        'width': 4.5
                    }
                }
            ],
            layout: {
                name: 'cose',
                animate: false
            }
        });

        // Event: Click on Node -> Open Dossier
        cy.on('tap', 'node', function(evt) {
            const node = evt.target;
            const ip = node.id();
            openHostDrawer(ip);
        });

        // Event: Click on Edge -> Quick Connection Toast/Detail
        cy.on('tap', 'edge', function(evt) {
            const edge = evt.target;
            const src = edge.data('source');
            const tgt = edge.data('target');
            const count = edge.data('count') || 1;
            const protocols = edge.data('protocols') || ['TCP'];
            const protoStr = Array.isArray(protocols) ? protocols.join(', ') : protocols;

            CTR.showToast(`Connection: ${src} &rarr; ${tgt} (${protoStr}) — ${count} flows`, 'info', 'Network Link');
        });

        // Event: Click on background -> Close Drawer
        cy.on('tap', function(evt) {
            if (evt.target === cy) {
                closeDrawer();
                cy.elements().removeClass('highlighted');
            }
        });
    }

    /**
     * Fetch Graph Data from /api/network/graph
     */
    async function loadGraphData() {
        if (!cy) return;
        const datasetId = CTR.getCurrentDatasetId();
        if (!datasetId) {
            nodeEdgeCountBadge.textContent = 'No dataset selected';
            cy.elements().remove();
            return;
        }

        CTR.showLoading(cyContainer, 'Computing topological graph layout...');

        try {
            const category = categorySelect ? categorySelect.value : '';
            let url = `/api/network/graph?dataset_id=${datasetId}`;
            if (category) url += `&category=${encodeURIComponent(category)}`;

            const graphData = await CTR.apiCall(url);
            cy.elements().remove();

            const nodes = graphData.nodes || [];
            const edges = graphData.edges || [];

            nodeEdgeCountBadge.textContent = `${nodes.length} nodes, ${edges.length} edges`;

            if (nodes.length === 0) {
                CTR.showToast('No active network connections found in this query.', 'warning');
                return;
            }

            // Convert to Cytoscape element structure
            const cyElements = [];
            nodes.forEach(n => {
                cyElements.push({
                    group: 'nodes',
                    data: {
                        id: n.id,
                        label: n.label || n.hostname || n.id,
                        hostname: n.hostname || '',
                        event_count: n.event_count || 1,
                        is_suspicious: !!n.is_suspicious,
                        type: n.is_server ? 'server' : 'host'
                    }
                });
            });

            edges.forEach(e => {
                cyElements.push({
                    group: 'edges',
                    data: {
                        id: `e_${e.source}_${e.target}`,
                        source: e.source,
                        target: e.target,
                        count: e.count || 1,
                        protocols: e.protocols || ['TCP']
                    }
                });
            });

            cy.add(cyElements);
            applyLayout(layoutSelect ? layoutSelect.value : 'cose');
        } catch (error) {
            console.error('Failed to load graph data:', error);
            CTR.showToast('Failed to load network graph: ' + error.message, 'error');
        } finally {
            CTR.hideLoading(cyContainer);
        }
    }

    /**
     * Apply Cytoscape Layout
     */
    function applyLayout(layoutName = 'cose') {
        if (!cy || cy.nodes().length === 0) return;

        let options = { name: layoutName, animate: true, animationDuration: 600 };

        if (layoutName === 'cose') {
            options = {
                name: 'cose',
                animate: true,
                randomize: false,
                nodeOverlap: 20,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            };
        } else if (layoutName === 'circle') {
            options = { name: 'circle', padding: 30 };
        } else if (layoutName === 'breadthfirst') {
            options = { name: 'breadthfirst', directed: true, padding: 30 };
        } else if (layoutName === 'concentric') {
            options = { name: 'concentric', minNodeSpacing: 50 };
        }

        cy.layout(options).run();
    }

    /**
     * Slide-out Drawer: Open and Fetch Host Dossier
     */
    async function openHostDrawer(ip) {
        if (!drawer) return;
        const datasetId = CTR.getCurrentDatasetId();
        drawerHostIp.textContent = ip;
        drawerBody.innerHTML = '<div class="text-center py-5"><div class="soc-spinner-cyan mb-2"></div><div class="text-cyan small">Querying host telemetry...</div></div>';
        drawer.classList.add('open');

        // Highlight host in Cytoscape
        cy.elements().removeClass('highlighted');
        const node = cy.$id(ip);
        if (node && node.length > 0) {
            node.addClass('highlighted');
            node.connectedEdges().addClass('highlighted');
        }

        try {
            const host = await CTR.apiCall(`/api/network/host/${encodeURIComponent(ip)}?dataset_id=${datasetId}`);
            
            const connections = host.connections || [];
            const recentEvents = host.recent_events || [];

            let connectionsHtml = '';
            if (connections.length === 0) {
                connectionsHtml = '<div class="text-secondary small">No recorded peer connections.</div>';
            } else {
                connectionsHtml = `
                    <div class="soc-table-wrapper border-secondary mb-3">
                        <table class="soc-table">
                            <thead>
                                <tr>
                                    <th>Remote Host</th>
                                    <th>Dir</th>
                                    <th class="text-end">Events</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${connections.slice(0, 8).map(c => `
                                    <tr>
                                        <td>${CTR.formatIP(c.remote_ip)}</td>
                                        <td><span class="badge ${c.direction === 'in' ? 'bg-primary' : 'bg-info'} fs-xs">${(c.direction || 'out').toUpperCase()}</span></td>
                                        <td class="text-end fw-bold text-light">${c.count || 1}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }

            let recentEventsHtml = '';
            if (recentEvents.length === 0) {
                recentEventsHtml = '<div class="text-secondary small">No recent telemetry logs.</div>';
            } else {
                recentEventsHtml = recentEvents.slice(0, 5).map(ev => `
                    <div class="p-2 mb-2 rounded soc-card border-secondary" style="background: rgba(15, 23, 42, 0.6);">
                        <div class="d-flex align-items-center justify-content-between mb-1">
                            ${CTR.severityBadge(ev.severity)}
                            <span class="fs-xs font-monospace text-muted">${CTR.formatTimestamp(ev.timestamp)}</span>
                        </div>
                        <div class="fs-xs text-light text-truncate">${ev.description || 'Flow observed'}</div>
                    </div>
                `).join('');
            }

            drawerBody.innerHTML = `
                <!-- Host Metadata -->
                <div class="soc-card p-3 mb-3 border-secondary" style="background: rgba(15, 23, 42, 0.5);">
                    <div class="d-flex justify-content-between mb-2">
                        <span class="text-secondary small">Hostname:</span>
                        <span class="text-light fw-semibold">${host.hostname || 'Unresolved DHCP'}</span>
                    </div>
                    <div class="d-flex justify-content-between mb-2">
                        <span class="text-secondary small">First Seen:</span>
                        <span class="text-light fs-xs font-monospace">${CTR.formatTimestamp(host.first_seen)}</span>
                    </div>
                    <div class="d-flex justify-content-between mb-2">
                        <span class="text-secondary small">Last Seen:</span>
                        <span class="text-light fs-xs font-monospace">${CTR.formatTimestamp(host.last_seen)}</span>
                    </div>
                    <div class="d-flex justify-content-between">
                        <span class="text-secondary small">Total Events:</span>
                        <span class="badge bg-cyan text-dark fw-bold">${(host.event_count || 0).toLocaleString()}</span>
                    </div>
                </div>

                <div class="d-grid mb-3">
                    <a href="/timeline?src_ip=${encodeURIComponent(ip)}" class="btn btn-sm soc-btn-outline-cyan">
                        <i class="bi bi-clock-history me-1"></i>Filter Timeline For This Host
                    </a>
                </div>

                <!-- Peer Connections -->
                <h6 class="text-light fw-bold small text-uppercase mb-2">
                    <i class="bi bi-arrow-left-right text-cyan me-1"></i> Active Peer Connections (${connections.length})
                </h6>
                ${connectionsHtml}

                <!-- Recent Telemetry -->
                <h6 class="text-light fw-bold small text-uppercase mb-2">
                    <i class="bi bi-activity text-cyan me-1"></i> Recent Transmissions
                </h6>
                ${recentEventsHtml}
            `;
        } catch (error) {
            console.error('Failed to load host detail:', error);
            drawerBody.innerHTML = `<div class="p-3 text-danger text-center">Failed to load host details: ${error.message}</div>`;
        }
    }

    function closeDrawer() {
        if (drawer) drawer.classList.remove('open');
    }

    if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeDrawer);

    // Search Node by IP or Hostname
    function handleSearch() {
        if (!cy) return;
        const query = searchInput.value.trim().toLowerCase();
        if (!query) {
            cy.elements().removeClass('highlighted');
            return;
        }

        const match = cy.nodes().filter(node => {
            const id = node.id().toLowerCase();
            const label = (node.data('label') || '').toLowerCase();
            const hostname = (node.data('hostname') || '').toLowerCase();
            return id.includes(query) || label.includes(query) || hostname.includes(query);
        });

        cy.elements().removeClass('highlighted');

        if (match.length > 0) {
            match.addClass('highlighted');
            cy.animate({
                center: { eles: match },
                zoom: 1.8,
                duration: 500
            });
            openHostDrawer(match[0].id());
        } else {
            CTR.showToast(`No host found matching "${query}"`, 'warning');
        }
    }

    if (searchBtn) searchBtn.addEventListener('click', handleSearch);
    if (searchInput) {
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') handleSearch();
        });
    }

    // Zoom and Fit controls
    if (zoomInBtn) zoomInBtn.addEventListener('click', () => cy && cy.zoom(cy.zoom() * 1.3));
    if (zoomOutBtn) zoomOutBtn.addEventListener('click', () => cy && cy.zoom(cy.zoom() * 0.7));
    if (fitBtn) fitBtn.addEventListener('click', () => cy && cy.fit(null, 40));

    // Layout Selector
    if (layoutSelect) {
        layoutSelect.addEventListener('change', (e) => {
            applyLayout(e.target.value);
        });
    }

    // Category Selector
    if (categorySelect) {
        categorySelect.addEventListener('change', () => {
            loadGraphData();
        });
    }

    // Legend Toggle
    if (legendCloseBtn && legendBox) {
        legendCloseBtn.addEventListener('click', () => {
            legendBox.style.display = legendBox.style.display === 'none' ? 'block' : 'none';
        });
    }

    // Window Resize -> cytoscape resize
    window.addEventListener('resize', () => {
        if (cy) cy.resize();
    });

    // Dataset Change Listener
    document.addEventListener('datasetChanged', () => {
        closeDrawer();
        loadGraphData();
    });

    // Start Cytoscape and load
    initCytoscape();
    loadGraphData();
});
