/**
 * visualizations.js - Scripts for network/security zone visualizations
 * Uses D3.js for security zone visualizations
 */

// Initialize visualizations when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Visualizations initialized');
    
    // Initialize security zone visualization if element exists
    const securityZoneContainer = document.getElementById('security-zone-visualization');
    if (securityZoneContainer) {
        initializeSecurityZoneVisualization(securityZoneContainer);
    }
    
    // Initialize network diagram if element exists
    const networkDiagramContainer = document.getElementById('network-diagram');
    if (networkDiagramContainer) {
        initializeNetworkDiagram(networkDiagramContainer);
    }
});

/**
 * Initialize security zone visualization using D3.js
 * @param {HTMLElement} container - Container element for visualization
 */
function initializeSecurityZoneVisualization(container) {
    // Get vessel ID from data attribute
    const vesselId = container.dataset.vesselId;
    if (!vesselId) {
        console.error('Vessel ID not found for security zone visualization');
        return;
    }
    
    // Fetch security zone data for the vessel
    fetch(`/api/security_zones?vessel_id=${vesselId}`)
        .then(response => response.json())
        .then(data => {
            if (data && Array.isArray(data)) {
                // Transform data into expected format
                const formattedData = {
                    vessel_name: document.getElementById('vessel-name')?.textContent || "Vessel",
                    zones: data.map(zone => ({
                        id: zone.id,
                        name: zone.name,
                        description: zone.description,
                        risk_level: zone.risk_level,
                        asset_count: 0,  // We'll update this later
                        assets: []
                    }))
                };
                
                // For now, we'll use a simpler approach without fetching assets
                // In the future, we can add an endpoint to get assets by zone
                formattedData.zones.forEach(zone => {
                    // Get asset count from database via our existing API
                    fetch(`/api/assets?security_zone_id=${zone.id}`)
                        .catch(() => ({ json: () => Promise.resolve([]) }))
                        .then(response => response.json())
                        .then(assets => {
                            zone.assets = assets || [];
                            zone.asset_count = assets?.length || 0;
                        })
                        .catch(error => {
                            console.error('Error fetching assets:', error);
                            zone.assets = [];
                            zone.asset_count = 0;
                        });
                });
                
                // Since we don't have Promise.all anymore, we'll render immediately
                // and let the asset counts update when they arrive
                renderSecurityZones(container, formattedData);
            } else {
                container.innerHTML = `<div class="alert alert-warning">No security zones found</div>`;
            }
        })
        .catch(error => {
            console.error('Error fetching security zones:', error);
            container.innerHTML = '<div class="alert alert-danger">Failed to load security zone data</div>';
        });
}

/**
 * Render security zones visualization using D3.js
 * @param {HTMLElement} container - Container element for visualization
 * @param {Object} data - Security zones data
 */
function renderSecurityZones(container, data) {
    // Clear container
    container.innerHTML = '';
    
    // Set dimensions
    const width = container.clientWidth;
    const height = 600;
    
    // Create SVG element
    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet');
    
    // Add vessel name as title
    svg.append('text')
        .attr('x', width / 2)
        .attr('y', 30)
        .attr('text-anchor', 'middle')
        .attr('class', 'h4')
        .text(`${data.vessel_name} - Security Zones`);
    
    // Create a group for all visualization elements
    const g = svg.append('g')
        .attr('transform', `translate(0, 60)`);
    
    // Create a force simulation
    const simulation = d3.forceSimulation()
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2 - 60))
        .force('collision', d3.forceCollide().radius(d => d.radius + 10));
    
    // Prepare zones data
    const zones = data.zones.map((zone, index) => {
        // Base radius on asset count
        const baseRadius = 50;
        const radius = baseRadius + (zone.asset_count * 5);
        
        return {
            id: zone.id,
            name: zone.name,
            description: zone.description,
            risk_level: zone.risk_level || 'medium',
            assets: zone.assets || [],
            asset_count: zone.asset_count,
            radius: radius,
            x: width / 2 + (index * 50) - ((data.zones.length * 50) / 2),
            y: height / 3
        };
    });
    
    // Draw zones
    const zoneElements = g.selectAll('.zone')
        .data(zones)
        .enter()
        .append('g')
        .attr('class', 'zone')
        .attr('id', d => `zone-${d.id}`);
    
    // Zone circles
    zoneElements.append('circle')
        .attr('r', d => d.radius)
        .attr('fill', d => getRiskLevelColor(d.risk_level, 0.2))
        .attr('stroke', d => getRiskLevelColor(d.risk_level, 1))
        .attr('stroke-width', 2);
    
    // Zone labels
    zoneElements.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', -5)
        .attr('class', 'zone-label')
        .text(d => d.name);
    
    // Zone asset count
    zoneElements.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 15)
        .attr('class', 'asset-count')
        .text(d => `${d.asset_count} assets`);
    
    // Create asset nodes
    let assets = [];
    zones.forEach(zone => {
        zone.assets.forEach(asset => {
            assets.push({
                id: asset.id,
                name: asset.name,
                type: asset.type,
                function: asset.function,
                parent_zone: zone.id,
                radius: 10,
                x: zone.x + (Math.random() * 40 - 20),
                y: zone.y + (Math.random() * 40 - 20)
            });
        });
    });
    
    // Draw assets
    const assetElements = g.selectAll('.asset')
        .data(assets)
        .enter()
        .append('g')
        .attr('class', 'asset')
        .attr('id', d => `asset-${d.id}`);
    
    // Asset circles
    assetElements.append('circle')
        .attr('r', d => d.radius)
        .attr('fill', '#495057')
        .attr('stroke', '#212529')
        .attr('stroke-width', 1);
    
    // Asset type icon (simplified to a letter)
    assetElements.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 3)
        .attr('class', 'asset-icon')
        .attr('fill', 'white')
        .attr('font-size', '8px')
        .text(d => d.type ? d.type.charAt(0).toUpperCase() : 'A');
    
    // Add hover tooltips
    zoneElements
        .append('title')
        .text(d => `${d.name}: ${d.description || 'No description'}\nRisk Level: ${d.risk_level || 'Unknown'}\nAssets: ${d.asset_count}`);
    
    assetElements
        .append('title')
        .text(d => `${d.name}\nType: ${d.type || 'Unknown'}\nFunction: ${d.function || 'Unknown'}`);
    
    // Update simulation with nodes
    simulation.nodes([...zones, ...assets])
        .on('tick', ticked);
    
    // Add forces for zone grouping
    simulation.force('zones', d3.forceLink()
        .id(d => d.id)
        .strength(d => {
            if (d.source.parent_zone && d.source.parent_zone === d.target.id) {
                return 0.8; // Strong attraction between asset and its zone
            }
            return 0; // No attraction between unrelated elements
        })
    );
    
    // Create links for assets to their zones
    const links = [];
    assets.forEach(asset => {
        links.push({
            source: asset.id,
            target: asset.parent_zone
        });
    });
    
    simulation.force('zones').links(links);
    
    // Tick function to update positions
    function ticked() {
        zoneElements
            .attr('transform', d => `translate(${d.x}, ${d.y})`);
        
        assetElements
            .attr('transform', d => `translate(${d.x}, ${d.y})`);
    }
    
    // Add legend
    const legendData = [
        { label: 'High Risk', color: getRiskLevelColor('high', 1) },
        { label: 'Medium Risk', color: getRiskLevelColor('medium', 1) },
        { label: 'Low Risk', color: getRiskLevelColor('low', 1) }
    ];
    
    const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', `translate(${width - 150}, 80)`);
    
    legend.selectAll('rect')
        .data(legendData)
        .enter()
        .append('rect')
        .attr('x', 0)
        .attr('y', (d, i) => i * 25)
        .attr('width', 15)
        .attr('height', 15)
        .attr('fill', d => d.color);
    
    legend.selectAll('text')
        .data(legendData)
        .enter()
        .append('text')
        .attr('x', 25)
        .attr('y', (d, i) => i * 25 + 12)
        .text(d => d.label);
}

/**
 * Initialize network diagram visualization
 * @param {HTMLElement} container - Container element for visualization
 */
function initializeNetworkDiagram(container) {
    // For a more detailed network diagram, we would fetch real network topology
    // This simplified version just shows connections between security zones
    
    // Get vessel ID from data attribute
    const vesselId = container.dataset.vesselId;
    if (!vesselId) {
        console.error('Vessel ID not found for network diagram');
        return;
    }
    
    // Fetch topology data from our new API endpoint
    fetch(`/api/topology?vessel_id=${vesselId}`)
        .then(response => response.json())
        .then(data => {
            if (data && data.nodes && data.links) {
                renderNetworkDiagram(container, data);
            } else {
                container.innerHTML = `<div class="alert alert-warning">Error loading network diagram: No valid topology data found</div>`;
            }
        })
        .catch(error => {
            console.error('Error fetching security zones for network diagram:', error);
            container.innerHTML = '<div class="alert alert-danger">Failed to load network diagram data</div>';
        });
}

/**
 * Render network diagram visualization using D3.js
 * @param {HTMLElement} container - Container element for visualization
 * @param {Object} data - Security zones data
 */
function renderNetworkDiagram(container, data) {
    // Clear container
    container.innerHTML = '';
    
    // Set dimensions
    const width = container.clientWidth;
    const height = 500;
    
    // Create SVG element
    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet');
    
    // Add vessel name as title
    svg.append('text')
        .attr('x', width / 2)
        .attr('y', 30)
        .attr('text-anchor', 'middle')
        .attr('class', 'h4')
        .text(`${data.vessel_name} - Network Diagram`);
    
    // Create a group for all visualization elements
    const g = svg.append('g')
        .attr('transform', `translate(0, 60)`);
    
    // Prepare zones data as nodes
    const nodes = data.zones.map(zone => ({
        id: zone.id,
        name: zone.name,
        risk_level: zone.risk_level || 'medium',
        asset_count: zone.asset_count
    }));
    
    // Create links between zones (simplified for demo)
    let links = [];
    
    // In a real implementation, we would fetch actual network connections
    // For demo, create a simple hierarchical structure
    for (let i = 0; i < nodes.length - 1; i++) {
        links.push({
            source: nodes[i].id,
            target: nodes[i + 1].id
        });
    }
    
    // Add some cross-connections for more complex networks
    if (nodes.length > 3) {
        links.push({
            source: nodes[0].id,
            target: nodes[nodes.length - 1].id
        });
        
        if (nodes.length > 4) {
            links.push({
                source: nodes[1].id,
                target: nodes[nodes.length - 2].id
            });
        }
    }
    
    // Create a force simulation
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2 - 60))
        .force('collision', d3.forceCollide().radius(40));
    
    // Create arrow marker for links
    svg.append('defs').append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '-0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('orient', 'auto')
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .append('path')
        .attr('d', 'M 0,-5 L 10,0 L 0,5')
        .attr('fill', '#999');
    
    // Draw links
    const link = g.append('g')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('stroke', '#999')
        .attr('stroke-width', 2)
        .attr('marker-end', 'url(#arrowhead)');
    
    // Draw nodes
    const node = g.append('g')
        .selectAll('.node')
        .data(nodes)
        .enter().append('g')
        .attr('class', 'node')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Add circles for nodes
    node.append('circle')
        .attr('r', d => 30 + d.asset_count * 2)
        .attr('fill', d => getRiskLevelColor(d.risk_level, 0.7))
        .attr('stroke', '#fff')
        .attr('stroke-width', 2);
    
    // Add text labels
    node.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 5)
        .attr('fill', '#fff')
        .text(d => d.name);
    
    // Add tooltips
    node.append('title')
        .text(d => `${d.name}\nRisk Level: ${d.risk_level}\nAssets: ${d.asset_count}`);
    
    // Update positions on simulation tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        node
            .attr('transform', d => `translate(${d.x}, ${d.y})`);
    });
    
    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    // Add legend
    const legendData = [
        { label: 'Data Flow', type: 'link' },
        { label: 'High Risk Zone', color: getRiskLevelColor('high', 0.7) },
        { label: 'Medium Risk Zone', color: getRiskLevelColor('medium', 0.7) },
        { label: 'Low Risk Zone', color: getRiskLevelColor('low', 0.7) }
    ];
    
    const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', `translate(${width - 160}, 80)`);
    
    // Add legend items
    const legendItems = legend.selectAll('.legend-item')
        .data(legendData)
        .enter()
        .append('g')
        .attr('class', 'legend-item')
        .attr('transform', (d, i) => `translate(0, ${i * 25})`);
    
    // Add legend icons/colors
    legendItems.each(function(d) {
        const item = d3.select(this);
        
        if (d.type === 'link') {
            item.append('line')
                .attr('x1', 0)
                .attr('y1', 7)
                .attr('x2', 15)
                .attr('y2', 7)
                .attr('stroke', '#999')
                .attr('stroke-width', 2)
                .attr('marker-end', 'url(#arrowhead)');
        } else {
            item.append('rect')
                .attr('width', 15)
                .attr('height', 15)
                .attr('fill', d.color);
        }
        
        item.append('text')
            .attr('x', 25)
            .attr('y', 12)
            .text(d.label);
    });
}

/**
 * Get color for security zone risk level
 * @param {string} risk_level - Risk level (high, medium, low)
 * @param {number} opacity - Opacity value (0-1)
 * @returns {string} CSS color value
 */
function getRiskLevelColor(risk_level, opacity = 1) {
    const colors = {
        'high': `rgba(220, 53, 69, ${opacity})`,     // danger
        'medium': `rgba(255, 193, 7, ${opacity})`,   // warning
        'low': `rgba(25, 135, 84, ${opacity})`,      // success
        'unknown': `rgba(108, 117, 125, ${opacity})` // secondary
    };
    
    return colors[risk_level?.toLowerCase()] || colors.unknown;
}
