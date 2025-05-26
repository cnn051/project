/**
 * dashboard.js - Scripts for dashboard functionality
 * Handles real-time updates and dashboard widgets
 */

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    
    // Initialize alerts counter
    updateAlertCounters();
    
    // Start polling for data updates
    startDataPolling();
    
    // Initialize charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
});

/**
 * Start polling for data updates
 * Updates alert counters and sensor data at regular intervals
 */
function startDataPolling() {
    // Poll for alerts updates
    setInterval(updateAlertCounters, 30000); // Every 30 seconds
    
    // Poll for vessel data updates
    setInterval(updateVesselData, 60000); // Every minute
}

/**
 * Update alert counters on the dashboard
 */
function updateAlertCounters() {
    fetch('/api/alerts/stats')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Update severity counters
                updateElementText('critical-alerts', data.by_severity.critical);
                updateElementText('high-alerts', data.by_severity.high);
                updateElementText('medium-alerts', data.by_severity.medium);
                updateElementText('low-alerts', data.by_severity.low);
                updateElementText('info-alerts', data.by_severity.info);
                
                // Update status counters
                updateElementText('new-alerts', data.by_status.new);
                updateElementText('acknowledged-alerts', data.by_status.acknowledged);
                updateElementText('resolved-alerts', data.by_status.resolved);
                
                // Update total
                const totalAlerts = data.by_status.new + data.by_status.acknowledged;
                updateElementText('total-active-alerts', totalAlerts);
                
                // Update recent alerts list if it exists
                updateRecentAlerts(data.recent);
            }
        })
        .catch(error => console.error('Error fetching alert stats:', error));
}

/**
 * Update vessel data on the dashboard
 */
function updateVesselData() {
    fetch('/api/vessel_data')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Update vessel cards if they exist
                updateVesselCards(data.vessels);
                
                // Update sensor readings
                updateLatestSensorReadings(data.vessels);
            }
        })
        .catch(error => console.error('Error fetching vessel data:', error));
}

/**
 * Update vessel cards with latest data
 * @param {Array} vessels - Array of vessel data objects
 */
function updateVesselCards(vessels) {
    vessels.forEach(vessel => {
        const vesselCard = document.getElementById(`vessel-card-${vessel.id}`);
        if (!vesselCard) return;
        
        // Update alert badges
        const criticalBadge = vesselCard.querySelector('.critical-badge');
        if (criticalBadge) criticalBadge.textContent = vessel.alerts.critical;
        
        const highBadge = vesselCard.querySelector('.high-badge');
        if (highBadge) highBadge.textContent = vessel.alerts.high;
        
        // Update asset count
        const assetCount = vesselCard.querySelector('.asset-count');
        if (assetCount) assetCount.textContent = vessel.asset_count;
    });
}

/**
 * Update the recent alerts list
 * @param {Array} alerts - Array of recent alert objects
 */
function updateRecentAlerts(alerts) {
    const alertsList = document.getElementById('recent-alerts-list');
    if (!alertsList) return;
    
    // Clear existing content
    alertsList.innerHTML = '';
    
    if (alerts.length === 0) {
        alertsList.innerHTML = '<div class="text-center py-3">No recent alerts</div>';
        return;
    }
    
    // Add each alert to the list
    alerts.forEach(alert => {
        const alertItem = document.createElement('div');
        alertItem.className = `alert-item ${alert.severity.toLowerCase()} mb-3 p-2`;
        
        const severity = alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1).toLowerCase();
        const timeAgo = timeAgoFromIsoDate(alert.created_at);
        
        alertItem.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <h6 class="mb-1">${alert.title}</h6>
                <span class="badge bg-${getSeverityClass(alert.severity)} ms-2">${severity}</span>
            </div>
            <p class="mb-1 small text-truncate-2">${alert.vessel_name}</p>
            <div class="d-flex justify-content-between small">
                <span>#${alert.id}</span>
                <span>${timeAgo}</span>
            </div>
        `;
        
        alertItem.addEventListener('click', () => {
            window.location.href = `/alerts?alert_id=${alert.id}`;
        });
        
        alertsList.appendChild(alertItem);
    });
}

/**
 * Update latest sensor readings display
 * @param {Array} vessels - Array of vessel data objects with sensor readings
 */
function updateLatestSensorReadings(vessels) {
    const sensorContainer = document.getElementById('latest-sensor-readings');
    if (!sensorContainer) return;
    
    // Only update if not already updating to avoid flicker
    if (sensorContainer.getAttribute('data-updating') === 'true') return;
    
    sensorContainer.setAttribute('data-updating', 'true');
    
    // Collect all sensor readings from all vessels
    let allSensors = [];
    vessels.forEach(vessel => {
        if (vessel.latest_sensors && vessel.latest_sensors.length > 0) {
            vessel.latest_sensors.forEach(sensor => {
                allSensors.push({
                    ...sensor,
                    vessel_name: vessel.name
                });
            });
        }
    });
    
    // Sort by timestamp (newest first)
    allSensors.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    // Take top 10
    allSensors = allSensors.slice(0, 10);
    
    // Update the container
    if (allSensors.length === 0) {
        sensorContainer.innerHTML = '<div class="text-center py-3">No recent sensor readings</div>';
    } else {
        sensorContainer.innerHTML = '';
        
        allSensors.forEach(sensor => {
            const sensorItem = document.createElement('div');
            sensorItem.className = 'border-bottom py-2';
            
            const timeAgo = timeAgoFromIsoDate(sensor.timestamp);
            
            sensorItem.innerHTML = `
                <div class="d-flex justify-content-between">
                    <div>
                        <div class="fw-bold">${sensor.sensor_type}</div>
                        <div class="small text-muted">${sensor.vessel_name} / ${sensor.cbs_name}</div>
                    </div>
                    <div class="text-end">
                        <div class="fw-bold">${sensor.value} ${sensor.unit || ''}</div>
                        <div class="small text-muted">${timeAgo}</div>
                    </div>
                </div>
            `;
            
            sensorContainer.appendChild(sensorItem);
        });
    }
    
    sensorContainer.setAttribute('data-updating', 'false');
}

/**
 * Initialize dashboard charts
 */
function initializeCharts() {
    // Initialize alert distribution chart
    initAlertDistributionChart();
    
    // Initialize sensor data trend chart
    initSensorTrendChart();
}

/**
 * Initialize the alert distribution chart
 */
function initAlertDistributionChart() {
    const chartElement = document.getElementById('alert-distribution-chart');
    if (!chartElement) return;
    
    fetch('/api/alerts/stats')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const ctx = chartElement.getContext('2d');
                
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [
                                data.by_severity.critical,
                                data.by_severity.high,
                                data.by_severity.medium,
                                data.by_severity.low,
                                data.by_severity.info
                            ],
                            backgroundColor: [
                                '#dc3545', // danger
                                '#ffc107', // warning
                                '#0d6efd', // primary
                                '#0dcaf0', // info
                                '#6c757d'  // secondary
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            },
                            title: {
                                display: true,
                                text: 'Active Alerts by Severity'
                            }
                        }
                    }
                });
            }
        })
        .catch(error => console.error('Error initializing alert chart:', error));
}

/**
 * Initialize the sensor trend chart
 */
function initSensorTrendChart() {
    // This would use real data from an API endpoint in production
    // For now, we'll use dummy data for demonstration
    const chartElement = document.getElementById('sensor-trend-chart');
    if (!chartElement) return;
    
    const ctx = chartElement.getContext('2d');
    
    // Generate labels for the last 7 days
    const labels = [];
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Network Traffic (GB)',
                data: [12, 19, 8, 15, 20, 14, 18],
                borderColor: '#0d6efd',
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                tension: 0.4,
                fill: true
            }, {
                label: 'CPU Load (%)',
                data: [45, 60, 30, 70, 50, 40, 65],
                borderColor: '#20c997',
                backgroundColor: 'rgba(32, 201, 151, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'System Performance Trends'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Helper function to update text content
 * @param {string} elementId - ID of element to update
 * @param {string|number} text - New text content
 */
function updateElementText(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = text;
    }
}

/**
 * Get Bootstrap class name for alert severity
 * @param {string} severity - Alert severity
 * @returns {string} Bootstrap class name
 */
function getSeverityClass(severity) {
    const classes = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'primary',
        'low': 'info',
        'info': 'secondary'
    };
    
    return classes[severity.toLowerCase()] || 'secondary';
}

/**
 * Calculate time ago from ISO date string
 * @param {string} isoDate - ISO format date string
 * @returns {string} Time ago text
 */
function timeAgoFromIsoDate(isoDate) {
    const date = new Date(isoDate);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.round(diffMs / 1000);
    
    if (diffSec < 60) return `${diffSec} seconds ago`;
    
    const diffMin = Math.round(diffSec / 60);
    if (diffMin < 60) return `${diffMin} minutes ago`;
    
    const diffHour = Math.round(diffMin / 60);
    if (diffHour < 24) return `${diffHour} hours ago`;
    
    const diffDay = Math.round(diffHour / 24);
    if (diffDay < 30) return `${diffDay} days ago`;
    
    const diffMonth = Math.round(diffDay / 30);
    if (diffMonth < 12) return `${diffMonth} months ago`;
    
    const diffYear = Math.round(diffMonth / 12);
    return `${diffYear} years ago`;
}
