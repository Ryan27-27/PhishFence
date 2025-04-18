// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    setupLogFeed();
    initializeCharts();
    setupStatsUpdates();
    setupFormValidation();
});

// Set up log feed with real-time updates via Socket.IO
function setupLogFeed() {
    const logBody = document.getElementById('log-body');

    if (!logBody) {
        console.warn('Log feed element not found');
        return;
    }

    // Load initial logs
    fetch('/api/logs/recent')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(logs => {
            // Make sure we have the expected logs data
            if (!Array.isArray(logs)) {
                console.warn('Received invalid logs data:', logs);
                return;
            }

            // Clear existing logs
            logBody.innerHTML = '';

            // Add each log entry
            logs.forEach(log => {
                const logElement = createLogEntry(log);
                logBody.appendChild(logElement);
            });

            // Scroll to bottom
            scrollToBottom(logBody.parentElement);
        })
        .catch(error => {
            console.error('Error loading logs:', error);
            // Show friendly error message in the log feed
            logBody.innerHTML = `<tr><td colspan="3" class="text-danger">
                Failed to load logs: ${error.message}.
                Please reload the page or check the server status.
            </td></tr>`;
        });

    // Set up Socket.IO for real-time updates
    const socket = io();

    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('log_update', logs => {
        if (!Array.isArray(logs)) {
            console.warn('Received invalid log update:', logs);
            return;
        }

        // Remember if we were scrolled to bottom before adding new logs
        const logContainer = logBody.parentElement;
        const wasAtBottom = isScrolledToBottom(logContainer);

        // Add each new log entry
        logs.forEach(log => {
            const logElement = createLogEntry(log);
            logBody.appendChild(logElement);

            // Limit the number of entries to avoid memory issues
            if (logBody.children.length > 1000) {
                logBody.removeChild(logBody.firstChild);
            }
        });

        // If we were at the bottom before, scroll down to see new logs
        if (wasAtBottom) {
            scrollToBottom(logContainer);
        }
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
    });
}

// Create a new log entry element
function createLogEntry(log) {
    const tr = document.createElement('tr');

    // Set class based on log level
    if (log.levelname === 'ERROR' || log.levelname === 'CRITICAL') {
        tr.className = 'table-danger';
    } else if (log.levelname === 'WARNING') {
        tr.className = 'table-warning';
    } else if (log.levelname === 'INFO') {
        tr.className = 'table-info';
    }

    // Format timestamp
    const timestamp = log.created ? new Date(log.created * 1000).toLocaleString() : '';

    // Create cells
    tr.innerHTML = `
        <td class="log-time">${timestamp}</td>
        <td class="log-level">${log.levelname || ''}</td>
        <td class="log-message">${log.message || ''}</td>
    `;

    return tr;
}

// Initialize charts
function initializeCharts() {
    const trafficChartCanvas = document.getElementById('traffic-chart');
    const threatTypesChartCanvas = document.getElementById('threat-types-chart');

    if (!trafficChartCanvas || !threatTypesChartCanvas) {
        console.warn('Chart elements not found');
        return;
    }

    // Traffic chart
    const trafficChart = new Chart(trafficChartCanvas, {
        type: 'line',
        data: {
            labels: generateTimeLabels(12),  // 12 time intervals
            datasets: [
                {
                    label: 'Total Requests',
                    data: Array(12).fill(0),  // Initialize with zeros
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Blocked Requests',
                    data: Array(12).fill(0),  // Initialize with zeros
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    position: 'top'
                },
                title: {
                    display: true,
                    text: 'Traffic Over Time'
                }
            }
        }
    });

    // Threat types chart
    const threatTypesChart = new Chart(threatTypesChartCanvas, {
        type: 'doughnut',
        data: {
            labels: ['Phishing', 'Malware', 'Suspicious IP', 'Tor Exit Node', 'Other'],
            datasets: [{
                label: 'Threat Types',
                data: [0, 0, 0, 0, 0],  // Initialize with zeros
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(54, 162, 235, 0.8)',
                    'rgba(255, 206, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)',
                    'rgba(153, 102, 255, 0.8)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top'
                },
                title: {
                    display: true,
                    text: 'Threat Types'
                }
            }
        }
    });

    // Update charts immediately and then periodically
    updateCharts(trafficChart, threatTypesChart);
    setInterval(() => updateCharts(trafficChart, threatTypesChart), 10000);
}

// Update charts with demo data
function updateCharts(trafficChart, threatTypesChart) {
    // Use fixed demo data instead of API
    const totalRequests = Math.floor(Math.random() * 10) + 100; // Random value between 100-110
    const blockedRequests = Math.floor(totalRequests * 0.15); // About 15% blocked
    const phishingDetected = Math.floor(blockedRequests * 0.6); // About 60% of blocked are phishing

    // Update traffic chart with simulated time data
    trafficChart.data.datasets[0].data.shift();
    trafficChart.data.datasets[0].data.push(totalRequests);

    trafficChart.data.datasets[1].data.shift();
    trafficChart.data.datasets[1].data.push(blockedRequests);

    trafficChart.data.labels.shift();
    trafficChart.data.labels.push(new Date().toLocaleTimeString());

    trafficChart.update();

    // Update threat types chart
    const threatData = [
        phishingDetected,
        Math.floor(blockedRequests * 0.3),  // Malware (sample)
        Math.floor(blockedRequests * 0.2),  // Suspicious IP (sample)
        Math.floor(blockedRequests * 0.1),  // Tor Exit Node (sample)
        Math.floor(blockedRequests * 0.1)   // Other (remaining)
    ];
    threatTypesChart.data.datasets[0].data = threatData;
    threatTypesChart.update();

    // Update stats counters
    const totalRequestsElement = document.getElementById('total-requests');
    if (totalRequestsElement) {
        totalRequestsElement.textContent = totalRequests;
    }

    const blockedRequestsElement = document.getElementById('blocked-requests');
    if (blockedRequestsElement) {
        blockedRequestsElement.textContent = blockedRequests;
    }

    const phishingDetectedElement = document.getElementById('phishing-detected');
    if (phishingDetectedElement) {
        phishingDetectedElement.textContent = phishingDetected;
    }
}

// Generate time labels for the past n intervals
function generateTimeLabels(count) {
    const labels = [];
    const now = new Date();

    for (let i = count - 1; i >= 0; i--) {
        const time = new Date(now - i * 5 * 60000);  // 5-minute intervals
        labels.push(time.toLocaleTimeString());
    }

    return labels;
}

// Set up real-time stats updates with demo data
function setupStatsUpdates() {
    // Initialize uptime counter
    let uptimeSeconds = 0;

    // Update stats every 5 seconds
    setInterval(() => {
        // Generate demo data
        const totalRequests = Math.floor(Math.random() * 10) + 100; // Random value between 100-110
        const blockedRequests = Math.floor(totalRequests * 0.15); // About 15% blocked
        const phishingDetected = Math.floor(blockedRequests * 0.6); // About 60% of blocked are phishing

        // Update uptime counter
        uptimeSeconds += 5;

        // Update stats display
        const elements = {
            'total-requests': totalRequests,
            'blocked-requests': blockedRequests,
            'phishing-detected': phishingDetected
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        }

        // Update uptime display
        const uptimeElement = document.getElementById('uptime');
        if (uptimeElement) {
            uptimeElement.textContent = formatUptime(uptimeSeconds);
        }
    }, 5000);
}

// Format uptime in days, hours, minutes, seconds
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    seconds %= 86400;
    const hours = Math.floor(seconds / 3600);
    seconds %= 3600;
    const minutes = Math.floor(seconds / 60);
    seconds = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    parts.push(`${seconds}s`);

    return parts.join(' ');
}

// Set up form validation
function setupFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');

    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }

            form.classList.add('was-validated');
        }, false);
    });
}

// Helper function: Check if element is scrolled to bottom
function isScrolledToBottom(element) {
    return element.scrollHeight - element.clientHeight <= element.scrollTop + 1;
}

// Helper function: Scroll element to bottom
function scrollToBottom(element) {
    element.scrollTop = element.scrollHeight;
}