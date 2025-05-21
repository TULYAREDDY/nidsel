// Global variables
let networkData = null;
let attackHistory = [];
let currentThreatLevel = "low";
let mlModelStats = null;
let simulationInterval = null;
let attackChart = null;
let trafficChart = null;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeNetworkMap();
    startRealTimeUpdates();
    loadAttackHistory();
    updateMLStats();
});

// Initialize charts
function initializeCharts() {
    // Attack Distribution Chart
    const attackCtx = document.getElementById('attackDistributionChart').getContext('2d');
    attackChart = new Chart(attackCtx, {
        type: 'pie',
        data: {
            labels: ['Malicious', 'Suspicious', 'Normal'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#dc3545', '#ffc107', '#28a745']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });

    // Traffic Analysis Chart
    const trafficCtx = document.getElementById('trafficAnalysisChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: Array(10).fill(''),
            datasets: [{
                label: 'Traffic Volume',
                data: Array(10).fill(0),
                borderColor: '#007bff',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Initialize network map
function initializeNetworkMap() {
    const width = document.getElementById('networkMap').offsetWidth;
    const height = 400;

    const svg = d3.select('#networkMap')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Add legend
    const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', 'translate(20, 20)');

    const nodeTypes = [
        { type: 'normal', color: '#28a745' },
        { type: 'attacker', color: '#dc3545' },
        { type: 'target', color: '#007bff' }
    ];

    nodeTypes.forEach((type, i) => {
        const legendRow = legend.append('g')
            .attr('transform', `translate(0, ${i * 20})`);

        legendRow.append('circle')
            .attr('r', 6)
            .attr('fill', type.color);

        legendRow.append('text')
            .attr('x', 12)
            .attr('y', 4)
            .text(type.type);
    });

    // Fetch initial network data
    fetch('/api/network-data')
        .then(response => response.json())
        .then(data => {
            networkData = data;
            visualizeNetwork(data);
        });
}

// Visualize network data
function visualizeNetwork(data) {
    const width = document.getElementById('networkMap').offsetWidth;
    const height = 400;

    const svg = d3.select('#networkMap svg');
    svg.selectAll('*').remove();

    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.links).id(d => d.id))
        .force('charge', d3.forceManyBody().strength(-100))
        .force('center', d3.forceCenter(width / 2, height / 2));

    const link = svg.append('g')
        .selectAll('line')
        .data(data.links)
        .enter()
        .append('line')
        .attr('stroke', '#999')
        .attr('stroke-opacity', 0.6)
        .attr('stroke-width', d => Math.sqrt(d.value));

    const node = svg.append('g')
        .selectAll('circle')
        .data(data.nodes)
        .enter()
        .append('circle')
        .attr('r', 5)
        .attr('fill', d => {
            switch(d.type) {
                case 'normal': return '#28a745';
                case 'attacker': return '#dc3545';
                case 'target': return '#007bff';
                default: return '#999';
            }
        })
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    node.append('title')
        .text(d => d.id);

    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
    });

    function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
    }

    function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
    }

    function dragended(event) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
    }
}

// Start real-time updates
function startRealTimeUpdates() {
    let firstLoad = true;
    setInterval(() => {
        fetch('/api/realtime-data')
            .then(response => response.json())
            .then(data => {
                updateAttackHistory(data.attack_history);
                updateThreatLevel(data.threat_level);
                updateMLStats(data.ml_stats);
                updateCharts(data.attack_history, data.ml_stats);
                updateNetworkMap();
                if (firstLoad) {
                    firstLoad = false;
                    hideLoading();
                }
            });
    }, 1000); // Poll every 1 second
}

// Show loading spinner/message
function showLoading() {
    const historyDiv = document.getElementById('attackHistory');
    historyDiv.innerHTML = '<div class="text-center text-muted">Loading data...</div>';
}
function hideLoading() {
    // No-op for now, can be used to hide spinner
}

// Update attack history
function updateAttackHistory(history) {
    const historyDiv = document.getElementById('attackHistory');
    if (!history || history.length === 0) {
        historyDiv.innerHTML = '<div class="text-center text-muted">No attacks detected yet. Start a simulation!</div>';
        return;
    }
    historyDiv.innerHTML = history.map(alert => `
        <div class="alert alert-${getAlertClass(alert.classification)}">
            <strong>${alert.type}</strong> - ${alert.timestamp}
            <br>
            From: ${alert.source_ip} To: ${alert.dest_ip}
        </div>
    `).join('');
}

// Update threat level
function updateThreatLevel(level) {
    const threatLevelDiv = document.getElementById('threatLevel');
    const badge = threatLevelDiv.querySelector('.badge');
    
    badge.className = `badge bg-${getThreatLevelClass(level)}`;
    badge.textContent = level.toUpperCase();
}

// Update ML stats
function updateMLStats(stats) {
    const statsDiv = document.getElementById('mlStats');
    statsDiv.innerHTML = `
        <div class="row">
            <div class="col-md-4">
                <div class="stat-card">
                    <h6>Accuracy</h6>
                    <p>${stats.accuracy}%</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <h6>False Positives</h6>
                    <p>${stats.false_positives}</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <h6>Detection Rate</h6>
                    <p>${stats.detection_rate}%</p>
                </div>
            </div>
        </div>
    `;
}

// Update charts with new data
function updateCharts(history, mlStats) {
    // Attack Distribution
    let malicious = 0, suspicious = 0, normal = 0;
    history.forEach(alert => {
        if (alert.classification === 'malicious') malicious++;
        else if (alert.classification === 'suspicious') suspicious++;
        else normal++;
    });
    attackChart.data.datasets[0].data = [malicious, suspicious, normal];
    attackChart.update();

    // Traffic Analysis
    let traffic = mlStats.traffic_volume || [];
    trafficChart.data.datasets[0].data = traffic.length ? traffic : Array(10).fill(0);
    trafficChart.update();
}

// Update network map
function updateNetworkMap() {
    fetch('/api/network-data')
        .then(response => response.json())
        .then(data => {
            networkData = data;
            visualizeNetwork(data);
        });
}

// Helper functions
function getAlertClass(classification) {
    switch(classification) {
        case 'malicious': return 'danger';
        case 'suspicious': return 'warning';
        default: return 'info';
    }
}

function getThreatLevelClass(level) {
    switch(level) {
        case 'high': return 'danger';
        case 'medium': return 'warning';
        default: return 'success';
    }
}

// Export data
function exportData() {
    const data = {
        networkData,
        attackHistory,
        currentThreatLevel,
        mlModelStats
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nids_export.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Toast/alert for simulation start
function showToast(msg) {
    let toast = document.createElement('div');
    toast.className = 'toast align-items-center text-bg-primary border-0 show position-fixed top-0 end-0 m-3';
    toast.style.zIndex = 9999;
    toast.innerHTML = `<div class="d-flex"><div class="toast-body">${msg}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
    document.body.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3000);
}

// Simulation controls
function startSimulation() {
    const attackType = document.getElementById('attackType').value;
    const duration = parseInt(document.getElementById('attackDuration').value);
    showToast('Starting simulation: ' + attackType);
    fetch('/api/simulate-attack', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            type: attackType,
            duration: duration
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('Simulation started: ' + attackType);
        } else {
            showToast('Error: ' + (data.error || data.message));
        }
    })
    .catch(error => {
        showToast('Error: ' + error);
    });
}

function stopSimulation() {
    if (simulationInterval) {
        clearInterval(simulationInterval);
        simulationInterval = null;
    }
} 