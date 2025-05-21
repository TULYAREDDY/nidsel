document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const modelSelect = document.getElementById('modelSelect');
    const startButton = document.getElementById('startSimulation');
    const resetButton = document.getElementById('resetSimulation');
    const modelVisualization = document.getElementById('modelVisualization');
    const modelControls = document.getElementById('modelControls');
    const simulationLog = document.getElementById('simulationLog');

    // Simulation state
    let isSimulating = false;
    let simulationInterval = null;
    let simulationSpeed = 2000; // 2 seconds between steps

    // Model Data
    const modelData = {
        bayesian: {
            nodes: [
                { 
                    id: 'source', 
                    name: 'Source Type', 
                    value: 'Trusted', 
                    options: ['Trusted', 'Unknown'],
                    icon: 'fa-shield-alt',
                    description: 'Evaluates the trustworthiness of the source'
                },
                { 
                    id: 'pattern', 
                    name: 'Attack Pattern', 
                    value: 'Known', 
                    options: ['Known', 'Unknown'],
                    icon: 'fa-bug',
                    description: 'Identifies known attack signatures'
                },
                { 
                    id: 'severity', 
                    name: 'Severity', 
                    value: 'High', 
                    options: ['High', 'Medium', 'Low'],
                    icon: 'fa-exclamation-triangle',
                    description: 'Assesses the threat level'
                }
            ],
            weights: {
                source: { Trusted: 0.9, Unknown: 0.4 },
                pattern: { Known: 0.8, Unknown: 0.3 },
                severity: { High: 0.9, Medium: 0.6, Low: 0.3 }
            },
            step: 0,
            currentVisited: null
        },
        markov: {
            states: ['Normal', 'Suspicious', 'Compromised', 'Resolved'],
            currentState: 'Normal',
            history: ['Normal'],
            matrix: {
                'Normal': { 'Normal': 0.7, 'Suspicious': 0.3, 'Compromised': 0, 'Resolved': 0 },
                'Suspicious': { 'Normal': 0.2, 'Suspicious': 0.5, 'Compromised': 0.3, 'Resolved': 0 },
                'Compromised': { 'Normal': 0, 'Suspicious': 0.2, 'Compromised': 0.6, 'Resolved': 0.2 },
                'Resolved': { 'Normal': 0.8, 'Suspicious': 0, 'Compromised': 0, 'Resolved': 0.2 }
            },
            step: 0
        },
        knapsack: {
            capacity: 100,
            alerts: [
                { id: 1, name: 'DDoS Attack', severity: 90, complexity: 40 },
                { id: 2, name: 'SQL Injection', severity: 85, complexity: 30 },
                { id: 3, name: 'XSS Attempt', severity: 70, complexity: 20 },
                { id: 4, name: 'Port Scan', severity: 60, complexity: 15 },
                { id: 5, name: 'Brute Force', severity: 75, complexity: 25 }
            ],
            step: 0
        }
    };

    // Log Functions
    function addLogEntry(type, message) {
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.innerHTML = `
            <i class="fas fa-${getIconForType(type)}"></i>
            <div class="log-content">
                <div class="timestamp">[${timestamp}]</div>
                <div class="message">${message}</div>
            </div>
        `;
        simulationLog.appendChild(entry);
        simulationLog.scrollTop = simulationLog.scrollHeight;
    }

    function getIconForType(type) {
        const icons = {
            info: 'info-circle',
            success: 'check-circle',
            warning: 'exclamation-triangle',
            error: 'times-circle'
        };
        return icons[type] || 'info-circle';
    }

    // Bayesian Network Implementation
    function initializeBayesian() {
        modelVisualization.innerHTML = '';
        modelControls.innerHTML = '';

        // Create nodes
        const nodesContainer = document.createElement('div');
        nodesContainer.style.display = 'flex';
        nodesContainer.style.flexDirection = 'column';
        nodesContainer.style.alignItems = 'center';
        nodesContainer.style.gap = '1.5rem';
        nodesContainer.style.padding = '2rem';

        modelData.bayesian.nodes.forEach(node => {
            const nodeElement = document.createElement('div');
            nodeElement.className = 'bayesian-node';
            if (node.id === modelData.bayesian.currentVisited) {
                nodeElement.classList.add('visited');
            }
            
            nodeElement.innerHTML = `
                <div class="node-icon">
                    <i class="fas ${node.icon}"></i>
                </div>
                <div class="node-content">
                    <div class="node-name">${node.name}</div>
                    <div class="node-value">${node.value}</div>
                </div>
                <div class="node-description">${node.description}</div>
            `;
            
            nodeElement.dataset.id = node.id;
            nodesContainer.appendChild(nodeElement);
        });

        modelVisualization.appendChild(nodesContainer);

        // Add confidence meter
        const confidenceMeter = document.createElement('div');
        confidenceMeter.className = 'confidence-meter';
        confidenceMeter.innerHTML = `
            <div class="meter-label">Threat Confidence</div>
            <div class="meter-bar">
                <div class="meter-fill" style="width: 0%"></div>
            </div>
            <div class="meter-value">0%</div>
        `;
        modelControls.appendChild(confidenceMeter);

        evaluateBayesian();
    }

    function stepBayesian() {
        const nodes = modelData.bayesian.nodes;
        const step = modelData.bayesian.step;
        
        // Cycle through nodes
        const nodeIndex = step % nodes.length;
        const node = nodes[nodeIndex];
        const currentIndex = node.options.indexOf(node.value);
        const nextIndex = (currentIndex + 1) % node.options.length;
        node.value = node.options[nextIndex];
        
        // Update visited node
        modelData.bayesian.currentVisited = node.id;
        
        // Update visualization
        const nodeElements = document.querySelectorAll('.bayesian-node');
        nodeElements.forEach(element => {
            element.classList.remove('visited');
            if (element.dataset.id === node.id) {
                element.classList.add('visited');
                element.querySelector('.node-value').textContent = node.value;
            }
        });
        
        evaluateBayesian();
        modelData.bayesian.step++;
    }

    function evaluateBayesian() {
        const confidence = modelData.bayesian.nodes.reduce((score, node) => {
            return score * modelData.bayesian.weights[node.id][node.value];
        }, 1);

        const confidencePercent = Math.round(confidence * 100);
        const meterFill = document.querySelector('.meter-fill');
        const meterValue = document.querySelector('.meter-value');
        
        meterFill.style.width = `${confidencePercent}%`;
        meterValue.textContent = `${confidencePercent}%`;

        let message = `Threat confidence: ${confidencePercent}%`;
        if (confidencePercent > 70) {
            message += ' - High probability of threat';
            addLogEntry('warning', message);
        } else if (confidencePercent > 40) {
            message += ' - Moderate threat level';
            addLogEntry('info', message);
        } else {
            message += ' - Low threat level';
            addLogEntry('success', message);
        }
    }

    // Markov Chain Implementation
    function initializeMarkov() {
        modelVisualization.innerHTML = '';
        modelControls.innerHTML = '';

        // Create state nodes
        const statesContainer = document.createElement('div');
        statesContainer.style.display = 'flex';
        statesContainer.style.justifyContent = 'space-around';
        statesContainer.style.alignItems = 'center';
        statesContainer.style.padding = '2rem';

        modelData.markov.states.forEach(state => {
            const stateElement = document.createElement('div');
            stateElement.className = 'markov-node';
            if (state === modelData.markov.currentState) {
                stateElement.classList.add('active');
            }
            stateElement.textContent = state;
            statesContainer.appendChild(stateElement);
        });

        modelVisualization.appendChild(statesContainer);

        // Add state history
        const historyContainer = document.createElement('div');
        historyContainer.className = 'state-history';
        historyContainer.innerHTML = `
            <div class="history-label">State History</div>
            <div class="history-content">${modelData.markov.history.join(' → ')}</div>
        `;
        modelControls.appendChild(historyContainer);

        addLogEntry('info', `Current state: ${modelData.markov.currentState}`);
    }

    function stepMarkov() {
        const currentState = modelData.markov.currentState;
        const probabilities = modelData.markov.matrix[currentState];
        
        const random = Math.random();
        let cumulative = 0;
        let nextState = currentState;
        
        for (const [state, prob] of Object.entries(probabilities)) {
            cumulative += prob;
            if (random <= cumulative) {
                nextState = state;
                break;
            }
        }
        
        modelData.markov.currentState = nextState;
        modelData.markov.history.push(nextState);
        
        initializeMarkov();
        addLogEntry('info', `State transition: ${currentState} → ${nextState}`);
        modelData.markov.step++;
    }

    // Knapsack Implementation
    function initializeKnapsack() {
        modelVisualization.innerHTML = '';
        modelControls.innerHTML = '';

        // Create alerts list
        const alertsContainer = document.createElement('div');
        alertsContainer.className = 'alerts-container';
        alertsContainer.style.padding = '1rem';

        modelData.knapsack.alerts.forEach(alert => {
            const alertElement = document.createElement('div');
            alertElement.className = 'alert-item';
            alertElement.innerHTML = `
                <div class="alert-info">
                    <div class="alert-name">${alert.name}</div>
                    <div class="alert-details">
                        Severity: ${alert.severity} | Complexity: ${alert.complexity}
                    </div>
                </div>
                <div class="alert-severity" style="width: ${alert.severity}%; height: 4px; background: var(--primary-color);"></div>
            `;
            alertsContainer.appendChild(alertElement);
        });

        modelVisualization.appendChild(alertsContainer);

        // Add capacity meter
        const capacityMeter = document.createElement('div');
        capacityMeter.className = 'capacity-meter';
        capacityMeter.innerHTML = `
            <div class="meter-label">Resource Capacity</div>
            <div class="meter-bar">
                <div class="meter-fill" style="width: 0%"></div>
            </div>
            <div class="meter-value">0/${modelData.knapsack.capacity}</div>
        `;
        modelControls.appendChild(capacityMeter);

        solveKnapsack();
    }

    function stepKnapsack() {
        // Modify alert severities and complexities
        modelData.knapsack.alerts.forEach(alert => {
            alert.severity = Math.max(10, Math.min(100, alert.severity + (Math.random() * 20 - 10)));
            alert.complexity = Math.max(5, Math.min(50, alert.complexity + (Math.random() * 10 - 5)));
        });
        
        solveKnapsack();
        modelData.knapsack.step++;
    }

    function solveKnapsack() {
        const alerts = modelData.knapsack.alerts;
        const capacity = modelData.knapsack.capacity;
        const n = alerts.length;
        
        // Create DP table
        const dp = Array(n + 1).fill().map(() => Array(capacity + 1).fill(0));
        
        // Fill DP table
        for (let i = 1; i <= n; i++) {
            for (let w = 0; w <= capacity; w++) {
                if (alerts[i-1].complexity <= w) {
                    dp[i][w] = Math.max(
                        alerts[i-1].severity + dp[i-1][w-alerts[i-1].complexity],
                        dp[i-1][w]
                    );
                } else {
                    dp[i][w] = dp[i-1][w];
                }
            }
        }
        
        // Find selected alerts
        const selected = [];
        let w = capacity;
        for (let i = n; i > 0; i--) {
            if (dp[i][w] !== dp[i-1][w]) {
                selected.push(alerts[i-1]);
                w -= alerts[i-1].complexity;
            }
        }
        
        // Update visualization
        const alertItems = document.querySelectorAll('.alert-item');
        alertItems.forEach(item => {
            const alertName = item.querySelector('.alert-name').textContent;
            const alert = alerts.find(a => a.name === alertName);
            if (alert) {
                item.querySelector('.alert-severity').style.width = `${alert.severity}%`;
                item.querySelector('.alert-details').textContent = 
                    `Severity: ${Math.round(alert.severity)} | Complexity: ${Math.round(alert.complexity)}`;
            }
            if (selected.some(alert => alert.name === alertName)) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        });

        // Update capacity meter
        const usedCapacity = selected.reduce((sum, alert) => sum + alert.complexity, 0);
        const meterFill = document.querySelector('.meter-fill');
        const meterValue = document.querySelector('.meter-value');
        
        meterFill.style.width = `${(usedCapacity / capacity) * 100}%`;
        meterValue.textContent = `${Math.round(usedCapacity)}/${capacity}`;

        addLogEntry('info', `Selected ${selected.length} alerts with total severity ${Math.round(dp[n][capacity])}`);
    }

    // Simulation Control
    function startSimulation() {
        if (isSimulating) {
            stopSimulation();
            return;
        }

        isSimulating = true;
        startButton.innerHTML = '<i class="fas fa-stop"></i> Stop Simulation';
        startButton.classList.add('active');
        resetButton.disabled = true;

        simulationInterval = setInterval(() => {
            const model = modelSelect.value;
            switch (model) {
                case 'bayesian':
                    stepBayesian();
                    break;
                case 'markov':
                    stepMarkov();
                    break;
                case 'knapsack':
                    stepKnapsack();
                    break;
            }
        }, simulationSpeed);
    }

    function stopSimulation() {
        isSimulating = false;
        clearInterval(simulationInterval);
        startButton.innerHTML = '<i class="fas fa-play"></i> Start Simulation';
        startButton.classList.remove('active');
        resetButton.disabled = false;
    }

    // Event Listeners
    modelSelect.addEventListener('change', () => {
        stopSimulation();
        const model = modelSelect.value;
        switch (model) {
            case 'bayesian':
                initializeBayesian();
                break;
            case 'markov':
                initializeMarkov();
                break;
            case 'knapsack':
                initializeKnapsack();
                break;
        }
        addLogEntry('info', `Switched to ${modelSelect.options[modelSelect.selectedIndex].text}`);
    });

    startButton.addEventListener('click', startSimulation);

    resetButton.addEventListener('click', () => {
        stopSimulation();
        const model = modelSelect.value;
        switch (model) {
            case 'markov':
                modelData.markov.currentState = 'Normal';
                modelData.markov.history = ['Normal'];
                modelData.markov.step = 0;
                break;
            case 'bayesian':
                modelData.bayesian.nodes.forEach(node => {
                    node.value = node.options[0];
                });
                modelData.bayesian.step = 0;
                break;
            case 'knapsack':
                modelData.knapsack.step = 0;
                break;
        }
        modelSelect.dispatchEvent(new Event('change'));
        simulationLog.innerHTML = '';
        addLogEntry('info', 'Simulation reset');
    });

    // Initialize
    modelSelect.dispatchEvent(new Event('change'));
}); 