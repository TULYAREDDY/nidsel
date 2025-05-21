document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const algorithmSelect = document.getElementById('algorithmSelect');
    const startButton = document.getElementById('startSimulation');
    const resetButton = document.getElementById('resetSimulation');
    const graphContainer = document.getElementById('graphContainer');
    const algorithmDetails = document.getElementById('algorithmDetails');
    const simulationLog = document.getElementById('simulationLog');

    // Enhanced network data with IP addresses and malware information
    const networkData = {
        nodes: [
            { 
                id: 'A', 
                x: 100, 
                y: 100, 
                label: 'Main Router',
                ip: '192.168.1.1',
                type: 'network',
                status: 'secure'
            },
            { 
                id: 'B', 
                x: 300, 
                y: 100, 
                label: 'Firewall',
                ip: '192.168.1.2',
                type: 'security',
                status: 'monitoring'
            },
            { 
                id: 'C', 
                x: 500, 
                y: 100, 
                label: 'Database Server',
                ip: '192.168.1.3',
                type: 'server',
                status: 'compromised',
                malware: {
                    type: 'SQL Injection',
                    severity: 'High',
                    timestamp: '2024-03-15 14:30:00'
                }
            },
            { 
                id: 'D', 
                x: 100, 
                y: 300, 
                label: 'Client PC',
                ip: '192.168.1.4',
                type: 'client',
                status: 'infected',
                malware: {
                    type: 'Ransomware',
                    severity: 'Critical',
                    timestamp: '2024-03-15 14:25:00'
                }
            },
            { 
                id: 'E', 
                x: 300, 
                y: 300, 
                label: 'Web Server',
                ip: '192.168.1.5',
                type: 'server',
                status: 'vulnerable',
                malware: {
                    type: 'XSS Attack',
                    severity: 'Medium',
                    timestamp: '2024-03-15 14:28:00'
                }
            },
            { 
                id: 'F', 
                x: 500, 
                y: 300, 
                label: 'Backup Server',
                ip: '192.168.1.6',
                type: 'server',
                status: 'secure'
            }
        ],
        edges: [
            { 
                from: 'A', 
                to: 'B', 
                weight: 5, 
                label: '5ms',
                type: 'normal',
                traffic: 'encrypted'
            },
            { 
                from: 'B', 
                to: 'C', 
                weight: 3, 
                label: '3ms',
                type: 'suspicious',
                traffic: 'malicious'
            },
            { 
                from: 'A', 
                to: 'D', 
                weight: 2, 
                label: '2ms',
                type: 'compromised',
                traffic: 'infected'
            },
            { 
                from: 'B', 
                to: 'E', 
                weight: 4, 
                label: '4ms',
                type: 'vulnerable',
                traffic: 'suspicious'
            },
            { 
                from: 'C', 
                to: 'F', 
                weight: 6, 
                label: '6ms',
                type: 'normal',
                traffic: 'encrypted'
            },
            { 
                from: 'D', 
                to: 'E', 
                weight: 3, 
                label: '3ms',
                type: 'compromised',
                traffic: 'malicious'
            },
            { 
                from: 'E', 
                to: 'F', 
                weight: 2, 
                label: '2ms',
                type: 'normal',
                traffic: 'encrypted'
            }
        ]
    };

    // Algorithm details
    const algorithmInfo = {
        dijkstra: {
            name: "Dijkstra's Algorithm",
            complexity: "O((V + E)logV)",
            description: "Finds the shortest path between nodes in a graph. Used in network routing and attack path analysis.",
            implementation: `
                <h4>Implementation in NIDS</h4>
                <p>In our NIDS project, Dijkstra's algorithm is used to:</p>
                <ul>
                    <li>Find the optimal path for network traffic routing</li>
                    <li>Analyze attack propagation paths through the network</li>
                    <li>Identify the most efficient paths for security updates</li>
                    <li>Calculate network latency and optimize traffic flow</li>
                </ul>
                <div class="use-case">
                    <strong>Real-world Application:</strong>
                    <p>When a security threat is detected, the algorithm helps identify the most likely path the attack took through the network, allowing for quick isolation and response.</p>
                </div>
                <div class="complexity">
                    Time Complexity: O((V + E)logV)<br>
                    Space Complexity: O(V)
                </div>
            `
        },
        dfs: {
            name: "Depth-First Search",
            complexity: "O(V + E)",
            description: "Explores as far as possible along each branch before backtracking. Used for attack propagation analysis.",
            implementation: `
                <h4>Implementation in NIDS</h4>
                <p>DFS is crucial for:</p>
                <ul>
                    <li>Deep inspection of network connections</li>
                    <li>Identifying hidden attack vectors</li>
                    <li>Analyzing malware propagation patterns</li>
                    <li>Detecting lateral movement in the network</li>
                </ul>
                <div class="use-case">
                    <strong>Real-world Application:</strong>
                    <p>When investigating a security breach, DFS helps trace the complete path of an attack, including any lateral movements or hidden connections the attacker might have established.</p>
                </div>
                <div class="complexity">
                    Time Complexity: O(V + E)<br>
                    Space Complexity: O(V)
                </div>
            `
        },
        bfs: {
            name: "Breadth-First Search",
            complexity: "O(V + E)",
            description: "Explores all nodes at present depth before moving to next level. Used for network exploration.",
            implementation: `
                <h4>Implementation in NIDS</h4>
                <p>BFS is used for:</p>
                <ul>
                    <li>Network topology discovery</li>
                    <li>Identifying affected systems in an attack</li>
                    <li>Finding the shortest path to compromised systems</li>
                    <li>Analyzing network connectivity patterns</li>
                </ul>
                <div class="use-case">
                    <strong>Real-world Application:</strong>
                    <p>During a DDoS attack, BFS helps quickly identify all affected systems and their relationships, enabling rapid response and mitigation.</p>
                </div>
                <div class="complexity">
                    Time Complexity: O(V + E)<br>
                    Space Complexity: O(V)
                </div>
            `
        },
        knapsack: {
            name: "Knapsack Algorithm",
            complexity: "O(nW)",
            description: "Solves optimization problems. Used for alert prioritization based on severity and resources.",
            implementation: `
                <h4>Implementation in NIDS</h4>
                <p>The Knapsack algorithm helps with:</p>
                <ul>
                    <li>Prioritizing security alerts based on severity</li>
                    <li>Optimizing resource allocation for threat response</li>
                    <li>Managing system resources during attacks</li>
                    <li>Balancing security measures with performance</li>
                </ul>
                <div class="use-case">
                    <strong>Real-world Application:</strong>
                    <p>When multiple security alerts are triggered simultaneously, the algorithm helps determine which threats to address first based on their severity and available system resources.</p>
                </div>
                <div class="complexity">
                    Time Complexity: O(nW)<br>
                    Space Complexity: O(W)
                </div>
            `
        }
    };

    // Initialize graph with enhanced node information
    function initializeGraph() {
        graphContainer.innerHTML = '';

        // Create nodes with enhanced information
        networkData.nodes.forEach(node => {
            const nodeElement = document.createElement('div');
            nodeElement.className = `node ${node.status}`;
            nodeElement.id = `node-${node.id}`;
            nodeElement.style.left = `${node.x}px`;
            nodeElement.style.top = `${node.y}px`;
            
            // Create node content with IP and status
            const nodeContent = document.createElement('div');
            nodeContent.className = 'node-content';
            nodeContent.innerHTML = `
                <div class="node-id">${node.id}</div>
                <div class="node-ip">${node.ip}</div>
                <div class="node-status">${node.status}</div>
            `;
            
            nodeElement.appendChild(nodeContent);
            nodeElement.title = `${node.label}\nIP: ${node.ip}\nStatus: ${node.status}${node.malware ? `\nMalware: ${node.malware.type}` : ''}`;
            
            graphContainer.appendChild(nodeElement);
        });

        // Create edges with enhanced information
        networkData.edges.forEach(edge => {
            const fromNode = networkData.nodes.find(n => n.id === edge.from);
            const toNode = networkData.nodes.find(n => n.id === edge.to);
            
            const edgeElement = document.createElement('div');
            edgeElement.className = `edge ${edge.type}`;
            edgeElement.id = `edge-${edge.from}-${edge.to}`;
            
            const dx = toNode.x - fromNode.x;
            const dy = toNode.y - fromNode.y;
            const length = Math.sqrt(dx * dx + dy * dy);
            const angle = Math.atan2(dy, dx) * 180 / Math.PI;
            
            edgeElement.style.width = `${length}px`;
            edgeElement.style.left = `${fromNode.x + 20}px`;
            edgeElement.style.top = `${fromNode.y + 20}px`;
            edgeElement.style.transform = `rotate(${angle}deg)`;
            
            // Add edge label
            const edgeLabel = document.createElement('div');
            edgeLabel.className = 'edge-label';
            edgeLabel.textContent = `${edge.label} (${edge.traffic})`;
            edgeElement.appendChild(edgeLabel);
            
            graphContainer.appendChild(edgeElement);
        });
    }

    // Enhanced log entry with more detailed information
    function addLogEntry(message, type = 'info', details = null) {
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        
        const timestamp = new Date().toLocaleTimeString();
        let content = `[${timestamp}] ${message}`;
        
        if (details) {
            content += `\n${JSON.stringify(details, null, 2)}`;
        }
        
        entry.innerHTML = content.replace(/\n/g, '<br>');
        simulationLog.appendChild(entry);
        simulationLog.scrollTop = simulationLog.scrollHeight;
    }

    // Update algorithm details
    function updateAlgorithmDetails(algorithm) {
        const info = algorithmInfo[algorithm];
        algorithmDetails.innerHTML = `
            <h3>${info.name}</h3>
            <p>${info.description}</p>
            ${info.implementation}
        `;
    }

    // Simulate algorithm
    async function simulateAlgorithm(algorithm) {
        resetButton.disabled = true;
        startButton.disabled = true;
        simulationLog.innerHTML = '';
        
        addLogEntry(`Starting ${algorithmInfo[algorithm].name} simulation...`, 'info');

        switch(algorithm) {
            case 'dijkstra':
                await simulateDijkstra();
                break;
            case 'dfs':
                await simulateDFS();
                break;
            case 'bfs':
                await simulateBFS();
                break;
            case 'knapsack':
                await simulateKnapsack();
                break;
        }

        addLogEntry('Simulation completed!', 'success');
        resetButton.disabled = false;
        startButton.disabled = false;
    }

    // Enhanced Dijkstra's Algorithm Simulation
    async function simulateDijkstra() {
        const startNode = 'A';
        const endNode = 'F';
        const distances = {};
        const visited = new Set();
        const previous = {};
        
        networkData.nodes.forEach(node => {
            distances[node.id] = Infinity;
            previous[node.id] = null;
        });
        distances[startNode] = 0;

        addLogEntry(`Starting shortest path analysis from ${networkData.nodes.find(n => n.id === startNode).label} (${networkData.nodes.find(n => n.id === startNode).ip}) to ${networkData.nodes.find(n => n.id === endNode).label} (${networkData.nodes.find(n => n.id === endNode).ip})`, 'info');

        while (visited.size < networkData.nodes.length) {
            let minDistance = Infinity;
            let currentNode = null;
            
            for (const node of networkData.nodes) {
                if (!visited.has(node.id) && distances[node.id] < minDistance) {
                    minDistance = distances[node.id];
                    currentNode = node.id;
                }
            }

            if (currentNode === null) break;

            visited.add(currentNode);
            const node = networkData.nodes.find(n => n.id === currentNode);
            document.getElementById(`node-${currentNode}`).classList.add('visited');
            
            addLogEntry(`Analyzing node: ${node.label} (${node.ip})`, 'info', {
                status: node.status,
                malware: node.malware,
                currentDistance: distances[currentNode]
            });

            const edges = networkData.edges.filter(e => e.from === currentNode);
            for (const edge of edges) {
                const newDistance = distances[currentNode] + edge.weight;
                if (newDistance < distances[edge.to]) {
                    distances[edge.to] = newDistance;
                    previous[edge.to] = currentNode;
                    document.getElementById(`edge-${edge.from}-${edge.to}`).classList.add('active');
                    
                    const targetNode = networkData.nodes.find(n => n.id === edge.to);
                    addLogEntry(`Found better path to ${targetNode.label} (${targetNode.ip})`, 'info', {
                        newDistance,
                        edgeType: edge.type,
                        traffic: edge.traffic
                    });
                }
            }

            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Reconstruct and log the path
        const path = [];
        let current = endNode;
        while (current) {
            path.unshift(current);
            current = previous[current];
        }

        addLogEntry(`Optimal path found: ${path.join(' → ')}`, 'success', {
            totalDistance: distances[endNode],
            pathDetails: path.map(nodeId => {
                const node = networkData.nodes.find(n => n.id === nodeId);
                return {
                    node: node.label,
                    ip: node.ip,
                    status: node.status
                };
            })
        });
    }

    // DFS Simulation
    async function simulateDFS() {
        const visited = new Set();
        const startNode = 'A';

        async function dfs(node) {
            visited.add(node);
            document.getElementById(`node-${node}`).classList.add('visited');
            addLogEntry(`Visiting node ${node}`, 'info');

            const edges = networkData.edges.filter(e => e.from === node);
            for (const edge of edges) {
                if (!visited.has(edge.to)) {
                    document.getElementById(`edge-${edge.from}-${edge.to}`).classList.add('active');
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    await dfs(edge.to);
                }
            }
        }

        await dfs(startNode);
        addLogEntry('DFS traversal completed!', 'success');
    }

    // BFS Simulation
    async function simulateBFS() {
        const visited = new Set();
        const queue = ['A'];
        visited.add('A');

        while (queue.length > 0) {
            const node = queue.shift();
            document.getElementById(`node-${node}`).classList.add('visited');
            addLogEntry(`Visiting node ${node}`, 'info');

            const edges = networkData.edges.filter(e => e.from === node);
            for (const edge of edges) {
                if (!visited.has(edge.to)) {
                    visited.add(edge.to);
                    queue.push(edge.to);
                    document.getElementById(`edge-${edge.from}-${edge.to}`).classList.add('active');
                }
            }

            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        addLogEntry('BFS traversal completed!', 'success');
    }

    // Knapsack Simulation
    async function simulateKnapsack() {
        const alerts = [
            { id: 1, severity: 8, resources: 3, description: 'SQL Injection Attempt' },
            { id: 2, severity: 6, resources: 2, description: 'Port Scan Detected' },
            { id: 3, severity: 9, resources: 4, description: 'DDoS Attack' },
            { id: 4, severity: 5, resources: 2, description: 'Suspicious Login' },
            { id: 5, severity: 7, resources: 3, description: 'Malware Detection' }
        ];

        const maxResources = 8;
        const dp = Array(alerts.length + 1).fill().map(() => Array(maxResources + 1).fill(0));

        addLogEntry('Starting alert prioritization...', 'info');

        for (let i = 1; i <= alerts.length; i++) {
            for (let w = 0; w <= maxResources; w++) {
                if (alerts[i-1].resources <= w) {
                    dp[i][w] = Math.max(
                        dp[i-1][w],
                        dp[i-1][w - alerts[i-1].resources] + alerts[i-1].severity
                    );
                } else {
                    dp[i][w] = dp[i-1][w];
                }
            }
            addLogEntry(`Processing alert ${alerts[i-1].description}`, 'info');
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Backtrack to find selected alerts
        let w = maxResources;
        const selectedAlerts = [];
        for (let i = alerts.length; i > 0; i--) {
            if (dp[i][w] !== dp[i-1][w]) {
                selectedAlerts.push(alerts[i-1]);
                w -= alerts[i-1].resources;
            }
        }

        addLogEntry('Selected alerts for investigation:', 'success');
        selectedAlerts.forEach(alert => {
            addLogEntry(`- ${alert.description} (Severity: ${alert.severity})`, 'info');
        });
    }

    // Event Listeners
    algorithmSelect.addEventListener('change', () => {
        updateAlgorithmDetails(algorithmSelect.value);
    });

    startButton.addEventListener('click', () => {
        initializeGraph();
        simulateAlgorithm(algorithmSelect.value);
    });

    resetButton.addEventListener('click', () => {
        initializeGraph();
        simulationLog.innerHTML = '';
        resetButton.disabled = true;
    });

    // Initialize
    initializeGraph();
    updateAlgorithmDetails(algorithmSelect.value);
}); 