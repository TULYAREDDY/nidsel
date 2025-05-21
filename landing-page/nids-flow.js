// JavaScript for NIDS Flow Visualization

document.addEventListener('DOMContentLoaded', () => {
    const commonStartButton = document.querySelector('.common-start-flow-btn');
    const unifiedFlowLog = document.getElementById('unifiedFlowLog');
    const backendNode = document.querySelector('#backend-api');
    const frontendNode = document.querySelector('#frontend-dashboard');
    const backendFrontendArrow = document.querySelector('#arrow-backend-frontend');

    // Get data packet elements
    const liveAlertPackets = [
        document.querySelector('#arrow-snort-ml .data-packet'),
        document.querySelector('#arrow-ml-backend .data-packet'),
        document.querySelector('#arrow-backend-frontend .data-packet')
    ];

    // WebSocket simulation state
    let wsConnected = false;
    let wsInterval = null;
    let packetCounter = 0;

    commonStartButton.addEventListener('click', () => {
        if (wsInterval) {
            clearInterval(wsInterval);
            wsInterval = null;
        }
        simulateFlow(unifiedFlowLog, liveAlertPackets);
    });

    function simulateWebSocketConnection() {
        if (!wsConnected) {
            wsConnected = true;
            backendNode.classList.add('websocket-active');
            frontendNode.classList.add('websocket-active');
            backendFrontendArrow.classList.add('websocket-active');
            
            addLogMessage(unifiedFlowLog, 'WebSocket connection established between Backend and Frontend', 'fas fa-plug');
            
            // Start sending periodic updates
            wsInterval = setInterval(() => {
                packetCounter++;
                const packet = document.createElement('div');
                packet.className = 'data-packet websocket-packet';
                backendFrontendArrow.appendChild(packet);
                
                // Simulate real-time data with more detailed information
                const alertTypes = [
                    { type: 'SQL Injection', icon: 'fas fa-database' },
                    { type: 'XSS Attack', icon: 'fas fa-code' },
                    { type: 'DDoS Attempt', icon: 'fas fa-network-wired' },
                    { type: 'Port Scan', icon: 'fas fa-search' },
                    { type: 'Malware Detection', icon: 'fas fa-virus' }
                ];
                const randomAlert = alertTypes[Math.floor(Math.random() * alertTypes.length)];
                const severity = ['Low', 'Medium', 'High'][Math.floor(Math.random() * 3)];
                const timestamp = new Date().toLocaleTimeString();
                const sourceIP = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
                
                addLogMessage(
                    unifiedFlowLog,
                    `[${timestamp}] [WebSocket] Alert #${packetCounter}: ${randomAlert.type} (Severity: ${severity}) from ${sourceIP}`,
                    randomAlert.icon
                );
                
                // Animate packet
                packet.style.animation = 'movePacketHorizontal 1s forwards';
                
                // Remove packet after animation
                setTimeout(() => {
                    packet.remove();
                }, 1000);
            }, 2000);
        }
    }

    function simulateFlow(logElement, packetElements) {
        logElement.innerHTML = ''; // Clear previous logs
        wsConnected = false;
        backendNode.classList.remove('websocket-active');
        frontendNode.classList.remove('websocket-active');
        backendFrontendArrow.classList.remove('websocket-active');

        // Reset packet animations
        packetElements.forEach(packet => {
            if (packet) {
                packet.style.animation = 'none';
                packet.style.opacity = 0;
            }
        });

        addLogMessage(logElement, 'Starting NIDS data flow simulation...', 'fas fa-play');

        const unifiedSteps = [
            { icon: 'fas fa-sensor', message: 'Snort Processor: Capturing and analyzing network packets.' },
            { icon: 'fas fa-cogs', message: 'Snort Processor: Applying rule engine for initial threat detection.' },
            { icon: 'fas fa-brain', message: 'ML Bridge: Receiving potential alerts for machine learning analysis.' },
            { icon: 'fas fa-dna', message: 'ML Bridge: Running machine learning models to score threats.' },
            { icon: 'fas fa-server', message: 'Backend API: Receiving analyzed alerts and simulation data.' },
            { icon: 'fas fa-database', message: 'Backend API: Storing alert and simulation data in the database.' },
            { icon: 'fas fa-plug', message: 'Backend API: Establishing WebSocket connection for real-time updates.' },
            { icon: 'fas fa-display', message: 'Frontend Dashboard: Displaying real-time alerts and visualizations.' },
            { icon: 'fas fa-chart-bar', message: 'Frontend Dashboard: Presenting analytics and reports.' },
            { icon: 'fas fa-skull-crossbones', message: 'Attack Simulator: Initiating various network attack simulations.' },
            { icon: 'fas fa-traffic-light', message: 'Attack Simulator: Generating realistic malicious traffic.' },
        ];

        let currentStep = 0;

        function executeStep() {
            if (currentStep < unifiedSteps.length) {
                const step = unifiedSteps[currentStep];
                addLogMessage(logElement, step.message, step.icon);

                // Animate packet
                if (packetElements[currentStep]) {
                    packetElements[currentStep].style.opacity = 1;
                    packetElements[currentStep].style.animation = 'movePacketHorizontal 1s forwards';
                }

                // Start WebSocket simulation after backend step
                if (currentStep === 5) {
                    setTimeout(simulateWebSocketConnection, 1000);
                }

                currentStep++;
                setTimeout(executeStep, 1500);
            } else {
                addLogMessage(logElement, 'Initial data flow simulation completed. WebSocket connection active for real-time updates.', 'fas fa-check-circle');
            }
        }

        executeStep();
    }

    function addLogMessage(logElement, message, iconClass) {
        const messageElement = document.createElement('p');
        if (iconClass) {
            messageElement.innerHTML = `<i class="${iconClass}"></i>${message}`;
        } else {
            messageElement.textContent = message;
        }
        logElement.appendChild(messageElement);
        logElement.scrollTop = logElement.scrollHeight;
    }
}); 