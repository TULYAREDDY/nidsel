// Create network grid
function createNetworkGrid() {
    const grid = document.createElement('div');
    grid.className = 'network-grid';
    document.body.appendChild(grid);
}

// Create network nodes and lines
function createNetworkElements() {
    const container = document.querySelector('.network-grid');
    const nodeCount = 20;
    const nodes = [];

    // Create nodes
    for (let i = 0; i < nodeCount; i++) {
        const node = document.createElement('div');
        node.className = 'network-node';
        node.style.left = `${Math.random() * 100}%`;
        node.style.top = `${Math.random() * 100}%`;
        container.appendChild(node);
        nodes.push(node);
    }

    // Create lines between nodes
    nodes.forEach((node, index) => {
        if (index < nodes.length - 1) {
            const line = document.createElement('div');
            line.className = 'network-line';
            
            const nodeRect = node.getBoundingClientRect();
            const nextNodeRect = nodes[index + 1].getBoundingClientRect();
            
            const angle = Math.atan2(
                nextNodeRect.top - nodeRect.top,
                nextNodeRect.left - nodeRect.left
            );
            
            const length = Math.hypot(
                nextNodeRect.left - nodeRect.left,
                nextNodeRect.top - nodeRect.top
            );
            
            line.style.width = `${length}px`;
            line.style.left = `${nodeRect.left}px`;
            line.style.top = `${nodeRect.top + nodeRect.height / 2}px`;
            line.style.transform = `rotate(${angle}rad)`;
            
            container.appendChild(line);
        }
    });
}

// Create floating particles
function createParticles() {
    const container = document.body;
    const particleCount = 50;

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = `${Math.random() * 100}%`;
        particle.style.animationDelay = `${Math.random() * 15}s`;
        container.appendChild(particle);
    }
}

// Update active navigation link based on scroll position
function updateActiveNavLink() {
    const sections = document.querySelectorAll('section, footer');
    const navLinks = document.querySelectorAll('.nav-links a');
    
    let currentSection = '';
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (window.scrollY >= (sectionTop - 100)) {
            currentSection = section.getAttribute('id');
        }
    });

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href').slice(1) === currentSection) {
            link.classList.add('active');
        }
    });
}

// Initialize animations and event listeners
document.addEventListener('DOMContentLoaded', () => {
    createNetworkGrid();
    createNetworkElements();
    createParticles();
    
    // Add scroll event listener for navigation
    window.addEventListener('scroll', updateActiveNavLink);
});

// Update network elements on window resize
let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        const grid = document.querySelector('.network-grid');
        if (grid) {
            grid.innerHTML = '';
            createNetworkElements();
        }
    }, 250);
}); 